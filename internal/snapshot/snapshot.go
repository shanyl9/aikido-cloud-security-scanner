// Package snapshot loads a point-in-time copy of an AWS account's EC2 network
// configuration. Each dataset is the raw response of one read-only EC2 API call,
// decoded into the official aws-sdk-go-v2 types, so a live collector can produce
// the same Snapshot without changing the checks.
package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Dataset names one collected API response.
type Dataset string

const (
	Instances      Dataset = "DescribeInstances"
	SecurityGroups Dataset = "DescribeSecurityGroups"
	RouteTables    Dataset = "DescribeRouteTables"
	NetworkAcls    Dataset = "DescribeNetworkAcls"
)

var files = map[Dataset]string{
	Instances:      "describe-instances.json",
	SecurityGroups: "describe-security-groups.json",
	RouteTables:    "describe-route-tables.json",
	NetworkAcls:    "describe-network-acls.json",
}

// CollectionError records an API call that failed while collecting the snapshot
// (typically a missing IAM permission).
type CollectionError struct {
	Operation string `json:"Operation"`
	Action    string `json:"Action"`
	Code      string `json:"Code"`
	Message   string `json:"Message"`
}

// Snapshot is everything the checks may look at. A dataset that could not be
// collected is absent from loaded; checks must treat it as unknown, never as empty.
type Snapshot struct {
	Dir            string
	AccountID      string
	Instances      []types.Instance
	SecurityGroups map[string]types.SecurityGroup // by GroupId
	RouteTables    []types.RouteTable
	NetworkAcls    []types.NetworkAcl
	Errors         map[Dataset]CollectionError

	loaded map[Dataset]bool
}

// Has reports whether a dataset was collected.
func (s *Snapshot) Has(d Dataset) bool { return s.loaded[d] }

// Gap explains why a dataset is missing.
func (s *Snapshot) Gap(d Dataset) string {
	if e, ok := s.Errors[d]; ok {
		return fmt.Sprintf("%s failed with %s (scanner needs %s)", d, e.Code, e.Action)
	}
	return fmt.Sprintf("%s was not collected", d)
}

// LoadDir reads a fixture directory laid out like fixtures/demo.
func LoadDir(dir string) (*Snapshot, error) {
	s := &Snapshot{
		Dir:            dir,
		SecurityGroups: map[string]types.SecurityGroup{},
		Errors:         map[Dataset]CollectionError{},
		loaded:         map[Dataset]bool{},
	}

	var errFile struct{ Errors []CollectionError }
	if ok, err := readJSON(filepath.Join(dir, "errors.json"), &errFile); err != nil {
		return nil, err
	} else if ok {
		for _, e := range errFile.Errors {
			s.Errors[Dataset(e.Operation)] = e
		}
	}

	var inst ec2.DescribeInstancesOutput
	var sgs ec2.DescribeSecurityGroupsOutput
	var rts ec2.DescribeRouteTablesOutput
	var acls ec2.DescribeNetworkAclsOutput
	targets := map[Dataset]any{Instances: &inst, SecurityGroups: &sgs, RouteTables: &rts, NetworkAcls: &acls}

	for d, v := range targets {
		ok, err := readJSON(filepath.Join(dir, files[d]), v)
		if err != nil {
			return nil, err
		}
		s.loaded[d] = ok
	}

	if !s.Has(Instances) {
		return nil, fmt.Errorf("cannot evaluate %s: %s", dir, s.Gap(Instances))
	}
	for _, r := range inst.Reservations {
		if s.AccountID == "" {
			s.AccountID = aws.ToString(r.OwnerId)
		}
		s.Instances = append(s.Instances, r.Instances...)
	}
	for _, g := range sgs.SecurityGroups {
		s.SecurityGroups[aws.ToString(g.GroupId)] = g
	}
	s.RouteTables = rts.RouteTables
	s.NetworkAcls = acls.NetworkAcls
	return s, nil
}

// readJSON decodes path into v. A missing file is not an error: it returns false.
func readJSON(path string, v any) (bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("decode %s: %w", path, err)
	}
	return true, nil
}
