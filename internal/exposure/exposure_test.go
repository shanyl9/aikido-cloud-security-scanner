package exposure

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/shanyl9/aikido-cloud-security-scanner/internal/snapshot"
)

const fixtures = "../../fixtures"

func load(t *testing.T, dir string) *snapshot.Snapshot {
	t.Helper()
	s, err := snapshot.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func byInstance(rep Report) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range rep.Findings {
		m[f.InstanceID] = f
	}
	return m
}

func stepFor(f Finding, layer string) Step {
	for _, s := range f.Evidence {
		if s.Layer == layer {
			return s
		}
	}
	return Step{}
}

// Every demo instance has the same internet-open security group; each differs
// from the exposed baseline by one control. See fixtures/README.md.
func TestDemoSnapshot(t *testing.T) {
	rep := Evaluate(load(t, filepath.Join(fixtures, "demo")), DefaultPorts)
	got := byInstance(rep)

	cases := []struct {
		instance  string
		want      Status
		severity  string
		blockedAt string // layer expected to block, if any
	}{
		{"i-0exposed000000001", Exposed, "HIGH", ""},
		{"i-0mainrt0000000001", Exposed, "HIGH", ""},
		{"i-0nopublicip000001", NotExposed, "NONE", LayerPublicIP},
		{"i-0natsubnet0000001", NotExposed, "NONE", LayerRoute},
		{"i-0nacldeny00000001", NotExposed, "NONE", LayerNACLInbound},
		{"i-0naclnoeph0000001", NotExposed, "NONE", LayerNACLOutbound},
		{"i-0stopped000000001", NotExposed, "INFO", LayerState},
	}
	if len(rep.Findings) != len(cases) {
		t.Fatalf("got %d findings, want %d", len(rep.Findings), len(cases))
	}
	for _, c := range cases {
		t.Run(c.instance, func(t *testing.T) {
			f, ok := got[c.instance]
			if !ok {
				t.Fatal("no result")
			}
			if f.Status != c.want || f.Severity != c.severity {
				t.Fatalf("got %s/%s, want %s/%s: %s", f.Status, f.Severity, c.want, c.severity, f.Summary)
			}
			if c.blockedAt != "" && stepFor(f, c.blockedAt).Result != Blocked {
				t.Errorf("expected %s to be BLOCKED, evidence: %+v", c.blockedAt, f.Evidence)
			}
			if len(f.Evidence) != 6 {
				t.Errorf("expected evidence for all 6 layers, got %d", len(f.Evidence))
			}
			if f.Status == Exposed && len(f.Remediation) == 0 {
				t.Error("exposed finding without remediation")
			}
		})
	}

	if len(rep.IgnoredGroups) != 1 || rep.IgnoredGroups[0].GroupID != "sg-0orphan0open00001" {
		t.Errorf("orphan open security group should be listed as ignored, got %+v", rep.IgnoredGroups)
	}
	if len(rep.DataGaps) != 0 {
		t.Errorf("unexpected data gaps: %v", rep.DataGaps)
	}
}

func TestMissingPermissionIsUnknownNotSafe(t *testing.T) {
	rep := Evaluate(load(t, filepath.Join(fixtures, "missing-permissions")), DefaultPorts)
	if len(rep.Findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(rep.Findings))
	}
	f := rep.Findings[0]
	if f.Status != Unknown {
		t.Fatalf("got %s, want UNKNOWN", f.Status)
	}
	if st := stepFor(f, LayerNACLInbound); st.Result != UnknownResult {
		t.Errorf("nacl-inbound should be UNKNOWN, got %+v", st)
	}
	if len(rep.DataGaps) != 1 {
		t.Errorf("want the denied DescribeNetworkAcls listed as a data gap, got %v", rep.DataGaps)
	}
}

// A layer we can see blocking is enough for NOT_EXPOSED, even if another
// layer's data is missing.
func TestKnownBlockWinsOverMissingData(t *testing.T) {
	src := filepath.Join(fixtures, "missing-permissions")
	dir := t.TempDir()
	for _, f := range []string{"describe-security-groups.json", "describe-route-tables.json", "errors.json"} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Same instance, but without a public IP.
	var out ec2.DescribeInstancesOutput
	b, _ := os.ReadFile(filepath.Join(src, "describe-instances.json"))
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	inst := &out.Reservations[0].Instances[0]
	inst.PublicIpAddress = nil
	for i := range inst.NetworkInterfaces {
		inst.NetworkInterfaces[i].Association = nil
	}
	b, _ = json.Marshal(out)
	if err := os.WriteFile(filepath.Join(dir, "describe-instances.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	f := Evaluate(load(t, dir), DefaultPorts).Findings[0]
	if f.Status != NotExposed {
		t.Fatalf("got %s, want NOT_EXPOSED: %s", f.Status, f.Summary)
	}
}

func TestSecurityGroupRuleMatching(t *testing.T) {
	perm := func(proto string, from, to int32, cidr string) types.SecurityGroup {
		p := types.IpPermission{IpProtocol: aws.String(proto), IpRanges: []types.IpRange{{CidrIp: aws.String(cidr)}}}
		if proto != "-1" {
			p.FromPort, p.ToPort = aws.Int32(from), aws.Int32(to)
		}
		return types.SecurityGroup{IpPermissions: []types.IpPermission{p}}
	}
	cases := []struct {
		name string
		sg   types.SecurityGroup
		want bool
	}{
		{"exact port from anywhere", perm("tcp", 22, 22, "0.0.0.0/0"), true},
		{"port range covering 22", perm("tcp", 0, 65535, "0.0.0.0/0"), true},
		{"all traffic", perm("-1", 0, 0, "0.0.0.0/0"), true},
		{"numeric tcp protocol", perm("6", 22, 22, "0.0.0.0/0"), true},
		{"other port", perm("tcp", 443, 443, "0.0.0.0/0"), false},
		{"restricted source", perm("tcp", 22, 22, "198.51.100.0/24"), false},
		{"udp", perm("udp", 22, 22, "0.0.0.0/0"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, got := worldOpenRule(c.sg, 22); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestNACLFirstMatchWinsRegardlessOfListOrder(t *testing.T) {
	entry := func(n int32, action types.RuleAction, proto string, ports *types.PortRange) types.NetworkAclEntry {
		return types.NetworkAclEntry{RuleNumber: aws.Int32(n), RuleAction: action, Protocol: aws.String(proto),
			PortRange: ports, CidrBlock: aws.String("0.0.0.0/0"), Egress: aws.Bool(false)}
	}
	ssh := &types.PortRange{From: aws.Int32(22), To: aws.Int32(22)}
	acl := &types.NetworkAcl{Entries: []types.NetworkAclEntry{
		entry(100, types.RuleActionAllow, "-1", nil), // listed first, but higher number
		entry(90, types.RuleActionDeny, "6", ssh),
	}}
	if e := firstMatch(acl, false, 22); e == nil || aws.ToInt32(e.RuleNumber) != 90 {
		t.Fatalf("rule 90 must match before 100, got %+v", e)
	}
	if e := firstMatch(acl, false, 443); e == nil || aws.ToInt32(e.RuleNumber) != 100 {
		t.Fatalf("port 443 should fall through to rule 100, got %+v", e)
	}
}
