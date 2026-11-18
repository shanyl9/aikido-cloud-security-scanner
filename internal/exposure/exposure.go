// Package exposure decides whether an EC2 instance is actually reachable from
// the internet on an administrative port. An open security group alone is not
// a finding: the packet must also get through the instance's public IP, the
// subnet's route table and the network ACL in both directions.
package exposure

import (
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/shanyl9/aikido-cloud-security-scanner/internal/snapshot"
)

// Status is the verdict for one instance and port.
type Status string

const (
	Exposed    Status = "EXPOSED"
	NotExposed Status = "NOT_EXPOSED"
	// Unknown means no layer was seen blocking, but at least one could not be
	// evaluated. It is reported, never silently treated as safe.
	Unknown Status = "UNKNOWN"
)

// Result is the verdict of one layer.
type Result string

const (
	Open          Result = "OPEN"
	Blocked       Result = "BLOCKED"
	UnknownResult Result = "UNKNOWN" // the layer's data could not be collected
)

// Layer names, in the order a packet meets them.
const (
	LayerState         = "instance-state"
	LayerSecurityGroup = "security-group"
	LayerPublicIP      = "public-ip"
	LayerRoute         = "route-table"
	LayerNACLInbound   = "nacl-inbound"
	LayerNACLOutbound  = "nacl-outbound"
)

// Step is the evidence for one layer.
type Step struct {
	Layer    string `json:"layer"`
	Result   Result `json:"result"`
	Resource string `json:"resource"`
	Detail   string `json:"detail"`
}

// Port is an administrative port the check looks for.
type Port struct {
	Number  int
	Service string
}

// DefaultPorts are remote-administration ports that should never face the internet.
var DefaultPorts = []Port{{22, "SSH"}, {3389, "RDP"}}

// Finding is the outcome for one instance and port whose security group is open to the internet.
type Finding struct {
	AccountID   string   `json:"account_id"`
	InstanceID  string   `json:"instance_id"`
	Name        string   `json:"name,omitempty"`
	Port        int      `json:"port"`
	Service     string   `json:"service"`
	Status      Status   `json:"status"`
	Severity    string   `json:"severity"`
	Summary     string   `json:"summary"`
	Evidence    []Step   `json:"evidence"`
	Remediation []string `json:"remediation,omitempty"`
}

// IgnoredGroup is a world-open security group that produced no finding.
type IgnoredGroup struct {
	GroupID string `json:"group_id"`
	Reason  string `json:"reason"`
}

// Report is the full result for one snapshot.
type Report struct {
	AccountID     string         `json:"account_id"`
	Findings      []Finding      `json:"findings"`
	IgnoredGroups []IgnoredGroup `json:"ignored_security_groups,omitempty"`
	DataGaps      []string       `json:"data_gaps,omitempty"`
}

// Evaluate runs the check over every instance in the snapshot.
func Evaluate(s *snapshot.Snapshot, ports []Port) Report {
	rep := Report{AccountID: s.AccountID}
	for _, d := range []snapshot.Dataset{snapshot.SecurityGroups, snapshot.RouteTables, snapshot.NetworkAcls} {
		if !s.Has(d) {
			rep.DataGaps = append(rep.DataGaps, s.Gap(d))
		}
	}

	attached := map[string]bool{}
	for _, inst := range s.Instances {
		for _, id := range instanceGroupIDs(inst) {
			attached[id] = true
		}
		for _, p := range ports {
			if f, ok := evaluateInstance(s, inst, p); ok {
				rep.Findings = append(rep.Findings, f)
			}
		}
	}

	// Open groups attached to nothing we can see are reported as ignored, so the
	// reader knows they were considered and why they are not findings.
	for id, g := range s.SecurityGroups {
		if attached[id] {
			continue
		}
		for _, p := range ports {
			if perm, cidr, open := worldOpenRule(g, p.Number); open {
				rep.IgnoredGroups = append(rep.IgnoredGroups, IgnoredGroup{
					GroupID: id,
					Reason: fmt.Sprintf("allows %s but is not attached to any EC2 instance in this snapshot (other resource types are not evaluated)",
						describePermission(perm, cidr)),
				})
				break
			}
		}
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		if rank(rep.Findings[i].Status) != rank(rep.Findings[j].Status) {
			return rank(rep.Findings[i].Status) < rank(rep.Findings[j].Status)
		}
		return rep.Findings[i].InstanceID < rep.Findings[j].InstanceID
	})
	sort.Slice(rep.IgnoredGroups, func(i, j int) bool { return rep.IgnoredGroups[i].GroupID < rep.IgnoredGroups[j].GroupID })
	return rep
}

func rank(s Status) int {
	return map[Status]int{Exposed: 0, Unknown: 1, NotExposed: 2}[s]
}

// evaluateInstance walks every layer and keeps all evidence, even after a layer
// blocks, so the output shows the full picture. ok=false means no attached
// security group opens the port, so the instance is not a candidate.
func evaluateInstance(s *snapshot.Snapshot, inst types.Instance, port Port) (Finding, bool) {
	sgStep, sg, perm, cidr, candidate := checkSecurityGroups(s, inst, port.Number)
	if !candidate {
		return Finding{}, false
	}
	nIn, nOut := checkNACL(s, inst, port.Number)
	steps := []Step{checkState(inst), sgStep, checkPublicIP(inst), checkRoute(s, inst), nIn, nOut}

	f := Finding{
		AccountID:  s.AccountID,
		InstanceID: aws.ToString(inst.InstanceId),
		Name:       nameTag(inst),
		Port:       port.Number,
		Service:    port.Service,
		Evidence:   steps,
	}

	var blocking []Step
	unknown := false
	for _, st := range steps {
		switch st.Result {
		case Blocked:
			blocking = append(blocking, st)
		case UnknownResult:
			unknown = true
		}
	}

	switch {
	case len(blocking) == 1 && blocking[0].Layer == LayerState && !unknown:
		// Every network layer is open; only the instance being stopped protects it.
		f.Status, f.Severity = NotExposed, "INFO"
		f.Summary = fmt.Sprintf("Not reachable now (instance is %s), but every network layer is open: it becomes exposed on %s as soon as it starts.", inst.State.Name, port.Service)
		f.Remediation = sgRemediation(sg, perm, cidr, port)
	case len(blocking) > 0:
		f.Status, f.Severity = NotExposed, "NONE"
		f.Summary = fmt.Sprintf("Security group is open to the internet on tcp/%d, but traffic is blocked at %s: %s", port.Number, blocking[0].Layer, blocking[0].Detail)
		if len(blocking) > 1 {
			f.Summary += fmt.Sprintf(" (and %d more layer(s))", len(blocking)-1)
		}
	case unknown:
		f.Status, f.Severity = Unknown, "UNVERIFIED"
		f.Summary = fmt.Sprintf("No layer was seen blocking tcp/%d, but some layers could not be evaluated. Treat as potentially exposed until verified.", port.Number)
		f.Remediation = []string{"Grant the scanner role the missing read-only permission(s) listed in the evidence, then rescan."}
		if sg != nil {
			f.Remediation = append(f.Remediation, sgRemediation(sg, perm, cidr, port)...)
		}
	default:
		f.Status, f.Severity = Exposed, "HIGH"
		f.Summary = fmt.Sprintf("%s (tcp/%d) is reachable from any internet address: every layer on the path allows it.", port.Service, port.Number)
		f.Remediation = append(sgRemediation(sg, perm, cidr, port),
			"Prefer AWS Systems Manager Session Manager or an EC2 Instance Connect Endpoint over a public "+port.Service+" port.",
			"If the instance does not need to be public, remove its public IP / Elastic IP or move it to a private subnet.")
	}
	return f, true
}

func sgRemediation(sg *types.SecurityGroup, perm types.IpPermission, cidr string, port Port) []string {
	if sg == nil {
		return nil
	}
	id := aws.ToString(sg.GroupId)
	if aws.ToString(perm.IpProtocol) == "-1" {
		return []string{fmt.Sprintf("Remove the all-traffic rule from %s and allow tcp/%d only from known ranges: aws ec2 revoke-security-group-ingress --group-id %s --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=%s}]'", id, port.Number, id, cidr)}
	}
	return []string{fmt.Sprintf("Restrict %s to known source ranges: aws ec2 revoke-security-group-ingress --group-id %s --protocol tcp --port %d-%d --cidr %s",
		id, id, aws.ToInt32(perm.FromPort), aws.ToInt32(perm.ToPort), cidr)}
}

func nameTag(inst types.Instance) string {
	for _, t := range inst.Tags {
		if aws.ToString(t.Key) == "Name" {
			return aws.ToString(t.Value)
		}
	}
	return ""
}
