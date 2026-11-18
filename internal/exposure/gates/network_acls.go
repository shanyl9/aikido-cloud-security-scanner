package gates

import (
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/shanyl9/aikido-cloud-security-scanner/internal/snapshot"
)

// Gates 5 and 6: the subnet's network ACL must allow the inbound connection and,
// because NACLs are stateless, the reply back to the client's ephemeral port.

const (
	ephemeralFrom = 1024
	ephemeralTo   = 65535
)

func naclFor(acls []types.NetworkAcl, subnetID string) *types.NetworkAcl {
	for i, a := range acls {
		for _, as := range a.Associations {
			if aws.ToString(as.SubnetId) == subnetID {
				return &acls[i]
			}
		}
	}
	return nil
}

// firstMatch returns the lowest-numbered NACL entry that applies to TCP traffic
// on port to/from an arbitrary internet address. NACLs are evaluated in rule
// number order and the first match wins. Entries scoped to a narrower CIDR are
// skipped: they do not apply to an arbitrary internet client.
func firstMatch(acl *types.NetworkAcl, egress bool, port int) *types.NetworkAclEntry {
	entries := append([]types.NetworkAclEntry(nil), acl.Entries...)
	sort.Slice(entries, func(i, j int) bool { return aws.ToInt32(entries[i].RuleNumber) < aws.ToInt32(entries[j].RuleNumber) })
	for i, e := range entries {
		if aws.ToBool(e.Egress) != egress || !isInternet(aws.ToString(e.CidrBlock)) {
			continue
		}
		switch aws.ToString(e.Protocol) {
		case "-1":
			return &entries[i]
		case "6":
			if e.PortRange == nil || (int(aws.ToInt32(e.PortRange.From)) <= port && port <= int(aws.ToInt32(e.PortRange.To))) {
				return &entries[i]
			}
		}
	}
	return nil
}

func describeEntry(e *types.NetworkAclEntry) string {
	ports := "all ports"
	if e.PortRange != nil {
		ports = fmt.Sprintf("ports %d-%d", aws.ToInt32(e.PortRange.From), aws.ToInt32(e.PortRange.To))
	}
	proto := map[string]string{"-1": "all protocols", "6": "tcp"}[aws.ToString(e.Protocol)]
	if proto == "" {
		proto = "protocol " + aws.ToString(e.Protocol)
	}
	return fmt.Sprintf("rule #%d (%s %s, %s)", aws.ToInt32(e.RuleNumber), e.RuleAction, proto, ports)
}

// CheckNACL evaluates both directions: inbound to the port, and outbound for the
// reply. NACLs are stateless, so the reply to the client's ephemeral port
// (1024-65535) must be allowed explicitly.
func CheckNACL(s *snapshot.Snapshot, inst types.Instance, port int) (in, out Step) {
	subnet := aws.ToString(inst.SubnetId)
	in = Step{Layer: LayerNACLInbound, Resource: subnet}
	out = Step{Layer: LayerNACLOutbound, Resource: subnet}
	if !s.Has(snapshot.NetworkAcls) {
		in.Result, in.Detail = Unknown, s.Gap(snapshot.NetworkAcls)
		out.Result, out.Detail = Unknown, s.Gap(snapshot.NetworkAcls)
		return in, out
	}
	acl := naclFor(s.NetworkAcls, subnet)
	if acl == nil {
		in.Result, in.Detail = Unknown, "no network ACL association found for "+subnet
		out.Result, out.Detail = in.Result, in.Detail
		return in, out
	}
	id := aws.ToString(acl.NetworkAclId)
	in.Resource, out.Resource = id, id

	if e := firstMatch(acl, false, port); e != nil && e.RuleAction == types.RuleActionAllow {
		in.Result, in.Detail = Open, fmt.Sprintf("%s: %s from 0.0.0.0/0", id, describeEntry(e))
	} else if e != nil {
		in.Result, in.Detail = Blocked, fmt.Sprintf("%s: %s from 0.0.0.0/0 matches tcp/%d first", id, describeEntry(e), port)
	} else {
		in.Result, in.Detail = Blocked, fmt.Sprintf("%s: no inbound rule allows tcp/%d", id, port)
	}

	// Count allowed reply ports. A simple scan is fine for a PoC; a production
	// version would intersect port intervals instead.
	allowed, firstAllow := 0, (*types.NetworkAclEntry)(nil)
	for p := ephemeralFrom; p <= ephemeralTo; p++ {
		if e := firstMatch(acl, true, p); e != nil && e.RuleAction == types.RuleActionAllow {
			allowed++
			if firstAllow == nil {
				firstAllow = e
			}
		}
	}
	total := ephemeralTo - ephemeralFrom + 1
	switch {
	case allowed == total:
		out.Result, out.Detail = Open, fmt.Sprintf("%s: %s permits replies to ephemeral ports %d-%d", id, describeEntry(firstAllow), ephemeralFrom, ephemeralTo)
	case allowed > 0:
		out.Result, out.Detail = Open, fmt.Sprintf("%s: only %d of %d ephemeral reply ports allowed; clients using those ports can connect", id, allowed, total)
	default:
		out.Result, out.Detail = Blocked, fmt.Sprintf("%s: no outbound rule allows replies to ephemeral ports %d-%d (NACLs are stateless)", id, ephemeralFrom, ephemeralTo)
	}
	return in, out
}
