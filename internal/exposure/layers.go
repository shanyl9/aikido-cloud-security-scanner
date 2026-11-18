package exposure

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/shanyl9/aikido-cloud-security-scanner/internal/snapshot"
)

// Each function below evaluates one layer of the path an internet client's
// packet takes to reach tcp/<port> on an instance, and the path of the reply.
// A layer returns Open, Blocked or Unknown plus the evidence for that verdict.

const (
	ephemeralFrom = 1024
	ephemeralTo   = 65535
)

// isInternet reports whether a CIDR covers the whole IPv4 internet (prefix length 0).
func isInternet(cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	return err == nil && p.Addr().Is4() && p.Bits() == 0
}

// --- instance state ---------------------------------------------------------

func checkState(inst types.Instance) Step {
	st := Step{Layer: LayerState, Resource: aws.ToString(inst.InstanceId)}
	name := types.InstanceStateName("")
	if inst.State != nil {
		name = inst.State.Name
	}
	st.Detail = string(name)
	if name == types.InstanceStateNameRunning {
		st.Result = Open
	} else {
		st.Result = Blocked
		st.Detail += " (not reachable while not running)"
	}
	return st
}

// --- security groups --------------------------------------------------------

// instanceGroupIDs returns every security group attached to the instance, from
// the instance itself and from each of its network interfaces.
func instanceGroupIDs(inst types.Instance) []string {
	seen := map[string]bool{}
	for _, g := range inst.SecurityGroups {
		seen[aws.ToString(g.GroupId)] = true
	}
	for _, eni := range inst.NetworkInterfaces {
		for _, g := range eni.Groups {
			seen[aws.ToString(g.GroupId)] = true
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// worldOpenRule finds an ingress rule in g that lets any IPv4 address reach tcp/port.
func worldOpenRule(g types.SecurityGroup, port int) (types.IpPermission, string, bool) {
	for _, p := range g.IpPermissions {
		proto := aws.ToString(p.IpProtocol)
		portOK := false
		switch proto {
		case "-1": // all traffic
			portOK = true
		case "tcp", "6":
			portOK = int(aws.ToInt32(p.FromPort)) <= port && port <= int(aws.ToInt32(p.ToPort))
		}
		if !portOK {
			continue
		}
		for _, r := range p.IpRanges {
			if cidr := aws.ToString(r.CidrIp); isInternet(cidr) {
				return p, cidr, true
			}
		}
	}
	return types.IpPermission{}, "", false
}

func describePermission(p types.IpPermission, cidr string) string {
	if aws.ToString(p.IpProtocol) == "-1" {
		return "all traffic from " + cidr
	}
	return fmt.Sprintf("tcp %d-%d from %s", aws.ToInt32(p.FromPort), aws.ToInt32(p.ToPort), cidr)
}

// checkSecurityGroups returns the open step and the matching group, if any.
// ok=false means no attached group opens the port to the internet: not a candidate.
func checkSecurityGroups(s *snapshot.Snapshot, inst types.Instance, port int) (step Step, sg *types.SecurityGroup, perm types.IpPermission, cidr string, ok bool) {
	step = Step{Layer: LayerSecurityGroup}
	ids := instanceGroupIDs(inst)
	if !s.Has(snapshot.SecurityGroups) {
		step.Result, step.Resource = UnknownResult, strings.Join(ids, ",")
		step.Detail = s.Gap(snapshot.SecurityGroups)
		return step, nil, perm, "", true
	}
	for _, id := range ids {
		g, found := s.SecurityGroups[id]
		if !found {
			continue
		}
		if p, c, open := worldOpenRule(g, port); open {
			step.Result, step.Resource = Open, id
			step.Detail = fmt.Sprintf("%s (%s) allows %s", id, aws.ToString(g.GroupName), describePermission(p, c))
			return step, &g, p, c, true
		}
	}
	return step, nil, perm, "", false
}

// --- public IP --------------------------------------------------------------

func checkPublicIP(inst types.Instance) Step {
	st := Step{Layer: LayerPublicIP, Resource: aws.ToString(inst.InstanceId)}
	ip := aws.ToString(inst.PublicIpAddress)
	if ip == "" {
		for _, eni := range inst.NetworkInterfaces {
			if eni.Association != nil && aws.ToString(eni.Association.PublicIp) != "" {
				ip = aws.ToString(eni.Association.PublicIp)
				break
			}
		}
	}
	if ip == "" {
		st.Result, st.Detail = Blocked, "no public IPv4 address or Elastic IP"
		return st
	}
	st.Result, st.Detail = Open, ip
	for _, eni := range inst.NetworkInterfaces {
		if eni.Association != nil && aws.ToString(eni.Association.PublicIp) == ip &&
			aws.ToString(eni.Association.IpOwnerId) != "amazon" {
			st.Detail += " (Elastic IP)"
		}
	}
	return st
}

// --- route table ------------------------------------------------------------

// routeTableFor returns the subnet's explicitly associated route table, falling
// back to the VPC's main route table, which applies to every subnet without one.
func routeTableFor(rts []types.RouteTable, vpcID, subnetID string) (*types.RouteTable, string) {
	for i, rt := range rts {
		for _, a := range rt.Associations {
			if aws.ToString(a.SubnetId) == subnetID {
				return &rts[i], "explicit subnet association"
			}
		}
	}
	for i, rt := range rts {
		if aws.ToString(rt.VpcId) != vpcID {
			continue
		}
		for _, a := range rt.Associations {
			if aws.ToBool(a.Main) {
				return &rts[i], "VPC main route table (subnet has no explicit association)"
			}
		}
	}
	return nil, ""
}

func routeTarget(r types.Route) string {
	for _, t := range []*string{r.GatewayId, r.NatGatewayId, r.TransitGatewayId, r.VpcPeeringConnectionId,
		r.NetworkInterfaceId, r.InstanceId, r.EgressOnlyInternetGatewayId, r.LocalGatewayId} {
		if v := aws.ToString(t); v != "" {
			return v
		}
	}
	return "unknown target"
}

func checkRoute(s *snapshot.Snapshot, inst types.Instance) Step {
	subnet := aws.ToString(inst.SubnetId)
	st := Step{Layer: LayerRoute, Resource: subnet}
	if !s.Has(snapshot.RouteTables) {
		st.Result, st.Detail = UnknownResult, s.Gap(snapshot.RouteTables)
		return st
	}
	rt, how := routeTableFor(s.RouteTables, aws.ToString(inst.VpcId), subnet)
	if rt == nil {
		st.Result, st.Detail = UnknownResult, "no route table found for "+subnet
		return st
	}
	st.Resource = aws.ToString(rt.RouteTableId)

	var defaultRoute *types.Route
	var partialIGW []string
	for i, r := range rt.Routes {
		if r.State == types.RouteStateBlackhole {
			continue
		}
		dest := aws.ToString(r.DestinationCidrBlock)
		toIGW := strings.HasPrefix(aws.ToString(r.GatewayId), "igw-")
		if isInternet(dest) {
			defaultRoute = &rt.Routes[i]
		} else if toIGW {
			partialIGW = append(partialIGW, dest)
		}
	}
	switch {
	case defaultRoute != nil && strings.HasPrefix(aws.ToString(defaultRoute.GatewayId), "igw-"):
		st.Result = Open
		st.Detail = fmt.Sprintf("%s via %s: 0.0.0.0/0 -> %s", st.Resource, how, aws.ToString(defaultRoute.GatewayId))
	case len(partialIGW) > 0:
		// Only some internet ranges route back via the IGW; those clients can still connect.
		st.Result = Open
		st.Detail = fmt.Sprintf("%s via %s: internet gateway reachable only for %s", st.Resource, how, strings.Join(partialIGW, ", "))
	case defaultRoute != nil:
		st.Result = Blocked
		st.Detail = fmt.Sprintf("%s via %s: 0.0.0.0/0 -> %s (not an internet gateway; outbound-only or private path)", st.Resource, how, routeTarget(*defaultRoute))
	default:
		st.Result = Blocked
		st.Detail = fmt.Sprintf("%s via %s: no route to an internet gateway", st.Resource, how)
	}
	return st
}

// --- network ACL ------------------------------------------------------------

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

// checkNACL evaluates both directions: inbound to the port, and outbound for the
// reply. NACLs are stateless, so the reply to the client's ephemeral port
// (1024-65535) must be allowed explicitly.
func checkNACL(s *snapshot.Snapshot, inst types.Instance, port int) (in, out Step) {
	subnet := aws.ToString(inst.SubnetId)
	in = Step{Layer: LayerNACLInbound, Resource: subnet}
	out = Step{Layer: LayerNACLOutbound, Resource: subnet}
	if !s.Has(snapshot.NetworkAcls) {
		in.Result, in.Detail = UnknownResult, s.Gap(snapshot.NetworkAcls)
		out.Result, out.Detail = UnknownResult, s.Gap(snapshot.NetworkAcls)
		return in, out
	}
	acl := naclFor(s.NetworkAcls, subnet)
	if acl == nil {
		in.Result, in.Detail = UnknownResult, "no network ACL association found for "+subnet
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
