package gates

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/shanyl9/aikido-cloud-security-scanner/internal/snapshot"
)

// Gate 2: an attached security group must allow tcp/<port> from the whole internet.
// Instances without such a rule are not candidates and produce no result.

// InstanceGroupIDs returns every security group attached to the instance, from
// the instance itself and from each of its network interfaces.
func InstanceGroupIDs(inst types.Instance) []string {
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

// WorldOpenRule finds an ingress rule in g that lets any IPv4 address reach tcp/port.
func WorldOpenRule(g types.SecurityGroup, port int) (types.IpPermission, string, bool) {
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

func DescribePermission(p types.IpPermission, cidr string) string {
	if aws.ToString(p.IpProtocol) == "-1" {
		return "all traffic from " + cidr
	}
	return fmt.Sprintf("tcp %d-%d from %s", aws.ToInt32(p.FromPort), aws.ToInt32(p.ToPort), cidr)
}

// CheckSecurityGroups returns the open step and the matching group, if any.
// ok=false means no attached group opens the port to the internet: not a candidate.
func CheckSecurityGroups(s *snapshot.Snapshot, inst types.Instance, port int) (step Step, sg *types.SecurityGroup, perm types.IpPermission, cidr string, ok bool) {
	step = Step{Layer: LayerSecurityGroup}
	ids := InstanceGroupIDs(inst)
	if !s.Has(snapshot.SecurityGroups) {
		step.Result, step.Resource = Unknown, strings.Join(ids, ",")
		step.Detail = s.Gap(snapshot.SecurityGroups)
		return step, nil, perm, "", true
	}
	for _, id := range ids {
		g, found := s.SecurityGroups[id]
		if !found {
			continue
		}
		if p, c, open := WorldOpenRule(g, port); open {
			step.Result, step.Resource = Open, id
			step.Detail = fmt.Sprintf("%s (%s) allows %s", id, aws.ToString(g.GroupName), DescribePermission(p, c))
			return step, &g, p, c, true
		}
	}
	return step, nil, perm, "", false
}
