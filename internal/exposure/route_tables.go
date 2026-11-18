package exposure

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/shanyl9/aikido-cloud-security-scanner/internal/snapshot"
)

// Gate 4: the subnet's route table must send internet traffic to an internet
// gateway. A NAT gateway only allows outbound connections, so it does not count.

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
