package gates

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

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
			if _, _, got := WorldOpenRule(c.sg, 22); got != c.want {
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
