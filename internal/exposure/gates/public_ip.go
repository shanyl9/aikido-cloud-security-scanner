package gates

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Gate 3: the instance needs a public IPv4 address or an Elastic IP.

func CheckPublicIP(inst types.Instance) Step {
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
