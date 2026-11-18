package gates

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Gate 1: an instance that is not running cannot be reached.

func CheckState(inst types.Instance) Step {
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
