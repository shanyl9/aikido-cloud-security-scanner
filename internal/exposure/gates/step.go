// Package gates holds one check per AWS control that an internet client's
// packet meets on its way to an instance (and the reply on its way back).
// Each gate returns a Step: OPEN, BLOCKED or UNKNOWN plus the evidence.
// Gates never decide the final verdict; package exposure does.
package gates

import "net/netip"

// Result is the verdict of one gate.
type Result string

const (
	Open    Result = "OPEN"
	Blocked Result = "BLOCKED"
	Unknown Result = "UNKNOWN" // the layer's data could not be collected
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

// isInternet reports whether a CIDR covers the whole IPv4 internet (prefix length 0).
func isInternet(cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	return err == nil && p.Addr().Is4() && p.Bits() == 0
}
