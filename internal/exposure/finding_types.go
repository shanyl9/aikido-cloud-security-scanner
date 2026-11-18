package exposure

import "github.com/shanyl9/aikido-cloud-security-scanner/internal/exposure/gates"

// Types of the verdict and report.

// Status is the verdict for one instance and port.
type Status string

const (
	Exposed    Status = "EXPOSED"
	NotExposed Status = "NOT_EXPOSED"
	// Unknown means no layer was seen blocking, but at least one could not be
	// evaluated. It is reported, never silently treated as safe.
	Unknown Status = "UNKNOWN"
)

// Port is an administrative port the check looks for.
type Port struct {
	Number  int
	Service string
}

// DefaultPorts are remote-administration ports that should never face the internet.
var DefaultPorts = []Port{{22, "SSH"}, {3389, "RDP"}}

// Finding is the outcome for one instance and port whose security group is open to the internet.
type Finding struct {
	AccountID   string       `json:"account_id"`
	InstanceID  string       `json:"instance_id"`
	Name        string       `json:"name,omitempty"`
	Port        int          `json:"port"`
	Service     string       `json:"service"`
	Status      Status       `json:"status"`
	Severity    string       `json:"severity"`
	Summary     string       `json:"summary"`
	Evidence    []gates.Step `json:"evidence"`
	Remediation []string     `json:"remediation,omitempty"`
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
