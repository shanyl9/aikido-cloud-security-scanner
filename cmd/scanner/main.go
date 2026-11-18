// Command scanner checks a snapshot of an AWS account for EC2 instances whose
// administrative ports are actually reachable from the internet.
//
//	go run ./cmd/scanner -snapshot fixtures/demo
//	go run ./cmd/scanner -snapshot fixtures/missing-permissions -format json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/shanyl9/aikido-cloud-security-scanner/internal/exposure"
	"github.com/shanyl9/aikido-cloud-security-scanner/internal/exposure/gates"
	"github.com/shanyl9/aikido-cloud-security-scanner/internal/snapshot"
)

func main() {
	dir := flag.String("snapshot", "fixtures/demo", "directory with describe-*.json files")
	format := flag.String("format", "text", "output format: text or json")
	portsFlag := flag.String("ports", "22:SSH,3389:RDP", "comma-separated port:service list to check")
	flag.Parse()

	ports, err := parsePorts(*portsFlag)
	if err != nil {
		fail(err)
	}
	snap, err := snapshot.LoadDir(*dir)
	if err != nil {
		fail(err)
	}
	rep := exposure.Evaluate(snap, ports)

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fail(err)
		}
	case "text":
		printText(os.Stdout, *dir, rep)
	default:
		fail(fmt.Errorf("unknown format %q", *format))
	}
}

func parsePorts(s string) ([]exposure.Port, error) {
	var out []exposure.Port
	for _, item := range strings.Split(s, ",") {
		num, svc, _ := strings.Cut(strings.TrimSpace(item), ":")
		n, err := strconv.Atoi(num)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", item)
		}
		if svc == "" {
			svc = "tcp/" + num
		}
		out = append(out, exposure.Port{Number: n, Service: svc})
	}
	return out, nil
}

var marks = map[gates.Result]string{gates.Open: "open   ", gates.Blocked: "BLOCKED", gates.Unknown: "unknown"}

func printText(w io.Writer, dir string, rep exposure.Report) {
	fmt.Fprintf(w, "Snapshot %s (account %s)\n", dir, rep.AccountID)
	fmt.Fprintf(w, "Check: is an administrative port actually reachable from the internet?\n\n")

	counts := map[exposure.Status]int{}
	for _, f := range rep.Findings {
		counts[f.Status]++
		name := f.InstanceID
		if f.Name != "" {
			name += " (" + f.Name + ")"
		}
		fmt.Fprintf(w, "%-11s [%s] %s  tcp/%d %s\n", f.Status, f.Severity, name, f.Port, f.Service)
		fmt.Fprintf(w, "  %s\n", f.Summary)
		for _, st := range f.Evidence {
			fmt.Fprintf(w, "    %s  %-15s %s\n", marks[st.Result], st.Layer, st.Detail)
		}
		if len(f.Remediation) > 0 {
			fmt.Fprintln(w, "  Remediation:")
			for _, r := range f.Remediation {
				fmt.Fprintf(w, "    - %s\n", r)
			}
		}
		fmt.Fprintln(w)
	}

	if len(rep.IgnoredGroups) > 0 {
		fmt.Fprintln(w, "Considered, no finding:")
		for _, g := range rep.IgnoredGroups {
			fmt.Fprintf(w, "  %s %s\n", g.GroupID, g.Reason)
		}
		fmt.Fprintln(w)
	}
	if len(rep.DataGaps) > 0 {
		fmt.Fprintln(w, "Data gaps (results depending on these are UNKNOWN, not safe):")
		for _, g := range rep.DataGaps {
			fmt.Fprintf(w, "  - %s\n", g)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Summary: %d exposed, %d unknown, %d not exposed (of %d %s)\n",
		counts[exposure.Exposed], counts[exposure.Unknown], counts[exposure.NotExposed], len(rep.Findings), plural(len(rep.Findings), "candidate", "candidates"))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
