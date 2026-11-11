// Package conformanceusage gives the cmd/conformance-* harnesses their
// -h text: a synopsis, what the harness is (a test harness for the OIDF
// conformance suite, never a deployment model), and its flags.
package conformanceusage

import (
	"flag"
	"fmt"
)

// Set makes flag.Usage print "usage: " and synopsis, then about, then
// the command line's flags.
func Set(synopsis, about string) {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "usage: %s\n\n%s\n\n", synopsis, about)
		flag.PrintDefaults()
	}
}
