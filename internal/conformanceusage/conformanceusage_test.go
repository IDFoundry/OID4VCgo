package conformanceusage_test

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformanceusage"
)

func TestSet(t *testing.T) {
	saved, savedUsage := flag.CommandLine, flag.Usage
	t.Cleanup(func() { flag.CommandLine, flag.Usage = saved, savedUsage })

	var out bytes.Buffer
	flag.CommandLine = flag.NewFlagSet("harness", flag.ContinueOnError)
	flag.CommandLine.SetOutput(&out)
	flag.String("config", "", "path to the JSON config file")

	conformanceusage.Set("harness -config <file>", "A test harness, not a deployment model.")
	flag.Usage()

	got := out.String()
	for _, want := range []string{
		"usage: harness -config <file>\n\nA test harness, not a deployment model.\n\n",
		"-config string",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("usage %q doesn't contain %q", got, want)
		}
	}
	if !strings.HasPrefix(got, "usage: ") {
		t.Errorf("usage %q doesn't start with the synopsis", got)
	}
}
