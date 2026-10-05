package haip_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// haip's recommendations are values an integrator copies into their own
// configuration, so they must be of types the integrator can name:
// nothing here may come from this module's internal packages, which
// another module can't import.
func TestUsesOnlyPublicTypes(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range parsed.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); strings.HasPrefix(p, "github.com/idfoundry/oid4vcgo/internal/") {
				t.Errorf("%s imports %s", f, p)
			}
		}
	}
}
