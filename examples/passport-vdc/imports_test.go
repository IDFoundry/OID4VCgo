// Package passportvdc_test holds module-wide checks for the demo.
package passportvdc_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestUsesOnlyPublicLibraryPackages: the demo is how an integrator would
// build on the library, so it must not import the library's internal
// packages — Go only allows it here because this module's path happens
// to sit under github.com/idfoundry/oid4vcgo.
func TestUsesOnlyPublicLibraryPackages(t *testing.T) {
	const internalPrefix = "github.com/idfoundry/oid4vcgo/internal/"
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") && path != "." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); strings.HasPrefix(p, internalPrefix) {
				t.Errorf("%s imports %s, which an integrator's module can't", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
