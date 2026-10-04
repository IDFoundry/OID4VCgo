package oid4vci_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestExamplesUseOnlyPublicPackages: a godoc example is code an
// integrator copies, so it mustn't import this module's internal
// packages, which their module can't.
func TestExamplesUseOnlyPublicPackages(t *testing.T) {
	const internalPrefix = "github.com/idfoundry/oid4vcgo/internal/"
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != "." && (strings.HasPrefix(d.Name(), ".") || d.Name() == "internal" || d.Name() == "examples") {
			return filepath.SkipDir // examples has its own check
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "example") || !strings.HasSuffix(path, "_test.go") {
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
