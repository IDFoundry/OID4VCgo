package oid4vci_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestExportedDeclarationsUsePublicTypes: an exported function, method,
// struct field or interface method mustn't name a type from this
// module's internal packages — another module can't import it, so godoc
// would show a type its readers can't write. The root package's aliases
// (JOSEAlg, COSEAlg, JWEAlg, JWEEnc, JWEZip) name the same types. The
// root's JWK embeds internal/jwk.JWK, its one deliberate exception.
func TestExportedDeclarationsUsePublicTypes(t *testing.T) {
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch {
			case path == ".":
				return nil
			case strings.HasPrefix(d.Name(), "."), d.Name() == "internal", d.Name() == "cmd", d.Name() == "examples",
				d.Name() == "conformance", d.Name() == "mobile", d.Name() == "testdata", strings.HasPrefix(d.Name(), "_"):
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		checkExported(t, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func checkExported(t *testing.T, path string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	internal := map[string]bool{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if !strings.HasPrefix(p, "github.com/idfoundry/oid4vcgo/internal/") {
			continue
		}
		name := filepath.Base(p)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		internal[name] = true
	}
	if len(internal) == 0 {
		return
	}
	report := func(n ast.Node, what string) {
		ast.Inspect(n, func(m ast.Node) bool {
			if sel, ok := m.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && internal[id.Name] {
					t.Errorf("%s: %s names %s.%s", fset.Position(sel.Pos()), what, id.Name, sel.Sel.Name)
				}
			}
			return true
		})
	}
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Name.IsExported() && (d.Recv == nil || exportedReceiver(d.Recv)) {
				report(d.Type, d.Name.Name)
			}
		case *ast.GenDecl:
			if d.Tok != token.TYPE {
				continue
			}
			for _, s := range d.Specs {
				ts := s.(*ast.TypeSpec)
				if !ts.Name.IsExported() || ts.Assign != 0 {
					continue
				}
				checkExportedType(ts, report)
			}
		}
	}
}

func checkExportedType(ts *ast.TypeSpec, report func(ast.Node, string)) {
	switch tt := ts.Type.(type) {
	case *ast.StructType:
		for _, fld := range tt.Fields.List {
			if len(fld.Names) > 0 && fld.Names[0].IsExported() {
				report(fld.Type, ts.Name.Name+"."+fld.Names[0].Name)
			}
		}
	case *ast.InterfaceType:
		for _, m := range tt.Methods.List {
			if len(m.Names) > 0 && m.Names[0].IsExported() {
				report(m.Type, ts.Name.Name+"."+m.Names[0].Name)
			}
		}
	default:
		report(ts.Type, ts.Name.Name)
	}
}

func exportedReceiver(r *ast.FieldList) bool {
	t := r.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	id, ok := t.(*ast.Ident)
	return ok && id.IsExported()
}
