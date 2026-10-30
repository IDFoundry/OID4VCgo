package sqlstore

import (
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var (
	tableNamePattern   = regexp.MustCompile(`oid4vc_[a-z_]+`)
	postgresParamRegex = regexp.MustCompile(`\$([0-9]+)`)
)

// statements are q's statements by field name.
func statements(q queries) map[string]string {
	v := reflect.ValueOf(q)
	out := make(map[string]string, v.NumField())
	for i := range v.NumField() {
		out[v.Type().Field(i).Name] = v.Field(i).String()
	}
	return out
}

// tableNames are the oid4vc_ names s mentions, sorted.
func tableNames(s string) []string {
	names := tableNamePattern.FindAllString(s, -1)
	slices.Sort(names)
	return slices.Compact(names)
}

// The two dialects' statements are the same statements: each is set in
// both, on the same tables, with the same arguments, and differs only
// in placeholders and Postgres's row locks.
func TestQueriesAreConsistent(t *testing.T) {
	sqlite, postgres := statements(sqliteQueries), statements(postgresQueries)
	for name, s := range sqlite {
		p := postgres[name]
		if s == "" || p == "" {
			t.Errorf("%s is empty: sqlite %q, postgres %q", name, s, p)
			continue
		}
		for _, stmt := range []string{s, p} {
			if strings.ContainsAny(stmt, "{}") {
				t.Errorf("%s holds a template: %q", name, stmt)
			}
		}
		if !slices.Equal(tableNames(s), tableNames(p)) || len(tableNames(s)) == 0 {
			t.Errorf("%s: tables %v in sqlite, %v in postgres", name, tableNames(s), tableNames(p))
		}
		if strings.Contains(s, "$") || strings.Contains(p, "?") {
			t.Errorf("%s: a placeholder of the other dialect: sqlite %q, postgres %q", name, s, p)
		}
		params := postgresParamRegex.FindAllStringSubmatch(p, -1)
		for i, m := range params {
			if m[1] != strconv.Itoa(i+1) {
				t.Errorf("%s: postgres placeholder %d is $%s, want $%d", name, i+1, m[1], i+1)
			}
		}
		if n := strings.Count(s, "?"); n != len(params) {
			t.Errorf("%s: %d sqlite placeholders, %d postgres", name, n, len(params))
		}
		asSQLite := strings.TrimSuffix(postgresParamRegex.ReplaceAllString(p, "?"), " FOR UPDATE")
		if asSQLite != s {
			t.Errorf("%s differs beyond placeholders and FOR UPDATE:\n sqlite   %s\n postgres %s", name, s, p)
		}
	}
}

// Every table a statement names is one the migrations create, in both
// dialects.
func TestQueriesNameMigratedTables(t *testing.T) {
	created := map[string][]string{}
	createPattern := regexp.MustCompile(`CREATE TABLE (oid4vc_[a-z_]+)`)
	for _, m := range migrations {
		for dialect, text := range map[string]string{"sqlite": m.sqlite, "postgres": m.postgres} {
			if strings.ContainsAny(text, "{}") {
				t.Errorf("%s migration %s holds a template", dialect, m.name)
			}
			for _, c := range createPattern.FindAllStringSubmatch(text, -1) {
				created[dialect] = append(created[dialect], c[1])
			}
		}
	}
	slices.Sort(created["sqlite"])
	slices.Sort(created["postgres"])
	if !slices.Equal(created["sqlite"], created["postgres"]) {
		t.Errorf("tables created: sqlite %v, postgres %v", created["sqlite"], created["postgres"])
	}
	known := append(created["sqlite"], "oid4vc_schema_migrations")
	for name, s := range statements(sqliteQueries) {
		for _, table := range tableNames(s) {
			if !slices.Contains(known, table) {
				t.Errorf("%s names %s, which no migration creates", name, table)
			}
		}
	}
}
