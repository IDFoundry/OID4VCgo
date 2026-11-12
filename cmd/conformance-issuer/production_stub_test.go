//go:build !conformance_production

package main

import (
	"strings"
	"testing"
)

// Without the conformance_production build tag, a production
// configuration is refused when the servers are built, not ignored.
func TestNewServers_ProductionNeedsBuildTag(t *testing.T) {
	_, err := newServers(withProduction(t, baseTestConfig(t)))
	if err == nil || !strings.Contains(err.Error(), "conformance_production") {
		t.Fatalf("newServers = %v, want the build tag named", err)
	}
}
