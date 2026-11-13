//go:build !conformance_production

package main

import (
	"strings"
	"testing"
)

func TestTransactionsEngine_ProductionNeedsTheBuildTag(t *testing.T) {
	cfg := newTxTestSetup(t).cfg
	cfg.Production = &ProductionConfig{DatabasePath: "/tmp/v.sqlite", SealingKey: "a2V5"}
	if _, _, err := newHandler(cfg); err == nil || !strings.Contains(err.Error(), "conformance_production") {
		t.Fatalf("newHandler = %v, want the missing build tag", err)
	}
}
