package oid4vci_test

import (
	"testing"

	"github.com/idfoundry/fapigo/extension"

	"github.com/idfoundry/oid4vcigo"
)

func TestIssuerStateExtension(t *testing.T) {
	def := oid4vci.IssuerStateExtension
	if def.Name != "issuer_state" {
		t.Errorf("Name = %q, want issuer_state", def.Name)
	}
	if def.Cardinality != extension.Single {
		t.Errorf("Cardinality = %v, want extension.Single", def.Cardinality)
	}
	if !def.AllowedSources.Allows(extension.SourcePlainParameter) {
		t.Errorf("AllowedSources does not allow SourcePlainParameter")
	}
	if !def.AllowedSources.Allows(extension.SourceRequestObject) {
		t.Errorf("AllowedSources does not allow SourceRequestObject")
	}
	if def.MaxBytes != 2048 {
		t.Errorf("MaxBytes = %d, want 2048", def.MaxBytes)
	}
}
