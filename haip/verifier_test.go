package haip_test

import (
	"testing"

	"github.com/idfoundry/oid4vcigo/haip"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
)

func TestRecommendedVerifierConfig(t *testing.T) {
	rec := haip.RecommendedVerifierConfig()
	if rec.SigningAlg != haip.RecommendedJOSEAlgorithm {
		t.Errorf("SigningAlg = %v, want %v", rec.SigningAlg, haip.RecommendedJOSEAlgorithm)
	}
	want := []jwe.Enc{jwe.A128GCM, jwe.A256GCM}
	if len(rec.EncValuesSupported) != len(want) {
		t.Fatalf("EncValuesSupported = %v, want %v", rec.EncValuesSupported, want)
	}
	for i, enc := range want {
		if rec.EncValuesSupported[i] != enc {
			t.Errorf("EncValuesSupported[%d] = %v, want %v", i, rec.EncValuesSupported[i], enc)
		}
	}
}
