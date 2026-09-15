package haip_test

import (
	"testing"

	"github.com/idfoundry/oid4vcigo/haip"
)

func TestRecommendedWalletConfig(t *testing.T) {
	rec := haip.RecommendedWalletConfig()
	if rec.ProofSigningAlg != haip.RecommendedJOSEAlgorithm {
		t.Errorf("ProofSigningAlg = %v, want %v", rec.ProofSigningAlg, haip.RecommendedJOSEAlgorithm)
	}
}
