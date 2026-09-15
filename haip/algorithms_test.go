package haip_test

import (
	"testing"

	"github.com/idfoundry/oid4vcigo/haip"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/jose"
)

func TestRecommendedAlgorithms(t *testing.T) {
	if haip.RecommendedJOSEAlgorithm != jose.ES256 {
		t.Errorf("RecommendedJOSEAlgorithm = %v, want %v", haip.RecommendedJOSEAlgorithm, jose.ES256)
	}
	if haip.RecommendedCOSEAlgorithm != cose.ES256 {
		t.Errorf("RecommendedCOSEAlgorithm = %v, want %v", haip.RecommendedCOSEAlgorithm, cose.ES256)
	}
}
