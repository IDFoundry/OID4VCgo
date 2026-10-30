package issuer_test

import (
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// TestNewReportsEveryProblem: New reports every configuration problem
// it finds, in Config, Dependencies and production assurance alike, not
// just the first, so a deployment fixes them in one pass.
func TestNewReportsEveryProblem(t *testing.T) {
	cfg, deps := productionIssuer(t)
	cfg.Endpoints.Credential = fapi.URL{}
	cfg.Limits.NonceLifetime = 24 * time.Hour
	deps.Random = nil
	deps.Audit = nil
	deps.Clock = issuer.ClockFunc(time.Now)
	_, err := issuer.New(cfg, deps)
	if err == nil {
		t.Fatal("New = nil error")
	}
	for _, want := range []string{
		"endpoints.credential is required",
		"random is required",
		"nonce_lifetime",
		"dependencies.audit is required",
		"dependencies.clock",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("New's error doesn't report %q:\n%v", want, err)
		}
	}
	for _, line := range strings.Split(err.Error(), "\n") {
		if !strings.HasPrefix(line, "issuer: ") {
			t.Errorf("error line %q doesn't start with %q", line, "issuer: ")
		}
	}
}
