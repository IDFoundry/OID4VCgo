package issuer_test

import (
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// recordingProfile is an issuer.Profile that records what New gives it
// and returns err.
type recordingProfile struct {
	err  error
	cfg  *issuer.Config
	deps *issuer.Dependencies
}

func (p recordingProfile) CheckIssuer(cfg issuer.Config, deps issuer.Dependencies) error {
	*p.cfg, *p.deps = cfg, deps
	return p.err
}

// TestNewRunsProfile: New runs Config.Profile with the configuration as
// the Issuer will use it (a pointer client authentication choice as its
// value, a nil Clock as the system clock), and refuses what it refuses.
func TestNewRunsProfile(t *testing.T) {
	cfg, deps := validConfig(t), validDependencies(t)
	var gotCfg issuer.Config
	var gotDeps issuer.Dependencies
	cfg.PreAuthorizedCodeClientAuthentication = &issuer.VerifiedPreAuthorizedCode{}
	cfg.Profile = recordingProfile{cfg: &gotCfg, deps: &gotDeps}
	if _, err := issuer.New(cfg, deps); err != nil {
		t.Fatalf("New with a profile that passes: %v", err)
	}
	if _, ok := gotCfg.PreAuthorizedCodeClientAuthentication.(issuer.VerifiedPreAuthorizedCode); !ok {
		t.Errorf("profile saw client authentication %T, want issuer.VerifiedPreAuthorizedCode", gotCfg.PreAuthorizedCodeClientAuthentication)
	}
	if gotDeps.Clock == nil {
		t.Error("profile saw a nil Clock, want the system clock")
	}

	refused := errors.New("not this profile's")
	cfg.Profile = recordingProfile{err: refused, cfg: &gotCfg, deps: &gotDeps}
	if _, err := issuer.New(cfg, deps); !errors.Is(err, refused) {
		t.Fatalf("New with a profile that refuses = %v, want its error", err)
	}
}
