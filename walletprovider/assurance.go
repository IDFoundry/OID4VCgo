package walletprovider

import (
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/testonly"
)

// AssuranceLevel gates how strict New is about what a Provider is
// built from (Config.Assurance), as issuer.AssuranceLevel and
// verifier.AssuranceLevel do for those roles.
type AssuranceLevel uint8

const (
	_ AssuranceLevel = iota

	// AssuranceDevelopment takes the stand-ins tests and emulators
	// build a provider with, walletprovidertest.FakeVerifier among
	// Dependencies.Evidence. A zero Config.Assurance means it.
	AssuranceDevelopment

	// AssuranceProduction refuses them: New refuses
	// walletprovidertest.FakeVerifier, or a type embedding it, among
	// Dependencies.Evidence. Its evidence is a JSON document anyone can
	// write, so a provider configured with it registers anyone and
	// attests any key, with whatever security level it was set to
	// report. Nothing else changes with it: the evidence verifiers'
	// own settings (appattest.Verifier.AllowDevelopment, say), sealing
	// (Config.RequireSealedStore) and the rest are set on their own.
	AssuranceProduction
)

// validate refuses a level other than zero, AssuranceDevelopment and
// AssuranceProduction.
func (a AssuranceLevel) validate() error {
	if a > AssuranceProduction {
		return fmt.Errorf("the assurance level %d is neither AssuranceDevelopment nor AssuranceProduction", a)
	}
	return nil
}

// checkProduction refuses what AssuranceProduction refuses: an
// evidence verifier that is a test stand-in.
func (d Dependencies) checkProduction() error {
	for i, v := range d.Evidence {
		if testonly.Is(v) {
			return fmt.Errorf("the EvidenceVerifier at Evidence[%d] (Kind %q) is, or embeds, walletprovidertest.FakeVerifier, whose evidence anyone can write: AssuranceProduction refuses it", i, v.Kind())
		}
	}
	return nil
}
