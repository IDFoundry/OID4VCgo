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

	// AssuranceDevelopment takes what tests, emulators and local runs
	// build a provider with: walletprovidertest.FakeVerifier among
	// Dependencies.Evidence, and stores that don't seal their records
	// (unless Config.RequireSealedStore). A zero Config.Assurance means
	// it.
	AssuranceDevelopment

	// AssuranceProduction refuses what production mustn't run with.
	// New refuses:
	//
	//   - walletprovidertest.FakeVerifier, or a type embedding it, among
	//     Dependencies.Evidence. Its evidence is a JSON document anyone
	//     can write, so a provider built with it registers anyone and
	//     attests any key, at whatever security level it was set to
	//     report;
	//   - Instances, InstanceKeys and Challenges stores that don't seal
	//     their records (sealing.Store), as Config.RequireSealedStore
	//     does at any level, unless Config.UnsealedStores accepts them.
	//
	// The evidence verifiers' own settings (appattest.Verifier's
	// AllowDevelopment, say) are set on their own.
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

// checkProduction refuses what AssuranceProduction refuses: an evidence
// verifier that is a test stand-in, and, unless unsealed, stores that
// don't seal their records.
func (d Dependencies) checkProduction(unsealed bool) error {
	for i, v := range d.Evidence {
		if testonly.Is(v) {
			return fmt.Errorf("the EvidenceVerifier at Evidence[%d] (Kind %q) is, or embeds, walletprovidertest.FakeVerifier, whose evidence anyone can write: AssuranceProduction refuses it", i, v.Kind())
		}
	}
	if unsealed {
		return nil
	}
	return d.checkSealed("AssuranceProduction requires sealed stores",
		"; or set UnsealedStores where the stores are as protected as the provider's signing key")
}
