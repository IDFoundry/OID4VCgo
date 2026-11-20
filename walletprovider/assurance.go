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
	// Dependencies.Evidence, stores that don't seal their records
	// (unless Config.RequireSealedStore), and the evidence verifiers'
	// development settings. A zero Config.Assurance means it.
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
	//     does at any level, unless Config.UnsealedStores accepts them;
	//   - an evidence verifier whose CheckConfiguration
	//     (ConfigurationCheck) refuses this level: androidkey's, whose
	//     Verifier fetches Google's status list through a StatusSource
	//     with AllowLoopback, and appattest's, whose Verifier sets
	//     AllowDevelopment.
	//
	// androidkey.EvidenceVerifier.AllowUncheckedLegacyEvidence is taken:
	// it's for an upgrade window, in production as in development, and
	// logs each record it lets through.
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

// ConfigurationCheck is implemented by an EvidenceVerifier that checks
// its own configuration, as androidkey's and appattest's
// EvidenceVerifier do. New calls CheckConfiguration, with the
// provider's assurance level (AssuranceDevelopment for a zero
// Config.Assurance), on each of Dependencies.Evidence that implements
// it, and refuses what it reports, as issuer.New does with its
// dependencies' issuer.ConfigurationCheck. A verifier of your own that
// embeds one of them (to count its calls, say) has its method
// promoted, so it keeps its checks; one that holds it in a named field
// hides them, and should implement CheckConfiguration by calling the
// field's.
type ConfigurationCheck interface {
	CheckConfiguration(assurance AssuranceLevel) error
}

// checkConfiguration runs v's ConfigurationCheck, if it has one.
func checkConfiguration(v EvidenceVerifier, assurance AssuranceLevel) error {
	if checked, ok := v.(ConfigurationCheck); ok {
		return checked.CheckConfiguration(assurance)
	}
	return nil
}

// checkProduction refuses what AssuranceProduction refuses of d itself:
// an evidence verifier that is a test stand-in, and, unless unsealed,
// stores that don't seal their records. The verifiers' own checks
// (checkConfiguration) run at every level.
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
