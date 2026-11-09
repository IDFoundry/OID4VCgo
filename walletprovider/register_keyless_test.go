package walletprovider_test

import (
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

// Registration needs evidence vouching for the registration key: a
// verifier that accepts the evidence but attests no key is refused, not
// taken as attesting the key at no security level.
func TestRegisterRefusesEvidenceAttestingNoKey(t *testing.T) {
	h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		d.Evidence = append(d.Evidence, misbehavingVerifier{kind: "keyless", report: func(walletprovider.EvidenceInput) walletprovider.VerifiedEvidence {
			return walletprovider.VerifiedEvidence{Platform: walletprovidertest.FakePlatform}
		}})
	})
	if _, _, err := h.tryRegister("keyless"); !errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("Register = %v, want ErrEvidenceRejected", err)
	}
}
