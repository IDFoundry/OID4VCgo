package passport

import (
	"errors"
	"fmt"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/passiveauth"
)

// ErrPassiveAuthentication is returned by VerifyDataGroups when the
// data groups don't verify against the trusted CSCA certificates.
var ErrPassiveAuthentication = errors.New("passport: passive authentication failed")

// VerifyDataGroups re-runs ICAO Passive Authentication over a passport's
// raw SOD and DG1 — as disclosed in a passport-derived credential — and
// returns the identity DG1 states. It is how a verifier trusts only the
// issuing country, not the credential's issuer: it checks the SOD's
// signature chains to a CSCA in cscaPool and that DG1's hash matches
// the SOD. Only the data groups given are checked, so the facial image
// (DG2) never needs to be disclosed.
//
// It proves the data is authentic, not that whoever presented it holds
// the passport: that binding comes from the credential's device key.
func VerifyDataGroups(sod, dg1 []byte, cscaPool cms.CertPool, now time.Time) (Identity, error) {
	if len(sod) == 0 || len(dg1) == 0 {
		return Identity{}, fmt.Errorf("%w: SOD and DG1 are required", ErrPassiveAuthentication)
	}
	var doc document.Document
	var err error
	// gmrtd's parse errors can embed the raw MRZ, so they're never
	// wrapped: nothing from the passport reaches a log line or page
	// through an error returned here.
	if doc.Mf.Lds1.Sod, err = document.NewSOD(sod); err != nil {
		return Identity{}, fmt.Errorf("%w: the SOD is malformed", ErrPassiveAuthentication)
	}
	if err := doc.NewDG(1, dg1); err != nil {
		return Identity{}, fmt.Errorf("%w: DG1 is malformed", ErrPassiveAuthentication)
	}

	result, err := passiveauth.PassiveAuth(&doc, cscaPool)
	if err != nil || result == nil || !result.Success {
		return Identity{}, fmt.Errorf("%w: the SOD signature, its certificate chain or the DG1 hash didn't verify", ErrPassiveAuthentication)
	}

	docEx := document.DocumentEx{Document: doc}
	docEx.Session.PassiveAuthResult = result
	attrs := docEx.Summary().IdentityAttributes
	if attrs == nil {
		return Identity{}, fmt.Errorf("passport: DG1 carries no identity attributes")
	}
	return identityFrom(attrs, false, now)
}
