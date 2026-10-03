package passport

import (
	"errors"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/verifier"
)

// SampleDocument returns Evidence from gmrtd's sample document
// (document.SampleDocument): ICAO 9303-10 worked-example data groups
// with an unrelated real signed security object (SOD), for running the
// demo without a passport. Its Passive Authentication fails —
// Checks.PassiveAuthentication is false — and it isn't one consistent
// person: the data groups come from different worked examples (DG11's
// names with DG1's sex, nationality "UTO", expired in 2012).
//
// Verify refuses its File, as a verifier re-verifying it will. now is
// the reference time, as for Verify.
func SampleDocument(now time.Time) (Evidence, error) {
	doc, err := document.SampleDocument()
	if err != nil {
		return Evidence{}, errors.New("passport: gmrtd's sample document")
	}
	data, err := (&document.DocumentEx{Document: *doc}).ToCbor()
	if err != nil {
		return Evidence{}, errors.New("passport: encode gmrtd's sample document")
	}
	// Decoded as an upload is, with no trust anchors: its Passive
	// Authentication fails whatever the pool.
	docEx, err := verifier.NewVerifier(&cms.GenericCertPool{}).Verify(data)
	if err != nil {
		return Evidence{}, ErrUnreadable
	}
	summary := docEx.Summary()
	if summary.DataTrusted {
		return Evidence{}, errors.New("passport: gmrtd's sample document verified, which it never should")
	}
	e, err := evidenceFrom(&docEx.Document, summary, now)
	if err != nil {
		return Evidence{}, err
	}
	e.Checks.PassiveAuthentication = false
	e.File = data
	return e, nil
}
