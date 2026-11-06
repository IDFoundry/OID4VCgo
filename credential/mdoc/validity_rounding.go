package mdoc

import "time"

// RoundedValidity computes Claims.Signed, ValidFrom and ValidUntil for
// an mdoc issued at now: signed and validFrom are the start of now's
// own UTC day, and validUntil that plus lifetime. It's the mso_mdoc
// counterpart of credential/sdjwtvc.RoundedExp: an MSO's validityInfo
// set from the issuance instant would let colluding Verifiers link
// presentations of the same mdoc to its issuance by those timestamps
// (the anti-linkability concern of RFC 9901 §10.1, which the OpenID
// Foundation conformance suite checks mdocs for too). Rounded to the
// day, every mdoc issued on one UTC day carries the same three values.
//
// The rounded signed time can be up to a day before now, and ISO/IEC
// 18013-5 §9.3.1 has it fall within the Document Signer certificate's
// validity, so that certificate's NotBefore must not be after the
// start of the day it signs on: issue it backdated by more than a day
// (internal/conformancecert's mdocCertificateBackdate does, by 25
// hours), or rotate it to a new one well before that day starts.
// validUntil must likewise not be after its NotAfter (§12.3.4), which
// Issue checks.
//
// An mdoc is valid for lifetime less however much of its UTC day had
// passed when it was issued: one issued just before midnight with a
// lifetime of 24 hours expires minutes later. Pass a day more than the
// shortest validity an mdoc needs.
func RoundedValidity(now time.Time, lifetime time.Duration) (signed, validFrom, validUntil time.Time) {
	dayStart := now.UTC().Truncate(24 * time.Hour)
	return dayStart, dayStart, dayStart.Add(lifetime)
}
