// Package passport turns a gmrtd portable passport file into verified,
// format-neutral Evidence: the holder's identity attributes plus the
// passport's original, ICAO-signed SOD and data-group bytes.
//
// It is the only part of the passport-vdc demo that depends on gmrtd.
// Everything downstream — the mso_mdoc and dc+sd-jwt encoders, the
// OID4VCI issuer — works from Evidence alone.
//
// # What verification proves
//
// Verify runs gmrtd's Passive Authentication (SOD signature, data-group
// hashes, Document Signer → CSCA chain) and refuses anything gmrtd does
// not report as DataTrusted. That proves the data is authentic: the
// issuing country signed it. It does not prove the person presenting
// the file holds the passport — a portable file can be copied. Chip
// authentication evidence (Chip Authentication, PACE-CAM, Active
// Authentication), when the file carries it, is reported in
// Evidence.Checks but only proves a genuine chip was read at some
// point; binding that read to this issuance needs an issuer-chosen
// Active Authentication challenge (gmrtd's verifier.WithAAChallenge),
// which this demo does not yet use.
package passport
