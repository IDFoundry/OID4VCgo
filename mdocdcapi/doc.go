// Package mdocdcapi implements a Verifier for "org-iso-mdoc": the
// presentation of an mdoc over the W3C Digital Credentials API, as
// ISO/IEC TS 18013-7:2025 Annex C defines it — the one protocol Safari
// supports, answered by Apple Wallet or an iOS document provider app.
//
// It is not OpenID4VP: the request is an ISO/IEC 18013-5 DeviceRequest,
// and the response an HPKE-encrypted DeviceResponse. For OpenID4VP over
// the Digital Credentials API (OpenID4VP Appendix A), see package
// verifier's BuildDCAPIAuthorizationRequest instead.
//
// A Verifier's server calls BuildRequest for the page's origin, the
// requested document type and data elements, and the reader keys that
// sign the request (each a ReaderAuthAll, ISO/IEC 18013-5 §12.5; the
// first also a ReaderAuth on the DocRequest, for mdocs that only check
// that). It hands Request.Data to the page, which passes it to
//
//	navigator.credentials.get({mediation: "required",
//	    digital: {requests: [{protocol: "org-iso-mdoc", data}]}})
//
// and sends back the credential's data.response. VerifyResponse then
// decrypts it with Request.Pending, which the server kept, and verifies
// the document: its issuer signature and digests (credential/mdoc), its
// device signature over this request's session transcript, which binds
// it to the origin and the encryption key, and that it disclosed only
// what was asked.
//
// The origin is the Verifier's own, from its configuration: never one
// the page reports, since the session transcript must be the one the
// browser gave the mdoc.
package mdocdcapi
