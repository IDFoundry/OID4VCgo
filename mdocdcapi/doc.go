// Package mdocdcapi implements both sides of "org-iso-mdoc": the
// presentation of an mdoc over the W3C Digital Credentials API, as
// ISO/IEC TS 18013-7:2025 Annex C defines it — the one protocol Safari
// supports, answered by Apple Wallet or an iOS document provider app.
// A Verifier builds the request and verifies the response; a wallet
// parses the request and answers it.
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
//
// # Wallet
//
// A wallet — an iOS document provider extension, given the request by
// ISO18013MobileDocumentRequestContext — calls ParseRequest with the
// request data and the requesting page's origin, which the platform
// reports. VerifyReaderTrust checks who signed the request against the
// reader roots the wallet trusts — and, with a LeafPolicy such as
// RequireReaderAuthenticationEKU, that the certificate is one issued
// for reader authentication — and returns the reader's certificate to
// show the holder; a request no trusted reader signed still comes from
// the origin the platform reports, which is what the holder sees then,
// unless the wallet refuses such requests. Respond answers one requested document with the held mdoc,
// disclosing only the elements the holder consented to — each of which
// must have been requested — signed by the mdoc's device key over the
// session transcript, and encrypted to the request's key. It returns
// the EncryptedResponse an iOS document provider hands back as
// ISO18013MobileDocumentResponse's responseData; ResponseData wraps it
// as the {"response"} object a platform that takes the whole object
// expects.
package mdocdcapi
