// Package oid4vpmdoc implements the OID4VP-specific wire structures
// the "mso_mdoc" Credential Format's own Presentation needs on top of
// credential/mdoc's own ISO/IEC 18013-5 primitives: DeviceResponse
// (ISO/IEC 18013-5 §10.3.2/§10.3.3, OID4VP Appendix B.2.5 — the VP
// Token array entry's own base64url-encoded wire shape), and
// SessionTranscriptBytes built per either of OID4VP's own two Handover
// structures — OpenID4VPHandover (Appendix B.2.6.1, redirect flow) or
// OpenID4VPDCAPIHandover (Appendix B.2.6.2, the DC API flow) — see
// below.
//
// credential/mdoc's own doc comment deliberately excludes
// SessionTranscript/Handover construction ("this needs OID4VP's own
// Handover construction, a different spec's concern entirely, not
// ISO/IEC 18013-5's proximity-flow one"); every one of its own
// DeviceSigned functions instead takes SessionTranscriptBytes as an
// opaque, caller-supplied value. This package is that caller — and
// both verifier (checking an incoming DeviceResponse's own
// DeviceSigned) and wallet (building one) import it, so the exact
// same bytes are computed on both sides by construction. Unlike
// dcql's own shared checks (SatisfiedBySDJWTVCClaims/
// SatisfiedByMdocClaims), a byte-level mismatch here wouldn't just be
// an inconsistency — it would break the cryptographic verification
// outright, which is why this lives in one shared package rather than
// each role package reimplementing it.
//
// # Scope
//
// BuildSessionTranscriptBytes implements Appendix B.2.6.1 (the
// redirect flow — DeviceEngagementBytes/EReaderKeyBytes both null,
// Handover the OpenID4VPHandover structure) and is already wired into
// both verifier and wallet's own redirect-flow "mso_mdoc" support.
// BuildDCAPISessionTranscriptBytes implements Appendix B.2.6.2 (the DC
// API flow — same null DeviceEngagementBytes/EReaderKeyBytes, Handover
// the OpenID4VPDCAPIHandover structure instead, committing to an
// Origin rather than a client_id/response_uri pair), not wired into
// verifier/wallet yet — see their own package doc comments for
// exactly what's still cut on the DC API side.
// MarshalDeviceResponse/UnmarshalDeviceResponse cover exactly one
// Document per DeviceResponse — HAIP §5.3.1's own MUST for multiple
// returned mdocs ("each ISO mdoc MUST be returned in a separate
// DeviceResponse") means this package never needs to build or accept
// more than one; "documentErrors"/"zkDocuments"/"encryptedDocuments"
// aren't modeled.
package oid4vpmdoc
