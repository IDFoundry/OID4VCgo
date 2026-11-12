package oid4vcgo.interop.multipaz

/**
 * What Multipaz sends that OID4VCgo is lenient about (SPECIFICATIONS.md,
 * "Known leniencies"), as Multipaz 0.102.0 sends it: each run checks it
 * hasn't changed, since OID4VCgo would accept the lenient form without
 * a word. A JWK Set is its keys as "alg=…,kid=…", "-" for a member a
 * key lacks (kid only as present or not: its value is per run), sorted
 * and joined by ";". Each one recorded so far follows the
 * specification (README.md, "What it found").
 */
object Observed {
    /**
     * Its Verifier's client_metadata.jwks, cross-device: OpenID4VP 1.0
     * §8.3 requires the response encryption key's alg; the wallet takes
     * a P-256 key without one.
     */
    const val VERIFIER_JWKS = "alg=ECDH-ES,kid=present"

    /** The same, over the Digital Credentials API. */
    const val VERIFIER_JWKS_DCAPI = "alg=ECDH-ES,kid=present"

    /**
     * Its issuer's credential_request_encryption.jwks, "none" when its
     * metadata has none (as now: the wallet's request encryption, kid
     * included — OpenID4VCI 1.0 §12.2.4 — isn't exercised).
     */
    const val REQUEST_ENC_JWKS = "none"

    /**
     * Its Authorization Server's token_type, to walletflow's DPoP-proved
     * Token Request: the wallet would take Bearer (RFC 9449 §5 lets the
     * server issue one) and use it as a bearer token.
     */
    const val TOKEN_TYPE = "DPoP"

    // Its wallet's Client Attestation PoP's iss is checked to be the
    // client_id, as draft-ietf-oauth-attestation-based-client-auth-07
    // §5.2 requires and Multipaz sends it: OID4VCgo's issuer (FAPIgo's
    // server) accepts a PoP without one.
}
