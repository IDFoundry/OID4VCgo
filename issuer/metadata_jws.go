package issuer

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// MetadataJWSTyp is the signed Credential Issuer Metadata JWT's own
// mandatory "typ" header value (§12.2.3).
const MetadataJWSTyp = "openidvci-issuer-metadata+jwt"

// SignMetadataJWS signs meta as a compact JWS per §12.2.3: "All
// metadata parameters used by the Credential Issuer MUST be added as
// top-level claims in the JWS payload" — json.Marshal already produces
// exactly that shape (oid4vci.Metadata's own json tags are what
// §12.2.4 defines), so this just adds the REQUIRED "sub" (the
// Credential Issuer Identifier — read back out of the marshaled
// metadata itself, since it's the same value as its own
// "credential_issuer" member) and "iat" claims. "iss"/"exp" are both
// OPTIONAL and left out: nothing about a signer's own identity is
// distinguishable from credential_issuer, and metadata has no separate
// validity window of its own. The "x5c" header entry is how a Wallet
// resolves the signing key here (§12.2.3: "e.g., using JOSE header
// parameters like x5c, kid or trust_chain") — this repo's own
// established convention (see verifier/authorization_request.go's
// signRequestObject).
func SignMetadataJWS(meta oid4vci.Metadata, signer crypto.Signer, alg jose.Alg, cert *x509.Certificate) (string, error) {
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("issuer: sign metadata: marshal metadata: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(metaJSON, &claims); err != nil {
		return "", fmt.Errorf("issuer: sign metadata: unmarshal metadata into claims: %w", err)
	}
	sub, _ := claims["credential_issuer"].(string)
	if sub == "" {
		return "", fmt.Errorf("issuer: sign metadata: credential_issuer is empty, cannot set sub claim")
	}
	claims["sub"] = sub
	claims["iat"] = time.Now().Unix()

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("issuer: sign metadata: marshal claims: %w", err)
	}
	header := map[string]any{
		"typ": MetadataJWSTyp,
		"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}
	signed, err := jose.Sign(alg, signer, header, claimsJSON)
	if err != nil {
		return "", fmt.Errorf("issuer: sign metadata: %w", err)
	}
	return signed, nil
}

// MetadataHandler serves GET /.well-known/openid-credential-issuer
// (§12.2). §12.2.2 makes this pure content negotiation, not a separate
// endpoint or field: a Wallet's Accept header names application/json
// and/or application/jwt, a Credential Issuer MUST always support the
// former and MAY support the latter (confirmed live against the OIDF
// conformance suite's own metadata-test-signed module, which detects
// support by the response's Content-Type header, not by any
// request-side signal this handler reads). Signing failure falls back
// to plain JSON rather than a 500 — an operator error in signer/cert
// config shouldn't take down the one endpoint every OID4VCI flow
// starts with.
func MetadataHandler(iss *Issuer, signer crypto.Signer, alg jose.Alg, cert *x509.Certificate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		meta := iss.Metadata()
		if strings.Contains(r.Header.Get("Accept"), "application/jwt") {
			if signed, err := SignMetadataJWS(meta, signer, alg, cert); err == nil {
				w.Header().Set("Content-Type", "application/jwt")
				_, _ = w.Write([]byte(signed))
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	}
}
