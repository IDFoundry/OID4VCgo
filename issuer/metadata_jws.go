package issuer

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
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
// "credential_issuer" member) and "iat" claims, and an "exp"
// DefaultMetadataLifetime after iat. "iss" is OPTIONAL and left out:
// nothing about a signer's own identity is distinguishable from
// credential_issuer. "exp" is OPTIONAL too, but without it a captured
// copy would verify for as long as its certificate, so a Wallet that
// doesn't bound the age itself would accept metadata long since
// replaced; the copy must therefore be signed again before it expires
// (NewMetadataHandler does that). The "x5c" header entry is how a Wallet
// resolves the signing key here (§12.2.3: "e.g., using JOSE header
// parameters like x5c, kid or trust_chain") — this repo's own
// established convention (see verifier/authorization_request.go's
// signRequestObject).
//
// cert must be issued by a CA, not self-signed, and intermediates are
// the CA certificates between it and the trust anchor, in order, the
// anchor left out: x5c carries cert followed by them (HAIP 1.0 §4.1).
func SignMetadataJWS(meta oid4vci.Metadata, signer crypto.Signer, alg oid4vci.JOSEAlg, cert *x509.Certificate, intermediates ...*x509.Certificate) (string, error) {
	return signMetadataJWSAt(time.Now(), DefaultMetadataLifetime, meta, signer, alg, cert, intermediates...)
}

// signMetadataJWSAt is SignMetadataJWS with iat now and exp lifetime
// later.
func signMetadataJWSAt(now time.Time, lifetime time.Duration, meta oid4vci.Metadata, signer crypto.Signer, alg oid4vci.JOSEAlg, cert *x509.Certificate, intermediates ...*x509.Certificate) (string, error) {
	if err := certchain.CheckPresentedChain(cert, intermediates); err != nil {
		return "", fmt.Errorf("issuer: sign metadata: %w", err)
	}
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
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(lifetime).Unix()

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("issuer: sign metadata: marshal claims: %w", err)
	}
	x5c := []string{base64.StdEncoding.EncodeToString(cert.Raw)}
	for _, c := range intermediates {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
	}
	header := map[string]any{
		"typ": MetadataJWSTyp,
		"x5c": x5c,
	}
	signed, err := jose.Sign(jose.Alg(alg), signer, header, claimsJSON)
	if err != nil {
		return "", fmt.Errorf("issuer: sign metadata: %w", err)
	}
	return signed, nil
}

// MetadataSigner signs the Credential Issuer Metadata
// NewMetadataHandler serves (§12.2.3).
type MetadataSigner struct {
	Signer crypto.Signer
	Alg    oid4vci.JOSEAlg

	// Certificate is Signer's, issued by a CA the Wallets trust for
	// metadata (HAIP 1.0 §4.1); Intermediates are the CA certificates
	// between it and the trust anchor, in order, the anchor left out.
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate

	// Refresh is how long a signed copy is served before it's signed
	// again, so its iat stays recent for a Wallet bounding its age.
	// Zero means DefaultMetadataRefresh.
	Refresh time.Duration

	// Lifetime is how long each signed copy is valid: its exp is
	// Lifetime after its iat, so a captured copy stops verifying once
	// the metadata has been signed again for long enough. It must be
	// longer than Refresh, so a Wallet is never served an expired copy,
	// and is best well over it, so a Wallet that caches the copy can
	// use it for a while. Zero means DefaultMetadataLifetime, or twice
	// Refresh if that is longer.
	Lifetime time.Duration
}

// DefaultMetadataRefresh is MetadataSigner.Refresh's default.
const DefaultMetadataRefresh = time.Hour

// DefaultMetadataLifetime is MetadataSigner.Lifetime's default, and
// the lifetime SignMetadataJWS gives its JWS.
const DefaultMetadataLifetime = 24 * time.Hour

// NewMetadataHandler serves the Credential Issuer Metadata at
// /.well-known/openid-credential-issuer (§12.2): signed (§12.2.3) to a
// Wallet whose Accept prefers application/jwt, as JSON otherwise
// (§12.2.2). signer nil serves JSON only.
//
// It checks signer up front, so a misconfigured one fails here rather
// than leaving Wallets unsigned metadata: the certificate's key must be
// the signer's, the chain well formed, the algorithm supported, and,
// under AssuranceProduction, the certificate not self-signed. A test
// signature is made too.
//
// The signed copy is made once and reused for signer.Refresh (dated by
// the Issuer's clock), so a client can't make the server sign at will.
// Only GET and HEAD are answered; responses carry Vary: Accept.
func NewMetadataHandler(iss *Issuer, signer *MetadataSigner) (http.Handler, error) {
	h := &metadataHandler{iss: iss}
	if signer == nil {
		return h, nil
	}
	s := *signer
	if s.Signer == nil || s.Certificate == nil {
		return nil, fmt.Errorf("issuer: metadata handler: signer and certificate are required")
	}
	if !jose.IsSupported(jose.Alg(s.Alg)) {
		return nil, fmt.Errorf("issuer: metadata handler: alg %q is not supported", s.Alg)
	}
	if err := checkSignerCertificate("metadata signer", s.Signer, s.Certificate, s.Intermediates, iss.cfg.Assurance); err != nil {
		return nil, fmt.Errorf("issuer: metadata handler: %w", err)
	}
	if s.Refresh <= 0 {
		s.Refresh = DefaultMetadataRefresh
	}
	switch {
	case s.Lifetime == 0:
		s.Lifetime = max(DefaultMetadataLifetime, 2*s.Refresh)
	case s.Lifetime <= s.Refresh:
		return nil, fmt.Errorf("issuer: metadata handler: Lifetime %s must be longer than Refresh %s, or Wallets are served expired metadata", s.Lifetime, s.Refresh)
	}
	h.signer = &s
	if _, err := h.signed(); err != nil {
		return nil, fmt.Errorf("issuer: metadata handler: %w", err)
	}
	return h, nil
}

type metadataHandler struct {
	iss    *Issuer
	signer *MetadataSigner

	mu       sync.Mutex
	jws      string
	signedAt time.Time
}

// signed is the signed metadata, signed again once Refresh has passed.
func (h *metadataHandler) signed() (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.iss.deps.Clock.Now()
	if h.jws != "" && !now.Before(h.signedAt) && now.Sub(h.signedAt) < h.signer.Refresh {
		return h.jws, nil
	}
	s := h.signer
	jws, err := signMetadataJWSAt(now, s.Lifetime, h.iss.Metadata(), s.Signer, s.Alg, s.Certificate, s.Intermediates...)
	if err != nil {
		return "", err
	}
	h.jws, h.signedAt = jws, now
	return jws, nil
}

func (h *metadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Vary", "Accept")
	if h.signer != nil && prefersJWT(r.Header.Values("Accept")) {
		signed, err := h.signed()
		if err != nil {
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(signed))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.iss.Metadata())
}

// prefersJWT reports whether an Accept header's application/jwt has a
// q above zero and no lower than application/json's (RFC 9110 §12.5.1).
func prefersJWT(accept []string) bool {
	jwtQ, jsonQ := 0.0, 0.0
	for _, line := range accept {
		for _, part := range strings.Split(line, ",") {
			mediaType, q, ok := parseAcceptPart(part)
			if !ok {
				continue
			}
			switch mediaType {
			case "application/jwt":
				jwtQ = max(jwtQ, q)
			case "application/json":
				jsonQ = max(jsonQ, q)
			}
		}
	}
	return jwtQ > 0 && jwtQ >= jsonQ
}

// parseAcceptPart parses one member of an Accept header into its media
// type and q, 1 when absent. ok is false for a member that doesn't parse
// or whose q isn't between 0 and 1.
func parseAcceptPart(part string) (mediaType string, q float64, ok bool) {
	mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(part))
	if err != nil {
		return "", 0, false
	}
	q = 1.0
	if v, has := params["q"]; has {
		if q, err = strconv.ParseFloat(v, 64); err != nil || q < 0 || q > 1 {
			return "", 0, false
		}
	}
	return mediaType, q, true
}

// MetadataHandler serves the Credential Issuer Metadata, signed when
// the Wallet asks for application/jwt and signing succeeds.
//
// Deprecated: Use NewMetadataHandler, which checks the signer up front
// instead of falling back to unsigned metadata when it's misconfigured,
// signs once per MetadataSigner.Refresh rather than per request, and
// reads the Accept header's q values. MetadataHandler is
// NewMetadataHandler, serving JSON only when the signer is refused —
// except under AssuranceProduction, where it then answers every
// request with a server error rather than metadata a Wallet relying
// on the signature couldn't trust.
func MetadataHandler(iss *Issuer, signer crypto.Signer, alg oid4vci.JOSEAlg, cert *x509.Certificate, intermediates ...*x509.Certificate) http.HandlerFunc {
	var ms *MetadataSigner
	if signer != nil {
		ms = &MetadataSigner{Signer: signer, Alg: alg, Certificate: cert, Intermediates: intermediates}
	}
	h, err := NewMetadataHandler(iss, ms)
	if err != nil {
		if iss.cfg.Assurance == AssuranceProduction {
			return func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "the Credential Issuer Metadata signer is misconfigured", http.StatusInternalServerError)
			}
		}
		h, _ = NewMetadataHandler(iss, nil)
	}
	return h.ServeHTTP
}
