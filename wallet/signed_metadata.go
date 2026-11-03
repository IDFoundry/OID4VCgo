package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwtdate"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// signedMetadataTyp is a signed Credential Issuer Metadata JWT's "typ"
// (OpenID4VCI §12.2.3).
const signedMetadataTyp = "openidvci-issuer-metadata+jwt"

// maxSignedMetadataClockSkew is how far a signed metadata JWT's iat may
// be ahead of the Wallet's clock.
const maxSignedMetadataClockSkew = time.Minute

// acceptSignedMetadata asks for signed metadata ahead of plain JSON
// (OpenID4VCI §12.2.2).
const acceptSignedMetadata = "application/jwt, application/json;q=0.5"

// metadataJSON returns a fetched metadata body as JSON: a signed
// response's verified claims, or a plain JSON body, refused when
// Config.RequireSignedIssuerMetadata is set. The body's shape decides,
// not its Content-Type, since the signature is what's trusted: a JSON
// document starts with "{", a compact JWT never does.
func (w *Wallet) metadataJSON(ctx context.Context, body []byte, issuerURL string) ([]byte, error) {
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		if w.cfg.RequireSignedIssuerMetadata {
			return nil, errors.New("the issuer sent unsigned metadata, and require_signed_issuer_metadata is set")
		}
		return body, nil
	}
	if w.cfg.IssuerMetadataRoots == nil {
		return nil, errors.New("the issuer sent signed metadata, and issuer_metadata_roots is not set to verify it")
	}
	return w.verifySignedMetadata(ctx, string(bytes.TrimSpace(body)), issuerURL)
}

// verifySignedMetadata verifies a signed Credential Issuer Metadata JWT
// (OpenID4VCI §12.2.3, HAIP 1.0 §4.1) and returns its metadata members
// as JSON. It checks:
//   - its typ;
//   - a signature by the key of an x5c leaf chaining to
//     Config.IssuerMetadataRoots ("the Wallet MUST establish trust in
//     the signer of the metadata") on a path IssuerMetadataLeafPolicy
//     approves and IssuerMetadataRevocation passes;
//   - sub naming the issuer;
//   - an iat that isn't in the future, and an exp, when present, not
//     past.
func (w *Wallet) verifySignedMetadata(ctx context.Context, token, issuerURL string) ([]byte, error) {
	header, _, err := jose.DecodeUnverifiedMax(token, int(w.cfg.Fetch.MaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("signed metadata: %w", err)
	}
	if typ, _ := header["typ"].(string); !jose.TypeIs(typ, signedMetadataTyp) {
		return nil, fmt.Errorf("signed metadata: typ %q, want %q", header["typ"], signedMetadataTyp)
	}
	x5c, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return nil, fmt.Errorf("signed metadata: %w", err)
	}
	if err := certchain.CheckNoAnchor(x5c); err != nil {
		return nil, fmt.Errorf("signed metadata: signer certificate: %w", err)
	}
	leaf, _, err := certchain.VerifyTrustedChainsAt(ctx, x5c, w.cfg.IssuerMetadataRoots, w.cfg.IssuerMetadataLeafPolicy, w.cfg.IssuerMetadataRevocation, w.deps.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("signed metadata: signer certificate: %w", err)
	}
	if w.cfg.RequireIssuerMetadataName {
		if err := certchain.CheckIssuerName(leaf, issuerURL); err != nil {
			return nil, fmt.Errorf("signed metadata: signer certificate doesn't name the issuer: %w", err)
		}
	}
	if certchain.IsSelfSigned(leaf) {
		return nil, errors.New("signed metadata: the signer certificate is self-signed")
	}
	alg, _ := header["alg"].(string)
	if !jose.IsSupported(jose.Alg(alg)) {
		return nil, fmt.Errorf("signed metadata: alg %q is not supported", alg)
	}
	_, payload, err := jose.VerifyMax(jose.Alg(alg), leaf.PublicKey, token, int(w.cfg.Fetch.MaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("signed metadata: %w", err)
	}
	var claims map[string]json.RawMessage
	if err := strictjson.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("signed metadata: claims: %w", err)
	}
	if err := w.checkSignedMetadataClaims(claims, issuerURL); err != nil {
		return nil, fmt.Errorf("signed metadata: %w", err)
	}
	// The JWT's own claims aren't metadata members.
	for _, name := range []string{"sub", "iat", "exp", "iss", "nbf"} {
		delete(claims, name)
	}
	return json.Marshal(claims)
}

// checkSignedMetadataClaims checks a signed metadata JWT's sub, iat,
// exp and nbf. Its times are NumericDates, which may be fractional
// (RFC 7519 §2).
func (w *Wallet) checkSignedMetadataClaims(claims map[string]json.RawMessage, issuerURL string) error {
	var sub string
	if err := strictjson.Unmarshal(claims["sub"], &sub); err != nil || sub != issuerURL {
		return fmt.Errorf("sub %s doesn't name the issuer %q", claims["sub"], issuerURL)
	}
	now := w.deps.Clock.Now()
	var iatValue float64
	if err := strictjson.Unmarshal(claims["iat"], &iatValue); err != nil {
		return errors.New("iat is missing or not a number")
	}
	iat, err := jwtdate.FromFloat(iatValue)
	if err != nil {
		return fmt.Errorf("iat: %w", err)
	}
	if iat.After(now.Add(maxSignedMetadataClockSkew)) {
		return errors.New("iat is in the future")
	}
	if age := w.cfg.MaxIssuerMetadataAge; age > 0 && iat.Before(now.Add(-age)) {
		return fmt.Errorf("issued %s ago, over the %s allowed", now.Sub(iat).Round(time.Second), age)
	}
	if raw, present := claims["exp"]; present {
		var exp float64
		// RFC 7519 §4.1.4: not accepted on or after exp.
		if err := strictjson.Unmarshal(raw, &exp); err != nil {
			return errors.New("exp isn't a number")
		}
		at, err := jwtdate.FromFloat(exp)
		if err != nil {
			return fmt.Errorf("exp: %w", err)
		}
		if !now.Before(at) {
			return errors.New("expired")
		}
	}
	if raw, present := claims["nbf"]; present {
		var nbf float64
		// RFC 7519 §4.1.5: not accepted before nbf.
		if err := strictjson.Unmarshal(raw, &nbf); err != nil {
			return errors.New("nbf isn't a number")
		}
		at, err := jwtdate.FromFloat(nbf)
		if err != nil {
			return fmt.Errorf("nbf: %w", err)
		}
		if now.Add(maxSignedMetadataClockSkew).Before(at) {
			return errors.New("not valid yet (nbf)")
		}
	}
	return nil
}
