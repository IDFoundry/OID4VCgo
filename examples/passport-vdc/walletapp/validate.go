package walletapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// validateReceived checks a credential the issuer returned before the
// wallet keeps it: its issuer signature, with the signing certificate
// chaining to issuerRoots (HAIP 1.0 §6.1.1: the Wallet, too, must
// support X.509 issuer key resolution); that it is bound to holder, the
// key the wallet proved possession of; and that it is the type conf
// describes (vct or doctype), valid at now.
func validateReceived(ctx context.Context, conf oid4vci.CredentialConfigurationMetadata, credential string, holder *ecdsa.PrivateKey, issuerRoots *x509.CertPool, now time.Time) error {
	switch conf.Format {
	case sdjwtvc.CredentialFormat:
		return validateSDJWT(ctx, conf.VCT, credential, &holder.PublicKey, issuerRoots, now)
	case mdoc.CredentialFormat:
		return validateMdoc(ctx, conf.DocType, credential, &holder.PublicKey, issuerRoots, now)
	default:
		return fmt.Errorf("unsupported format %q", conf.Format)
	}
}

func validateSDJWT(ctx context.Context, vct, credential string, holder *ecdsa.PublicKey, issuerRoots *x509.CertPool, now time.Time) error {
	pres, err := sdjwtvc.Parse(credential)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	var header map[string]any
	if err := decodeJOSEHeader(pres.IssuerJWT, &header); err != nil {
		return err
	}
	issuerPub, alg, err := verifier.X5CIssuerKeyResolver{Roots: issuerRoots}.ResolveIssuerKey(ctx, header, nil)
	if err != nil {
		return fmt.Errorf("issuer certificate: %w", err)
	}
	payload, _, err := sdjwtvc.Verify(credential, issuerPub, alg, sdjwtvc.VerifyOptions{
		RequireKeyBinding: sdjwtvc.KeyBindingNotRequired, Now: func() time.Time { return now },
	})
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if got, _ := payload["vct"].(string); got != vct {
		return fmt.Errorf("vct is %q, want %q", got, vct)
	}
	cnf, _ := payload["cnf"].(map[string]any)
	jwk, _ := cnf["jwk"].(map[string]any)
	if !jwkIsKey(jwk, holder) {
		return errors.New("cnf.jwk isn't the holder key the wallet proved possession of")
	}
	return nil
}

func validateMdoc(ctx context.Context, docType, credential string, holder *ecdsa.PublicKey, issuerRoots *x509.CertPool, now time.Time) error {
	raw, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	signed, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	x5chain, err := issuerAuthX5Chain(signed.IssuerAuth)
	if err != nil {
		return err
	}
	issuerPub, alg, err := verifier.X5ChainIssuerKeyResolver{Roots: issuerRoots}.ResolveMdocIssuerKey(ctx, x5chain, docType)
	if err != nil {
		return fmt.Errorf("issuer certificate: %w", err)
	}
	mso, err := mdoc.Verify(signed, docType, issuerPub, alg, mdoc.VerifyOptions{Now: func() time.Time { return now }})
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	if deviceKey, ok := mso.DeviceKey.(*ecdsa.PublicKey); !ok || !deviceKey.Equal(holder) {
		return errors.New("the MSO's DeviceKey isn't the holder key the wallet proved possession of")
	}
	return nil
}

// issuerAuthX5Chain reads the x5chain (COSE header label 33, RFC 9360)
// from an mdoc's IssuerAuth — an untagged COSE_Sign1, [protected,
// unprotected, payload, signature] — where ISO/IEC 18013-5 puts it: in
// the unprotected header, as one certificate or an array of them. It's
// untrusted until the chain verifies against the issuer roots.
func issuerAuthX5Chain(issuerAuth []byte) ([][]byte, error) {
	var sign1 []cbor.RawMessage
	if err := cbor.Unmarshal(issuerAuth, &sign1); err != nil || len(sign1) != 4 {
		return nil, errors.New("issuerAuth isn't a COSE_Sign1")
	}
	var unprotected map[int]cbor.RawMessage
	if err := cbor.Unmarshal(sign1[1], &unprotected); err != nil {
		return nil, fmt.Errorf("issuerAuth unprotected header: %w", err)
	}
	const x5chainLabel = 33
	rawChain, ok := unprotected[x5chainLabel]
	if !ok {
		return nil, errors.New("issuerAuth has no x5chain")
	}
	var one []byte
	if cbor.Unmarshal(rawChain, &one) == nil {
		return [][]byte{one}, nil
	}
	var many [][]byte
	if err := cbor.Unmarshal(rawChain, &many); err != nil || len(many) == 0 {
		return nil, errors.New("issuerAuth x5chain is neither a certificate nor a non-empty array of them")
	}
	return many, nil
}

// decodeJOSEHeader decodes a compact JWS's protected header, unverified.
func decodeJOSEHeader(compact string, v any) error {
	encoded, _, ok := strings.Cut(compact, ".")
	if !ok {
		return errors.New("issuer JWT isn't a compact JWS")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("issuer JWT header: %w", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("issuer JWT header: %w", err)
	}
	return nil
}

// jwkIsKey reports whether jwk is key, a P-256 public key.
func jwkIsKey(jwk map[string]any, key *ecdsa.PublicKey) bool {
	raw, err := key.Bytes() // uncompressed: 0x04 || X || Y
	if err != nil {
		return false
	}
	size := (len(raw) - 1) / 2
	b64 := base64.RawURLEncoding
	return jwk["kty"] == "EC" && jwk["crv"] == "P-256" &&
		jwk["x"] == b64.EncodeToString(raw[1:1+size]) && jwk["y"] == b64.EncodeToString(raw[1+size:])
}
