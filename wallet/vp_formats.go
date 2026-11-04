package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// VPFormats is a Verifier's vp_formats_supported (OpenID4VP 1.0 §11.1,
// Appendix B): the Credential Formats it accepts, each with the
// algorithms it verifies. nil, when the request carries none, accepts
// every format.
type VPFormats map[string]VPFormat

// VPFormat is one format's entry in VPFormats. An empty list accepts
// any algorithm.
type VPFormat struct {
	// SDJWTAlgValues and KBJWTAlgValues are a dc+sd-jwt credential's
	// Issuer-signed JWT and Key Binding JWT algorithms (Appendix B.3).
	SDJWTAlgValues []string `json:"sd-jwt_alg_values,omitempty"`
	KBJWTAlgValues []string `json:"kb-jwt_alg_values,omitempty"`
	// IssuerAuthAlgValues and DeviceAuthAlgValues are an mso_mdoc
	// credential's IssuerAuth and DeviceSignature COSE algorithms
	// (Appendix B.2).
	IssuerAuthAlgValues []int64 `json:"issuerauth_alg_values,omitempty"`
	DeviceAuthAlgValues []int64 `json:"deviceauth_alg_values,omitempty"`
}

// parseVPFormats is client_metadata's vp_formats_supported, nil when
// it has none.
func parseVPFormats(clientMetadata json.RawMessage) (VPFormats, error) {
	var meta struct {
		VPFormats VPFormats `json:"vp_formats_supported"`
	}
	if len(clientMetadata) == 0 {
		return nil, nil
	}
	if err := strictjson.Unmarshal(clientMetadata, &meta); err != nil {
		return nil, fmt.Errorf("client_metadata.vp_formats_supported: %w", err)
	}
	return meta.VPFormats, nil
}

// Accepts reports whether the Verifier can take held: its format is
// listed, and the algorithms it's signed with, and the wallet signs its
// presentation with, are among the format's. A credential the wallet
// can't read isn't accepted. The wallet's own signatures are ES256
// (COSE -7), or the fully specified ESP256 (-9), with a P-256 key.
func (f VPFormats) Accepts(held HeldCredential) bool {
	if f == nil {
		return true
	}
	format, ok := f[held.Format]
	if !ok {
		return false
	}
	switch held.Format {
	case sdjwtvc.CredentialFormat:
		return format.acceptsSDJWTVC(held)
	case mdoc.CredentialFormat:
		return format.acceptsMdoc(held)
	}
	return true
}

func (f VPFormat) acceptsSDJWTVC(held HeldCredential) bool {
	if len(f.SDJWTAlgValues) > 0 {
		pres, err := sdjwtvc.Parse(held.Credential)
		if err != nil {
			return false
		}
		header, _, err := jose.DecodeUnverified(pres.IssuerJWT)
		if err != nil {
			return false
		}
		alg, _ := header["alg"].(string)
		if !slices.Contains(f.SDJWTAlgValues, alg) {
			return false
		}
	}
	if len(f.KBJWTAlgValues) > 0 && sdjwtvcBound(held.Credential) {
		alg := string(held.HolderKeyAlg)
		if alg == "" {
			alg = string(jose.ES256)
		}
		return slices.Contains(f.KBJWTAlgValues, alg)
	}
	return true
}

// coseESP256 is the fully specified ECDSA P-256 with SHA-256 (-9).
const coseESP256 = -9

func (f VPFormat) acceptsMdoc(held HeldCredential) bool {
	if len(f.DeviceAuthAlgValues) > 0 && !slices.Contains(f.DeviceAuthAlgValues, int64(cose.ES256)) && !slices.Contains(f.DeviceAuthAlgValues, coseESP256) {
		return false
	}
	if len(f.IssuerAuthAlgValues) == 0 {
		return true
	}
	raw, err := base64.RawURLEncoding.DecodeString(held.Credential)
	if err != nil {
		return false
	}
	signed, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		return false
	}
	protected, unprotected, _, err := cose.DecodeUnverified(signed.IssuerAuth)
	if err != nil {
		return false
	}
	alg := int64(protected.Alg)
	if slices.Contains(f.IssuerAuthAlgValues, alg) {
		return true
	}
	// Appendix B.2.3: -9 matches -7 signed with a P-256 key, and so
	// RFC 9864's -51 and -52 match -35 and -36 on P-384 and P-521.
	esp, ok := coseESPAliases[alg]
	return ok && slices.Contains(f.IssuerAuthAlgValues, esp.alias) && signedOnCurve(esp.curve, protected, unprotected)
}

// coseESPAliases are the fully specified ECDSA identifiers (RFC 9864)
// of ES256, ES384 and ES512, by those algorithms' own, with the one
// curve each names.
var coseESPAliases = map[int64]struct {
	alias int64
	curve elliptic.Curve
}{
	int64(cose.ES256): {coseESP256, elliptic.P256()},
	int64(cose.ES384): {-51, elliptic.P384()},
	int64(cose.ES512): {-52, elliptic.P521()},
}

// signedOnCurve reports whether the x5chain leaf's key is on curve.
func signedOnCurve(curve elliptic.Curve, headers ...cose.Headers) bool {
	for _, h := range headers {
		if len(h.X5Chain) == 0 {
			continue
		}
		leaf, err := x509.ParseCertificate(h.X5Chain[0])
		if err != nil {
			return false
		}
		pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		return ok && pub.Curve == curve
	}
	return false
}
