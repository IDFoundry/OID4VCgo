package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// A credential is offered only when the Verifier's vp_formats_supported
// (OpenID4VP 1.0 §11.1, Appendix B) lists its format and the algorithms
// it's signed with and the wallet signs with; no vp_formats_supported
// accepts everything.
func TestVPFormats_Accepts(t *testing.T) {
	ca, caKey := testcert.CA(t, "formats test CA")
	leaf, leafKey := testcert.Leaf(t, "formats test issuer", ca, caKey)
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderJWK, err := jwk.Marshal(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	credential, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{VCT: "urn:x", Exp: &exp, CNF: map[string]any{"jwk": holderJWK}}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
	if err != nil {
		t.Fatal(err)
	}
	sdjwt := wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: credential, HolderKeyAlg: jose.ES256}
	mdl := heldMdoc(t, testmdoc.Issue(t))
	mdl384 := heldMdoc(t, testmdoc.IssueOn(t, elliptic.P384(), elliptic.P256()))
	mdl521 := heldMdoc(t, testmdoc.IssueOn(t, elliptic.P521(), elliptic.P256()))

	for name, tc := range map[string]struct {
		formats wallet.VPFormats
		held    wallet.HeldCredential
		want    bool
	}{
		"none given":            {nil, sdjwt, true},
		"format not listed":     {wallet.VPFormats{"mso_mdoc": {}}, sdjwt, false},
		"sd-jwt, any algorithm": {wallet.VPFormats{"dc+sd-jwt": {}}, sdjwt, true},
		"sd-jwt issuer alg":     {wallet.VPFormats{"dc+sd-jwt": {SDJWTAlgValues: []string{"ES384"}}}, sdjwt, false},
		"sd-jwt kb alg":         {wallet.VPFormats{"dc+sd-jwt": {SDJWTAlgValues: []string{"ES256"}, KBJWTAlgValues: []string{"EdDSA"}}}, sdjwt, false},
		"sd-jwt both match":     {wallet.VPFormats{"dc+sd-jwt": {SDJWTAlgValues: []string{"ES256"}, KBJWTAlgValues: []string{"ES256"}}}, sdjwt, true},
		"mdoc issuerauth -7":    {wallet.VPFormats{"mso_mdoc": {IssuerAuthAlgValues: []int64{-7}}}, mdl, true},
		"mdoc issuerauth -9":    {wallet.VPFormats{"mso_mdoc": {IssuerAuthAlgValues: []int64{-9}}}, mdl, true},
		"mdoc issuerauth -35":   {wallet.VPFormats{"mso_mdoc": {IssuerAuthAlgValues: []int64{-35}}}, mdl, false},
		"P-384 mdoc -35":        {wallet.VPFormats{"mso_mdoc": {IssuerAuthAlgValues: []int64{-35}}}, mdl384, true},
		"P-384 mdoc -51":        {wallet.VPFormats{"mso_mdoc": {IssuerAuthAlgValues: []int64{-51}}}, mdl384, true},
		"P-384 mdoc -7, -9":     {wallet.VPFormats{"mso_mdoc": {IssuerAuthAlgValues: []int64{-7, -9}}}, mdl384, false},
		"P-384 mdoc -52":        {wallet.VPFormats{"mso_mdoc": {IssuerAuthAlgValues: []int64{-52}}}, mdl384, false},
		"P-521 mdoc -52":        {wallet.VPFormats{"mso_mdoc": {IssuerAuthAlgValues: []int64{-52}}}, mdl521, true},
		"P-521 mdoc -51":        {wallet.VPFormats{"mso_mdoc": {IssuerAuthAlgValues: []int64{-51}}}, mdl521, false},
		"mdoc deviceauth -9":    {wallet.VPFormats{"mso_mdoc": {DeviceAuthAlgValues: []int64{-9}}}, mdl, true},
		"mdoc deviceauth mac":   {wallet.VPFormats{"mso_mdoc": {DeviceAuthAlgValues: []int64{-65537}}}, mdl, false},
	} {
		if got := tc.formats.Accepts(tc.held); got != tc.want {
			t.Errorf("%s: Accepts = %v, want %v", name, got, tc.want)
		}
	}
}
