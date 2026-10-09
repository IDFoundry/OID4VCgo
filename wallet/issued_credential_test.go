package wallet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

const (
	issuedVCT     = "https://credentials.example.com/identity_credential"
	issuedDocType = "org.iso.18013.5.1.mDL"
)

// issuedFixture is a credential of each format issued to holder, signed
// by a leaf certificate issuer under roots' CA.
type issuedFixture struct {
	holder       *ecdsa.PrivateKey
	roots        *x509.CertPool
	sdjwt, mdocB string
	sdjwtConf    oid4vci.CredentialConfigurationMetadata
	mdocConf     oid4vci.CredentialConfigurationMetadata
	now          time.Time
}

func newIssuedFixture(t testing.TB, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, roots *x509.CertPool) issuedFixture {
	t.Helper()
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderJWK, err := jwk.Marshal(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	exp := now.Add(time.Hour).Unix()
	sdjwt, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{
		VCT: issuedVCT, Exp: &exp, CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{"given_name": sdjwtvc.SD("Alice")},
	}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
	if err != nil {
		t.Fatalf("sdjwtvc.Issue: %v", err)
	}
	signed, err := mdoc.Issue(leafKey, cose.ES256, mdoc.Claims{
		DocType:    issuedDocType,
		NameSpaces: map[string]map[string]interface{}{"org.iso.18013.5.1": {"given_name": "Alice"}},
		DeviceKey:  &holder.PublicKey,
		Signed:     now, ValidFrom: now, ValidUntil: now.Add(time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{leaf.Raw}})
	if err != nil {
		t.Fatalf("mdoc.Issue: %v", err)
	}
	raw, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return issuedFixture{
		holder: holder, roots: roots, now: now,
		sdjwt: sdjwt, mdocB: base64.RawURLEncoding.EncodeToString(raw),
		sdjwtConf: oid4vci.CredentialConfigurationMetadata{Format: sdjwtvc.CredentialFormat, VCT: issuedVCT, CryptographicBindingMethodsSupported: []string{"jwk"}},
		mdocConf:  oid4vci.CredentialConfigurationMetadata{Format: mdoc.CredentialFormat, DocType: issuedDocType, CryptographicBindingMethodsSupported: []string{"cose_key"}},
	}
}

func caIssuedFixture(t testing.TB) issuedFixture {
	t.Helper()
	ca, caKey := testcert.CA(t, "issued credential test CA")
	leaf, leafKey := testcert.Leaf(t, "issued credential test issuer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return newIssuedFixture(t, leaf, leafKey, roots)
}

func (f issuedFixture) byFormat() map[string]struct {
	conf       oid4vci.CredentialConfigurationMetadata
	credential string
} {
	return map[string]struct {
		conf       oid4vci.CredentialConfigurationMetadata
		credential string
	}{"dc+sd-jwt": {f.sdjwtConf, f.sdjwt}, "mso_mdoc": {f.mdocConf, f.mdocB}}
}

func TestVerifyIssuedCredential_Accepts(t *testing.T) {
	f := caIssuedFixture(t)
	for format, c := range f.byFormat() {
		got, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
			Configuration: c.conf, Credential: c.credential, HolderKey: &f.holder.PublicKey, IssuerRoots: f.roots,
		})
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if got.IssuerCertificate == nil || got.IssuerCertificate.Subject.CommonName != "issued credential test issuer" {
			t.Errorf("%s: IssuerCertificate = %v", format, got.IssuerCertificate)
		}
		var givenName any
		if format == "mso_mdoc" {
			ns, _ := got.Claims["org.iso.18013.5.1"].(map[string]interface{})
			givenName = ns["given_name"]
		} else {
			givenName = got.Claims["given_name"]
		}
		if givenName != "Alice" {
			t.Errorf("%s: given_name = %v, want the disclosed claim", format, givenName)
		}
	}
}

// A credential whose configuration declares no binding must be bound to
// no key (OpenID4VCI 1.0 §12.2.4): an SD-JWT VC naming one in cnf is
// refused, since the wallet proved no key, and one without is accepted.
func TestVerifyIssuedCredential_Unbound(t *testing.T) {
	f := caIssuedFixture(t)
	unboundConf := f.sdjwtConf
	unboundConf.CryptographicBindingMethodsSupported = nil
	if _, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
		Configuration: unboundConf, Credential: f.sdjwt, IssuerRoots: f.roots,
	}); err == nil || !strings.Contains(err.Error(), "cnf") {
		t.Errorf("an unbound configuration's credential naming a key: %v, want it refused", err)
	}

	ca, caKey := testcert.CA(t, "unbound test CA")
	leaf, leafKey := testcert.Leaf(t, "unbound test issuer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	exp := time.Now().Add(time.Hour).Unix()
	unbound, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{VCT: issuedVCT, Exp: &exp}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
		Configuration: unboundConf, Credential: unbound, IssuerRoots: roots,
	}); err != nil {
		t.Errorf("an unbound credential: %v", err)
	}
}

// A credential valid from the moment the issuer signed it is accepted by
// a wallet whose clock is a little behind the issuer's — within a
// minute, not beyond.
func TestVerifyIssuedCredential_AllowsIssuerClockSkew(t *testing.T) {
	f := caIssuedFixture(t)
	verify := func(at time.Time) error {
		_, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
			Configuration: f.mdocConf, Credential: f.mdocB, HolderKey: &f.holder.PublicKey, IssuerRoots: f.roots, Now: at,
		})
		return err
	}
	if err := verify(f.now.Add(-30 * time.Second)); err != nil {
		t.Errorf("wallet clock 30 s behind the issuer's: %v", err)
	}
	if err := verify(f.now.Add(-2 * time.Minute)); err == nil {
		t.Error("wallet clock 2 minutes behind: accepted, want not yet valid")
	}
}

// TestVerifyIssuedCredential_Rejects covers what a Wallet must not keep.
func TestVerifyIssuedCredential_Rejects(t *testing.T) {
	f := caIssuedFixture(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	selfSigned, selfSignedKey := testcert.SelfSignedLeaf(t, "self-signed issuer")
	selfRoots := x509.NewCertPool()
	selfRoots.AddCert(selfSigned)
	selfF := newIssuedFixture(t, selfSigned, selfSignedKey, selfRoots)

	for format, c := range f.byFormat() {
		wrongType := c.conf
		wrongType.VCT, wrongType.DocType = "https://other.example/vct", "org.example.other.1"
		tampered := []byte(c.credential)
		if i := len(tampered) / 3; tampered[i] == 'A' {
			tampered[i] = 'B'
		} else {
			tampered[i] = 'A'
		}
		base := wallet.VerifyIssuedCredentialParams{Configuration: c.conf, Credential: c.credential, HolderKey: &f.holder.PublicKey, IssuerRoots: f.roots}
		cases := map[string]func(p *wallet.VerifyIssuedCredentialParams){
			"untrusted issuer":            func(p *wallet.VerifyIssuedCredentialParams) { p.IssuerRoots = x509.NewCertPool() },
			"another holder key":          func(p *wallet.VerifyIssuedCredentialParams) { p.HolderKey = &other.PublicKey },
			"another type":                func(p *wallet.VerifyIssuedCredentialParams) { p.Configuration = wrongType },
			"expired":                     func(p *wallet.VerifyIssuedCredentialParams) { p.Now = f.now.Add(2 * time.Hour) },
			"tampered":                    func(p *wallet.VerifyIssuedCredentialParams) { p.Credential = string(tampered) },
			"no holder key, bound format": func(p *wallet.VerifyIssuedCredentialParams) { p.HolderKey = nil },
			"no roots":                    func(p *wallet.VerifyIssuedCredentialParams) { p.IssuerRoots = nil },
			"self-signed issuer, even as a root": func(p *wallet.VerifyIssuedCredentialParams) {
				p.Credential, p.IssuerRoots, p.HolderKey = selfF.byFormat()[format].credential, selfF.roots, &selfF.holder.PublicKey
			},
		}
		for name, mutate := range cases {
			p := base
			mutate(&p)
			if _, err := wallet.VerifyIssuedCredential(context.Background(), p); err == nil {
				t.Errorf("%s / %s: accepted", format, name)
			} else if name == "self-signed issuer, even as a root" && !strings.Contains(err.Error(), "self-signed") {
				t.Errorf("%s / %s: error = %v, want it refused as self-signed", format, name, err)
			}
		}
	}
}
