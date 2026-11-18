package verifier_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

const (
	anchorTestPID     = "urn:pid:1"
	anchorTestLoyalty = "urn:loyalty:1"
)

// anchorTestCredential is an SD-JWT VC of type vct, with iss and
// aka_vcts when set, signed with leafKey under leaf (and
// intermediates), and the key its holder presents it with.
func anchorTestCredential(t *testing.T, vct, iss string, aka []string, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, intermediates ...*x509.Certificate) (string, *ecdsa.PrivateKey) {
	t.Helper()
	holderKey := testP256Key(t)
	holderJWK, err := jwk.Marshal(&holderKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cred, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{
		Iss: iss, VCT: vct, AkaVCTs: aka, CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{"family_name": sdjwtvc.SD("Mallory")},
	}, sdjwtvc.IssueOptions{IssuerCertificate: leaf, IssuerIntermediates: intermediates})
	if err != nil {
		t.Fatal(err)
	}
	return cred, holderKey
}

// verifyAnchorTestCredential presents cred for a query asking for a
// urn:pid:1 credential's family_name, and verifies it with keys and
// authorized.
func verifyAnchorTestCredential(t *testing.T, cred string, holderKey *ecdsa.PrivateKey, keys verifier.SDJWTVCIssuerKeyResolver, authorized func(context.Context, verifier.IssuerAuthorization) error) (verifier.VerifyResponseResult, error) {
	t.Helper()
	ctx := context.Background()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{anchorTestPID}})
	if err != nil {
		t.Fatal(err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "pid", Format: sdjwtvc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("family_name")}}},
	}}}
	v := newTestVerifier(t)
	const nonce = "nonce-0123456789abcdef"
	vpToken, err := wallet.PresentCredentials(ctx, wallet.PresentationRequest{
		Query: query, Audience: v.ClientID(), Nonce: nonce,
		Credentials: []wallet.HeldCredential{{Format: sdjwtvc.CredentialFormat, Credential: cred, HolderKey: holderKey, HolderKeyAlg: jose.ES256}},
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	return v.VerifyResponse(ctx, verifier.VerifyResponseRequest{
		Query: query, Response: verifier.ParsedResponse{VPToken: vpToken}, ExpectedNonce: nonce,
		IssuerKeys: keys, MaxKeyBindingAge: time.Hour, NoStatusCheck: true,
		IssuerAuthorized: authorized, AnyIssuerForAnyType: authorized == nil,
	})
}

// authorizeByAnchor is an IssuerAuthorized deciding as
// IssuerAuthorization's doc says: by the anchor that verified the
// issuer's chain, compared by key with the anchors assigned to each
// matched type.
func authorizeByAnchor(anchorFor map[string]*x509.Certificate) func(context.Context, verifier.IssuerAuthorization) error {
	return func(_ context.Context, a verifier.IssuerAuthorization) error {
		if a.IssuerAnchor == nil || len(a.MatchedTypes) == 0 {
			return errors.New("no verified anchor or matched type")
		}
		for _, typ := range a.MatchedTypes {
			if anchor := anchorFor[typ]; anchor == nil || !verifier.AnchorIs(a.IssuerAnchor, anchor) {
				return errors.New("the issuer's anchor isn't authorized for " + typ)
			}
		}
		return nil
	}
}

// requireUntrustedIssuer fails t unless err refuses the presentation as
// an untrusted issuer's.
func requireUntrustedIssuer(t *testing.T, err error) {
	t.Helper()
	var verr *verifier.Error
	if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonUntrustedIssuer {
		t.Fatalf("err = %v; want ReasonUntrustedIssuer", err)
	}
}

// Two trusted roots share a subject name, as any root operator can
// choose. The loyalty root, trusted for urn:loyalty:1 only, issues an
// intermediate claiming the PID root's key identifier, and under it a
// PID: the path's top certificate names the PID root as its issuer, by
// name and authority key identifier, but the loyalty root verified it.
// A hook deciding by IssuerAnchor refuses it, and RootsByVCT refuses it
// without a hook; the PID root's own PID passes both.
func TestIssuerAnchor_CoTrustedRootSharingAName(t *testing.T) {
	shared := pkix.Name{CommonName: "Ecosystem Root CA", Organization: []string{"Example Gov"}, Country: []string{"EU"}}
	pidRoot, pidRootKey := testcert.CAWithSubject(t, shared)
	loyaltyRoot, loyaltyRootKey := testcert.CAWithSubject(t, shared)

	spoofParent := *loyaltyRoot
	spoofParent.SubjectKeyId = pidRoot.SubjectKeyId
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "PID Issuing CA (not really)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}, &spoofParent, &interKey.PublicKey, loyaltyRootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(inter.RawIssuer, pidRoot.RawSubject) || !bytes.Equal(inter.AuthorityKeyId, pidRoot.SubjectKeyId) {
		t.Fatal("the forged intermediate doesn't name the PID root")
	}
	forgedLeaf, forgedKey := testcert.Leaf(t, "pid-issuer.example", inter, interKey)
	forged, forgedHolder := anchorTestCredential(t, anchorTestPID, "", nil, forgedLeaf, forgedKey, inter)

	genuineInter, genuineInterKey := testcert.Intermediate(t, "PID Issuing CA", pidRoot, pidRootKey)
	genuineLeaf, genuineKey := testcert.Leaf(t, "pid-issuer.example", genuineInter, genuineInterKey)
	genuine, genuineHolder := anchorTestCredential(t, anchorTestPID, "", nil, genuineLeaf, genuineKey, genuineInter)

	roots := x509.NewCertPool()
	roots.AddCert(pidRoot)
	roots.AddCert(loyaltyRoot)
	byAnchor := authorizeByAnchor(map[string]*x509.Certificate{anchorTestPID: pidRoot, anchorTestLoyalty: loyaltyRoot})
	pooled := verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}

	t.Run("IssuerAnchor", func(t *testing.T) {
		result, err := verifyAnchorTestCredential(t, genuine, genuineHolder, pooled, byAnchor)
		if err != nil {
			t.Fatalf("the PID root's own PID: %v", err)
		}
		if got := result.Credentials[0].IssuerAnchor; !bytes.Equal(got, pidRoot.Raw) {
			t.Fatal("VerifiedCredential.IssuerAnchor isn't the PID root")
		}
		_, err = verifyAnchorTestCredential(t, forged, forgedHolder, pooled, byAnchor)
		requireUntrustedIssuer(t, err)
	})
	t.Run("RootsByVCT", func(t *testing.T) {
		byType := verifier.X5CIssuerKeyResolver{RootsByVCT: map[string]*x509.CertPool{anchorTestPID: certPool(pidRoot), anchorTestLoyalty: certPool(loyaltyRoot)}, Revocation: certrevocation.NoCheck{}}
		if _, err := verifyAnchorTestCredential(t, genuine, genuineHolder, byType, nil); err != nil {
			t.Fatalf("the PID root's own PID: %v", err)
		}
		_, err := verifyAnchorTestCredential(t, forged, forgedHolder, byType, nil)
		requireUntrustedIssuer(t, err)
	})
}

// A provider CA trusted for loyalty cards certifies a leaf naming the
// PID provider's URI, and signs a PID with that iss: RequireIssuerName
// passes, and IssuerAuthorization.Issuer is the PID provider's. A hook
// deciding by IssuerAnchor (by key, or by the key identifiers a
// trusted_authorities "aki" query names) refuses it, and so does
// RootsByVCT; the PID provider's own PID passes all three.
func TestIssuerAnchor_CoTrustedCANamingAnotherIssuer(t *testing.T) {
	const pidIssuer = "https://pid-provider.example"
	pidCA, pidCAKey := testcert.CA(t, "PID Provider CA")
	loyaltyCA, loyaltyCAKey := testcert.CA(t, "Loyalty Club CA")
	issuerURI, err := url.Parse(pidIssuer)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(ca *x509.Certificate, caKey *ecdsa.PrivateKey) (string, *ecdsa.PrivateKey) {
		leaf, leafKey := testcert.Issue(t, &x509.Certificate{
			Subject: pkix.Name{CommonName: "pid-provider"}, URIs: []*url.URL{issuerURI}, KeyUsage: x509.KeyUsageDigitalSignature,
		}, ca, caKey)
		return anchorTestCredential(t, anchorTestPID, pidIssuer, nil, leaf, leafKey)
	}
	genuine, genuineHolder := issue(pidCA, pidCAKey)
	forged, forgedHolder := issue(loyaltyCA, loyaltyCAKey)

	roots := x509.NewCertPool()
	roots.AddCert(pidCA)
	roots.AddCert(loyaltyCA)
	named := verifier.X5CIssuerKeyResolver{Roots: roots, RequireIssuerName: true, Revocation: certrevocation.NoCheck{}}

	pidAKI, err := dcql.AKITrustedAuthorities(pidCA)
	if err != nil {
		t.Fatal(err)
	}
	byKeyIdentifier := func(_ context.Context, a verifier.IssuerAuthorization) error {
		if a.Issuer != pidIssuer {
			t.Errorf("Issuer = %q; want the checked iss", a.Issuer)
		}
		if !verifier.AnchorHasKeyIdentifier(a.IssuerAnchor, pidAKI.Values...) {
			return errors.New("the issuer's anchor isn't the PID provider's")
		}
		return nil
	}
	for name, authorized := range map[string]func(context.Context, verifier.IssuerAuthorization) error{
		"AnchorIs":               authorizeByAnchor(map[string]*x509.Certificate{anchorTestPID: pidCA, anchorTestLoyalty: loyaltyCA}),
		"AnchorHasKeyIdentifier": byKeyIdentifier,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyAnchorTestCredential(t, genuine, genuineHolder, named, authorized); err != nil {
				t.Fatalf("the PID provider's own PID: %v", err)
			}
			_, err := verifyAnchorTestCredential(t, forged, forgedHolder, named, authorized)
			requireUntrustedIssuer(t, err)
		})
	}
	t.Run("RootsByVCT", func(t *testing.T) {
		byType := named
		byType.Roots = nil
		byType.RootsByVCT = map[string]*x509.CertPool{anchorTestPID: certPool(pidCA), anchorTestLoyalty: certPool(loyaltyCA)}
		if _, err := verifyAnchorTestCredential(t, genuine, genuineHolder, byType, nil); err != nil {
			t.Fatalf("the PID provider's own PID: %v", err)
		}
		_, err := verifyAnchorTestCredential(t, forged, forgedHolder, byType, nil)
		requireUntrustedIssuer(t, err)
	})
}

// A loyalty card listing the PID type in its aka_vcts answers a PID
// query (SD-JWT VC draft-19 §2.2.2.2), but under RootsByVCT its issuer
// must be trusted for that type too: refused, where one pool for every
// type accepts it.
func TestRootsByVCT_AkaVCTs(t *testing.T) {
	pidCA, _ := testcert.CA(t, "PID Provider CA")
	loyaltyCA, loyaltyCAKey := testcert.CA(t, "Loyalty Club CA")
	leaf, leafKey := testcert.Leaf(t, "loyalty.example", loyaltyCA, loyaltyCAKey)
	cred, holder := anchorTestCredential(t, anchorTestLoyalty, "", []string{anchorTestPID}, leaf, leafKey)
	pooled := verifier.X5CIssuerKeyResolver{Roots: certPool(pidCA, loyaltyCA), Revocation: certrevocation.NoCheck{}}
	if _, err := verifyAnchorTestCredential(t, cred, holder, pooled, nil); err != nil {
		t.Fatalf("one pool for every type: %v", err)
	}
	byType := verifier.X5CIssuerKeyResolver{RootsByVCT: map[string]*x509.CertPool{anchorTestPID: certPool(pidCA), anchorTestLoyalty: certPool(loyaltyCA)}, Revocation: certrevocation.NoCheck{}}
	_, err := verifyAnchorTestCredential(t, cred, holder, byType, nil)
	requireUntrustedIssuer(t, err)
}

// Without a chain verified against configured roots there's no anchor:
// a resolver that only resolves the key gives the hook, and the
// result, a nil IssuerAnchor.
func TestIssuerAnchor_NilWithoutAVerifiedChain(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuer CA")
	leaf, leafKey := testcert.Leaf(t, "issuer.example", ca, caKey)
	cred, holder := anchorTestCredential(t, anchorTestPID, "", nil, leaf, leafKey)
	keyOnly := keyOnlySDJWTResolver{verifier.X5CIssuerKeyResolver{Roots: certPool(ca), Revocation: certrevocation.NoCheck{}}}
	var seen verifier.IssuerAuthorization
	result, err := verifyAnchorTestCredential(t, cred, holder, keyOnly, func(_ context.Context, a verifier.IssuerAuthorization) error {
		seen = a
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen.IssuerAnchor != nil || result.Credentials[0].IssuerAnchor != nil {
		t.Fatal("a resolver that verifies no chain gave an anchor")
	}
	if len(seen.IssuerChain) == 0 {
		t.Fatal("the hook got no (header) chain")
	}
	if verifier.AnchorIs(nil, ca) || verifier.AnchorHasKeyIdentifier(nil, "AAAA") {
		t.Fatal("a nil anchor matched")
	}
}

// keyOnlySDJWTResolver resolves keys with an X5CIssuerKeyResolver but
// gives no verified chains.
type keyOnlySDJWTResolver struct{ r verifier.X5CIssuerKeyResolver }

func (k keyOnlySDJWTResolver) ResolveIssuerKey(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	return k.r.ResolveIssuerKey(ctx, header, payload)
}

// The same for an OpenID4VP mdoc: a co-trusted IACA sharing the mDL
// IACA's name issues a document signer naming the mDL IACA, by name and
// authority key identifier, and signs an mDL with it. A hook deciding by
// IssuerAnchor refuses it; the mDL IACA's own mDL passes, its
// VerifiedCredential.IssuerAnchor the mDL IACA.
func TestIssuerAnchor_Mdoc(t *testing.T) {
	shared := pkix.Name{CommonName: "Ecosystem IACA", Country: []string{"US"}}
	mdlIACA, mdlKey := testcert.CAWithSubject(t, shared)
	loyaltyIACA, loyaltyKey := testcert.CAWithSubject(t, shared)
	spoofParent := *loyaltyIACA
	spoofParent.SubjectKeyId = mdlIACA.SubjectKeyId
	signer := func(parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		return testcert.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "mDL document signer", Country: []string{"US"}}, KeyUsage: x509.KeyUsageDigitalSignature}, parent, parentKey)
	}
	genuineDS, genuineKey := signer(mdlIACA, mdlKey)
	forgedDS, forgedKey := signer(&spoofParent, loyaltyKey)
	if !bytes.Equal(forgedDS.RawIssuer, mdlIACA.RawSubject) || !bytes.Equal(forgedDS.AuthorityKeyId, mdlIACA.SubjectKeyId) {
		t.Fatal("the forged document signer doesn't name the mDL IACA")
	}

	mf := newMdocVerifyFixture(t)
	protected, unprotected, payload, err := cose.DecodeUnverified(mf.f.IssuerSigned.IssuerAuth)
	if err != nil {
		t.Fatal(err)
	}
	under := func(ds *x509.Certificate, key *ecdsa.PrivateKey) mdocVerifyFixture {
		f := mf
		u := unprotected
		u.X5Chain = [][]byte{ds.Raw}
		if f.f.IssuerSigned.IssuerAuth, err = cose.Sign(cose.ES256, key, protected, u, payload, []byte{}); err != nil {
			t.Fatal(err)
		}
		return f
	}
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: certPool(mdlIACA, loyaltyIACA), LeafPolicy: verifier.AnyIssuerLeaf, Revocation: certrevocation.NoCheck{}}
	byAnchor := authorizeByAnchor(map[string]*x509.Certificate{testmdoc.DocType: mdlIACA, "org.example.loyalty.1": loyaltyIACA})
	verify := func(f mdocVerifyFixture) (verifier.VerifyResponseResult, error) {
		return f.verifyWith(t, f.nonce, func(r *verifier.VerifyResponseRequest) {
			r.MdocIssuerKeys, r.IssuerAuthorized = resolver, byAnchor
		})
	}
	result, err := verify(under(genuineDS, genuineKey))
	if err != nil {
		t.Fatalf("the mDL IACA's own mDL: %v", err)
	}
	if !bytes.Equal(result.Credentials[0].IssuerAnchor, mdlIACA.Raw) {
		t.Error("VerifiedCredential.IssuerAnchor isn't the mDL IACA")
	}
	_, err = verify(under(forgedDS, forgedKey))
	requireUntrustedIssuer(t, err)
}

// AnchorIs compares keys: a root reissued with the same key matches,
// one with another key and the same name and key identifier doesn't.
func TestAnchorIs_ComparesKeys(t *testing.T) {
	shared := pkix.Name{CommonName: "Root"}
	root, rootKey := testcert.CAWithSubject(t, shared)
	other, _ := testcert.CAWithSubject(t, shared)
	reissued := testcert.SelfSigned(t, "Root (reissued)", &rootKey.PublicKey, rootKey)
	if !verifier.AnchorIs(root.Raw, reissued) || !verifier.AnchorIs(root.Raw, other, root) {
		t.Fatal("the same key didn't match")
	}
	if verifier.AnchorIs(root.Raw, other) || verifier.AnchorIs(root.Raw) || verifier.AnchorIs([]byte("junk"), root) || verifier.AnchorIs(root.Raw, nil) {
		t.Fatal("a different key, no anchors or junk matched")
	}
	declaredOnly, err := dcql.AKITrustedAuthorities(other)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.AnchorHasKeyIdentifier(root.Raw, declaredOnly.Values...) {
		t.Fatal("another key's identifier matched")
	}
}
