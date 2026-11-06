package identifierlist

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// testURI is ISO/IEC 18013-5 Annex D.6's identifier list uri.
const testURI = "https://example.com/identifierlists/1"

// testPKI is an IACA with a document signer and an identifier list
// signer under it.
type testPKI struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	leaf   *x509.Certificate
	key    *ecdsa.PrivateKey
	roots  *x509.CertPool
	dsPath []*x509.Certificate
}

func newPKI(t *testing.T) testPKI {
	t.Helper()
	ca, caKey := testcert.CA(t, "identifier list test IACA")
	leaf, key := testcert.Leaf(t, "identifier list signer", ca, caKey)
	ds, _ := testcert.Leaf(t, "document signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return testPKI{ca: ca, caKey: caKey, leaf: leaf, key: key, roots: roots, dsPath: []*x509.Certificate{ds}}
}

func claimsAt(now time.Time, ids ...[]byte) TokenClaims {
	exp := now.Add(time.Hour).Unix()
	ttl := int64(300)
	return TokenClaims{Sub: testURI, Iat: now.Unix(), Exp: &exp, TTL: &ttl, Identifiers: ids}
}

func issue(t *testing.T, pki testPKI, claims TokenClaims, opts IssueOptions) []byte {
	t.Helper()
	token, err := IssueToken(pki.key, cose.ES256, claims, []*x509.Certificate{pki.leaf}, opts)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	return token
}

// signRaw signs claims as a token without IssueToken's checks, for
// tokens IssueToken refuses to make.
func signRaw(t *testing.T, pki testPKI, typ string, claims map[int]any) []byte {
	t.Helper()
	raw, err := encMode.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	token, err := cose.SignTagged(cose.ES256, pki.key, cose.Headers{Typ: typ, X5Chain: [][]byte{pki.leaf.Raw}}, cose.Headers{}, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func wantErr(t *testing.T, name string, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s: err = %v, want one containing %q", name, err, want)
	}
}

// edLeaf issues an Ed25519 signer certificate under pki's CA.
func edLeaf(t *testing.T, pki testPKI) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "ed25519 identifier list signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}, pki.ca, pub, pki.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

// TestIssueCheck_RoundTrips: an MSO whose id is on the list is revoked,
// another isn't, for both key types and both COSE_Sign1 forms.
func TestIssueCheck_RoundTrips(t *testing.T) {
	pki := newPKI(t)
	edCert, edKey := edLeaf(t, pki)
	now := time.Now()
	for name, s := range map[string]struct {
		key  crypto.Signer
		alg  cose.Alg
		cert *x509.Certificate
	}{"ES256": {pki.key, cose.ES256, pki.leaf}, "EdDSA": {edKey, cose.EdDSA, edCert}} {
		t.Run(name, func(t *testing.T) {
			token, err := IssueToken(s.key, s.alg, claimsAt(now, []byte{0xcc, 0xcc}, []byte{0x01}), []*x509.Certificate{s.cert}, IssueOptions{})
			if err != nil {
				t.Fatalf("IssueToken: %v", err)
			}
			for form, tok := range map[string][]byte{"tagged": token, "untagged": token[1:]} {
				for id, want := range map[string]bool{"\xcc\xcc": true, "\xcc\xcd": false} {
					revoked, claims, err := Check(context.Background(), tok, pki.roots, Ref{ID: []byte(id), URI: testURI}, pki.dsPath, VerifyOptions{})
					if err != nil || revoked != want {
						t.Errorf("%s, id %x: revoked %v, %v; want %v", form, id, revoked, err, want)
					}
					if err == nil && (len(claims.Identifiers) != 2 || claims.TTL == nil || *claims.TTL != 300 || claims.Exp == nil) {
						t.Errorf("%s: claims = %+v", form, claims)
					}
				}
			}
		})
	}
}

// TestIssueToken_AnnexD6Shape decodes a token by hand: ISO/IEC 18013-5
// Annex D.6's structure, RFC 9360's bare-bstr x5chain for one
// certificate, and an empty unprotected header.
func TestIssueToken_AnnexD6Shape(t *testing.T) {
	pki := newPKI(t)
	token := issue(t, pki, claimsAt(time.Unix(1_686_920_170, 0), []byte{0xcc, 0xcc}), IssueOptions{})

	var tagged cbor.RawTag
	if err := cbor.Unmarshal(token, &tagged); err != nil || tagged.Number != 18 {
		t.Fatalf("not COSE_Sign1_Tagged: tag %d, %v", tagged.Number, err)
	}
	var sign1 struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected map[int]any
		Payload     []byte
		Signature   []byte
	}
	if err := cbor.Unmarshal(tagged.Content, &sign1); err != nil {
		t.Fatal(err)
	}
	var protected map[int]any
	if err := cbor.Unmarshal(sign1.Protected, &protected); err != nil {
		t.Fatal(err)
	}
	if protected[1] != int64(-7) || protected[16] != MediaType {
		t.Errorf("protected = %v, want alg -7 and typ %q", protected, MediaType)
	}
	if der, ok := protected[33].([]byte); !ok || !bytes.Equal(der, pki.leaf.Raw) {
		t.Errorf("x5chain = %T, want the leaf as a bare bstr", protected[33])
	}
	if len(sign1.Unprotected) != 0 || len(sign1.Signature) != 64 {
		t.Errorf("unprotected %v, signature %d bytes", sign1.Unprotected, len(sign1.Signature))
	}
	var payload map[int]cbor.RawMessage
	if err := cbor.Unmarshal(sign1.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	for _, key := range []int{2, 4, 6, 65534, 65530} {
		if _, ok := payload[key]; !ok {
			t.Errorf("claim %d missing", key)
		}
	}
	var list map[string]map[cbor.ByteString]map[any]any
	if err := cbor.Unmarshal(payload[65530], &list); err != nil {
		t.Fatal(err)
	}
	if got := list["identifiers"]; len(got) != 1 || got["\xcc\xcc"] == nil || len(got["\xcc\xcc"]) != 0 {
		t.Errorf("identifiers = %v, want {h'cccc': {}}", got)
	}
}

// TestTyp: tokens are issued as MediaType unless Typ says BareTyp, and
// verification accepts either, in any case, but nothing else.
func TestTyp(t *testing.T) {
	pki := newPKI(t)
	now := time.Now()
	ref := Ref{ID: []byte{1}, URI: testURI}
	for _, typ := range []string{"", BareTyp} {
		token := issue(t, pki, claimsAt(now, []byte{1}), IssueOptions{Typ: typ})
		protected, _, _, err := cose.DecodeUnverifiedTagged(token)
		want := typ
		if want == "" {
			want = MediaType
		}
		if err != nil || protected.Typ != want {
			t.Errorf("Typ %q: issued typ %q, %v", typ, protected.Typ, err)
		}
		if revoked, _, err := Check(context.Background(), token, pki.roots, ref, pki.dsPath, VerifyOptions{}); err != nil || !revoked {
			t.Errorf("Typ %q: revoked %v, %v", typ, revoked, err)
		}
	}
	_, err := IssueToken(pki.key, cose.ES256, claimsAt(now), []*x509.Certificate{pki.leaf}, IssueOptions{Typ: "application/statuslist+cwt"})
	wantErr(t, "IssueToken, another typ", err, "want \"application/identifierlist+cwt\" or \"identifierlist+cwt\"")

	exp := now.Add(time.Hour).Unix()
	claims := map[int]any{cwtClaimSub: testURI, cwtClaimIat: now.Unix(), cwtClaimExp: exp, cwtClaimIdentifierList: map[string]any{"identifiers": map[string]any{}}}
	if _, err := VerifyToken(context.Background(), signRaw(t, pki, "Application/IdentifierList+CWT", claims), pki.roots, VerifyOptions{}); err != nil {
		t.Errorf("typ in another case: %v", err)
	}
	_, err = VerifyToken(context.Background(), signRaw(t, pki, "application/statuslist+cwt", claims), pki.roots, VerifyOptions{})
	wantErr(t, "VerifyToken, a status list's typ", err, "want \"application/identifierlist+cwt\" or \"identifierlist+cwt\"")
}

// TestCheck_Refuses: a token that doesn't verify, isn't the
// reference's, is stale, or isn't an identifier list is refused, and
// reported revoked.
func TestCheck_Refuses(t *testing.T) {
	pki := newPKI(t)
	now := time.Now()
	token := issue(t, pki, claimsAt(now, []byte{1}), IssueOptions{})
	tampered := bytes.Clone(token)
	tampered[len(tampered)-1] ^= 0xff
	otherCA, _ := testcert.CA(t, "another CA")
	untrusted := x509.NewCertPool()
	untrusted.AddCert(otherCA)
	ref := Ref{ID: []byte{2}, URI: testURI}
	sign := func(claims map[int]any) []byte { return signRaw(t, pki, MediaType, claims) }
	list := map[string]any{"identifiers": map[string]any{}}
	exp := now.Add(time.Hour).Unix()
	at := func(d time.Duration) func() time.Time { return func() time.Time { return now.Add(d) } }
	rawClaims, err := encMode.Marshal(map[int]any{cwtClaimSub: testURI, cwtClaimIat: now.Unix(), cwtClaimExp: exp, cwtClaimIdentifierList: list})
	if err != nil {
		t.Fatal(err)
	}
	unprotectedChain, err := cose.SignTagged(cose.ES256, pki.key, cose.Headers{Typ: MediaType}, cose.Headers{X5Chain: [][]byte{pki.leaf.Raw}}, rawClaims, nil)
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		token []byte
		roots *x509.CertPool
		ref   Ref
		opts  VerifyOptions
		want  string
	}{
		"untrusted root":            {token, untrusted, ref, VerifyOptions{}, "token signer"},
		"nil roots, no certificate": {token, nil, ref, VerifyOptions{}, "no trust anchors"},
		"tampered signature":        {tampered, pki.roots, ref, VerifyOptions{}, "verify CWT signature"},
		"not a COSE_Sign1":          {[]byte{0xa0}, pki.roots, ref, VerifyOptions{}, "decode token"},
		"another list's sub":        {token, pki.roots, Ref{ID: []byte{2}, URI: "https://example.com/identifierlists/2"}, VerifyOptions{}, "isn't the reference's uri"},
		"no id in the reference":    {token, pki.roots, Ref{URI: testURI}, VerifyOptions{}, "needs an id and a uri"},
		"expired":                   {token, pki.roots, ref, VerifyOptions{Now: at(time.Hour)}, "is expired"},
		"issued in the future":      {token, pki.roots, ref, VerifyOptions{Now: at(-time.Hour)}, "issued in the future"},
		"older than MaxAge":         {token, pki.roots, ref, VerifyOptions{Now: at(30 * time.Minute), MaxAge: time.Minute}, "over the 1m0s allowed"},
		"negative MaxAge":           {token, pki.roots, ref, VerifyOptions{MaxAge: -time.Second}, "MaxAge is negative"},
		"no exp":                    {sign(map[int]any{cwtClaimSub: testURI, cwtClaimIat: now.Unix(), cwtClaimIdentifierList: list}), pki.roots, ref, VerifyOptions{}, "missing the required exp"},
		"x5chain unprotected":       {unprotectedChain, pki.roots, ref, VerifyOptions{}, "token signer"},
		"not yet valid (nbf)":       {sign(map[int]any{cwtClaimSub: testURI, cwtClaimIat: now.Unix(), cwtClaimExp: exp, cwtClaimNbf: now.Add(time.Hour).Unix(), cwtClaimIdentifierList: list}), pki.roots, ref, VerifyOptions{}, "isn't valid before"},
		"iat zero":                  {sign(map[int]any{cwtClaimSub: testURI, cwtClaimIat: 0, cwtClaimExp: exp, cwtClaimIdentifierList: list}), pki.roots, ref, VerifyOptions{}, "missing the required iat"},
		"no identifier_list":        {sign(map[int]any{cwtClaimSub: testURI, cwtClaimIat: now.Unix(), cwtClaimExp: exp}), pki.roots, ref, VerifyOptions{}, "missing the required identifier_list"},
		"a status_list claim too":   {sign(map[int]any{cwtClaimSub: testURI, cwtClaimIat: now.Unix(), cwtClaimExp: exp, cwtClaimStatusList: map[string]any{"bits": 1, "lst": []byte{0}}, cwtClaimIdentifierList: list}), pki.roots, ref, VerifyOptions{}, "carries a status_list claim"},
		"no identifiers map":        {sign(map[int]any{cwtClaimSub: testURI, cwtClaimIat: now.Unix(), cwtClaimExp: exp, cwtClaimIdentifierList: map[string]any{}}), pki.roots, ref, VerifyOptions{}, "has no identifiers map"},
		"no sub":                    {sign(map[int]any{cwtClaimIat: now.Unix(), cwtClaimExp: exp, cwtClaimIdentifierList: list}), pki.roots, ref, VerifyOptions{}, "missing the required sub"},
		"zero ttl":                  {sign(map[int]any{cwtClaimSub: testURI, cwtClaimIat: now.Unix(), cwtClaimExp: exp, cwtClaimTTL: 0, cwtClaimIdentifierList: list}), pki.roots, ref, VerifyOptions{}, "ttl claim isn't a positive integer"},
		"LeafPolicy refuses":        {token, pki.roots, ref, VerifyOptions{LeafPolicy: func(*x509.Certificate, [][]*x509.Certificate) error { return errors.New("refused") }}, "leaf certificate policy"},
	} {
		t.Run(name, func(t *testing.T) {
			revoked, _, err := Check(context.Background(), tc.token, tc.roots, tc.ref, pki.dsPath, tc.opts)
			if !revoked {
				t.Error("not reported revoked")
			}
			wantErr(t, name, err, tc.want)
		})
	}
}

// TestCheck_CertificatePin: a reference's Certificate is the sole trust
// anchor (ISO/IEC 18013-5 §12.3.6.2): a chain to it is accepted without
// roots or a document signer path, and one to another CA is refused
// even when roots and the path would accept it.
func TestCheck_CertificatePin(t *testing.T) {
	pki := newPKI(t)
	token := issue(t, pki, claimsAt(time.Now(), []byte{1}), IssueOptions{})
	otherCA, _ := testcert.CA(t, "another CA")

	if revoked, _, err := Check(context.Background(), token, nil, Ref{ID: []byte{1}, URI: testURI, Certificate: pki.ca.Raw}, nil, VerifyOptions{}); err != nil || !revoked {
		t.Errorf("pinned to its CA: revoked %v, %v", revoked, err)
	}
	_, _, err := Check(context.Background(), token, pki.roots, Ref{ID: []byte{1}, URI: testURI, Certificate: otherCA.Raw}, pki.dsPath, VerifyOptions{})
	wantErr(t, "pinned to another CA", err, "token signer")
	_, _, err = Check(context.Background(), token, pki.roots, Ref{ID: []byte{1}, URI: testURI, Certificate: []byte{1, 2, 3}}, pki.dsPath, VerifyOptions{})
	wantErr(t, "unparseable pinned certificate", err, "status certificate")
}

// TestCheck_IACABinding: without a Certificate, the list's signer must
// be under the CA that signed the document signer (ISO/IEC 18013-5
// §12.3.6.2), not another IACA the roots trust. With no document signer
// path either, it must chain to the roots.
func TestCheck_IACABinding(t *testing.T) {
	iaca, iacaKey := testcert.CA(t, "IACA")
	other, otherKey := testcert.CA(t, "another IACA")
	ds, _ := testcert.Leaf(t, "document signer", iaca, iacaKey)
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	roots.AddCert(other)
	tokenUnder := func(ca *x509.Certificate, caKey *ecdsa.PrivateKey) []byte {
		leaf, key := testcert.Leaf(t, "list signer", ca, caKey)
		token, err := IssueToken(key, cose.ES256, claimsAt(time.Now()), []*x509.Certificate{leaf}, IssueOptions{})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	ref := Ref{ID: []byte{1}, URI: testURI}
	dsPath := []*x509.Certificate{ds}

	_, _, err := Check(context.Background(), tokenUnder(other, otherKey), roots, ref, dsPath, VerifyOptions{})
	wantErr(t, "under another IACA", err, "isn't under the CA that signed the document signer")
}

// TestCheck_UnboundSigner: with neither a document signer path nor a
// pinned Certificate, nothing binds the list's signer to the mdoc's
// issuer, so the check is refused — another issuer's signer under the
// same roots would otherwise vouch for the MSO — unless
// VerifyOptions.UnboundSigner decides the signer.
func TestCheck_UnboundSigner(t *testing.T) {
	victim, _ := testcert.CA(t, "IACA")
	other, otherKey := testcert.CA(t, "another IACA")
	roots := x509.NewCertPool()
	roots.AddCert(victim)
	roots.AddCert(other)
	leaf, key := testcert.Leaf(t, "another issuer's list signer", other, otherKey)
	token, err := IssueToken(key, cose.ES256, claimsAt(time.Now()), []*x509.Certificate{leaf}, IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ref := Ref{ID: []byte{1}, URI: testURI}
	refuse := func(*x509.Certificate, [][]*x509.Certificate) error { return errors.New("refused") }

	revoked, _, err := Check(context.Background(), token, roots, ref, nil, VerifyOptions{})
	wantErr(t, "no path, no certificate", err, "can't be bound to the mdoc's issuer")
	if !revoked {
		t.Error("no path, no certificate: not reported revoked")
	}
	if revoked, _, err := Check(context.Background(), token, roots, ref, nil, VerifyOptions{UnboundSigner: AnyListSigner}); err != nil || revoked {
		t.Errorf("AnyListSigner: revoked %v, %v", revoked, err)
	}
	_, _, err = Check(context.Background(), token, roots, ref, nil, VerifyOptions{UnboundSigner: refuse})
	wantErr(t, "UnboundSigner refuses", err, "refused")
	_, _, err = Check(context.Background(), token, roots, ref, nil, VerifyOptions{UnboundSigner: AnyListSigner, LeafPolicy: refuse})
	wantErr(t, "LeafPolicy with AnyListSigner", err, "refused")
	_, _, err = Check(context.Background(), token, x509.NewCertPool(), ref, nil, VerifyOptions{UnboundSigner: AnyListSigner})
	wantErr(t, "AnyListSigner, not under the roots", err, "token signer")
}

// VerifyOptions.Revocation refuses an identifier list whose signer's
// certificate is revoked.
func TestCheck_SignerRevocation(t *testing.T) {
	pki := newPKI(t)
	token := issue(t, pki, claimsAt(time.Now()), IssueOptions{})
	testcert.RunRevocationCases(t, pki.ca, pki.caKey, pki.leaf, func(t *testing.T, revocation certrevocation.Checker) error {
		_, _, err := Check(context.Background(), token, pki.roots, Ref{ID: []byte{1}, URI: testURI}, pki.dsPath, VerifyOptions{Revocation: revocation})
		return err
	})
}

// TestIssueToken_Refuses: claims a Relying Party would refuse, and a
// chain that isn't the signer's, aren't signed.
func TestIssueToken_Refuses(t *testing.T) {
	pki := newPKI(t)
	selfSigned, selfKey := testcert.SelfSignedLeaf(t, "self-signed")
	now := time.Now()
	zero, before := int64(0), now.Add(-time.Hour).Unix()
	withExp := func(c TokenClaims) TokenClaims { c.Exp = claimsAt(now).Exp; return c }
	tooMany := make([][]byte, maxIdentifiers+1)
	for i := range tooMany {
		tooMany[i] = []byte{byte(i >> 16), byte(i >> 8), byte(i)}
	}
	tooBig := make([][]byte, DefaultMaxTokenBytes/1000+1)
	for i := range tooBig {
		tooBig[i] = append(bytes.Repeat([]byte{0}, 996), byte(i>>16), byte(i>>8), byte(i))
	}
	for name, tc := range map[string]struct {
		key    crypto.Signer
		claims TokenClaims
		chain  []*x509.Certificate
		want   string
	}{
		"no sub":               {pki.key, withExp(TokenClaims{Iat: now.Unix()}), []*x509.Certificate{pki.leaf}, "Sub is required"},
		"no iat":               {pki.key, withExp(TokenClaims{Sub: testURI}), []*x509.Certificate{pki.leaf}, "Iat is required"},
		"no exp":               {pki.key, TokenClaims{Sub: testURI, Iat: now.Unix()}, []*x509.Certificate{pki.leaf}, "Exp is required"},
		"exp before iat":       {pki.key, TokenClaims{Sub: testURI, Iat: now.Unix(), Exp: &before}, []*x509.Certificate{pki.leaf}, "Exp must be after Iat"},
		"zero ttl":             {pki.key, withExp(TokenClaims{Sub: testURI, Iat: now.Unix(), TTL: &zero}), []*x509.Certificate{pki.leaf}, "TTL must be positive"},
		"empty identifier":     {pki.key, claimsAt(now, []byte{1}, []byte{}), []*x509.Certificate{pki.leaf}, "empty identifier"},
		"too many identifiers": {pki.key, claimsAt(now, tooMany...), []*x509.Certificate{pki.leaf}, "identifiers, over the"},
		"too many bytes":       {pki.key, claimsAt(now, tooBig...), []*x509.Certificate{pki.leaf}, "bytes, over the"},
		"no chain":             {pki.key, claimsAt(now), nil, "a certificate chain is required"},
		"another key's chain":  {selfKey, claimsAt(now), []*x509.Certificate{pki.leaf}, "isn't the signer's"},
		"self-signed leaf":     {selfKey, claimsAt(now), []*x509.Certificate{selfSigned}, "self-signed"},
	} {
		_, err := IssueToken(tc.key, cose.ES256, tc.claims, tc.chain, IssueOptions{})
		wantErr(t, name, err, tc.want)
	}
}

// TestIssueToken_Duplicates: a duplicate identifier is issued once.
func TestIssueToken_Duplicates(t *testing.T) {
	pki := newPKI(t)
	claims, err := VerifyToken(context.Background(), issue(t, pki, claimsAt(time.Now(), []byte{1}, []byte{1}, []byte{2}), IssueOptions{}), pki.roots, VerifyOptions{})
	if err != nil || len(claims.Identifiers) != 2 {
		t.Errorf("%d identifiers, %v; want 2", len(claims.Identifiers), err)
	}
}
