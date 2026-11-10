package appattest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// testAppID is the App ID the tests' Verifier accepts.
const testAppID = "ABCDE12345.dev.example.wallet"

// fakeApple stands in for Apple's App Attest service: a root and an
// intermediate that issue credential certificates as Apple's do.
// Apple publishes no test vectors, so the attestations here follow its
// documented format.
type fakeApple struct {
	root, inter       *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
}

func newFakeApple(t testing.TB) *fakeApple {
	t.Helper()
	f := &fakeApple{rootKey: newKey(t, elliptic.P384()), interKey: newKey(t, elliptic.P384())}
	f.root = createCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test App Attestation Root CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, nil, &f.rootKey.PublicKey, f.rootKey)
	f.inter = createCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "Test App Attestation CA 1"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, f.root, &f.interKey.PublicKey, f.rootKey)
	return f
}

func newKey(t testing.TB, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func createCert(t testing.TB, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(24 * time.Hour)
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// attSpec is an attestation to make. Its zero value, given a
// clientDataHash, is a good production one for testAppID; each other
// field spoils one thing.
type attSpec struct {
	clientDataHash []byte

	appID        string // "" means testAppID
	aaguid       []byte // nil means production's
	counter      uint32
	format       string // "" means apple-appattest
	nonceHash    []byte // the client data hash the nonce covers; nil means clientDataHash
	credentialID []byte // nil means the key's ID
	noNonce      bool
	nonceTrailer []byte            // appended to the nonce extension's value
	key          *ecdsa.PrivateKey // nil means a new P-256 key
	notAfter     time.Time
}

// attest makes an attestation object as attestKey returns it, and the
// App Attest key's private key.
func (f *fakeApple) attest(t testing.TB, s attSpec) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key := s.key
	if key == nil {
		key = newKey(t, elliptic.P256())
	}
	appID := s.appID
	if appID == "" {
		appID = testAppID
	}
	aaguid := s.aaguid
	if aaguid == nil {
		aaguid = aaguidProduction
	}
	credID := s.credentialID
	if credID == nil {
		credID = KeyID(&key.PublicKey)
	}
	authData := attAuthData(t, appID, s.counter, aaguid, credID, &key.PublicKey)
	nonceHash := s.nonceHash
	if nonceHash == nil {
		nonceHash = s.clientDataHash
	}
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "credential"}, KeyUsage: x509.KeyUsageDigitalSignature, NotAfter: s.notAfter}
	if !s.noNonce {
		nonce := sha256.Sum256(slices.Concat(authData, nonceHash))
		ext, err := asn1.Marshal(struct {
			Nonce []byte `asn1:"tag:1,explicit"`
		}{nonce[:]})
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: NonceExtensionOID, Value: append(ext, s.nonceTrailer...)}}
	}
	cred := createCert(t, tmpl, f.inter, &key.PublicKey, f.interKey)
	format := s.format
	if format == "" {
		format = "apple-appattest"
	}
	obj, err := cbor.Marshal(map[string]any{
		"fmt":      format,
		"attStmt":  map[string]any{"x5c": [][]byte{cred.Raw, f.inter.Raw}, "receipt": []byte("receipt")},
		"authData": authData,
	})
	if err != nil {
		t.Fatal(err)
	}
	return obj, key
}

// attAuthData is an attestation's authenticator data: the RP ID hash,
// flags with attested credential data, the counter, the AAGUID, the
// credential ID and the key as a COSE_Key.
func attAuthData(t testing.TB, appID string, counter uint32, aaguid, credID []byte, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	rp := sha256.Sum256([]byte(appID))
	b := slices.Concat(rp[:], []byte{0x41}, binary.BigEndian.AppendUint32(nil, counter), aaguid,
		binary.BigEndian.AppendUint16(nil, uint16(len(credID))), credID)
	point, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	coseKey, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:]})
	if err != nil {
		t.Fatal(err)
	}
	return append(b, coseKey...)
}

// assert makes an assertion as generateAssertion returns it: key's
// signature over SHA-256(authenticatorData ‖ clientDataHash).
func assert(t testing.TB, key *ecdsa.PrivateKey, appID string, counter uint32, clientDataHash []byte) []byte {
	t.Helper()
	return assertPadded(t, key, appID, counter, clientDataHash, 0)
}

// assertPadded is assert with pad bytes of extensions after the
// authenticator data's fixed part, which the signature covers.
func assertPadded(t testing.TB, key *ecdsa.PrivateKey, appID string, counter uint32, clientDataHash []byte, pad int) []byte {
	t.Helper()
	rp := sha256.Sum256([]byte(appID))
	authData := slices.Concat(rp[:], []byte{0x00}, binary.BigEndian.AppendUint32(nil, counter), make([]byte, pad))
	nonce := sha256.Sum256(slices.Concat(authData, clientDataHash))
	digest := sha256.Sum256(nonce[:])
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	obj, err := cbor.Marshal(map[string][]byte{"signature": sig, "authenticatorData": authData})
	if err != nil {
		t.Fatal(err)
	}
	return obj
}

func (f *fakeApple) verifier() *Verifier {
	return &Verifier{Apps: []string{testAppID}, Roots: []*x509.Certificate{f.root}}
}

func hashOf(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
