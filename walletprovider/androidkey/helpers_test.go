package androidkey_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// The testdata chains are real devices' attestation chains, from
// Google's android-key-attestation library's test resources
// (https://github.com/google/android-key-attestation, Apache-2.0,
// commit f9846cd019289f1788cec65b062d9f81c0c4884c,
// src/test/resources/pem/algorithm_EC_SecurityLevel_TEE and
// algorithm_EC_SecurityLevel_StrongBox), as the passport-vdc demo
// carries them. The TEE chain ends at Google's 2016 RSA root
// certificate; the StrongBox one at a pre-production root of its own.
// Both were made over the challenge "abc" in 2018 and 2019, on devices
// with unlocked bootloaders, by a system app sharing Android's user ID.
var vectorTime = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func readChain(t testing.TB, name string) [][]byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var chain [][]byte
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		chain = append(chain, block.Bytes)
	}
	return chain
}

func mustParse(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// extensionOf returns cert's attestation extension value.
func extensionOf(t testing.TB, der []byte) []byte {
	t.Helper()
	for _, e := range mustParse(t, der).Extensions {
		if e.Id.Equal(androidkey.ExtensionOID) {
			return e.Value
		}
	}
	t.Fatal("no attestation extension")
	return nil
}

// DER builders for key descriptions.

func mustMarshal(t testing.TB, v any) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func derInt(t testing.TB, n int64) []byte { return mustMarshal(t, n) }

func derEnum(t testing.TB, n int) []byte { return mustMarshal(t, asn1.Enumerated(n)) }

func derOctets(t testing.TB, b []byte) []byte { return mustMarshal(t, b) }

func derNull() []byte { return []byte{0x05, 0x00} }

func derBool(b bool) []byte {
	if b {
		return []byte{0x01, 0x01, 0xff}
	}
	return []byte{0x01, 0x01, 0x00}
}

func derConstructed(t testing.TB, tag int, elems ...[]byte) []byte {
	t.Helper()
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: tag, IsCompound: true, Bytes: body})
}

func derSeq(t testing.TB, elems ...[]byte) []byte {
	return derConstructed(t, asn1.TagSequence, elems...)
}

func derSet(t testing.TB, elems ...[]byte) []byte { return derConstructed(t, asn1.TagSet, elems...) }

func derIntSet(t testing.TB, ns ...int64) []byte {
	var elems [][]byte
	for _, n := range ns {
		elems = append(elems, derInt(t, n))
	}
	return derSet(t, elems...)
}

// field is one authorization list entry: an EXPLICIT context tag around
// inner.
type field struct {
	tag   int
	inner []byte
}

func explicit(t testing.TB, f field) []byte {
	return mustMarshal(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: f.tag, IsCompound: true, Bytes: f.inner})
}

func authList(t testing.TB, fields []field) []byte {
	var elems [][]byte
	for _, f := range fields {
		elems = append(elems, explicit(t, f))
	}
	return derSeq(t, elems...)
}

func rootOfTrust(t testing.TB, bootKey []byte, locked bool, state androidkey.VerifiedBootState) []byte {
	return derSeq(t, derOctets(t, bootKey), derBool(locked), derEnum(t, int(state)), derOctets(t, make([]byte, 32)))
}

type pkg struct {
	name    string
	version int64
}

func appID(t testing.TB, pkgs []pkg, digests ...[]byte) []byte {
	var infos, ds [][]byte
	for _, p := range pkgs {
		infos = append(infos, derSeq(t, derOctets(t, []byte(p.name)), derInt(t, p.version)))
	}
	for _, d := range digests {
		ds = append(ds, derOctets(t, d))
	}
	return derOctets(t, derSeq(t, derSet(t, infos...), derSet(t, ds...)))
}

// Fixtures for the synthetic chains.
var (
	appPackage    = "com.example.wallet"
	appDigest     = sha256.Sum256([]byte("wallet signing certificate"))
	otherDigest   = sha256.Sum256([]byte("another signing certificate"))
	bootKey       = sha256.Sum256([]byte("verified boot key"))
	testApp       = androidkey.AllowedApp{Package: appPackage, SigningCertificateDigests: [][]byte{appDigest[:]}}
	testChallenge = []byte("a fresh challenge from the provider")
)

// spec describes a synthetic key description.
type spec struct {
	version      int
	attLevel     androidkey.SecurityLevel
	keyLevel     androidkey.SecurityLevel
	challenge    []byte
	hw, sw       []field
	rawExtension []byte // used as is when set
}

// goodHW is a hardware-enforced list for a P-256 signing key generated
// in the TEE on a locked, verified device.
func goodHW(t testing.TB) []field {
	return []field{
		{1, derIntSet(t, int64(androidkey.PurposeSign))},
		{2, derInt(t, int64(androidkey.AlgorithmEC))},
		{3, derInt(t, 256)},
		{5, derIntSet(t, 4)},
		{10, derInt(t, int64(androidkey.CurveP256))},
		{503, derNull()},
		{702, derInt(t, int64(androidkey.OriginGenerated))},
		{704, rootOfTrust(t, bootKey[:], true, androidkey.Verified)},
		{705, derInt(t, 150000)},
		{706, derInt(t, 202509)},
		{718, derInt(t, 20250901)},
		{719, derInt(t, 20250901)},
	}
}

func goodSW(t testing.TB) []field {
	return []field{
		{701, derInt(t, time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC).UnixMilli())},
		{709, appID(t, []pkg{{appPackage, 42}}, appDigest[:])},
	}
}

func goodSpec(t testing.TB) spec {
	return spec{
		version: 300, attLevel: androidkey.TrustedEnvironment, keyLevel: androidkey.TrustedEnvironment,
		challenge: testChallenge, hw: goodHW(t), sw: goodSW(t),
	}
}

// replace returns fields with tag's entry replaced by inner (added
// when there's none), or removed when inner is nil.
func replace(fields []field, tag int, inner []byte) []field {
	var out []field
	found := false
	for _, f := range fields {
		if f.tag != tag {
			out = append(out, f)
			continue
		}
		found = true
		if inner != nil {
			out = append(out, field{tag, inner})
		}
	}
	if !found && inner != nil {
		out = append(out, field{tag, inner})
	}
	return out
}

func (s spec) encode(t testing.TB) []byte {
	if s.rawExtension != nil {
		return s.rawExtension
	}
	return derSeq(t,
		derInt(t, int64(s.version)), derEnum(t, int(s.attLevel)),
		derInt(t, int64(s.version)), derEnum(t, int(s.keyLevel)),
		derOctets(t, s.challenge), derOctets(t, nil),
		authList(t, s.sw), authList(t, s.hw))
}

// testChain is a synthetic attestation chain: leaf, intermediate, root.
type testChain struct {
	der      [][]byte
	root     *x509.Certificate
	inter    *x509.Certificate
	interKey *ecdsa.PrivateKey
	leafKey  *ecdsa.PrivateKey
}

type chainOpts struct {
	leafCurve     elliptic.Curve
	leafValidity  [2]time.Time // zero: an hour ago to a day from now
	interValidity [2]time.Time // zero: an hour ago to a day from now
	rootValidity  [2]time.Time // zero: an hour ago to a day from now
	serials       [3]int64     // leaf, intermediate, root; zero: 1, 2, 3
}

func newChain(t testing.TB, s spec, o chainOpts) testChain {
	t.Helper()
	if o.leafCurve == nil {
		o.leafCurve = elliptic.P256()
	}
	serial := func(i int) int64 {
		if o.serials[i] != 0 {
			return o.serials[i]
		}
		return int64(i + 1)
	}
	rootKey := newKey(t, elliptic.P256())
	root := issue(t, withValidity(certTemplate("Test Attestation Root", serial(2), true), o.rootValidity), nil, rootKey, &rootKey.PublicKey)
	interKey := newKey(t, elliptic.P256())
	interTmpl := withValidity(certTemplate("Test Attestation Intermediate", serial(1), true), o.interValidity)
	inter := issue(t, interTmpl, root, rootKey, &interKey.PublicKey)
	leafKey := newKey(t, o.leafCurve)
	leaf := issue(t, withValidity(leafTemplate(s.encode(t), serial(0)), o.leafValidity), inter, interKey, &leafKey.PublicKey)
	return testChain{
		der: [][]byte{leaf.Raw, inter.Raw, root.Raw}, root: root, inter: inter,
		interKey: interKey, leafKey: leafKey,
	}
}

func newKey(t testing.TB, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func certTemplate(cn string, serial int64, ca bool) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: ca, BasicConstraintsValid: ca, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
}

// withValidity sets tmpl's validity to validity, unless that's zero.
func withValidity(tmpl *x509.Certificate, validity [2]time.Time) *x509.Certificate {
	if !validity[0].IsZero() {
		tmpl.NotBefore, tmpl.NotAfter = validity[0], validity[1]
	}
	return tmpl
}

// issue signs tmpl with parentKey under parent (self-signed when nil).
func issue(t testing.TB, tmpl, parent *x509.Certificate, parentKey crypto.Signer, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return mustParse(t, der)
}

// makeLeaf issues a leaf for pub with ext as its attestation extension
// (none when nil).
func makeLeaf(t testing.TB, parent *x509.Certificate, parentKey crypto.Signer, pub crypto.PublicKey, ext []byte, serial int64) *x509.Certificate {
	t.Helper()
	return issue(t, leafTemplate(ext, serial), parent, parentKey, pub)
}

// leafTemplate is a leaf's template with ext as its attestation
// extension (none when nil).
func leafTemplate(ext []byte, serial int64) *x509.Certificate {
	tmpl := certTemplate("Android Keystore Key", serial, false)
	if ext != nil {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: androidkey.ExtensionOID, Value: ext}}
	}
	return tmpl
}

// statusFixture parses testdata/status.json.
func statusFixture(t testing.TB) *androidkey.StatusList {
	t.Helper()
	data, err := os.ReadFile("testdata/status.json")
	if err != nil {
		t.Fatal(err)
	}
	l, err := androidkey.ParseStatusList(data)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// verifierFor is a strict verifier trusting c's root, with the test app
// allowed and the fixture status list.
func verifierFor(t testing.TB, c testChain) *androidkey.Verifier {
	return &androidkey.Verifier{
		Roots:      []*x509.Certificate{c.root},
		Revocation: statusFixture(t),
		Apps:       []androidkey.AllowedApp{testApp},
	}
}
