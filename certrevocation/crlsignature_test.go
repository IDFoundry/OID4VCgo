package certrevocation

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	_ "crypto/md5" // MD5WithRSA, which x509 refuses, signed to show it's refused here too
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// signingCA is a self-signed CA certificate for key, which may sign
// CRLs.
func signingCA(t *testing.T, name string, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// signedList is a CRL of two entries issued by ca/key under algorithm,
// the default for key when it's UnknownSignatureAlgorithm.
func signedList(t *testing.T, ca *x509.Certificate, key crypto.Signer, algorithm x509.SignatureAlgorithm) []byte {
	t.Helper()
	revoked := time.Now().Add(-time.Minute)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		SignatureAlgorithm: algorithm, Number: big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(7), RevocationTime: revoked}, {SerialNumber: big.NewInt(9), RevocationTime: revoked}},
	}, ca, key)
	if err != nil {
		t.Fatalf("CreateRevocationList(%v): %v", algorithm, err)
	}
	return der
}

// rebuiltList is the CRL der with its tbsCertList's signature
// AlgorithmIdentifier set to inner, the outer one to outer, signed
// with sign, and trailing appended inside the CertificateList, after
// its signatureValue: what x509.CreateRevocationList won't produce.
func rebuiltList(t *testing.T, der []byte, inner, outer pkix.AlgorithmIdentifier, sign func([]byte) []byte, trailing ...[]byte) []byte {
	t.Helper()
	var cl pkix.CertificateList
	if _, err := asn1.Unmarshal(der, &cl); err != nil {
		t.Fatal(err)
	}
	cl.TBSCertList.Raw = nil
	cl.TBSCertList.Signature = inner
	tbs, err := asn1.Marshal(cl.TBSCertList)
	if err != nil {
		t.Fatal(err)
	}
	sig := sign(tbs)
	ai, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	bits, err := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return derSequence(append([][]byte{tbs, ai, bits}, trailing...)...)
}

// pkcs1Signer signs a tbsCertList with key under RSA PKCS #1 v1.5 and
// hash, pssSigner under RSA-PSS with the given salt length, and
// ecdsaSigner with key under ECDSA and SHA-256.
func pkcs1Signer(t *testing.T, key *rsa.PrivateKey, hash crypto.Hash) func([]byte) []byte {
	return func(tbs []byte) []byte {
		h := hash.New()
		h.Write(tbs)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, h.Sum(nil))
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
}

func pssSigner(t *testing.T, key *rsa.PrivateKey, saltLength int) func([]byte) []byte {
	return func(tbs []byte) []byte {
		h := crypto.SHA256.New()
		h.Write(tbs)
		sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, h.Sum(nil), &rsa.PSSOptions{SaltLength: saltLength})
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
}

func ecdsaSigner(t *testing.T, key *ecdsa.PrivateKey) func([]byte) []byte {
	return func(tbs []byte) []byte {
		h := crypto.SHA256.New()
		h.Write(tbs)
		sig, err := ecdsa.SignASN1(rand.Reader, key, h.Sum(nil))
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
}

// pssAlgorithm is the RSASSA-PSS AlgorithmIdentifier (RFC 4055) for
// SHA-256, MGF1 with SHA-256, and saltLength.
func pssAlgorithm(t *testing.T, saltLength int) pkix.AlgorithmIdentifier {
	t.Helper()
	sha256 := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, Parameters: asn1.NullRawValue}
	mgfParams, err := asn1.Marshal(sha256)
	if err != nil {
		t.Fatal(err)
	}
	params, err := asn1.Marshal(struct {
		Hash       pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
		MGF        pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
		SaltLength int                      `asn1:"explicit,tag:2"`
	}{sha256, pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}, Parameters: asn1.RawValue{FullBytes: mgfParams}}, saltLength})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}, Parameters: asn1.RawValue{FullBytes: params}}
}

// generated is key, generated without err, which only a broken
// random source returns.
func generated[K any](key K, err error) K {
	if err != nil {
		panic(err)
	}
	return key
}

// TestSignedByOneOf checks the signature check made over a list's raw
// tbsCertList before the list is parsed against what parsing it and
// RevocationList.CheckSignatureFrom decide: the same, for a list under
// every algorithm x509 verifies CRLs under, and for lists x509 refuses.
// Every honestly signed list but MD5WithRSA's verifies. Lists that
// split badly — the inner and outer algorithms differing, bytes after
// the list or its signatureValue — are refused unparsed.
func TestSignedByOneOf(t *testing.T) {
	p256 := generated(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	p384 := generated(ecdsa.GenerateKey(elliptic.P384(), rand.Reader))
	p521 := generated(ecdsa.GenerateKey(elliptic.P521(), rand.Reader))
	rsaKey := generated(rsa.GenerateKey(rand.Reader, 2048))
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecCA, ec384CA, ec521CA := signingCA(t, "EC CA", p256), signingCA(t, "EC P-384 CA", p384), signingCA(t, "EC P-521 CA", p521)
	rsaCA, edCA := signingCA(t, "RSA CA", rsaKey), signingCA(t, "Ed25519 CA", edKey)
	// A CA by the EC CA's name, with another key.
	impostor := signingCA(t, "EC CA", generated(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)))

	honest := signedList(t, ecCA, p256, x509.ECDSAWithSHA256)
	rsaList := signedList(t, rsaCA, rsaKey, x509.SHA256WithRSA)
	ecdsaSHA256 := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	unknown := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4}}
	md5WithRSA := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}, Parameters: asn1.NullRawValue}
	edWithParams := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}, Parameters: asn1.NullRawValue}
	// The list with the second entry's serial number, 9, changed to 8.
	tampered := bytes.Replace(honest, []byte{0x02, 0x01, 0x09}, []byte{0x02, 0x01, 0x08}, 1)
	if bytes.Equal(tampered, honest) {
		t.Fatal("no serial number 9 to tamper with")
	}

	tests := map[string]struct {
		der      []byte
		issuers  []*x509.Certificate
		verified bool // and parsing then accepts it
		split    bool // false: refused as malformed
	}{
		"ECDSA with SHA-1":   {signedList(t, ecCA, p256, x509.ECDSAWithSHA1), []*x509.Certificate{ecCA}, true, true},
		"ECDSA with SHA-256": {honest, []*x509.Certificate{ecCA}, true, true},
		"ECDSA with SHA-384": {signedList(t, ec384CA, p384, x509.ECDSAWithSHA384), []*x509.Certificate{ec384CA}, true, true},
		"ECDSA with SHA-512": {signedList(t, ec521CA, p521, x509.ECDSAWithSHA512), []*x509.Certificate{ec521CA}, true, true},
		"RSA with SHA-1":     {signedList(t, rsaCA, rsaKey, x509.SHA1WithRSA), []*x509.Certificate{rsaCA}, true, true},
		"RSA with SHA-256":   {rsaList, []*x509.Certificate{rsaCA}, true, true},
		"RSA with SHA-384":   {signedList(t, rsaCA, rsaKey, x509.SHA384WithRSA), []*x509.Certificate{rsaCA}, true, true},
		"RSA with SHA-512":   {signedList(t, rsaCA, rsaKey, x509.SHA512WithRSA), []*x509.Certificate{rsaCA}, true, true},
		"RSA-PSS, SHA-256":   {signedList(t, rsaCA, rsaKey, x509.SHA256WithRSAPSS), []*x509.Certificate{rsaCA}, true, true},
		"RSA-PSS, SHA-384":   {signedList(t, rsaCA, rsaKey, x509.SHA384WithRSAPSS), []*x509.Certificate{rsaCA}, true, true},
		"RSA-PSS, SHA-512":   {signedList(t, rsaCA, rsaKey, x509.SHA512WithRSAPSS), []*x509.Certificate{rsaCA}, true, true},
		"RSA-PSS, hand-built parameters": {rebuiltList(t, rsaList, pssAlgorithm(t, 32), pssAlgorithm(t, 32), pssSigner(t, rsaKey, 32)),
			[]*x509.Certificate{rsaCA}, true, true},
		"Ed25519":                               {signedList(t, edCA, edKey, x509.PureEd25519), []*x509.Certificate{edCA}, true, true},
		"the second of two issuers by one name": {honest, []*x509.Certificate{impostor, ecCA}, true, true},

		"another key by the issuer's name": {honest, []*x509.Certificate{impostor}, false, true},
		"another issuer's name":            {honest, []*x509.Certificate{rsaCA}, false, true},
		"tampered tbsCertList":             {tampered, []*x509.Certificate{ecCA}, false, true},
		"unknown algorithm":                {rebuiltList(t, honest, unknown, unknown, ecdsaSigner(t, p256)), []*x509.Certificate{ecCA}, false, true},
		"MD5 with RSA":                     {rebuiltList(t, rsaList, md5WithRSA, md5WithRSA, pkcs1Signer(t, rsaKey, crypto.MD5)), []*x509.Certificate{rsaCA}, false, true},
		"RSA-PSS, salt not the hash's size": {rebuiltList(t, rsaList, pssAlgorithm(t, 20), pssAlgorithm(t, 20), pssSigner(t, rsaKey, 20)),
			[]*x509.Certificate{rsaCA}, false, true},
		"Ed25519 with parameters": {rebuiltList(t, signedList(t, edCA, edKey, x509.PureEd25519), edWithParams, edWithParams, func(tbs []byte) []byte { return ed25519.Sign(edKey, tbs) }),
			[]*x509.Certificate{edCA}, false, true},

		"inner and outer algorithms differ": {rebuiltList(t, honest, ecdsaSHA256, unknown, ecdsaSigner(t, p256)), []*x509.Certificate{ecCA}, false, false},
		"bytes after the list":              {append(append([]byte(nil), honest...), 0x00, 0x00), []*x509.Certificate{ecCA}, false, false},
		"bytes after the signatureValue":    {rebuiltList(t, honest, ecdsaSHA256, ecdsaSHA256, ecdsaSigner(t, p256), []byte{0x05, 0x00}), []*x509.Certificate{ecCA}, false, false},
		"not DER":                           {[]byte("not a CRL"), []*x509.Certificate{ecCA}, false, false},
		"truncated":                         {honest[:len(honest)/2], []*x509.Certificate{ecCA}, false, false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := signedByOneOf(tc.der, tc.issuers)
			if (err == nil) != tc.split {
				t.Fatalf("signedByOneOf error = %v, want split %v", err, tc.split)
			}
			if got != tc.verified {
				t.Errorf("signedByOneOf = %v, want %v", got, tc.verified)
			}
			list, err := x509.ParseRevocationList(tc.der)
			if err != nil {
				return
			}
			parsedVerified := signerOf(list, tc.issuers) != nil
			if tc.split && parsedVerified != got {
				t.Errorf("signedByOneOf = %v, but the parsed list's CheckSignatureFrom says %v", got, parsedVerified)
			}
			if parts, err := splitSignedList(tc.der); err == nil && signatureAlgorithmOf(parts.algorithm) != list.SignatureAlgorithm {
				t.Errorf("signatureAlgorithmOf = %v, x509 parses %v", signatureAlgorithmOf(parts.algorithm), list.SignatureAlgorithm)
			}
		})
	}
}
