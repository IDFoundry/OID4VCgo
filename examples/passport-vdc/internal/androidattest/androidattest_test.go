package androidattest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/androidattest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/androidattest/attesttest"
)

// The testdata chains are real devices' attestation chains, from
// Google's android-key-attestation library's test resources
// (https://github.com/google/android-key-attestation, Apache-2.0,
// commit f9846cd019289f1788cec65b062d9f81c0c4884c,
// src/test/resources/pem/algorithm_EC_SecurityLevel_TEE and
// algorithm_EC_SecurityLevel_StrongBox, cert0.pem to cert3.pem).
//
// The TEE chain ends at Google's 2016 hardware attestation root; the
// StrongBox one at a root of its own (not Google's), so it shows an
// unanchored chain. Both were made over the challenge "abc", in 2018:
// a fixed time keeps their certificates valid.
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

// TestGoogleRoots: the embedded roots are the ones Google publishes,
// pinned by fingerprint.
func TestGoogleRoots(t *testing.T) {
	want := []string{
		"cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",
		"6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0",
	}
	var got []string
	for _, r := range androidattest.GoogleRoots() {
		sum := sha256.Sum256(r.Raw)
		got = append(got, hex.EncodeToString(sum[:]))
	}
	if !slices.Equal(got, want) {
		t.Errorf("Google roots' SHA-256 = %v, want %v", got, want)
	}
}

// TestVerify_RealChains: a real TEE chain to Google's root is hardware;
// a real StrongBox chain to another root isn't anchored.
func TestVerify_RealChains(t *testing.T) {
	tee, err := androidattest.Verify(readChain(t, "ec_tee_chain.pem"), androidattest.GoogleRoots(), vectorTime)
	if err != nil {
		t.Fatalf("TEE chain: %v", err)
	}
	if !tee.Anchored || !tee.Hardware() || tee.AttestationSecurityLevel != androidattest.TrustedEnvironment ||
		tee.KeyMintSecurityLevel != androidattest.TrustedEnvironment || string(tee.AttestationChallenge) != "abc" || tee.AttestationVersion != 3 {
		t.Errorf("TEE chain = %+v", tee)
	}
	if _, ok := tee.Leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("TEE chain's leaf key is a %T", tee.Leaf.PublicKey)
	}

	sb, err := androidattest.Verify(readChain(t, "ec_strongbox_chain.pem"), androidattest.GoogleRoots(), vectorTime)
	if err != nil {
		t.Fatalf("StrongBox chain: %v", err)
	}
	if sb.Anchored || sb.Hardware() || sb.AttestationSecurityLevel != androidattest.StrongBox || string(sb.AttestationChallenge) != "abc" {
		t.Errorf("StrongBox chain = %+v", sb)
	}

	// Years later, its intermediates have expired.
	late, err := androidattest.Verify(readChain(t, "ec_tee_chain.pem"), androidattest.GoogleRoots(), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if late.Hardware() || !slices.Equal(late.OutOfValidity, []int{1, 2}) {
		t.Errorf("TEE chain in 2030: out of validity %v, hardware %v; want [1 2], false", late.OutOfValidity, late.Hardware())
	}
}

// TestVerify_Refuses: a chain whose signatures don't hold, whose leaf
// lacks the extension, or that has it elsewhere, is refused.
func TestVerify_Refuses(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opts := attesttest.Options{Level: androidattest.StrongBox, Challenge: []byte("challenge")}
	good := attesttest.New(t, &key.PublicKey, opts)
	roots := []*x509.Certificate{good.Root}
	a, err := androidattest.Verify(good.DER, roots, time.Now())
	if err != nil || !a.Hardware() || string(a.AttestationChallenge) != "challenge" {
		t.Fatalf("the good chain: %+v, %v", a, err)
	}
	// Without its root, the chain is still anchored by the root's
	// signature.
	if a, err := androidattest.Verify(good.DER[:2], roots, time.Now()); err != nil || !a.Anchored {
		t.Errorf("the chain without its root: %+v, %v", a, err)
	}
	if a, err := androidattest.Verify(good.DER, androidattest.GoogleRoots(), time.Now()); err != nil || a.Anchored || a.Hardware() {
		t.Errorf("the chain against Google's roots: %+v, %v; want verified, not anchored", a, err)
	}

	other := attesttest.New(t, &key.PublicKey, opts)
	// The attested key signs a "leaf" of its own, for another key,
	// claiming whatever it likes.
	another, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := attesttest.Leaf(t, mustParse(t, good.DER[0]), key, &another.PublicKey, attesttest.KeyDescription(t, opts))
	noExt := attesttest.Leaf(t, mustParse(t, good.DER[1]), good.IntermediateKey, &key.PublicKey, nil)
	tampered := slices.Clone(good.DER[0])
	tampered[len(tampered)-1] ^= 1

	for name, chain := range map[string][][]byte{
		"empty":                     nil,
		"too long":                  slices.Repeat([][]byte{good.DER[0]}, androidattest.MaxChainLength+1),
		"not DER":                   {[]byte("certificate")},
		"another chain's root":      {good.DER[0], good.DER[1], other.DER[2]},
		"tampered signature":        {tampered, good.DER[1], good.DER[2]},
		"no extension":              {noExt.Raw, good.DER[1], good.DER[2]},
		"extension below the leaf":  {forged.Raw, good.DER[0], good.DER[1], good.DER[2]},
		"intermediate out of order": {good.DER[0], good.DER[2], good.DER[1]},
	} {
		if a, err := androidattest.Verify(chain, roots, time.Now()); err == nil {
			t.Errorf("%s: verified, %+v", name, a)
		} else if name == "extension below the leaf" && !strings.Contains(err.Error(), "not the leaf") {
			t.Errorf("%s: %v, want it refused for the extension", name, err)
		}
	}
}

func mustParse(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestParseKeyDescription_Refuses: malformed key descriptions.
func TestParseKeyDescription_Refuses(t *testing.T) {
	good := attesttest.KeyDescription(t, attesttest.Options{Level: androidattest.TrustedEnvironment, Challenge: []byte("c")})
	if _, err := androidattest.ParseKeyDescription(good); err != nil {
		t.Fatalf("the good description: %v", err)
	}
	unknownLevel := attesttest.KeyDescription(t, attesttest.Options{Level: 3, Challenge: []byte("c")})
	longChallenge := attesttest.KeyDescription(t, attesttest.Options{Level: androidattest.StrongBox, Challenge: make([]byte, 129)})
	for name, der := range map[string][]byte{
		"empty":              nil,
		"trailing data":      append(slices.Clone(good), 0),
		"truncated":          good[:len(good)-1],
		"unknown level":      unknownLevel,
		"129-byte challenge": longChallenge,
		"not a SEQUENCE":     {0x04, 0x00},
	} {
		if kd, err := androidattest.ParseKeyDescription(der); err == nil {
			t.Errorf("%s: parsed, %+v", name, kd)
		}
	}
	if s := androidattest.SecurityLevel(7).String(); !strings.Contains(s, "7") {
		t.Errorf("SecurityLevel(7) = %q", s)
	}
}

// FuzzParseKeyDescription: any input parses or is refused, without
// panicking, and what parses has known security levels.
func FuzzParseKeyDescription(f *testing.F) {
	for _, name := range []string{"ec_tee_chain.pem", "ec_strongbox_chain.pem"} {
		leaf := mustParse(f, readChain(f, name)[0])
		for _, e := range leaf.Extensions {
			if e.Id.Equal(androidattest.OID) {
				f.Add(e.Value)
			}
		}
	}
	f.Add(attesttest.KeyDescription(f, attesttest.Options{Level: androidattest.Software, Challenge: []byte("c")}))
	f.Fuzz(func(t *testing.T, der []byte) {
		kd, err := androidattest.ParseKeyDescription(der)
		if err != nil {
			return
		}
		if kd.AttestationSecurityLevel > androidattest.StrongBox || kd.KeyMintSecurityLevel > androidattest.StrongBox ||
			kd.AttestationSecurityLevel < 0 || kd.KeyMintSecurityLevel < 0 || len(kd.AttestationChallenge) > 128 {
			t.Errorf("parsed %+v", kd)
		}
	})
}
