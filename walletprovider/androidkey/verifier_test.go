package androidkey_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// TestGoogleRoots: the embedded roots are the ones Google publishes,
// pinned by SHA-256 fingerprint.
func TestGoogleRoots(t *testing.T) {
	want := []string{
		"cedb1cb6dc896ae5ec797348bce9286753c2b38ee71ce0fbe34a9a1248800dfc",
		"6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0",
	}
	roots := androidkey.GoogleRoots()
	var got []string
	for _, r := range roots {
		sum := sha256.Sum256(r.Raw)
		got = append(got, hex.EncodeToString(sum[:]))
	}
	if !slices.Equal(got, want) {
		t.Errorf("Google roots' SHA-256 = %v, want %v", got, want)
	}
	roots[0] = nil
	if androidkey.GoogleRoots()[0] == nil {
		t.Error("GoogleRoots shares its slice with callers")
	}
}

// realApps allows every package the real chains name, signed with the
// platform certificate they carry.
func realApps(t *testing.T, chain [][]byte) []androidkey.AllowedApp {
	kd, err := androidkey.ParseKeyDescription(extensionOf(t, chain[0]))
	if err != nil {
		t.Fatal(err)
	}
	var apps []androidkey.AllowedApp
	for _, p := range kd.SoftwareEnforced.ApplicationID.Packages {
		apps = append(apps, androidkey.AllowedApp{Package: p.Name, SigningCertificateDigests: kd.SoftwareEnforced.ApplicationID.SignatureDigests})
	}
	return apps
}

// TestVerify_RealTEEChain: a real device's TEE chain to Google's 2016
// root certificate verifies, once its unlocked bootloader is allowed,
// and reports what the device attested.
func TestVerify_RealTEEChain(t *testing.T) {
	chain := readChain(t, "ec_tee_chain.pem")
	v := &androidkey.Verifier{
		Revocation: statusFixture(t),
		Apps:       realApps(t, chain),
		Now:        func() time.Time { return vectorTime },
	}
	ctx := context.Background()
	if _, err := v.Verify(ctx, chain, []byte("abc")); !errors.Is(err, androidkey.ErrBootState) {
		t.Fatalf("strict verifier: %v, want ErrBootState (the device's bootloader is unlocked)", err)
	}
	v.AllowUntrustedBoot = true
	r, err := v.Verify(ctx, chain, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	kd := r.KeyDescription
	if kd.AttestationVersion != 3 || kd.KeyMintVersion != 4 || kd.AttestationSecurityLevel != androidkey.TrustedEnvironment ||
		kd.KeyMintSecurityLevel != androidkey.TrustedEnvironment || r.StrongBox() || !r.RevocationChecked {
		t.Errorf("result = %+v", kd)
	}
	if r.Enforced != &kd.HardwareEnforced || r.Enforced.RootOfTrust.VerifiedBootState != androidkey.Unverified ||
		r.Enforced.RootOfTrust.DeviceLocked || !r.Enforced.NoAuthRequired || *r.Enforced.OSPatchLevel != 201907 {
		t.Errorf("enforced = %+v", r.Enforced)
	}
	if pub, ok := r.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(r.Chain[0].PublicKey) {
		t.Errorf("public key = %T", r.PublicKey)
	}
	if r.Root != androidkey.GoogleRoots()[0] || r.App == nil || r.App.Packages[0].Name != "android" {
		t.Errorf("root %v, app %+v", r.Root.Subject, r.App)
	}

	for name, tc := range map[string]struct {
		mutate    func(v *androidkey.Verifier)
		challenge string
		want      error
	}{
		"wrong challenge":  {challenge: "abd", want: androidkey.ErrChallenge},
		"StrongBox wanted": {mutate: func(v *androidkey.Verifier) { v.RequireStrongBox = true }, want: androidkey.ErrSoftwareLevel},
		"only android":     {mutate: func(v *androidkey.Verifier) { v.Apps = v.Apps[:1] }, want: androidkey.ErrAppNotAllowed},
		"patch level":      {mutate: func(v *androidkey.Verifier) { v.MinOSPatchLevel = 202001 }, want: androidkey.ErrPatchLevel},
		"intermediates expired": {mutate: func(v *androidkey.Verifier) {
			v.Now = func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
		}, want: androidkey.ErrCertificateValidity},
		"version 4 wanted": {mutate: func(v *androidkey.Verifier) { v.MinAttestationVersion = 4 }, want: androidkey.ErrAttestationVersion},
		"revoked intermediate": {mutate: func(v *androidkey.Verifier) {
			l, err := androidkey.ParseStatusList([]byte(`{"entries":{"388266760658996857D":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}`))
			if err != nil {
				t.Fatal(err)
			}
			v.Revocation = l
		}, want: androidkey.ErrRevoked},
	} {
		t.Run(name, func(t *testing.T) {
			v := *v
			if tc.mutate != nil {
				tc.mutate(&v)
			}
			challenge := "abc"
			if tc.challenge != "" {
				challenge = tc.challenge
			}
			if _, err := v.Verify(ctx, chain, []byte(challenge)); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerify_RealStrongBoxChain: the StrongBox chain ends at a root
// that isn't Google's; trusting its root, it verifies as StrongBox.
func TestVerify_RealStrongBoxChain(t *testing.T) {
	chain := readChain(t, "ec_strongbox_chain.pem")
	v := &androidkey.Verifier{
		Revocation: statusFixture(t), Apps: realApps(t, chain), AllowUntrustedBoot: true,
		Now: func() time.Time { return vectorTime },
	}
	if _, err := v.Verify(context.Background(), chain, []byte("abc")); !errors.Is(err, androidkey.ErrUntrustedRoot) {
		t.Fatalf("against Google's roots: %v, want ErrUntrustedRoot", err)
	}
	v.Roots = []*x509.Certificate{mustParse(t, chain[len(chain)-1])}
	v.RequireStrongBox = true
	r, err := v.Verify(context.Background(), chain, []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	if !r.StrongBox() || r.KeyDescription.AttestationVersion != 3 {
		t.Errorf("result = %+v", r.KeyDescription)
	}
}

// TestVerify_Synthetic: a synthetic chain with every check's input
// right verifies; each change below fails the check it targets.
func TestVerify_Synthetic(t *testing.T) {
	ctx := context.Background()
	good := newChain(t, goodSpec(t), chainOpts{})
	r, err := verifierFor(t, good).Verify(ctx, good.der, testChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if !r.RevocationChecked || r.StrongBox() || !r.Enforced.HasPurpose(androidkey.PurposeSign) ||
		!r.PublicKey.(*ecdsa.PublicKey).Equal(&good.leafKey.PublicKey) || r.App.Packages[0].Version != 42 {
		t.Errorf("result = %+v", r)
	}
	// A chain that leaves its root out is anchored by the root's
	// signature on its last certificate.
	if _, err := verifierFor(t, good).Verify(ctx, good.der[:2], testChallenge); err != nil {
		t.Errorf("without its root: %v", err)
	}

	hw := goodHW(t)
	sw := goodSW(t)
	type tc struct {
		spec   func(s *spec)
		opts   chainOpts
		policy func(v *androidkey.Verifier)
		want   error
	}
	cases := map[string]tc{
		"software key": {spec: func(s *spec) { s.keyLevel = androidkey.Software }, want: androidkey.ErrSoftwareLevel},
		"software attestation": {
			spec: func(s *spec) { s.attLevel = androidkey.Software }, want: androidkey.ErrSoftwareLevel},
		"StrongBox key, TEE attestation, when StrongBox required": {
			spec:   func(s *spec) { s.keyLevel = androidkey.StrongBox },
			policy: func(v *androidkey.Verifier) { v.RequireStrongBox = true }, want: androidkey.ErrSoftwareLevel},
		"TEE when StrongBox required": {policy: func(v *androidkey.Verifier) { v.RequireStrongBox = true }, want: androidkey.ErrSoftwareLevel},
		"StrongBox": {
			spec:   func(s *spec) { s.keyLevel, s.attLevel = androidkey.StrongBox, androidkey.StrongBox },
			policy: func(v *androidkey.Verifier) { v.RequireStrongBox = true }},
		"software key allowed, its list carrying the properties": {
			spec: func(s *spec) {
				s.keyLevel, s.attLevel = androidkey.Software, androidkey.Software
				s.sw, s.hw = append(slices.Clone(hw), sw...), nil
			},
			policy: func(v *androidkey.Verifier) { v.AllowSoftware = true }},
		"software key allowed, properties only in the hardware list": {
			spec:   func(s *spec) { s.keyLevel, s.attLevel = androidkey.Software, androidkey.Software },
			policy: func(v *androidkey.Verifier) { v.AllowSoftware = true },
			want:   androidkey.ErrKeyProperties},
		"version 2": {spec: func(s *spec) { s.version = 2 }, want: androidkey.ErrAttestationVersion},
		"version 2 allowed": {
			spec: func(s *spec) { s.version = 2 }, policy: func(v *androidkey.Verifier) { v.MinAttestationVersion = 1 }},
		"version 400": {spec: func(s *spec) { s.version = 400 }},
		"version 500": {spec: func(s *spec) { s.version = 500; s.hw = append(slices.Clone(hw), field{11, derInt(t, 1)}) }},
		"unlocked bootloader": {
			spec: func(s *spec) { s.hw = replace(hw, 704, rootOfTrust(t, bootKey[:], false, androidkey.Unverified)) }, want: androidkey.ErrBootState},
		"verified, unlocked": {
			spec: func(s *spec) { s.hw = replace(hw, 704, rootOfTrust(t, bootKey[:], false, androidkey.Verified)) }, want: androidkey.ErrBootState},
		"self-signed boot, another key trusted": {
			spec: func(s *spec) { s.hw = replace(hw, 704, rootOfTrust(t, bootKey[:], true, androidkey.SelfSigned)) },
			policy: func(v *androidkey.Verifier) {
				other := sha256.Sum256([]byte("another verified boot key"))
				v.TrustedBootKeys = [][]byte{other[:]}
			}, want: androidkey.ErrBootState},
		"locked, unverified": {
			spec: func(s *spec) { s.hw = replace(hw, 704, rootOfTrust(t, bootKey[:], true, androidkey.Unverified)) }, want: androidkey.ErrBootState},
		"locked, failed": {
			spec: func(s *spec) { s.hw = replace(hw, 704, rootOfTrust(t, bootKey[:], true, androidkey.Failed)) }, want: androidkey.ErrBootState},
		"self-signed boot, key unknown": {
			spec: func(s *spec) { s.hw = replace(hw, 704, rootOfTrust(t, bootKey[:], true, androidkey.SelfSigned)) }, want: androidkey.ErrBootState},
		"self-signed boot, key trusted": {
			spec:   func(s *spec) { s.hw = replace(hw, 704, rootOfTrust(t, bootKey[:], true, androidkey.SelfSigned)) },
			policy: func(v *androidkey.Verifier) { v.TrustedBootKeys = [][]byte{bootKey[:]} }},
		"no root of trust": {spec: func(s *spec) { s.hw = replace(hw, 704, nil) }, want: androidkey.ErrBootState},
		"root of trust in the software list": {
			spec: func(s *spec) {
				s.hw = replace(hw, 704, nil)
				s.sw = append(slices.Clone(sw), field{704, rootOfTrust(t, bootKey[:], true, androidkey.Verified)})
			}, want: androidkey.ErrBootState},
		"unlocked, allowed": {
			spec:   func(s *spec) { s.hw = replace(hw, 704, rootOfTrust(t, bootKey[:], false, androidkey.Unverified)) },
			policy: func(v *androidkey.Verifier) { v.AllowUntrustedBoot = true }},
		"old patch level":     {policy: func(v *androidkey.Verifier) { v.MinOSPatchLevel = 202510 }, want: androidkey.ErrPatchLevel},
		"current patch level": {policy: func(v *androidkey.Verifier) { v.MinOSPatchLevel = 202509 }},
		"no patch level": {
			spec: func(s *spec) { s.hw = replace(hw, 706, nil) }, policy: func(v *androidkey.Verifier) { v.MinOSPatchLevel = 202001 },
			want: androidkey.ErrPatchLevel},
		"verify only": {
			spec: func(s *spec) { s.hw = replace(hw, 1, derIntSet(t, int64(androidkey.PurposeVerify))) }, want: androidkey.ErrKeyProperties},
		"sign and agree": {
			spec: func(s *spec) {
				s.hw = replace(hw, 1, derIntSet(t, int64(androidkey.PurposeSign), int64(androidkey.PurposeAgreeKey)))
			}},
		"purpose in the software list only": {
			spec: func(s *spec) {
				s.hw = replace(hw, 1, nil)
				s.sw = append(slices.Clone(sw), field{1, derIntSet(t, int64(androidkey.PurposeSign))})
			}, want: androidkey.ErrKeyProperties},
		"RSA":                          {spec: func(s *spec) { s.hw = replace(hw, 2, derInt(t, int64(androidkey.AlgorithmRSA))) }, want: androidkey.ErrKeyProperties},
		"no algorithm":                 {spec: func(s *spec) { s.hw = replace(hw, 2, nil) }, want: androidkey.ErrKeyProperties},
		"claims P-384":                 {spec: func(s *spec) { s.hw = replace(hw, 10, derInt(t, int64(androidkey.CurveP384))) }, want: androidkey.ErrKeyProperties},
		"no curve, as Keymaster 4 may": {spec: func(s *spec) { s.hw = replace(hw, 10, nil) }},
		"wrong key size":               {spec: func(s *spec) { s.hw = replace(hw, 3, derInt(t, 384)) }, want: androidkey.ErrKeyProperties},
		"no curve and no key size": {
			spec: func(s *spec) { s.hw = replace(replace(hw, 10, nil), 3, nil) }, want: androidkey.ErrKeyProperties},
		"no curve, wrong key size": {
			spec: func(s *spec) { s.hw = replace(replace(hw, 10, nil), 3, derInt(t, 384)) }, want: androidkey.ErrKeyProperties},
		"imported":  {spec: func(s *spec) { s.hw = replace(hw, 702, derInt(t, int64(androidkey.OriginImported))) }, want: androidkey.ErrKeyProperties},
		"no origin": {spec: func(s *spec) { s.hw = replace(hw, 702, nil) }, want: androidkey.ErrKeyProperties},
		"P-384 key, P-256 only": {
			spec: func(s *spec) { s.hw = p384(t, hw) },
			opts: chainOpts{leafCurve: elliptic.P384()}, want: androidkey.ErrKeyProperties},
		"P-384 key allowed": {
			spec: func(s *spec) { s.hw = p384(t, hw) },
			opts: chainOpts{leafCurve: elliptic.P384()},
			policy: func(v *androidkey.Verifier) {
				v.Curves = []androidkey.ECCurve{androidkey.CurveP256, androidkey.CurveP384}
			}},
		"another package": {
			spec: func(s *spec) { s.sw = replace(sw, 709, appID(t, []pkg{{"com.example.other", 1}}, appDigest[:])) }, want: androidkey.ErrAppNotAllowed},
		"another signer": {
			spec: func(s *spec) { s.sw = replace(sw, 709, appID(t, []pkg{{appPackage, 1}}, otherDigest[:])) }, want: androidkey.ErrAppNotAllowed},
		"an extra signer": {
			spec: func(s *spec) { s.sw = replace(sw, 709, appID(t, []pkg{{appPackage, 1}}, appDigest[:], otherDigest[:])) },
			want: androidkey.ErrAppNotAllowed},
		"a second, unknown package": {
			spec: func(s *spec) {
				s.sw = replace(sw, 709, appID(t, []pkg{{appPackage, 1}, {"com.example.other", 1}}, appDigest[:]))
			}, want: androidkey.ErrAppNotAllowed},
		"no signer": {
			spec: func(s *spec) { s.sw = replace(sw, 709, appID(t, []pkg{{appPackage, 1}})) }, want: androidkey.ErrAppNotAllowed},
		"another package in the hardware-enforced list": {
			spec: func(s *spec) {
				s.hw = append(slices.Clone(hw), field{709, appID(t, []pkg{{"com.example.other", 42}}, appDigest[:])})
			},
			want: androidkey.ErrAppNotAllowed},
		"no application ID": {spec: func(s *spec) { s.sw = replace(sw, 709, nil) }, want: androidkey.ErrAppNotAllowed},
		"old app version": {
			policy: func(v *androidkey.Verifier) {
				v.Apps = []androidkey.AllowedApp{{Package: appPackage, SigningCertificateDigests: [][]byte{appDigest[:]}, MinVersion: 43}}
			}, want: androidkey.ErrAppNotAllowed},
		"rotated signer allowed": {
			spec: func(s *spec) { s.sw = replace(sw, 709, appID(t, []pkg{{appPackage, 1}}, otherDigest[:])) },
			policy: func(v *androidkey.Verifier) {
				v.Apps = []androidkey.AllowedApp{{Package: appPackage, SigningCertificateDigests: [][]byte{appDigest[:], otherDigest[:]}}}
			}},
		"revoked intermediate": {opts: chainOpts{serials: [3]int64{0, 0xf00d, 0}}, want: androidkey.ErrRevoked},
		"suspended leaf":       {opts: chainOpts{serials: [3]int64{0xbeef, 0, 0}}, want: androidkey.ErrRevoked},
		"revoked root":         {opts: chainOpts{serials: [3]int64{0, 0, 0xf00d}}, want: androidkey.ErrRevoked},
		"status unavailable": {
			policy: func(v *androidkey.Verifier) { v.Revocation = failingStatus{} }, want: androidkey.ErrStatusUnavailable},
		"nil status list": {
			policy: func(v *androidkey.Verifier) { v.Revocation = nilStatus{} }, want: androidkey.ErrStatusUnavailable},
		"status unavailable, optional": {
			policy: func(v *androidkey.Verifier) { v.Revocation, v.RevocationOptional = failingStatus{}, true }},
		"no status provider, optional": {
			policy: func(v *androidkey.Verifier) { v.Revocation, v.RevocationOptional = nil, true }},
		"expired intermediate": {
			opts: chainOpts{interValidity: [2]time.Time{time.Now().Add(-48 * time.Hour), time.Now().Add(-24 * time.Hour)}},
			want: androidkey.ErrCertificateValidity},
		"intermediate not yet valid": {
			opts: chainOpts{interValidity: [2]time.Time{time.Now().Add(time.Hour), time.Now().Add(48 * time.Hour)}},
			want: androidkey.ErrCertificateValidity},
		"expired leaf": {
			opts: chainOpts{leafValidity: [2]time.Time{time.Now().Add(-48 * time.Hour), time.Now().Add(-24 * time.Hour)}},
			want: androidkey.ErrCertificateValidity},
		"leaf not yet valid": {
			opts: chainOpts{leafValidity: [2]time.Time{time.Now().Add(time.Hour), time.Now().Add(48 * time.Hour)}},
			want: androidkey.ErrCertificateValidity},
		"configured root expired, the rest valid": {
			opts: chainOpts{rootValidity: [2]time.Time{time.Now().Add(-48 * time.Hour), time.Now().Add(-24 * time.Hour)}},
			want: androidkey.ErrCertificateValidity},
		"root expired": {
			policy: func(v *androidkey.Verifier) { v.Now = func() time.Time { return time.Now().Add(48 * time.Hour) } },
			want:   androidkey.ErrCertificateValidity},
		"untrusted root": {
			policy: func(v *androidkey.Verifier) { v.Roots = androidkey.GoogleRoots() }, want: androidkey.ErrUntrustedRoot},
		"default roots": {policy: func(v *androidkey.Verifier) { v.Roots = nil }, want: androidkey.ErrUntrustedRoot},
		"malformed extension": {
			spec: func(s *spec) { s.rawExtension = []byte{0x30, 0x03, 0x02, 0x01, 0x03} }, want: androidkey.ErrMalformed},
		"wrong challenge":                    {spec: func(s *spec) { s.challenge = []byte("another challenge") }, want: androidkey.ErrChallenge},
		"empty challenge in the attestation": {spec: func(s *spec) { s.challenge = nil }, want: androidkey.ErrChallenge},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := goodSpec(t)
			if c.spec != nil {
				c.spec(&s)
			}
			chain := newChain(t, s, c.opts)
			v := verifierFor(t, chain)
			if c.policy != nil {
				c.policy(v)
			}
			r, err := v.Verify(ctx, chain.der, testChallenge)
			switch {
			case c.want == nil && err != nil:
				t.Fatalf("err = %v, want success", err)
			case c.want != nil && !errors.Is(err, c.want):
				t.Fatalf("err = %v, want %v", err, c.want)
			case c.want == nil && r.RevocationChecked != (v.Revocation != nil && !v.RevocationOptional):
				t.Errorf("RevocationChecked = %v", r.RevocationChecked)
			}
		})
	}
}

// p384 is hw for a P-384 key.
func p384(t testing.TB, hw []field) []field {
	return replace(replace(hw, 10, derInt(t, int64(androidkey.CurveP384))), 3, derInt(t, 384))
}

type failingStatus struct{}

func (failingStatus) Current(context.Context) (*androidkey.StatusList, error) {
	return nil, errors.New("status list server down")
}

type nilStatus struct{}

func (nilStatus) Current(context.Context) (*androidkey.StatusList, error) { return nil, nil }

// TestVerify_RevokedError: a revocation names the certificate and its
// entry.
func TestVerify_RevokedError(t *testing.T) {
	c := newChain(t, goodSpec(t), chainOpts{serials: [3]int64{0, 0xf00d, 0}})
	_, err := verifierFor(t, c).Verify(context.Background(), c.der, testChallenge)
	var revoked *androidkey.RevokedError
	if !errors.As(err, &revoked) || revoked.Position != 1 || revoked.Serial != "f00d" ||
		revoked.Entry.Status != androidkey.StatusRevoked || revoked.Entry.Reason != "KEY_COMPROMISE" {
		t.Fatalf("err = %#v", err)
	}
	if !strings.Contains(err.Error(), "KEY_COMPROMISE") || !strings.Contains(err.Error(), "f00d") {
		t.Errorf("message %q", err)
	}
}

// TestVerify_MalformedChains: chains of the wrong shape are refused
// before their content is trusted.
func TestVerify_MalformedChains(t *testing.T) {
	good := newChain(t, goodSpec(t), chainOpts{})
	other := newChain(t, goodSpec(t), chainOpts{})
	ext := goodSpec(t).encode(t)
	// The attested key signs a "leaf" of its own, for another key.
	another := newKey(t, elliptic.P256())
	forged := makeLeaf(t, mustParse(t, good.der[0]), good.leafKey, &another.PublicKey, ext, 9)
	noExt := makeLeaf(t, good.inter, good.interKey, &good.leafKey.PublicKey, nil, 9)
	tampered := slices.Clone(good.der[0])
	tampered[len(tampered)-1] ^= 1
	modulus := new(big.Int).Lsh(big.NewInt(1), 8192)
	modulus.SetBit(modulus, 0, 1)
	bigRSA := makeLeaf(t, good.inter, good.interKey, &rsa.PublicKey{N: modulus, E: 65537}, ext, 9)
	huge := slices.Clone(good.der[0])
	huge = append(huge, make([]byte, androidkey.MaxCertificateBytes)...)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	smallExponent := makeLeaf(t, good.inter, good.interKey, &rsa.PublicKey{N: rsaKey.N, E: 3}, ext, 9)

	for name, tc := range map[string]struct {
		chain [][]byte
		want  error
	}{
		"empty":                     {nil, androidkey.ErrMalformed},
		"too long":                  {slices.Repeat([][]byte{good.der[0]}, androidkey.MaxChainLength+1), androidkey.ErrMalformed},
		"not DER":                   {[][]byte{[]byte("certificate")}, androidkey.ErrMalformed},
		"oversized certificate":     {[][]byte{huge, good.der[1], good.der[2]}, androidkey.ErrMalformed},
		"oversized RSA key":         {[][]byte{bigRSA.Raw, good.der[1], good.der[2]}, androidkey.ErrMalformed},
		"RSA exponent 3":            {[][]byte{smallExponent.Raw, good.der[1], good.der[2]}, androidkey.ErrMalformed},
		"oversized, well-formed":    {[][]byte{paddedLeaf(t, good, androidkey.MaxCertificateBytes+1), good.der[1], good.der[2]}, androidkey.ErrMalformed},
		"another chain's root":      {[][]byte{good.der[0], good.der[1], other.der[2]}, androidkey.ErrChainSignature},
		"tampered signature":        {[][]byte{tampered, good.der[1], good.der[2]}, androidkey.ErrChainSignature},
		"intermediate out of order": {[][]byte{good.der[0], good.der[2], good.der[1]}, androidkey.ErrChainSignature},
		"no extension":              {[][]byte{noExt.Raw, good.der[1], good.der[2]}, androidkey.ErrMalformed},
		"extension below the leaf":  {[][]byte{forged.Raw, good.der[0], good.der[1], good.der[2]}, androidkey.ErrMalformed},
		"leaf alone":                {[][]byte{good.der[0]}, androidkey.ErrUntrustedRoot},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifierFor(t, good).Verify(context.Background(), tc.chain, testChallenge); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerify_CertificateAtMaxBytes: a certificate of exactly
// MaxCertificateBytes is accepted.
func TestVerify_CertificateAtMaxBytes(t *testing.T) {
	good := newChain(t, goodSpec(t), chainOpts{})
	chain := [][]byte{paddedLeaf(t, good, androidkey.MaxCertificateBytes), good.der[1], good.der[2]}
	if _, err := verifierFor(t, good).Verify(context.Background(), chain, testChallenge); err != nil {
		t.Fatal(err)
	}
}

// paddedLeaf is c's leaf again, padded with an unknown extension to
// size bytes.
func paddedLeaf(t testing.TB, c testChain, size int) []byte {
	t.Helper()
	ext := goodSpec(t).encode(t)
	pad := size - 1000
	// An ECDSA signature's length varies by a byte or two: adjust the
	// padding until the certificate comes out at size.
	for range 50 {
		tmpl := leafTemplate(ext, 9)
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: make([]byte, pad)})
		der := issue(t, tmpl, c.inter, c.interKey, &c.leafKey.PublicKey).Raw
		if len(der) == size {
			return der
		}
		pad += size - len(der)
	}
	t.Fatalf("no %d-byte certificate", size)
	return nil
}

// TestVerify_Config: a misconfigured Verifier refuses every chain.
func TestVerify_Config(t *testing.T) {
	good := newChain(t, goodSpec(t), chainOpts{})
	for name, tc := range map[string]struct {
		mutate    func(v *androidkey.Verifier)
		challenge []byte
	}{
		"no apps":         {mutate: func(v *androidkey.Verifier) { v.Apps = nil }},
		"no revocation":   {mutate: func(v *androidkey.Verifier) { v.Revocation = nil }},
		"empty challenge": {challenge: []byte{}},
		"long challenge":  {challenge: make([]byte, androidkey.MaxChallengeBytes+1)},
		"app without name": {mutate: func(v *androidkey.Verifier) {
			v.Apps = []androidkey.AllowedApp{{SigningCertificateDigests: [][]byte{appDigest[:]}}}
		}},
		"app without digest": {mutate: func(v *androidkey.Verifier) { v.Apps = []androidkey.AllowedApp{{Package: appPackage}} }},
		"short digest": {mutate: func(v *androidkey.Verifier) {
			v.Apps = []androidkey.AllowedApp{{Package: appPackage, SigningCertificateDigests: [][]byte{appDigest[:20]}}}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			v := verifierFor(t, good)
			if tc.mutate != nil {
				tc.mutate(v)
			}
			challenge := testChallenge
			if tc.challenge != nil {
				challenge = tc.challenge
			}
			if _, err := v.Verify(context.Background(), good.der, challenge); !errors.Is(err, androidkey.ErrConfig) {
				t.Errorf("err = %v, want ErrConfig", err)
			}
		})
	}
}
