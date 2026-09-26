package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// FuzzVerifySigned exercises Verify's post-signature path — the issuer
// JWT's claims and validity window, ResolveDisclosures (including its
// recursion-depth bound) and the Key Binding JWT's own checks — which
// FuzzParse can't reach: a mutated presentation there almost never
// carries a valid issuer signature. Here the fuzzer controls the issuer
// JWT payload, the "~"-separated disclosures and the Key Binding JWT
// payload, and the harness signs both JWTs itself. With inject set,
// the harness also adds each parsed disclosure's digest to the payload,
// so mutated disclosures still get resolved rather than rejected as
// unreferenced. A non-empty kbPayload that is a JSON object gets the
// presentation's real sd_hash, so mutations of its other claims reach
// VerifyKeyBindingJWT's remaining checks.
func FuzzVerifySigned(f *testing.F) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate issuer key: %v", err)
	}
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate holder key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const aud, nonce = "https://example.com/verifier", "fuzz-nonce"

	kbSeed, err := json.Marshal(map[string]any{"aud": aud, "nonce": nonce, "iat": now.Unix()})
	if err != nil {
		f.Fatalf("marshal kb seed: %v", err)
	}
	for _, additional := range []map[string]any{
		{"given_name": "Alice", "family_name": SD("Doe")},
		{"address": SD(map[string]any{"street": SD("Main St"), "country": "US"}), "nationalities": []any{SDElement("US"), "DE"}},
	} {
		sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{
			VCT: "https://credentials.example.com/identity_credential",
			Iss: "https://example.com/issuer", Additional: additional,
		}, IssueOptions{})
		if err != nil {
			f.Fatalf("Issue: %v", err)
		}
		pres, err := Parse(sdjwt)
		if err != nil {
			f.Fatalf("Parse: %v", err)
		}
		_, payload, err := jose.DecodeUnverified(pres.IssuerJWT)
		if err != nil {
			f.Fatalf("DecodeUnverified: %v", err)
		}
		encoded := make([]string, len(pres.Disclosures))
		for i, d := range pres.Disclosures {
			if encoded[i], err = d.Encode(); err != nil {
				f.Fatalf("Encode: %v", err)
			}
		}
		disclosures := strings.Join(encoded, "~")
		f.Add(payload, disclosures, []byte{}, false)
		f.Add(payload, disclosures, kbSeed, false)
		f.Add(payload, disclosures, []byte{}, true)
	}

	f.Fuzz(func(t *testing.T, payload []byte, disclosures string, kbPayload []byte, inject bool) {
		var parsed []Disclosure
		var rawDisclosures []string
		for _, s := range strings.Split(disclosures, "~") {
			if s == "" {
				continue
			}
			rawDisclosures = append(rawDisclosures, s)
			if d, err := ParseDisclosure(s); err == nil {
				parsed = append(parsed, d)
			}
		}
		if inject {
			payload = injectDigests(payload, parsed)
		}

		issuerJWT, err := jose.Sign(jose.ES256, issuerKey, map[string]any{"typ": TypHeader}, payload)
		if err != nil {
			t.Fatalf("sign issuer JWT: %v", err)
		}
		sdjwt := issuerJWT + "~"
		for _, s := range rawDisclosures {
			sdjwt += s + "~"
		}

		opts := VerifyOptions{RequireKeyBinding: KeyBindingNotRequired, Now: func() time.Time { return now }}
		presentation := sdjwt
		if len(kbPayload) > 0 {
			kbJWT, err := jose.Sign(jose.ES256, holderKey, map[string]any{"typ": KeyBindingTyp}, withSDHash(kbPayload, sdjwt))
			if err != nil {
				t.Fatalf("sign kb JWT: %v", err)
			}
			presentation += kbJWT
			opts.RequireKeyBinding = KeyBindingRequired
			opts.HolderPublicKey = &holderKey.PublicKey
			opts.KeyBindingAlg = jose.ES256
			opts.ExpectedAudience = aud
			opts.ExpectedNonce = nonce
			opts.MaxKeyBindingAge = time.Hour
		}

		_, _, _ = Verify(presentation, &issuerKey.PublicKey, jose.ES256, opts)
	})
}

// injectDigests adds each disclosure's SHA-256 digest to payload — an
// object disclosure to the top-level "_sd" array, an array-element one
// as a {"...": digest} entry of a synthetic array claim, skipping an
// object digest "_sd" already lists — leaving
// payload unchanged if it isn't a JSON object or its "_sd" isn't an
// array.
func injectDigests(payload []byte, disclosures []Disclosure) []byte {
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil || m == nil {
		return payload
	}
	sd, _ := m["_sd"].([]any)
	if _, present := m["_sd"]; present && sd == nil {
		return payload
	}
	present := make(map[string]bool, len(sd))
	for _, v := range sd {
		if digest, ok := v.(string); ok {
			present[digest] = true
		}
	}
	var elements []any
	for _, d := range disclosures {
		digest, err := d.Digest(SHA256)
		if err != nil {
			continue
		}
		if d.IsArrayElement() {
			elements = append(elements, map[string]any{"...": digest})
		} else if !present[digest] {
			sd = append(sd, digest)
			present[digest] = true
		}
	}
	if len(sd) > 0 {
		m["_sd"] = sd
	}
	if len(elements) > 0 {
		m["fuzz_elements"] = elements
	}
	out, err := json.Marshal(m)
	if err != nil {
		return payload
	}
	return out
}

// withSDHash sets kbPayload's sd_hash claim to sdjwt's real SHA-256
// digest if kbPayload is a JSON object, or returns it unchanged.
func withSDHash(kbPayload []byte, sdjwt string) []byte {
	var m map[string]any
	if json.Unmarshal(kbPayload, &m) != nil || m == nil {
		return kbPayload
	}
	sdHash, err := hashString(SHA256, sdjwt)
	if err != nil {
		return kbPayload
	}
	m["sd_hash"] = sdHash
	out, err := json.Marshal(m)
	if err != nil {
		return kbPayload
	}
	return out
}
