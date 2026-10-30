package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/dpop"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// signClaims signs claims as a DPoP proof with typ as its "typ".
func signClaims(t *testing.T, key *ecdsa.PrivateKey, typ string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	proof, err := jose.Sign(jose.ES256, key, map[string]any{"typ": typ, "jwk": mustJWK(t, key)}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return proof
}

// expiringReplay is a replay store that forgets a record at its
// expiresAt, by the time now reports, as a store expiring records on
// time does. Several Verify calls, standing for several servers, share
// one.
type expiringReplay struct {
	mu   sync.Mutex
	now  func() time.Time
	seen map[string]time.Time
}

func (r *expiringReplay) UseOnce(_ context.Context, jti string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if exp, ok := r.seen[jti]; ok && r.now().Before(exp) {
		return fakeErr("jti already used")
	}
	r.seen[jti] = expiresAt
	return nil
}

// TestVerifyKeepsReplayRecordsAcrossClockSkew: a proof taken by one
// server is refused by another whose clock runs MaxClockSkew behind,
// however late it arrives there within its MaxProofAge: the record is
// kept for MaxProofAge plus twice MaxClockSkew (the audit's skewed
// second instance PoC, inverted).
func TestVerifyKeepsReplayRecordsAcrossClockSkew(t *testing.T) {
	const age, skew = time.Minute, 10 * time.Second
	real := time.Unix(1_700_000_000, 0)
	key := testP256Key(t)
	// The proof says it was made skew ahead of server A's clock.
	proof := signedProof(t, key, "j1", "", real.Add(skew))
	var current time.Time
	replay := &expiringReplay{now: func() time.Time { return current }, seen: map[string]time.Time{}}
	verify := func(serverClock time.Time) error {
		_, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
			Proof: proof, Method: "POST", URL: testHTU, Now: serverClock,
			MaxProofAge: age, MaxClockSkew: skew, Replay: replay,
		})
		return err
	}

	current = real
	if err := verify(real); err != nil {
		t.Fatalf("server A: %v", err)
	}
	// Server B's clock is skew behind; the proof is still within
	// MaxProofAge by it until real time iat+age+skew.
	for _, at := range []time.Duration{time.Second, age, age + 2*skew - time.Second} {
		current = real.Add(at)
		if err := verify(current.Add(-skew)); err == nil {
			t.Errorf("server B at real T+%s: replayed proof accepted", at)
		}
	}
}

// TestVerifyChecksExpAndNbf: exp and nbf, when present, are enforced
// with MaxClockSkew's tolerance (RFC 7519 §4.1.4-§4.1.5).
func TestVerifyChecksExpAndNbf(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const skew = 10 * time.Second
	key := testP256Key(t)
	for name, tc := range map[string]struct {
		extra map[string]any
		ok    bool
	}{
		"exp an hour ago":         {map[string]any{"exp": now.Add(-time.Hour).Unix()}, false},
		"exp just past, in skew":  {map[string]any{"exp": now.Add(-skew + time.Second).Unix()}, true},
		"exp ahead":               {map[string]any{"exp": now.Add(time.Minute).Unix()}, true},
		"nbf an hour ahead":       {map[string]any{"nbf": now.Add(time.Hour).Unix()}, false},
		"nbf just ahead, in skew": {map[string]any{"nbf": now.Add(skew - time.Second).Unix()}, true},
		"nbf now":                 {map[string]any{"nbf": now.Unix()}, true},
		"exp not a number":        {map[string]any{"exp": "soon"}, false},
		"nbf out of range":        {map[string]any{"nbf": -1}, false},
	} {
		claims := map[string]any{"jti": "j-" + name, "htm": "POST", "htu": testHTU, "iat": now.Unix()}
		for k, v := range tc.extra {
			claims[k] = v
		}
		_, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
			Proof: signClaims(t, key, "dpop+jwt", claims), Method: "POST", URL: testHTU,
			Now: now, MaxProofAge: time.Minute, MaxClockSkew: skew, Replay: newFakeReplayChecker(),
		})
		if (err == nil) != tc.ok {
			t.Errorf("%s: Verify = %v, want ok=%v", name, err, tc.ok)
		}
	}
}

// TestVerifyComparesTypAsMediaType: typ is a media type (RFC 7515
// §4.1.9), compared case-insensitively with "application/" implied.
func TestVerifyComparesTypAsMediaType(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := testP256Key(t)
	for typ, ok := range map[string]bool{
		"dpop+jwt": true, "DPoP+JWT": true, "application/dpop+jwt": true, "Application/DPOP+jwt": true,
		"jwt": false, "dpop": false, "text/dpop+jwt": false, "": false,
	} {
		claims := map[string]any{"jti": "j-" + typ, "htm": "POST", "htu": testHTU, "iat": now.Unix()}
		_, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
			Proof: signClaims(t, key, typ, claims), Method: "POST", URL: testHTU,
			Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
		})
		if (err == nil) != ok {
			t.Errorf("typ %q: Verify = %v, want ok=%v", typ, err, ok)
		}
	}
}

// TestVerifyAcceptsFractionalNumericDates: a NumericDate may be
// fractional (RFC 7519 §2).
func TestVerifyAcceptsFractionalNumericDates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := testP256Key(t)
	claims := map[string]any{
		"jti": "j1", "htm": "POST", "htu": testHTU,
		"iat": float64(now.Unix()) - 0.25, "nbf": float64(now.Unix()) - 0.5, "exp": float64(now.Unix()) + 30.5,
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: signClaims(t, key, "dpop+jwt", claims), Method: "POST", URL: testHTU,
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err != nil {
		t.Fatalf("Verify with fractional NumericDates: %v", err)
	}
}

// TestVerifyNormalizesHTU: htu and the request's URI are compared after
// RFC 3986 §6.2.2-§6.2.3 normalization, query and fragment ignored
// (RFC 9449 §4.3), as fapigo/server compares them.
func TestVerifyNormalizesHTU(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := testP256Key(t)
	for htu, ok := range map[string]bool{
		"https://issuer.example.com/token":                   true,
		"https://ISSUER.example.com/token":                   true,
		"HTTPS://issuer.example.com/token":                   true,
		"https://issuer.example.com:443/token":               true,
		"https://issuer.example.com/token?":                  true,
		"https://issuer.example.com/token?a=b#frag":          true,
		"https://issuer.example.com/./token":                 true,
		"https://issuer.example.com/x/../token":              true,
		"https://issuer.example.com/%74oken":                 true,
		"https://user@issuer.example.com/token":              true,
		"https://issuer.example.com:8443/token":              false,
		"http://issuer.example.com/token":                    false,
		"https://issuer.example.com/Token":                   false,
		"https://issuer.example.com/token/":                  false,
		"https://other.example.com/token":                    false,
		"/token":                                             false,
		"wss://issuer.example.com/token":                     false,
		"https://İssuer.example.com/token":                   false,
		"https://issuer.example.com/%2Ftoken":                false,
		"https://issuer.example.com/token%2F..%2Fadmin":      false,
		"https://issuer.example.com/admin/../../../../token": true,
	} {
		claims := map[string]any{"jti": "j-" + htu, "htm": "POST", "htu": htu, "iat": now.Unix()}
		_, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
			Proof: signClaims(t, key, "dpop+jwt", claims), Method: "POST", URL: testHTU,
			Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
		})
		if (err == nil) != ok {
			t.Errorf("htu %q: Verify = %v, want ok=%v", htu, err, ok)
		}
	}

	// The request's own URI is normalized as well.
	claims := map[string]any{"jti": "j-target", "htm": "POST", "htu": testHTU, "iat": now.Unix()}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: signClaims(t, key, "dpop+jwt", claims), Method: "POST", URL: "https://Issuer.Example.com:443/token",
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err != nil {
		t.Errorf("Verify against a non-normalized request URI: %v", err)
	}
	if _, err := dpop.Verify(context.Background(), dpop.VerifyRequest{
		Proof: signClaims(t, key, "dpop+jwt", claims), Method: "POST", URL: "/token",
		Now: now, MaxProofAge: time.Minute, Replay: newFakeReplayChecker(),
	}); err == nil {
		t.Error("Verify against a relative request URI = nil error, want it refused")
	}
}
