package statuslist

import (
	"math"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// VerifyToken reads a token's times and applies VerifyOptions' freshness
// rules to them (jwtdate.Window's own table covers the rules). Without
// these, an old list signed before a revocation could be replayed.
func TestVerifyToken_Freshness(t *testing.T) {
	key := testKey(t)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// Signed without IssueToken's checks, which refuse some of these.
	issue := func(iat int64, exp, ttl *int64) string {
		t.Helper()
		token, err := signToken(key, jose.ES256, TokenClaims{Sub: "https://example.com/statuslists/1", Iat: iat, Exp: exp, TTL: ttl, StatusList: sl}, map[string]any{"typ": TokenTyp})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	outOfRange := int64(math.MaxInt64 - 10)
	zero, negative, iatNow := int64(0), int64(-1), now.Unix()
	for name, tc := range map[string]struct {
		token string
		opts  VerifyOptions
	}{
		"no iat":               {issue(0, nil, nil), VerifyOptions{UnboundSigner: AnyListSigner}},
		"iat out of range":     {issue(outOfRange, nil, nil), VerifyOptions{UnboundSigner: AnyListSigner}},
		"exp out of range":     {issue(now.Unix(), &outOfRange, nil), VerifyOptions{UnboundSigner: AnyListSigner}},
		"older than MaxAge":    {issue(now.Add(-2*time.Hour).Unix(), nil, nil), VerifyOptions{UnboundSigner: AnyListSigner, MaxAge: time.Hour}},
		"negative MaxAge":      {issue(now.Unix(), nil, nil), VerifyOptions{UnboundSigner: AnyListSigner, MaxAge: -time.Second}},
		"beyond a stated skew": {issue(now.Add(10*time.Second).Unix(), nil, nil), VerifyOptions{UnboundSigner: AnyListSigner, MaxClockSkew: time.Second}},
		"no exp, RequireExp":   {issue(now.Unix(), nil, nil), VerifyOptions{UnboundSigner: AnyListSigner, RequireExp: true}},
		"ttl 0":                {issue(now.Unix(), nil, &zero), VerifyOptions{UnboundSigner: AnyListSigner}},
		"ttl negative":         {issue(now.Unix(), nil, &negative), VerifyOptions{UnboundSigner: AnyListSigner}},
		"exp at iat":           {issue(iatNow, &iatNow, nil), VerifyOptions{UnboundSigner: AnyListSigner, Now: func() time.Time { return now.Add(-30 * time.Second) }}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyToken(tc.token, &key.PublicKey, jose.ES256, tc.opts); err == nil {
				t.Error("accepted")
			}
		})
	}
	if _, err := VerifyToken(issue(now.Unix(), nil, nil), &key.PublicKey, jose.ES256, VerifyOptions{UnboundSigner: AnyListSigner}); err != nil {
		t.Errorf("fresh, no exp: refused: %v", err)
	}
}
