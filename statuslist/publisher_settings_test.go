package statuslist

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// Token refuses a TTL or Lifetime a token can't carry, and a TTL longer
// than the token lives, rather than failing every request later.
func TestPublisher_RefusesTimesATokenCantCarry(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	cert, key := testcert.Leaf(t, "status signer", ca, caKey)
	for name, tc := range map[string]struct {
		lifetime, ttl time.Duration
		want          string
	}{
		"sub-second TTL":      {time.Hour, 500 * time.Millisecond, "TTL"},
		"sub-second Lifetime": {500 * time.Millisecond, 0, "Lifetime"},
		"TTL over Lifetime":   {time.Minute, time.Hour, "longer than its Lifetime"},
		"TTL of the Lifetime": {time.Hour, time.Hour, ""},
	} {
		p := &Publisher{
			URI: "https://issuer.example/statuslists/1", Signer: key, Chain: []*x509.Certificate{cert},
			Lifetime: tc.lifetime, TTL: tc.ttl,
			Statuses: func(context.Context) ([]uint8, error) { return []uint8{0}, nil },
		}
		_, err := p.Token(context.Background(), false)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: %v, want an error containing %q", name, err, tc.want)
		}
	}
}

// Token refuses a token over MaxTokenBytes, which a Checker would
// refuse as too large.
func TestPublisher_RefusesATokenOverMaxTokenBytes(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	cert, key := testcert.Leaf(t, "status signer", ca, caKey)
	p := &Publisher{
		URI: "https://issuer.example/statuslists/1", Signer: key, Chain: []*x509.Certificate{cert},
		MaxTokenBytes: 600,
		Statuses:      func(context.Context) ([]uint8, error) { return make([]uint8, 16), nil },
	}
	if _, err := p.Token(context.Background(), false); err == nil || !strings.Contains(err.Error(), "MaxTokenBytes") {
		t.Errorf("a token over 600 bytes: %v, want it refused", err)
	}
	p.MaxTokenBytes = 0
	if _, err := p.Token(context.Background(), false); err != nil {
		t.Errorf("the default limit: %v", err)
	}
}

// servesCWT chooses by q, ignoring a media type the Accept header
// excludes with q=0 (RFC 9110 §12.5.1).
func TestPublisher_ServesCWTByQ(t *testing.T) {
	for _, tc := range []struct {
		accept      string
		defaultForm Form
		cwt         bool
	}{
		{CWTTokenMediaType, FormJWT, true},
		{TokenMediaType, FormCWT, false},
		{CWTTokenMediaType + ";q=0, " + TokenMediaType, FormCWT, false},
		{CWTTokenMediaType + "; q=0", FormJWT, false},
		{CWTTokenMediaType + "; q=0", FormCWT, true},
		{TokenMediaType + ";q=0.5, " + CWTTokenMediaType + ";q=0.9", FormJWT, true},
		{TokenMediaType + ";q=1, " + CWTTokenMediaType + ";q=0.9", FormCWT, false},
		{"APPLICATION/STATUSLIST+CWT", FormJWT, true},
		{"", FormCWT, true},
		{"*/*", FormJWT, false},
	} {
		p := &Publisher{DefaultForm: tc.defaultForm}
		if got := p.servesCWT(tc.accept); got != tc.cwt {
			t.Errorf("Accept %q, default %v: cwt = %v, want %v", tc.accept, tc.defaultForm, got, tc.cwt)
		}
	}
}
