package walletprovider_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// gate is a Config.InstanceLimit that refuses every request while
// closed, recording each it's asked about.
type gate struct {
	mu         sync.Mutex
	closed     bool
	retryAfter time.Duration
	asked      []walletprovider.InstanceRequest
}

func (g *gate) limit(_ context.Context, req walletprovider.InstanceRequest) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.asked = append(g.asked, req)
	if g.closed {
		return walletprovider.RateLimited(g.retryAfter)
	}
	return nil
}

func (g *gate) set(closed bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = closed
}

func (g *gate) requests() []walletprovider.InstanceRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]walletprovider.InstanceRequest(nil), g.asked...)
}

// limitedInstance is a registered instance with a recorded instance
// key, behind a provider limited by its gate.
type limitedInstance struct {
	h           *harness
	ts          *httptest.Server
	c           *walletprovider.Client
	g           *gate
	id          string
	regKey      *ecdsa.PrivateKey
	instanceKey *ecdsa.PrivateKey
}

func newLimitedInstance(t *testing.T) *limitedInstance {
	t.Helper()
	g := &gate{}
	h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) { c.InstanceLimit = g.limit })
	ts, c := h.server("")
	id, regKey := h.clientRegister(c, kindTEE)
	instanceKey, _ := h.clientWalletAttestation(c, id, regKey, kindTEE)
	return &limitedInstance{h: h, ts: ts, c: c, g: g, id: id, regKey: regKey, instanceKey: instanceKey}
}

// revision is the instance's stored record's revision.
func (li *limitedInstance) revision() uint64 {
	li.h.t.Helper()
	in, err := li.h.deps.Instances.Get(context.Background(), li.id)
	if err != nil {
		li.h.t.Fatal(err)
	}
	return in.Revision
}

// body is a request body for path: a Wallet Attestation for the
// recorded instance key, or a Key Attestation for one holder key, for
// that instance key's issuance.
func (li *limitedInstance) body(path string) string {
	t := li.h.t
	t.Helper()
	ik, err := jwk.Marshal(&li.instanceKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	members := map[string]any{"instance_key": ik}
	if path == walletprovider.WalletAttestationPath {
		members["client_id"] = clientID
	} else {
		holder := newKey(t)
		hk, err := jwk.Marshal(&holder.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		ch := li.h.challenge(walletprovider.PurposeHolder)
		ev := evidence(t, kindTEE, ch, &holder.PublicKey)
		members["challenge"], members["keys"], members["nonce"] = ch, []any{hk}, "c-nonce"
		members["evidence"] = []any{map[string]string{"kind": ev.Kind, "data": base64.RawURLEncoding.EncodeToString(ev.Data)}}
	}
	b, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// signed signs body for path as the instance sub, with key, over a
// fresh request challenge.
func (li *limitedInstance) signed(key *ecdsa.PrivateKey, sub, path, body string) string {
	li.h.t.Helper()
	jwt, err := walletprovider.SignRequest(key, sub, li.h.challenge(walletprovider.PurposeRequest), http.MethodPost, path, []byte(body), li.h.clock.now())
	if err != nil {
		li.h.t.Fatal(err)
	}
	return jwt
}

func (li *limitedInstance) send(path, body, jwt string) (*http.Response, []byte) {
	li.h.t.Helper()
	return rawPost(li.h.t, li.ts, path, body, map[string]string{walletprovider.RequestHeader: jwt})
}

// TestInstanceLimit_RefusesBeforeWriting: a signed request the limit
// refuses is answered 429 rate_limited, with the limit's Retry-After,
// and writes nothing: the instance's record is unchanged, and the
// request's challenge is unused, so the same request goes through once
// the limit allows it.
func TestInstanceLimit_RefusesBeforeWriting(t *testing.T) {
	for _, path := range []string{walletprovider.WalletAttestationPath, walletprovider.KeyAttestationPath} {
		t.Run(path, func(t *testing.T) {
			li := newLimitedInstance(t)
			body := li.body(path)
			jwt := li.signed(li.regKey, li.id, path, body)
			before := li.revision()

			li.g.set(true)
			li.g.retryAfter = 1500 * time.Millisecond
			resp, data := li.send(path, body, jwt)
			if resp.StatusCode != http.StatusTooManyRequests || errorCode(t, data) != walletprovider.CodeRateLimited {
				t.Fatalf("refused: HTTP %d %s, want 429 rate_limited", resp.StatusCode, data)
			}
			if got := resp.Header.Get("Retry-After"); got != "2" {
				t.Errorf("Retry-After = %q, want 2", got)
			}
			if strings.Contains(string(data), "InstanceLimit") || strings.Contains(string(data), li.id) {
				t.Errorf("the refusal tells internal text: %s", data)
			}
			if got := li.revision(); got != before {
				t.Errorf("the refused request wrote the instance: revision %d → %d", before, got)
			}

			li.g.set(false)
			if resp, data := li.send(path, body, jwt); resp.StatusCode != http.StatusOK {
				t.Fatalf("the same request once allowed: HTTP %d %s, want 200: its challenge was used", resp.StatusCode, data)
			}
		})
	}
}

// TestInstanceLimit_NoRetryAfterUnlessSaid: a refusal that says nothing
// of when to retry has no Retry-After.
func TestInstanceLimit_NoRetryAfterUnlessSaid(t *testing.T) {
	li := newLimitedInstance(t)
	li.g.set(true)
	body := li.body(walletprovider.WalletAttestationPath)
	resp, _ := li.send(walletprovider.WalletAttestationPath, body, li.signed(li.regKey, li.id, walletprovider.WalletAttestationPath, body))
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "" {
		t.Fatalf("HTTP %d, Retry-After %q: want 429 without one", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

// TestInstanceLimit_SeesTheVerifiedInstance: the limit is asked about
// a request only once it verified, with the instance its signature
// proved: a request naming another instance as its sub, signed with
// another key, is the one 401 without reaching it, so it can't spend
// that instance's limit.
func TestInstanceLimit_SeesTheVerifiedInstance(t *testing.T) {
	li := newLimitedInstance(t)
	other, otherKey := li.h.clientRegister(li.c, kindTEE)
	path := walletprovider.WalletAttestationPath
	body := li.body(path)
	asked := len(li.g.requests())

	resp, _ := li.send(path, body, li.signed(otherKey, li.id, path, body))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a request naming another instance: HTTP %d, want 401", resp.StatusCode)
	}
	if got := li.g.requests()[asked:]; len(got) != 0 {
		t.Fatalf("the limit was asked about a request that didn't verify: %+v", got)
	}

	if resp, data := li.send(path, body, li.signed(li.regKey, li.id, path, body)); resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d %s", resp.StatusCode, data)
	}
	got := li.g.requests()[asked:]
	want := walletprovider.InstanceRequest{InstanceID: li.id, Method: http.MethodPost, Path: path}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("the limit was asked about %+v, want only %+v", got, want)
	}
	if li.id == other {
		t.Fatal("two instances share an ID")
	}
}

// TestInstanceLimit_ClientAndVerifyRequest: a Client's refusal matches
// ErrRateLimited, as VerifyRequest's own error does, and refused there
// the request's challenge stays unused.
func TestInstanceLimit_ClientAndVerifyRequest(t *testing.T) {
	li := newLimitedInstance(t)
	li.g.set(true)
	ctx := context.Background()
	_, err := li.c.WalletAttestation(ctx, li.regKey, walletprovider.WalletAttestationRequest{InstanceID: li.id, ClientID: clientID, InstanceKey: &li.instanceKey.PublicKey})
	if refusedCode(t, err) != walletprovider.CodeRateLimited || !errors.Is(err, walletprovider.ErrRateLimited) {
		t.Fatalf("Client.WalletAttestation = %v, want a refusal matching ErrRateLimited", err)
	}

	req := li.h.signRequest(li.regKey, li.id, li.h.challenge(walletprovider.PurposeRequest))
	if _, err := li.h.p.VerifyRequest(ctx, req); !errors.Is(err, walletprovider.ErrRateLimited) {
		t.Fatalf("VerifyRequest = %v, want ErrRateLimited", err)
	}
	li.g.set(false)
	if _, err := li.h.p.VerifyRequest(ctx, req); err != nil {
		t.Fatalf("VerifyRequest once allowed = %v: the refused request used its challenge", err)
	}
}

// TestInstanceLimit_OtherErrorIsTheProviders: an error from the limit
// that isn't ErrRateLimited fails the request as the provider's own
// failure, without its text.
func TestInstanceLimit_OtherErrorIsTheProviders(t *testing.T) {
	h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) {
		c.InstanceLimit = func(context.Context, walletprovider.InstanceRequest) error { return errors.New("limiter backend down") }
	})
	ts, c := h.server("")
	id, regKey := h.clientRegister(c, kindTEE)
	const body = `{"client_id":"x"}`
	jwt, err := walletprovider.SignRequest(regKey, id, h.challenge(walletprovider.PurposeRequest), http.MethodPost, walletprovider.WalletAttestationPath, []byte(body), h.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	resp, data := rawPost(t, ts, walletprovider.WalletAttestationPath, body, map[string]string{walletprovider.RequestHeader: jwt})
	if resp.StatusCode != http.StatusInternalServerError || errorCode(t, data) != "server_error" || strings.Contains(string(data), "backend") {
		t.Fatalf("HTTP %d %s, want 500 server_error without the limit's text", resp.StatusCode, data)
	}
}
