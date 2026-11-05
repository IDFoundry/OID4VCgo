package walletprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/statuslist"
	wp "github.com/idfoundry/oid4vcgo/walletprovider"
)

// libraryFixture is a service over TLS, with the service itself at
// hand.
type libraryFixture struct {
	p   *Provider
	s   *service
	srv *httptest.Server
	c   Client
}

func newLibraryFixture(t *testing.T) *libraryFixture {
	t.Helper()
	p, err := New(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.newService(ServiceConfig{ClientID: "wallet-1", Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(s.handler())
	t.Cleanup(srv.Close)
	return &libraryFixture{p: p, s: s, srv: srv, c: Client{URL: srv.URL, HTTP: srv.Client()}}
}

// TestService_KeyAttestationFromLibrary: a Key Attestation carries the
// provider's certificate (not the CA) as x5c, verifies with its key,
// attests the keys sent, claims no key_storage for the demo's keys, and
// names the provider's status list.
func TestService_KeyAttestationFromLibrary(t *testing.T) {
	f := newLibraryFixture(t)
	holder := p256(t)
	compact, err := f.c.KeyAttestation(context.Background(), registered(t, f.c), []*ecdsa.PublicKey{&holder.PublicKey}, "c-nonce")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := attestation.Parse(compact)
	if err != nil {
		t.Fatal(err)
	}
	if x5c := parsed.X5C(); len(x5c) != 1 || x5c[0] != base64.StdEncoding.EncodeToString(f.p.Certificate.Raw) {
		t.Fatalf("x5c = %v, want just the provider's certificate", x5c)
	}
	v, err := parsed.Verify(f.p.Certificate.PublicKey, oid4vci.ES256, attestation.VerifyOptions{Now: time.Now(), ExpectedNonce: "c-nonce", RequireExpiry: true})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := v.KeyAttested(&holder.PublicKey); err != nil || !ok {
		t.Fatalf("KeyAttested = %v, %v", ok, err)
	}
	if v.KeyStorage != nil || v.UserAuthentication != nil {
		t.Error("the demo claims an attack-potential level for its keys")
	}
	ref, err := statuslist.ParseStatusClaim(v.Status)
	if err != nil || !strings.HasPrefix(ref.URI, DefaultURL+wp.StatusPath+"/") {
		t.Fatalf("status = %v (%v)", v.Status, err)
	}
}

// TestService_InstancesFromLibrary: a Wallet Attestation carries x5c,
// wallet_name and its instance key's status; an instance key is
// recorded for one instance, whose revocation stops it and sets its
// status INVALID.
func TestService_InstancesFromLibrary(t *testing.T) {
	f := newLibraryFixture(t)
	ctx := context.Background()
	instance := p256(t)
	wa, err := f.c.WalletAttestation(ctx, "wallet-1", &instance.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := strings.Cut(wa, ".")
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(raw, &h); err != nil || len(h.X5C) != 1 || h.X5C[0] != base64.StdEncoding.EncodeToString(f.p.Certificate.Raw) {
		t.Fatalf("x5c = %v (%v), want just the provider's certificate", h.X5C, err)
	}
	claims := jwtClaims(t, wa)
	if claims["wallet_name"] != WalletName || claims["status"] == nil {
		t.Fatalf("claims = %v", claims)
	}
	again, err := f.c.WalletAttestation(ctx, "wallet-1", &instance.PublicKey)
	if err != nil {
		t.Fatalf("a second Wallet Attestation for the instance key: %v", err)
	}
	if n := countInstances(t, f.s); n != 1 {
		t.Fatalf("%d instances registered for one instance key", n)
	}
	ik, err := f.s.store.keys().Get(ctx, thumbprintOf(t, &instance.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := statuslist.ParseStatusClaim(jwtClaims(t, again)["status"].(map[string]any))
	if err != nil || ref != ik.Status {
		t.Fatalf("status %+v (%v), want the instance key's %+v", ref, err, ik.Status)
	}
	if err := f.s.lib.Revoke(ctx, ik.InstanceID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.WalletAttestation(ctx, "wallet-1", &instance.PublicKey); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a revoked instance: %v, want refused as revoked", err)
	}

	list := strings.TrimPrefix(ik.Status.URI, DefaultURL)
	resp, err := f.srv.Client().Get(f.srv.URL + list)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/statuslist+jwt" {
		t.Fatalf("GET %s: %d %s", list, resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

func thumbprintOf(t *testing.T, key *ecdsa.PublicKey) string {
	t.Helper()
	_, tp, err := parseP256Key(jwkOf(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

// TestService_V1RefusesDemoEvidence: the demo-only evidence kind can't
// be presented over the library's own protocol: only the service mints
// its tokens.
func TestService_V1RefusesDemoEvidence(t *testing.T) {
	f := newLibraryFixture(t)
	ctx := context.Background()
	wc, err := wp.NewClient(f.srv.URL, wp.ClientOptions{HTTP: f.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := wc.Challenge(ctx, wp.PurposeRegistration)
	if err != nil {
		t.Fatal(err)
	}
	key := p256(t)
	_, err = wc.Register(ctx, wp.RegisterRequest{
		Challenge: ch.Value, RegistrationKey: &key.PublicKey,
		Evidence: wp.Evidence{Kind: DemoEvidenceKind, Data: []byte("0123456789abcdef0123456789abcdef")},
	})
	if code := refusal(t, err); code != "evidence_rejected" {
		t.Fatalf("demo evidence over /v1: %s, want evidence_rejected", code)
	}
}

func refusal(t *testing.T, err error) string {
	t.Helper()
	r, ok := err.(*wp.RefusedError)
	if !ok {
		t.Fatalf("err = %v, want a *RefusedError", err)
	}
	return r.Code
}

// TestDemoVerifier: a token vouches once, for its challenge, and only
// for the keys it names.
func TestDemoVerifier(t *testing.T) {
	d := newDemoVerifier()
	ctx := context.Background()
	a, b := p256(t), p256(t)
	challenge := []byte("challenge")
	ev, err := d.vouch(challenge, demoKey{key: &a.PublicKey, level: wp.SecurityLevelTEE})
	if err != nil {
		t.Fatal(err)
	}
	in := wp.EvidenceInput{Evidence: ev, Challenge: []byte("another"), Keys: []crypto.PublicKey{&a.PublicKey}}
	if _, err := d.Verify(ctx, in); err == nil {
		t.Fatal("a token for another challenge was accepted")
	}
	ev, err = d.vouch(challenge, demoKey{key: &a.PublicKey, level: wp.SecurityLevelTEE})
	if err != nil {
		t.Fatal(err)
	}
	in = wp.EvidenceInput{Evidence: ev, Challenge: challenge, Keys: []crypto.PublicKey{&b.PublicKey, &a.PublicKey}}
	out, err := d.Verify(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if out.Platform != DemoPlatform || len(out.Keys) != 1 || !a.PublicKey.Equal(out.Keys[0].Key) || out.Keys[0].SecurityLevel != wp.SecurityLevelTEE {
		t.Fatalf("verified %+v", out)
	}
	if _, err := d.Verify(ctx, in); err == nil {
		t.Fatal("a token was accepted twice")
	}
	ev, err = d.vouch(challenge)
	if err != nil {
		t.Fatal(err)
	}
	d.forget(ev)
	if _, err := d.Verify(ctx, wp.EvidenceInput{Evidence: ev, Challenge: challenge}); err == nil {
		t.Fatal("a forgotten token was accepted")
	}
}
