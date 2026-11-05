package walletprovider_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// server serves h's provider over TLS, at prefix, and returns a Client
// for it.
func (h *harness) server(prefix string) (*httptest.Server, *walletprovider.Client) {
	h.t.Helper()
	handler := h.p.Handler()
	if prefix != "" {
		mux := http.NewServeMux()
		mux.Handle(prefix+"/", http.StripPrefix(prefix, handler))
		handler = mux
	}
	ts := httptest.NewTLSServer(handler)
	h.t.Cleanup(ts.Close)
	c, err := walletprovider.NewClient(ts.URL+prefix, walletprovider.ClientOptions{HTTP: ts.Client(), Clock: h.clock.now})
	if err != nil {
		h.t.Fatal(err)
	}
	return ts, c
}

// clientRegister registers an instance through c with evidence of kind.
func (h *harness) clientRegister(c *walletprovider.Client, kind string) (string, *ecdsa.PrivateKey) {
	h.t.Helper()
	ctx := context.Background()
	key := newKey(h.t)
	ch, err := c.Challenge(ctx, walletprovider.PurposeInstance)
	if err != nil {
		h.t.Fatal(err)
	}
	id, err := c.Register(ctx, walletprovider.RegisterRequest{
		Challenge: ch.Value, InstanceKey: &key.PublicKey, Evidence: evidence(h.t, kind, ch.Value, &key.PublicKey),
	})
	if err != nil {
		h.t.Fatalf("Register: %v", err)
	}
	return id, key
}

func refusedCode(t *testing.T, err error) string {
	t.Helper()
	var r *walletprovider.RefusedError
	if !errors.As(err, &r) || !errors.Is(err, walletprovider.ErrRefused) {
		t.Fatalf("err = %v, want a *RefusedError", err)
	}
	return r.Code
}

// TestHandlerRoundTrip: a wallet registers, gets a Wallet Attestation
// and a Key Attestation through the Client, and reads its status.
func TestHandlerRoundTrip(t *testing.T) {
	for _, prefix := range []string{"", "/provider"} {
		t.Run("prefix "+prefix, func(t *testing.T) {
			h := newHarness(t, nil)
			ts, c := h.server(prefix)
			ctx := context.Background()
			id, key := h.clientRegister(c, kindStrongBox)

			in, err := h.deps.Instances.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if in.Evidence.SecurityLevel != walletprovider.SecurityLevelStrongBox {
				t.Fatalf("registered %+v", in.Evidence)
			}

			jwt, err := c.WalletAttestation(ctx, key, walletprovider.WalletAttestationRequest{InstanceID: id, ClientID: clientID})
			if err != nil {
				t.Fatalf("WalletAttestation: %v", err)
			}
			if _, _, err := verifyES256(&h.signer.PublicKey, jwt); err != nil {
				t.Fatalf("the Wallet Attestation doesn't verify: %v", err)
			}

			holder := newKey(t)
			ch, err := c.Challenge(ctx, walletprovider.PurposeHolder)
			if err != nil {
				t.Fatal(err)
			}
			res, err := c.KeyAttestation(ctx, key, walletprovider.KeyAttestationRequest{
				InstanceID: id, Challenge: ch.Value, Nonce: "c-nonce",
				Keys:     []crypto.PublicKey{&holder.PublicKey},
				Evidence: []walletprovider.Evidence{evidence(t, kindStrongBox, ch.Value, &holder.PublicKey)},
			})
			if err != nil {
				t.Fatalf("KeyAttestation: %v", err)
			}
			h.verifyKeyAttestation(res, in, &holder.PublicKey)

			for _, accept := range []string{"application/statuslist+jwt", "application/statuslist+cwt"} {
				req, _ := http.NewRequest(http.MethodGet, ts.URL+prefix+walletprovider.StatusPath, nil)
				req.Header.Set("Accept", accept)
				resp, err := ts.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != accept {
					t.Fatalf("GET status with Accept %s: %d %s", accept, resp.StatusCode, resp.Header.Get("Content-Type"))
				}
			}

			stored, err := h.deps.Instances.Get(ctx, id)
			if err != nil || stored.WalletAttestations != 1 || stored.KeyAttestations != 1 {
				t.Fatalf("instance after the round trip: %+v, %v", stored, err)
			}
		})
	}
}

func verifyES256(pub crypto.PublicKey, jwt string) (map[string]any, []byte, error) {
	return jose.Verify(oid4vci.ES256, pub, jwt)
}

// rawPost posts body to the server's path with the headers given.
func rawPost(t *testing.T, ts *httptest.Server, path, body string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		t.Fatalf("error body %s: %v", body, err)
	}
	return e.Error
}

// TestHandlerRefusesMalformedRequests: bodies the protocol doesn't
// define are refused before the provider sees them.
func TestHandlerRefusesMalformedRequests(t *testing.T) {
	h := newHarness(t, nil)
	ts, _ := h.server("")
	cases := []struct {
		name, path, body string
		contentType      string
		status           int
	}{
		{"unknown member", walletprovider.ChallengePath, `{"purpose":"instance","extra":1}`, "", http.StatusBadRequest},
		{"member in another case", walletprovider.ChallengePath, `{"Purpose":"instance"}`, "", http.StatusBadRequest},
		{"duplicate member", walletprovider.ChallengePath, `{"purpose":"holder","purpose":"instance"}`, "", http.StatusBadRequest},
		{"data after the object", walletprovider.ChallengePath, `{"purpose":"instance"} {}`, "", http.StatusBadRequest},
		{"not JSON", walletprovider.ChallengePath, `purpose=instance`, "", http.StatusBadRequest},
		{"unknown purpose", walletprovider.ChallengePath, `{"purpose":"other"}`, "", http.StatusBadRequest},
		{"wrong content type", walletprovider.ChallengePath, `{"purpose":"instance"}`, "text/plain", http.StatusUnsupportedMediaType},
		{"oversized body", walletprovider.InstancesPath, `{"challenge":"` + strings.Repeat("a", walletprovider.MaxRequestBytes) + `"}`, "", http.StatusRequestEntityTooLarge},
		{"private instance key", walletprovider.InstancesPath,
			`{"challenge":"x","instance_key":{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"d"},"evidence":{"kind":"fake","data":"e30"}}`, "", http.StatusBadRequest},
		{"evidence not base64url", walletprovider.InstancesPath,
			`{"challenge":"x","instance_key":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},"evidence":{"kind":"fake","data":"e30="}}`, "", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.contentType != "" {
				headers["Content-Type"] = tc.contentType
			}
			resp, body := rawPost(t, ts, tc.path, tc.body, headers)
			if resp.StatusCode != tc.status || errorCode(t, body) != "invalid_request" {
				t.Fatalf("%d %s, want %d invalid_request", resp.StatusCode, body, tc.status)
			}
			if resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("headers %v", resp.Header)
			}
		})
	}
	t.Run("wrong method", func(t *testing.T) {
		resp, err := ts.Client().Get(ts.URL + walletprovider.ChallengePath)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s = %d", walletprovider.ChallengePath, resp.StatusCode)
		}
	})
}

// TestHandlerChallenges: a challenge is used once, for its purpose.
func TestHandlerChallenges(t *testing.T) {
	h := newHarness(t, nil)
	_, c := h.server("")
	ctx := context.Background()
	key := newKey(t)

	register := func(ch string) error {
		_, err := c.Register(ctx, walletprovider.RegisterRequest{
			Challenge: ch, InstanceKey: &key.PublicKey, Evidence: evidence(t, kindStrongBox, ch, &key.PublicKey),
		})
		return err
	}
	holder, err := c.Challenge(ctx, walletprovider.PurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	if code := refusedCode(t, register(holder.Value)); code != "invalid_challenge" {
		t.Fatalf("registering with a holder challenge: %s, want invalid_challenge", code)
	}
	ch, err := c.Challenge(ctx, walletprovider.PurposeInstance)
	if err != nil {
		t.Fatal(err)
	}
	if err := register(ch.Value); err != nil {
		t.Fatal(err)
	}
	if code := refusedCode(t, register(ch.Value)); code != "invalid_challenge" {
		t.Fatalf("registering with a used challenge: %s, want invalid_challenge", code)
	}

	// The same instance key registers once.
	ch, err = c.Challenge(ctx, walletprovider.PurposeInstance)
	if err != nil {
		t.Fatal(err)
	}
	err = register(ch.Value)
	var r *walletprovider.RefusedError
	if !errors.As(err, &r) || r.Code != "instance_key_registered" || r.Status != http.StatusConflict {
		t.Fatalf("registering the instance key again: %v, want 409 instance_key_registered", err)
	}
}

// TestHandlerRefusals: the provider's refusals reach the Client as the
// protocol's codes, with fixed descriptions.
func TestHandlerRefusals(t *testing.T) {
	h := newHarness(t, nil)
	_, c := h.server("")
	ctx := context.Background()

	key := newKey(t)
	ch, err := c.Challenge(ctx, walletprovider.PurposeInstance)
	if err != nil {
		t.Fatal(err)
	}
	other := newKey(t)
	_, err = c.Register(ctx, walletprovider.RegisterRequest{
		Challenge: ch.Value, InstanceKey: &key.PublicKey, Evidence: evidence(t, kindStrongBox, ch.Value, &other.PublicKey),
	})
	var r *walletprovider.RefusedError
	if !errors.As(err, &r) || r.Code != "evidence_rejected" || r.Status != http.StatusForbidden || r.Description != "The evidence didn't verify." {
		t.Fatalf("evidence for another key: %v, want 403 evidence_rejected with the fixed description", err)
	}

	ch, err = c.Challenge(ctx, walletprovider.PurposeInstance)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Register(ctx, walletprovider.RegisterRequest{
		Challenge: ch.Value, InstanceKey: &key.PublicKey, Evidence: evidence(t, kindOldApp, ch.Value, &key.PublicKey),
	})
	if code := refusedCode(t, err); code != "policy_refused" {
		t.Fatalf("an app below the minimum version: %s, want policy_refused", code)
	}

	_, err = c.Register(ctx, walletprovider.RegisterRequest{Challenge: ch.Value, InstanceKey: &key.PublicKey})
	if code := refusedCode(t, err); code != "evidence_required" {
		t.Fatalf("no evidence: %s, want evidence_required", code)
	}

	id, key := h.clientRegister(c, kindStrongBox)
	_, err = c.WalletAttestation(ctx, key, walletprovider.WalletAttestationRequest{InstanceID: id, ClientID: "other-client"})
	if code := refusedCode(t, err); code != "unknown_client" {
		t.Fatalf("another client: %s, want unknown_client", code)
	}

	holder := newKey(t)
	hch, err := c.Challenge(ctx, walletprovider.PurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.KeyAttestation(ctx, key, walletprovider.KeyAttestationRequest{
		InstanceID: id, Challenge: hch.Value, Nonce: "n", Keys: []crypto.PublicKey{&holder.PublicKey},
		Evidence: []walletprovider.Evidence{evidence(t, kindSoftware, hch.Value, &holder.PublicKey)},
	})
	if code := refusedCode(t, err); code != "no_key_attested" {
		t.Fatalf("a software holder key: %s, want no_key_attested", code)
	}

	if err := h.p.Suspend(ctx, id, "lost"); err != nil {
		t.Fatal(err)
	}
	_, err = c.WalletAttestation(ctx, key, walletprovider.WalletAttestationRequest{InstanceID: id, ClientID: clientID})
	if code := refusedCode(t, err); code != "instance_not_active" {
		t.Fatalf("a suspended instance: %s, want instance_not_active", code)
	}
	if err := h.p.Revoke(ctx, id, "stolen"); err != nil {
		t.Fatal(err)
	}
	_, err = c.WalletAttestation(ctx, key, walletprovider.WalletAttestationRequest{InstanceID: id, ClientID: clientID})
	if code := refusedCode(t, err); code != "instance_revoked" {
		t.Fatalf("a revoked instance: %s, want instance_revoked", code)
	}
	// Someone without the instance key learns nothing of its state.
	_, err = c.WalletAttestation(ctx, newKey(t), walletprovider.WalletAttestationRequest{InstanceID: id, ClientID: clientID})
	if code := refusedCode(t, err); code != "invalid_signed_request" {
		t.Fatalf("a forged request for a revoked instance: %s, want invalid_signed_request", code)
	}
	if got := h.status(statusRef(t, h, id), false); got != statuslist.StatusInvalid {
		t.Fatalf("status %v, want INVALID", got)
	}
}

func statusRef(t *testing.T, h *harness, id string) statuslist.StatusListRef {
	t.Helper()
	in, err := h.deps.Instances.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return in.Status
}

// TestHandlerUnauthorizedIsUniform: a signed request that doesn't
// verify gets one response, whatever the reason, and doesn't use up
// the challenge it names.
func TestHandlerUnauthorizedIsUniform(t *testing.T) {
	h := newHarness(t, nil)
	ts, c := h.server("")
	ctx := context.Background()
	id, key := h.clientRegister(c, kindStrongBox)
	body := `{"client_id":"` + clientID + `"}`

	challenge := func() string {
		ch, err := c.Challenge(ctx, walletprovider.PurposeRequest)
		if err != nil {
			t.Fatal(err)
		}
		return ch.Value
	}
	sign := func(k crypto.Signer, instanceID, ch, path, signedBody string) string {
		jwt, err := walletprovider.SignRequest(k, instanceID, ch, http.MethodPost, path, []byte(signedBody), h.clock.now())
		if err != nil {
			t.Fatal(err)
		}
		return jwt
	}
	post := func(jwt string) (*http.Response, []byte) {
		headers := map[string]string{}
		if jwt != "" {
			headers[walletprovider.RequestHeader] = jwt
		}
		return rawPost(t, ts, walletprovider.WalletAttestationPath, body, headers)
	}

	// The challenge every forged request below names, which the genuine
	// request then uses.
	shared := challenge()
	used := challenge()
	if resp, b := post(sign(key, id, used, walletprovider.WalletAttestationPath, body)); resp.StatusCode != http.StatusOK {
		t.Fatalf("a genuine request: %d %s", resp.StatusCode, b)
	}
	forged := map[string]string{
		"unknown instance":      sign(key, "no-such-instance", shared, walletprovider.WalletAttestationPath, body),
		"another key":           sign(newKey(t), id, shared, walletprovider.WalletAttestationPath, body),
		"another path":          sign(key, id, shared, walletprovider.KeyAttestationPath, body),
		"another body":          sign(key, id, shared, walletprovider.WalletAttestationPath, `{"client_id":"x"}`),
		"a used challenge":      sign(key, id, used, walletprovider.WalletAttestationPath, body),
		"not a JWT":             "not-a-jwt",
		"no signed request":     "",
		"an unknown challenge":  sign(key, id, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", walletprovider.WalletAttestationPath, body),
		"tampered signature":    sign(key, id, shared, walletprovider.WalletAttestationPath, body) + "A",
		"an unsigned algorithm": "eyJhbGciOiJub25lIiwidHlwIjoid2FsbGV0LXByb3ZpZGVyLXJlcXVlc3Qrand0In0.e30.",
	}
	var first []byte
	var firstHeader http.Header
	for name, jwt := range forged {
		resp, b := post(jwt)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: %d %s, want 401", name, resp.StatusCode, b)
		}
		if first == nil {
			first, firstHeader = b, resp.Header
			continue
		}
		if !bytes.Equal(b, first) {
			t.Fatalf("%s: body %s differs from %s", name, b, first)
		}
		for _, hdr := range []string{"Content-Type", "Cache-Control", "WWW-Authenticate", "Content-Length"} {
			if resp.Header.Get(hdr) != firstHeader.Get(hdr) {
				t.Fatalf("%s: %s %q differs from %q", name, hdr, resp.Header.Get(hdr), firstHeader.Get(hdr))
			}
		}
	}
	if errorCode(t, first) != "invalid_signed_request" {
		t.Fatalf("401 body %s", first)
	}

	// None of the forged requests used up the challenge they named.
	if resp, b := post(sign(key, id, shared, walletprovider.WalletAttestationPath, body)); resp.StatusCode != http.StatusOK {
		t.Fatalf("a genuine request with the challenge forged ones named: %d %s", resp.StatusCode, b)
	}
	// A genuine request is accepted once.
	replay := sign(key, id, challenge(), walletprovider.WalletAttestationPath, body)
	if resp, _ := post(replay); resp.StatusCode != http.StatusOK {
		t.Fatalf("first use: %d", resp.StatusCode)
	}
	if resp, _ := post(replay); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a replayed request: %d, want 401", resp.StatusCode)
	}

	// A signed request with an unknown member is refused after it
	// verified.
	jwt := sign(key, id, challenge(), walletprovider.WalletAttestationPath, `{"client_id":"`+clientID+`","x":1}`)
	resp, b := rawPost(t, ts, walletprovider.WalletAttestationPath, `{"client_id":"`+clientID+`","x":1}`, map[string]string{walletprovider.RequestHeader: jwt})
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, b) != "invalid_request" {
		t.Fatalf("a signed request with an unknown member: %d %s", resp.StatusCode, b)
	}
}

func TestNewClientRefuses(t *testing.T) {
	for _, u := range []string{"http://provider.example", "https://", "https://u:p@provider.example", "https://provider.example?x=1", "provider.example"} {
		if _, err := walletprovider.NewClient(u, walletprovider.ClientOptions{}); err == nil {
			t.Errorf("NewClient(%q) succeeded", u)
		}
	}
}

// TestClientChecksAnswers: the Client refuses an answer that isn't for
// what it asked.
func TestClientChecksAnswers(t *testing.T) {
	h := newHarness(t, nil)
	_, c := h.server("")
	ctx := context.Background()
	id, key := h.clientRegister(c, kindStrongBox)

	// A provider answering another client's Wallet Attestation.
	var answer string
	fake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == walletprovider.ChallengePath {
			_, _ = io.WriteString(w, `{"challenge":"c","purpose":"request","expires_at":1}`)
			return
		}
		_, _ = io.WriteString(w, `{"wallet_attestation":"`+answer+`"}`)
	}))
	defer fake.Close()
	jwt, err := c.WalletAttestation(ctx, key, walletprovider.WalletAttestationRequest{InstanceID: id, ClientID: clientID})
	if err != nil {
		t.Fatal(err)
	}
	answer = jwt
	fc, err := walletprovider.NewClient(fake.URL, walletprovider.ClientOptions{HTTP: fake.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fc.WalletAttestation(ctx, newKey(t), walletprovider.WalletAttestationRequest{InstanceID: id, ClientID: clientID}); err == nil {
		t.Fatal("a Wallet Attestation for another instance key was accepted")
	}
	if _, err := fc.WalletAttestation(ctx, key, walletprovider.WalletAttestationRequest{InstanceID: id, ClientID: "other"}); err == nil {
		t.Fatal("a Wallet Attestation for another client was accepted")
	}
}
