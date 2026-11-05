package walletprovider_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletprovider"
)

const (
	requestPath = "/v1/wallet-attestation"
	requestBody = `{"client_id":"wallet-client"}`
)

func (h *harness) signRequest(key crypto.Signer, id, challenge string) walletprovider.Request {
	h.t.Helper()
	jwt, err := walletprovider.SignRequest(key, id, challenge, "POST", requestPath, []byte(requestBody), h.clock.now())
	if err != nil {
		h.t.Fatal(err)
	}
	return walletprovider.Request{JWT: jwt, Method: "POST", Path: requestPath, Body: []byte(requestBody)}
}

func TestVerifyRequest(t *testing.T) {
	h := newHarness(t, nil)
	in, key := h.register(kindStrongBox)
	ctx := context.Background()

	req := h.signRequest(key, in.ID, h.challenge(walletprovider.PurposeRequest))
	got, err := h.p.VerifyRequest(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != in.ID {
		t.Fatalf("VerifyRequest returned instance %q, want %q", got.ID, in.ID)
	}
	if _, err := h.p.VerifyRequest(ctx, req); !errors.Is(err, walletprovider.ErrChallenge) {
		t.Fatalf("a replayed request = %v, want ErrChallenge", err)
	}

	other, otherKey := h.register(kindStrongBox)
	cases := []struct {
		name string
		req  func() walletprovider.Request
		want error
	}{
		{"wrong key", func() walletprovider.Request {
			return h.signRequest(otherKey, in.ID, h.challenge(walletprovider.PurposeRequest))
		}, walletprovider.ErrInvalidRequest},
		{"wrong path", func() walletprovider.Request {
			r := h.signRequest(key, in.ID, h.challenge(walletprovider.PurposeRequest))
			r.Path = "/v1/key-attestation"
			return r
		}, walletprovider.ErrInvalidRequest},
		{"wrong method", func() walletprovider.Request {
			r := h.signRequest(key, in.ID, h.challenge(walletprovider.PurposeRequest))
			r.Method = "PUT"
			return r
		}, walletprovider.ErrInvalidRequest},
		{"wrong body", func() walletprovider.Request {
			r := h.signRequest(key, in.ID, h.challenge(walletprovider.PurposeRequest))
			r.Body = []byte(`{"client_id":"other"}`)
			return r
		}, walletprovider.ErrInvalidRequest},
		{"challenge for another purpose", func() walletprovider.Request {
			return h.signRequest(key, in.ID, h.challenge(walletprovider.PurposeHolder))
		}, walletprovider.ErrChallenge},
		{"unknown challenge", func() walletprovider.Request {
			return h.signRequest(key, in.ID, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		}, walletprovider.ErrChallenge},
		{"unknown instance", func() walletprovider.Request {
			return h.signRequest(key, "nope", h.challenge(walletprovider.PurposeRequest))
		}, walletprovider.ErrInstanceNotFound},
		{"not a JWT", func() walletprovider.Request {
			return walletprovider.Request{JWT: "x", Method: "POST", Path: requestPath}
		}, walletprovider.ErrInvalidRequest},
		{"stale", func() walletprovider.Request {
			ch := h.challenge(walletprovider.PurposeRequest)
			jwt, err := walletprovider.SignRequest(key, in.ID, ch, "POST", requestPath, []byte(requestBody), h.clock.now().Add(-time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			return walletprovider.Request{JWT: jwt, Method: "POST", Path: requestPath, Body: []byte(requestBody)}
		}, walletprovider.ErrInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := h.p.VerifyRequest(ctx, tc.req()); !errors.Is(err, tc.want) {
				t.Fatalf("VerifyRequest = %v, want %v", err, tc.want)
			}
		})
	}

	// A request whose signature fails doesn't use up its challenge.
	ch := h.challenge(walletprovider.PurposeRequest)
	if _, err := h.p.VerifyRequest(ctx, h.signRequest(otherKey, in.ID, ch)); !errors.Is(err, walletprovider.ErrInvalidRequest) {
		t.Fatalf("VerifyRequest = %v, want ErrInvalidRequest", err)
	}
	if _, err := h.p.VerifyRequest(ctx, h.signRequest(key, in.ID, ch)); err != nil {
		t.Fatalf("VerifyRequest with the challenge a forged request named: %v", err)
	}

	if err := h.p.Revoke(ctx, other.ID, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.VerifyRequest(ctx, h.signRequest(otherKey, other.ID, h.challenge(walletprovider.PurposeRequest))); !errors.Is(err, walletprovider.ErrInstanceRevoked) {
		t.Fatalf("VerifyRequest from a revoked instance = %v, want ErrInstanceRevoked", err)
	}
	// Only the instance key's holder learns the instance is revoked.
	forged := h.signRequest(key, other.ID, h.challenge(walletprovider.PurposeRequest))
	if _, err := h.p.VerifyRequest(ctx, forged); !errors.Is(err, walletprovider.ErrInvalidRequest) || errors.Is(err, walletprovider.ErrInstanceNotActive) {
		t.Fatalf("a forged request for a revoked instance = %v, want ErrInvalidRequest alone", err)
	}
}

func TestVerifyRequestEd25519(t *testing.T) {
	h := newHarness(t, nil)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ch := h.challenge(walletprovider.PurposeInstance)
	in, err := h.p.Register(context.Background(), walletprovider.RegisterRequest{
		Challenge: ch, InstanceKey: pub, Evidence: evidence(t, kindFake, ch, pub),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.VerifyRequest(context.Background(), h.signRequest(priv, in.ID, h.challenge(walletprovider.PurposeRequest))); err != nil {
		t.Fatal(err)
	}
	if _, err := h.walletAttestation(in.ID); err != nil {
		t.Fatal(err)
	}
}
