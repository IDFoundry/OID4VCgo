package walletprovider_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// TestVerifyRequestConsumesChallengeOfInactiveInstance: a signed
// request that verifies uses up its challenge though it's refused
// because its instance is suspended, so the same request replayed after
// Resume is refused too.
func TestVerifyRequestConsumesChallengeOfInactiveInstance(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	in, key := h.register(kindStrongBox)
	req := h.signRequest(key, in.ID, h.challenge(walletprovider.PurposeRequest))
	if err := h.p.Suspend(ctx, in.ID, "lost"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.VerifyRequest(ctx, req); !errors.Is(err, walletprovider.ErrInstanceNotActive) {
		t.Fatalf("a suspended instance's request = %v, want ErrInstanceNotActive", err)
	}
	if err := h.p.Resume(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.VerifyRequest(ctx, req); !errors.Is(err, walletprovider.ErrChallenge) {
		t.Fatalf("the request replayed after Resume = %v, want ErrChallenge", err)
	}
}

// TestHandlerSuspendedRequestNotReplayable: through Handler, a renewal
// refused while the instance is suspended is refused again, as a
// signed request that doesn't verify, when replayed after Resume.
func TestHandlerSuspendedRequestNotReplayable(t *testing.T) {
	h := newHarness(t, nil)
	ts, c := h.server("")
	ctx := context.Background()
	id, regKey := h.clientRegister(c, kindTEE)
	instanceKey, _ := h.clientWalletAttestation(c, id, regKey, kindTEE)

	ch, err := c.Challenge(ctx, walletprovider.PurposeRequest)
	if err != nil {
		t.Fatal(err)
	}
	ikJWK, err := jwk.Marshal(&instanceKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"client_id": clientID, "instance_key": ikJWK})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := walletprovider.SignRequest(regKey, id, ch.Value, http.MethodPost, walletprovider.WalletAttestationPath, body, h.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	send := func() int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+walletprovider.WalletAttestationPath, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(walletprovider.RequestHeader, signed)
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if err := h.p.Suspend(ctx, id, "operator"); err != nil {
		t.Fatal(err)
	}
	if got := send(); got != http.StatusForbidden {
		t.Fatalf("while suspended: HTTP %d, want 403", got)
	}
	if err := h.p.Resume(ctx, id); err != nil {
		t.Fatal(err)
	}
	if got := send(); got != http.StatusUnauthorized {
		t.Fatalf("replayed after Resume: HTTP %d, want 401", got)
	}
}
