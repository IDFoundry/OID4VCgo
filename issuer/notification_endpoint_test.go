package issuer_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/issuer"
)

func TestIssueNotificationID(t *testing.T) {
	store := newFakeNotificationStore()
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Notifications = store
	iss := newTestIssuer(t, cfg, deps)

	id, err := iss.IssueNotificationID(context.Background(), issuer.AuthorizedRequest{ClientID: "client-a"})
	if err != nil {
		t.Fatalf("IssueNotificationID: %v", err)
	}
	if id == "" {
		t.Fatalf("notification id is empty")
	}

	record, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if record.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", record.ClientID, "client-a")
	}
}

func TestIssueNotificationID_RejectsWhenNotConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.Notification = fapi.URL{}
	deps := validDependencies(t)
	deps.Notifications = nil
	iss := newTestIssuer(t, cfg, deps)

	if _, err := iss.IssueNotificationID(context.Background(), issuer.AuthorizedRequest{}); err == nil {
		t.Fatalf("IssueNotificationID = nil error, want error")
	}
}

func TestRequestCredential_LeavesNotificationIDEmptyWhenNotConfigured(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)

	result, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, proof)
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if result.NotificationID != "" {
		t.Errorf("NotificationID = %q, want empty (notifications not configured in this fixture)", result.NotificationID)
	}
}

func TestRequestCredential_SetsNotificationIDWhenConfigured(t *testing.T) {
	store := newFakeNotificationStore()
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Notifications = store
	iss := newTestIssuer(t, cfg, deps)

	nonceResult, err := iss.RequestNonce(context.Background())
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonceResult.CNonce)

	result, err := iss.RequestCredential(context.Background(),
		issuer.AuthorizedRequest{ClientID: "client-a", Scopes: []string{"identity_credential"}},
		issuer.CredentialRequest{
			CredentialConfigurationID: "IdentityCredential",
			Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
			SDJWTClaims:               testSDJWTClaims(),
		},
	)
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if result.NotificationID == "" {
		t.Fatalf("NotificationID is empty, want a fresh value")
	}
	record, err := store.Get(context.Background(), result.NotificationID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if record.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", record.ClientID, "client-a")
	}
}

func TestRequestNotification_Succeeds(t *testing.T) {
	store := newFakeNotificationStore()
	handler := &fakeNotificationHandler{}
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Notifications = store
	deps.NotificationHandler = handler
	iss := newTestIssuer(t, cfg, deps)

	store.put("notif-1", issuer.NotificationRecord{ClientID: "client-a"})

	err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{ClientID: "client-a"}, issuer.NotificationRequest{
		NotificationID:   "notif-1",
		Event:            issuer.NotificationEventCredentialAccepted,
		EventDescription: "stored ok",
	})
	if err != nil {
		t.Fatalf("RequestNotification: %v", err)
	}
	if len(handler.calls) != 1 {
		t.Fatalf("handler calls = %d, want 1", len(handler.calls))
	}
	call := handler.calls[0]
	if call.NotificationID != "notif-1" || call.Event != issuer.NotificationEventCredentialAccepted || call.Description != "stored ok" {
		t.Errorf("call = %+v", call)
	}
}

func TestRequestNotification_SucceedsWithoutHandler(t *testing.T) {
	store := newFakeNotificationStore()
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Notifications = store
	iss := newTestIssuer(t, cfg, deps)

	store.put("notif-1", issuer.NotificationRecord{})

	err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{}, issuer.NotificationRequest{
		NotificationID: "notif-1",
		Event:          issuer.NotificationEventCredentialAccepted,
	})
	if err != nil {
		t.Fatalf("RequestNotification: %v", err)
	}
}

func TestRequestNotification_IsIdempotent(t *testing.T) {
	store := newFakeNotificationStore()
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Notifications = store
	iss := newTestIssuer(t, cfg, deps)

	store.put("notif-1", issuer.NotificationRecord{})

	req := issuer.NotificationRequest{NotificationID: "notif-1", Event: issuer.NotificationEventCredentialAccepted}
	for i := 0; i < 3; i++ {
		if err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{}, req); err != nil {
			t.Fatalf("RequestNotification (call %d): %v", i, err)
		}
	}
}

func TestRequestNotification_RejectsInvalidRequest(t *testing.T) {
	store := newFakeNotificationStore()
	store.put("notif-1", issuer.NotificationRecord{})
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Notifications = store
	iss := newTestIssuer(t, cfg, deps)

	cases := map[string]issuer.NotificationRequest{
		"missing notification_id": {Event: issuer.NotificationEventCredentialAccepted},
		"missing event":           {NotificationID: "notif-1"},
		"invalid event":           {NotificationID: "notif-1", Event: "bogus"},
		"event_description with quote": {
			NotificationID: "notif-1", Event: issuer.NotificationEventCredentialAccepted, EventDescription: `bad "quote"`,
		},
		"event_description with backslash": {
			NotificationID: "notif-1", Event: issuer.NotificationEventCredentialAccepted, EventDescription: `bad\path`,
		},
		"event_description with control character": {
			NotificationID: "notif-1", Event: issuer.NotificationEventCredentialAccepted, EventDescription: "bad\ndescription",
		},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{}, req)
			assertIssuerError(t, err, issuer.ErrorInvalidNotificationRequest)
		})
	}
}

func TestRequestNotification_RejectsUnknownNotificationID(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{}, issuer.NotificationRequest{
		NotificationID: "no-such-id",
		Event:          issuer.NotificationEventCredentialAccepted,
	})
	assertIssuerError(t, err, issuer.ErrorInvalidNotificationID)
}

func TestRequestNotification_RejectsMismatchedClient(t *testing.T) {
	store := newFakeNotificationStore()
	store.put("notif-1", issuer.NotificationRecord{ClientID: "client-a"})
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Notifications = store
	iss := newTestIssuer(t, cfg, deps)

	err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{ClientID: "client-b"}, issuer.NotificationRequest{
		NotificationID: "notif-1",
		Event:          issuer.NotificationEventCredentialAccepted,
	})
	assertIssuerError(t, err, issuer.ErrorInvalidNotificationID)
}

func TestRequestNotification_RejectsWhenNotConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.Notification = fapi.URL{}
	deps := validDependencies(t)
	deps.Notifications = nil
	iss := newTestIssuer(t, cfg, deps)

	err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{}, issuer.NotificationRequest{
		NotificationID: "anything",
		Event:          issuer.NotificationEventCredentialAccepted,
	})
	if err == nil {
		t.Fatalf("RequestNotification = nil error, want error")
	}
}

func TestRequestNotification_PropagatesHandlerError(t *testing.T) {
	store := newFakeNotificationStore()
	store.put("notif-1", issuer.NotificationRecord{})
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Notifications = store
	deps.NotificationHandler = &fakeNotificationHandler{err: errHandlerFailed}
	iss := newTestIssuer(t, cfg, deps)

	err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{}, issuer.NotificationRequest{
		NotificationID: "notif-1",
		Event:          issuer.NotificationEventCredentialFailure,
	})
	if err == nil {
		t.Fatalf("RequestNotification = nil error, want error")
	}
	var ierr *issuer.Error
	if errors.As(err, &ierr) {
		t.Fatalf("RequestNotification returned an *issuer.Error (%v), want a plain error for a handler failure", ierr)
	}
	if !strings.Contains(err.Error(), "simulated handler failure") {
		t.Errorf("Error() = %q, want it to mention the handler failure", err.Error())
	}
}

const errHandlerFailed = fakeErr("simulated handler failure")
