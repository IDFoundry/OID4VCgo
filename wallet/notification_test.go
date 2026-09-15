package wallet_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/wallet"
)

func testNotificationEndpointForWallet(t *testing.T) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL("http://localhost/notification", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return u
}

func TestRequestNotification_Succeeds(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			res := jsonResponse(nil)
			res.StatusCode = http.StatusNoContent
			return res, nil
		},
	}

	err = w.RequestNotification(context.Background(), resource, testNotificationEndpointForWallet(t), wallet.NotificationRequest{
		NotificationID:   "notif-1",
		Event:            oid4vci.NotificationEventCredentialAccepted,
		EventDescription: "stored ok",
	})
	if err != nil {
		t.Fatalf("RequestNotification: %v", err)
	}

	var sentBody struct {
		NotificationID   string `json:"notification_id"`
		Event            string `json:"event"`
		EventDescription string `json:"event_description"`
	}
	if err := json.Unmarshal(resource.lastBody, &sentBody); err != nil {
		t.Fatalf("unmarshal sent body: %v", err)
	}
	if sentBody.NotificationID != "notif-1" {
		t.Errorf("notification_id = %q", sentBody.NotificationID)
	}
	if sentBody.Event != "credential_accepted" {
		t.Errorf("event = %q, want credential_accepted", sentBody.Event)
	}
	if sentBody.EventDescription != "stored ok" {
		t.Errorf("event_description = %q", sentBody.EventDescription)
	}
}

func TestRequestNotification_RejectsMissingNotificationID(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{do: func(context.Context, *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	}}
	err = w.RequestNotification(context.Background(), resource, testNotificationEndpointForWallet(t), wallet.NotificationRequest{
		Event: oid4vci.NotificationEventCredentialAccepted,
	})
	if err == nil {
		t.Fatalf("RequestNotification = nil error, want error")
	}
}

func TestRequestNotification_RejectsInvalidEvent(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{do: func(context.Context, *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	}}
	err = w.RequestNotification(context.Background(), resource, testNotificationEndpointForWallet(t), wallet.NotificationRequest{
		NotificationID: "notif-1",
		Event:          "bogus",
	})
	if err == nil {
		t.Fatalf("RequestNotification = nil error, want error")
	}
}

func TestRequestNotification_ParsesErrorResponse(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			res := jsonResponse([]byte(`{"error":"invalid_notification_id"}`))
			res.StatusCode = http.StatusBadRequest
			return res, nil
		},
	}
	err = w.RequestNotification(context.Background(), resource, testNotificationEndpointForWallet(t), wallet.NotificationRequest{
		NotificationID: "notif-unknown",
		Event:          oid4vci.NotificationEventCredentialFailure,
	})
	var werr *wallet.Error
	if !errors.As(err, &werr) {
		t.Fatalf("error = %v, want *wallet.Error", err)
	}
	if werr.Code != "invalid_notification_id" {
		t.Errorf("Code = %q, want invalid_notification_id", werr.Code)
	}
}

func TestRequestNotification_PropagatesTransportError(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("simulated network failure")
		},
	}
	err = w.RequestNotification(context.Background(), resource, testNotificationEndpointForWallet(t), wallet.NotificationRequest{
		NotificationID: "notif-1",
		Event:          oid4vci.NotificationEventCredentialDeleted,
	})
	if err == nil {
		t.Fatalf("RequestNotification = nil error, want error")
	}
}
