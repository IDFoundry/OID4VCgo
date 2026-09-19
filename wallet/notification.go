package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
)

// maxNotificationResponseBytes bounds how much of a Notification
// Endpoint response body RequestNotification reads — the same
// reasoning maxTokenResponseBytes documents for
// RequestPreAuthorizedCodeToken (this call goes through the
// caller-supplied ProtectedResourceClient, not a transport this
// package can assume already bounds response size itself). A
// successful response has no body worth keeping at all (§11.2
// recommends 204 No Content) and an error response is a small JSON
// object (parseError's own wire shape), so this stays as tight as
// maxTokenResponseBytes rather than needing jwe.MaxCompactBytes'
// headroom the way a Credential Response does — notifications are
// never encrypted.
const maxNotificationResponseBytes = 1 << 16

// NotificationRequest is a Notification Request (§11.1) — its own wire
// shape, marshaled directly.
type NotificationRequest struct {
	// NotificationID is REQUIRED: a value previously returned as a
	// Credential Response's or Deferred Credential Response's own
	// notification_id.
	NotificationID string `json:"notification_id"`

	// Event is REQUIRED: one of the three oid4vci.NotificationEvent
	// values.
	Event oid4vci.NotificationEvent `json:"event"`

	// EventDescription is OPTIONAL human-readable text for the
	// Credential Issuer developer — its character set is restricted
	// per §11.1 (%x20-21 / %x23-5B / %x5D-7E); this package sends it
	// as-is and lets the Issuer reject a malformed value rather than
	// duplicating that check here.
	EventDescription string `json:"event_description,omitempty"`
}

// RequestNotification implements the Notification Endpoint's own
// client side (§11.1): it POSTs req to endpoint as a sender-
// constrained request via resource — a valid Access Token issued at
// the Token Endpoint (§11: "The Wallet MUST present to the
// Notification Endpoint a valid Access Token issued at the Token
// Endpoint"). A successful call means the Credential Issuer responded
// with an HTTP 2xx status (§11.2 recommends 204 No Content) — there is
// no response body to parse. A non-2xx response is returned as a
// *Error.
//
// This call is naturally repeatable: §11's own idempotency requirement
// ("When the Credential Issuer receives multiple identical calls from
// the Wallet for the same notification_id, it returns success") means
// sending the same request twice must both succeed, so there is
// nothing here to track as "already sent."
func (w *Wallet) RequestNotification(
	ctx context.Context, resource ProtectedResourceClient, endpoint fapi.URL, req NotificationRequest,
) error {
	if req.NotificationID == "" {
		return fmt.Errorf("wallet: request notification: notification_id is required")
	}
	switch req.Event {
	case oid4vci.NotificationEventCredentialAccepted, oid4vci.NotificationEventCredentialDeleted, oid4vci.NotificationEventCredentialFailure:
	default:
		return fmt.Errorf("wallet: request notification: event must be credential_accepted, credential_failure, or credential_deleted")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("wallet: request notification: marshal request: %w", err)
	}

	target := endpoint.URL()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("wallet: request notification: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := resource.Do(ctx, httpReq)
	if err != nil {
		return fmt.Errorf("wallet: request notification: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(res.Body, maxNotificationResponseBytes))
	if err != nil {
		return fmt.Errorf("wallet: request notification: read response: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return parseError(res.StatusCode, respBody)
	}
	return nil
}
