package issuer

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/idfoundry/oid4vcgo"
)

// notificationIDEntropyBytes sets how much randomness backs a
// notification_id. 256 bits, matching this package's own c_nonce and
// Deferred Issuance reference entropy choices.
const notificationIDEntropyBytes = 32

// unknownNotificationID is the one description an unknown, expired or
// another client's notification_id gets, so they can't be told apart.
const unknownNotificationID = "unknown notification_id"

// NotificationHandler reacts to a validated Notification Request's
// event — entirely this deployment's own business logic; this package
// has none of its own (§11: "These events enable the Credential Issuer
// to take subsequent actions after issuance"). Its return value is
// only ever surfaced as a plain (non-Error) error — a handler failure
// isn't itself evidence the Notification Request was malformed.
//
// It's called only for a notificationID this issuer issued, sent with
// an access token of the client and Subject it was issued to
// (NotificationRecord): RequestNotification checks that first. To
// know which holder and issuance the event is about, look the
// notificationID up in Dependencies.Notifications (whose
// NotificationRecord names the client and Subject) or in the
// deployment's own records of what it issued. The same request may
// arrive any number of times — §11 requires each repeat to succeed,
// so nothing limits them — and a later event may follow an earlier
// one for the same notificationID: act on an event idempotently, and
// don't count deliveries.
type NotificationHandler interface {
	HandleNotification(ctx context.Context, notificationID string, event oid4vci.NotificationEvent, description string) error
}

// NotificationRequest is a Notification Request (§11.1).
type NotificationRequest struct {
	// NotificationID is REQUIRED: a value previously returned as a
	// Credential Response's or Deferred Credential Response's own
	// notification_id.
	NotificationID string

	// Event is REQUIRED: one of the three NotificationEvent values.
	Event oid4vci.NotificationEvent

	// EventDescription is OPTIONAL human-readable text. Its character
	// set is restricted per §11.1 — see validateEventDescription.
	EventDescription string
}

// IssueNotificationID generates a fresh notification_id, persists a
// NotificationRecord binding it to auth's client via
// Dependencies.Notifications, and returns it. RequestCredential calls
// this once per issuance flow when Config.Endpoints.Notification is
// set; a caller resolving a Deferred Issuance transaction (see
// DeferredTransactionRecord's own doc comment) should call it too,
// before setting DeferredTransactionRecord.NotificationID — a value
// there that was never issued through this method fails validation at
// RequestNotification, since it was never persisted to
// Dependencies.Notifications.
func (iss *Issuer) IssueNotificationID(ctx context.Context, auth AuthorizedRequest) (string, error) {
	if iss.deps.Notifications == nil {
		return "", fmt.Errorf("issuer: issue notification id: notifications are not configured")
	}
	if err := requireClientIdentityDecision(auth); err != nil {
		return "", err
	}
	raw := make([]byte, notificationIDEntropyBytes)
	if _, err := io.ReadFull(iss.deps.Random, raw); err != nil {
		return "", fmt.Errorf("issuer: issue notification id: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(raw)
	record := NotificationRecord{ClientID: auth.ClientID(), Subject: auth.Subject}
	if lifetime := iss.cfg.Limits.NotificationLifetime; lifetime > 0 {
		record.ExpiresAt = iss.deps.Clock.Now().Add(lifetime)
	}
	if err := iss.deps.Notifications.Issue(ctx, id, record); err != nil {
		return "", fmt.Errorf("issuer: issue notification id: %w", err)
	}
	return id, nil
}

// RequestNotification implements the Notification Endpoint (§11): it
// validates req's shape, retrieves the NotificationRecord
// req.NotificationID identifies, checks it's bound to auth's client,
// and — if Dependencies.NotificationHandler is configured — hands the
// event off to it. A successful call always means "respond 2xx" (§11.2
// recommends 204 No Content); this method has no response body to
// return, unlike RequestCredential/RequestDeferredCredential.
//
// This is intentionally repeatable: §11's own idempotency requirement
// means calling this twice with the same req must both succeed, so
// there is nothing here for a caller to treat as "already notified" —
// NotificationHandler implementations are themselves responsible for
// idempotent handling of a repeated (notificationID, Event) pair, if
// that matters to their own side effects.
func (iss *Issuer) RequestNotification(ctx context.Context, auth AuthorizedRequest, req NotificationRequest) error {
	if iss.deps.Notifications == nil {
		return fmt.Errorf("issuer: request notification: notifications are not configured")
	}
	if err := requireClientIdentityDecision(auth); err != nil {
		return err
	}
	if req.NotificationID == "" {
		return newError(ErrorInvalidNotificationRequest, 400, "notification_id is required", nil)
	}
	switch req.Event {
	case oid4vci.NotificationEventCredentialAccepted, oid4vci.NotificationEventCredentialDeleted, oid4vci.NotificationEventCredentialFailure:
	default:
		return newError(ErrorInvalidNotificationRequest, 400,
			"event must be credential_accepted, credential_failure, or credential_deleted", nil)
	}
	if err := validateEventDescription(req.EventDescription); err != nil {
		return newError(ErrorInvalidNotificationRequest, 400, err.Error(), nil)
	}

	record, err := iss.deps.Notifications.Get(ctx, req.NotificationID)
	if errors.Is(err, ErrNotificationIDUnknown) {
		return newError(ErrorInvalidNotificationID, 400, unknownNotificationID, err)
	}
	if err != nil {
		return fmt.Errorf("issuer: request notification: dependencies.notifications: %w", err)
	}
	if !record.ExpiresAt.IsZero() && !iss.deps.Clock.Now().Before(record.ExpiresAt) {
		return newError(ErrorInvalidNotificationID, 400, unknownNotificationID, errors.New("notification_id has expired"))
	}
	// auth.ClientID() == "" here only ever means an explicit
	// NoClientIdentity (this method's own requireClientIdentityDecision
	// already rejected any other empty case before this ever runs) —
	// this check is deliberately skipped for that acknowledged
	// deployment choice, not by silent default.
	if record.ClientID != "" && auth.ClientID() != record.ClientID || record.Subject != "" && auth.Subject != record.Subject {
		// The same answer as an unknown one: which notification_ids
		// exist isn't this caller's business.
		return newError(ErrorInvalidNotificationID, 400, unknownNotificationID, nil)
	}

	if iss.deps.NotificationHandler == nil {
		return nil
	}
	if err := iss.deps.NotificationHandler.HandleNotification(ctx, req.NotificationID, req.Event, req.EventDescription); err != nil {
		return fmt.Errorf("issuer: request notification: handle notification: %w", err)
	}
	return nil
}

// validateEventDescription rejects any character outside §11.1's own
// allowed set for event_description: %x20-21 / %x23-5B / %x5D-7E —
// printable ASCII excluding '"' (0x22) and '\' (0x5C).
func validateEventDescription(s string) error {
	for _, r := range s {
		if r < 0x20 || r > 0x7E || r == 0x22 || r == 0x5C {
			return fmt.Errorf("event_description contains a character outside the allowed set (%%x20-21 / %%x23-5B / %%x5D-7E)")
		}
	}
	return nil
}
