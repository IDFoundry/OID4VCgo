package issuer

import (
	"context"
	"errors"
	"time"
)

// ErrNotificationIDUnknown is what a NotificationStore's Get returns,
// or wraps, for a notification_id it holds no record of: one never
// issued, or one dropped after its ExpiresAt. RequestNotification
// answers it invalid_notification_id. Any other Get error means the
// store couldn't answer (its backend unreachable, a timeout,
// context.Canceled or context.DeadlineExceeded), and fails the request
// as a plain error, a 500 from WriteError.
var ErrNotificationIDUnknown = errors.New("issuer: unknown notification_id")

// NotificationRecord is what NotificationStore.Get returns for one
// notification_id — see IssueNotificationID's own doc comment for how
// one comes to exist.
type NotificationRecord struct {
	// Owner is the Credential Issuer that issued the notification_id,
	// its Config.Issuer: only that Issuer accepts it, so Credential
	// Issuers sharing a store each receive only their own
	// notifications. IssueNotificationID sets it. One with none is
	// accepted only under AssuranceDevelopment.
	Owner string

	// ClientID binds this notification_id to the client the
	// Credential(s) it identifies were issued to.
	// When set, RequestNotification rejects a request whose
	// AuthorizedRequest.ClientIdentity isn't that client — including an
	// anonymous one.
	ClientID string
	// Subject binds it to the access token's subject too, when set: a
	// HAIP client_id names a whole wallet solution, shared by every
	// installation, so the client alone doesn't say whose credential
	// it is.
	Subject string

	// ExpiresAt is when this notification_id stops being accepted:
	// IssueNotificationID sets it from Limits.NotificationLifetime, and
	// leaves it zero, never expiring, when that's zero. RequestNotification
	// answers an expired one as unknown, so a store may drop a record
	// past its ExpiresAt; the store never judges expiry itself.
	ExpiresAt time.Time
}

// NotificationStore persists notification_id values this issuer has
// handed out, keyed by the notification_id itself. Unlike NonceStore,
// there is no Consume: §11's own idempotency requirement ("When the
// Credential Issuer receives multiple identical calls from the Wallet
// for the same notification_id, it returns success") means a
// notification_id must keep validating after use, not be retired by
// the first Notification Request that presents it.
type NotificationStore interface {
	// Issue persists a freshly generated notification_id — see
	// IssueNotificationID.
	Issue(ctx context.Context, notificationID string, record NotificationRecord) error

	// Get retrieves the record identified by notificationID. It
	// returns an error wrapping ErrNotificationIDUnknown if
	// notificationID is unknown, and any other error only when it
	// couldn't answer.
	Get(ctx context.Context, notificationID string) (NotificationRecord, error)
}
