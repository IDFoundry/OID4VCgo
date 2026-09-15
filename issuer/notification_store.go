package issuer

import "context"

// NotificationRecord is what NotificationStore.Get returns for one
// notification_id — see IssueNotificationID's own doc comment for how
// one comes to exist.
type NotificationRecord struct {
	// ClientID binds this notification_id to the client the
	// Credential(s) it identifies were issued to.
	// RequestNotification rejects a request whose
	// AuthorizedRequest.ClientID doesn't match, when both are
	// non-empty.
	ClientID string
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
	// returns an error if notificationID is unknown.
	Get(ctx context.Context, notificationID string) (NotificationRecord, error)
}
