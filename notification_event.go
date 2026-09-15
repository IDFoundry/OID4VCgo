package oid4vci

// NotificationEvent is a Notification Request's own "event" parameter
// (§11.1) — the closed set of outcomes a Wallet reports for a
// previously issued Credential (or batch thereof).
type NotificationEvent string

const (
	// NotificationEventCredentialAccepted means the Credential(s) were
	// successfully stored in the Wallet, with or without user action.
	NotificationEventCredentialAccepted NotificationEvent = "credential_accepted" //nolint:gosec // an OID4VCI event name, not a credential

	// NotificationEventCredentialDeleted means the unsuccessful
	// Credential issuance was caused by a user action.
	NotificationEventCredentialDeleted NotificationEvent = "credential_deleted" //nolint:gosec // an OID4VCI event name, not a credential

	// NotificationEventCredentialFailure covers every other
	// unsuccessful case.
	NotificationEventCredentialFailure NotificationEvent = "credential_failure" //nolint:gosec // an OID4VCI event name, not a credential
)
