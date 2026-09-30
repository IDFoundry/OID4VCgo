package oid4vci

// IssuedCredential is one element of a Credential Response's
// "credentials" array (§8.3).
type IssuedCredential struct {
	// Credential is the issued Credential, encoded per its format's own
	// Credential Format Profile (Appendix A): the compact SD-JWT VC
	// string for credential/sdjwtvc's own CredentialFormat, or the
	// base64url-encoded CBOR IssuerSigned structure for
	// credential/mdoc's own CredentialFormat.
	Credential string `json:"credential"`
}

// CredentialResponse is a Credential Response (§8.3): either the
// issued Credentials, or — when the Credential Issuer defers issuance —
// a TransactionID and Interval for the Wallet to poll the Deferred
// Credential Endpoint with (§9), sent as HTTP 202.
type CredentialResponse struct {
	Credentials []IssuedCredential `json:"credentials,omitempty"`

	// TransactionID identifies a deferred issuance, in place of
	// Credentials; Interval is the minimum number of seconds the
	// Wallet waits before polling for it (REQUIRED with TransactionID).
	TransactionID string `json:"transaction_id,omitempty"`
	Interval      int64  `json:"interval,omitempty"`

	// NotificationID is OPTIONAL: identifies this issuance flow for a
	// later Notification Request (§11.1). Absent unless the Credential
	// Issuer actually supports the Notification Endpoint.
	NotificationID string `json:"notification_id,omitempty"`
}
