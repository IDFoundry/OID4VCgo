package wallet

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/oid4vcigo"
)

// CredentialResult is returned by a successful RequestCredential or
// RequestDeferredCredential — both endpoints share one wire shape for
// their own response (§9.2's own MUST: "the Deferred Credential
// Response MUST use the credentials parameter as defined in Section
// 8.3 ... MUST use the interval and transaction_id parameters as
// defined in Section 8.3"), so one result type serves both. Exactly
// one of the two cases below applies to any given result:
//
//   - Completed (HTTP 200): Credentials is non-empty, and
//     NotificationID is set if the Issuer supports the Notification
//     Endpoint. TransactionID and Interval are both zero.
//   - Still pending (HTTP 202): TransactionID and Interval are both
//     set — pass TransactionID to RequestDeferredCredential again once
//     Interval has elapsed. Credentials and NotificationID are both
//     zero.
type CredentialResult struct {
	Credentials    []oid4vci.IssuedCredential
	NotificationID string
	TransactionID  string
	Interval       time.Duration
}

// credentialResponseBody is the wire shape §8.3 defines for a
// Credential Response, reused by §9.2's own Deferred Credential
// Response per its own text (see CredentialResult's own doc comment)
// — covers both the completed and still-pending cases in one struct,
// since a caller must inspect the HTTP status to know which one
// actually applies; interval arrives as a plain JSON number of
// seconds, not RFC 3339 duration text.
type credentialResponseBody struct {
	Credentials    []oid4vci.IssuedCredential `json:"credentials"`
	NotificationID string                     `json:"notification_id,omitempty"`
	TransactionID  string                     `json:"transaction_id,omitempty"`
	Interval       int64                      `json:"interval,omitempty"`
}

// parseCredentialResult decodes a Credential Response or Deferred
// Credential Response body: HTTP 200 or 202 decode as
// credentialResponseBody; anything else is a *Error built from
// statusCode/body via parseError.
func parseCredentialResult(statusCode int, body []byte) (CredentialResult, error) {
	switch statusCode {
	case http.StatusOK, http.StatusAccepted:
		var wire credentialResponseBody
		if err := json.Unmarshal(body, &wire); err != nil {
			return CredentialResult{}, fmt.Errorf("decode response: %w", err)
		}
		return CredentialResult{
			Credentials:    wire.Credentials,
			NotificationID: wire.NotificationID,
			TransactionID:  wire.TransactionID,
			Interval:       time.Duration(wire.Interval) * time.Second,
		}, nil
	default:
		return CredentialResult{}, parseError(statusCode, body)
	}
}
