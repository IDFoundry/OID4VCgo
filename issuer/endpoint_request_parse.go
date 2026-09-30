package issuer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
)

// MaxNotificationRequestBytes caps the Notification Request body
// ParseNotificationRequest accepts: an identifier, an event and a short
// description.
const MaxNotificationRequestBytes = 16 << 10

type wireDeferredCredentialRequest struct {
	TransactionID                string                  `json:"transaction_id"`
	CredentialResponseEncryption *wireResponseEncryption `json:"credential_response_encryption"`
}

// ParseDeferredCredentialRequest turns a Deferred Credential Endpoint
// request body into the DeferredCredentialRequest
// RequestDeferredCredential takes — ParseCredentialRequest's
// counterpart for §9.1. It decrypts the body first when it arrived as a
// JWE (§10, as contentType says), reads transaction_id and
// credential_response_encryption, and sets RequestWasEncrypted. The
// body may be at most MaxCredentialRequestBytes. Errors are *Error,
// ready for WriteError.
func (iss *Issuer) ParseDeferredCredentialRequest(body []byte, contentType string) (DeferredCredentialRequest, error) {
	if len(body) > MaxCredentialRequestBytes {
		return DeferredCredentialRequest{}, newError(ErrorInvalidCredentialRequest, http.StatusBadRequest,
			fmt.Sprintf("deferred credential request exceeds %d bytes", MaxCredentialRequestBytes), nil)
	}
	plaintext, wasEncrypted, err := iss.DecryptRequestBody(body, contentType)
	if err != nil {
		return DeferredCredentialRequest{}, err
	}
	var wire wireDeferredCredentialRequest
	if err := decodeJSONObject(plaintext, &wire); err != nil {
		return DeferredCredentialRequest{}, newError(ErrorInvalidCredentialRequest, http.StatusBadRequest, "deferred credential request is not a JSON object", err)
	}
	req := DeferredCredentialRequest{TransactionID: wire.TransactionID, RequestWasEncrypted: wasEncrypted}
	if e := wire.CredentialResponseEncryption; e != nil {
		req.ResponseEncryption = &ResponseEncryptionRequest{JWK: e.JWK, Enc: jwe.Enc(e.Enc), Zip: jwe.Zip(e.Zip)}
	}
	return req, nil
}

type wireNotificationRequest struct {
	NotificationID   string                    `json:"notification_id"`
	Event            oid4vci.NotificationEvent `json:"event"`
	EventDescription string                    `json:"event_description"`
}

// ParseNotificationRequest turns a Notification Endpoint request body
// (§11.1, application/json) into the NotificationRequest
// RequestNotification takes, which validates its fields. The body may
// be at most MaxNotificationRequestBytes. Errors are *Error, ready for
// WriteError.
func ParseNotificationRequest(body []byte) (NotificationRequest, error) {
	if len(body) > MaxNotificationRequestBytes {
		return NotificationRequest{}, newError(ErrorInvalidNotificationRequest, http.StatusBadRequest,
			fmt.Sprintf("notification request exceeds %d bytes", MaxNotificationRequestBytes), nil)
	}
	var wire wireNotificationRequest
	if err := decodeJSONObject(body, &wire); err != nil {
		return NotificationRequest{}, newError(ErrorInvalidNotificationRequest, http.StatusBadRequest, "notification request is not a JSON object", err)
	}
	return NotificationRequest(wire), nil
}

// decodeJSONObject decodes body, which must be a JSON object, into v.
func decodeJSONObject(body []byte, v any) error {
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		return fmt.Errorf("not a JSON object")
	}
	return json.Unmarshal(body, v)
}
