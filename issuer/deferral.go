package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// transactionIDEntropyBytes sets how much randomness backs a
// transaction_id: 256 bits, like a notification_id.
const transactionIDEntropyBytes = 32

// Deferral asks RequestCredential to defer issuance — see
// CredentialRequest.Defer.
type Deferral struct {
	// Reference is the deployment's own handle for the business
	// process that will decide the request — kept on the
	// DeferredTransactionRecord, never sent to the Wallet.
	Reference string
}

// ErrDeferredTransactionResolved is returned by IssueDeferredCredential
// and DenyDeferredCredential for a transaction that isn't pending any
// more: already issued, denied or expired.
var ErrDeferredTransactionResolved = errors.New("issuer: the deferred transaction is no longer pending")

// requireDeferral checks this Issuer can defer: it has a Deferred
// Credential Endpoint to poll, and a store for the transactions.
func (iss *Issuer) requireDeferral() error {
	if iss.cfg.Endpoints.DeferredCredential.IsZero() || iss.deps.DeferredTransactions == nil {
		return fmt.Errorf("issuer: request credential: deferral needs Endpoints.DeferredCredential and Dependencies.DeferredTransactions")
	}
	return nil
}

// startDeferral saves a pending transaction for a checked request and
// returns the Credential Response that tells the Wallet to poll for it.
func (iss *Issuer) startDeferral(ctx context.Context, auth AuthorizedRequest, configID string, keys []resolvedKey, d Deferral) (oid4vci.CredentialResponse, error) {
	raw := make([]byte, transactionIDEntropyBytes)
	if _, err := io.ReadFull(iss.deps.Random, raw); err != nil {
		return oid4vci.CredentialResponse{}, fmt.Errorf("issuer: request credential: transaction_id: %w", err)
	}
	transactionID := base64.RawURLEncoding.EncodeToString(raw)
	bindingKeys := make([]json.RawMessage, len(keys))
	for i, k := range keys {
		bindingKeys[i] = k.JWKRaw
	}
	record := DeferredTransactionRecord{
		ClientID: auth.ClientID(), Status: DeferredTransactionPending,
		CredentialConfigurationID: configID, BindingKeys: bindingKeys, Reference: d.Reference,
		ExpiresAt: iss.deps.Clock.Now().Add(iss.cfg.Limits.DeferredTransactionLifetime),
	}
	if err := iss.deps.DeferredTransactions.Create(ctx, transactionID, record); err != nil {
		return oid4vci.CredentialResponse{}, fmt.Errorf("issuer: request credential: save deferred transaction: %w", err)
	}
	return oid4vci.CredentialResponse{
		TransactionID: transactionID,
		Interval:      int64(iss.cfg.Limits.DeferredIssuancePollInterval.Seconds()),
	}, nil
}

// DeferredIssuance is what IssueDeferredCredential issues: the
// Credential content, as a CredentialRequest's SDJWTClaims, MdocClaims
// and PerCredential would give it for an immediate issuance.
type DeferredIssuance struct {
	SDJWTClaims   *sdjwtvc.Claims
	MdocClaims    *mdoc.Claims
	PerCredential func(ctx context.Context, instance *CredentialInstance) error
}

// IssueDeferredCredential resolves the pending transaction
// transactionID by issuing its Credentials: one per binding key its
// request's proofs established, built from content, exactly as
// RequestCredential would have issued them. It issues a notification_id
// bound to the transaction's client when Endpoints.Notification is set.
// The Wallet's next poll of the Deferred Credential Endpoint receives
// them. It returns ErrDeferredTransactionResolved for a transaction
// that isn't pending, and an error for an unknown one.
func (iss *Issuer) IssueDeferredCredential(ctx context.Context, transactionID string, content DeferredIssuance) error {
	clientID, err := iss.issueDeferredCredential(ctx, transactionID, content)
	iss.audit(ctx, AuditEventIssueDeferredCredential, clientID, err)
	return err
}

func (iss *Issuer) issueDeferredCredential(ctx context.Context, transactionID string, content DeferredIssuance) (string, error) {
	record, err := iss.pendingDeferredTransaction(ctx, transactionID)
	if err != nil {
		return "", err
	}
	cc, ok := iss.cfg.CredentialConfigurationsSupported[record.CredentialConfigurationID]
	if !ok || len(record.BindingKeys) == 0 {
		return record.ClientID, fmt.Errorf("issuer: issue deferred credential: the transaction wasn't created by a deferred Credential Request")
	}
	keys := make([]resolvedKey, len(record.BindingKeys))
	for i, raw := range record.BindingKeys {
		pub, err := jwk.ParsePublicKey(raw)
		if err != nil {
			return record.ClientID, fmt.Errorf("issuer: issue deferred credential: binding key %d: %w", i, err)
		}
		keys[i] = resolvedKey{Public: pub, JWKRaw: raw}
	}
	credentials, err := iss.issueBatch(ctx, cc, CredentialRequest{
		SDJWTClaims: content.SDJWTClaims, MdocClaims: content.MdocClaims, PerCredential: content.PerCredential,
	}, keys)
	if err != nil {
		return record.ClientID, err
	}
	var notificationID string
	if iss.deps.Notifications != nil {
		if notificationID, err = iss.IssueNotificationID(ctx, deferredClient(record)); err != nil {
			return record.ClientID, fmt.Errorf("issuer: issue deferred credential: %w", err)
		}
	}
	err = iss.deps.DeferredTransactions.Update(ctx, transactionID, func(cur *DeferredTransactionRecord) error {
		if err := iss.checkPending(*cur); err != nil {
			return err
		}
		cur.Status, cur.Credentials, cur.NotificationID = DeferredTransactionIssued, credentials, notificationID
		return nil
	})
	return record.ClientID, err
}

// DenyDeferredCredential resolves the pending transaction
// transactionID by refusing it: the Wallet's next poll receives
// credential_request_denied (§9.3). It returns
// ErrDeferredTransactionResolved for a transaction that isn't pending.
func (iss *Issuer) DenyDeferredCredential(ctx context.Context, transactionID string) error {
	var clientID string
	err := iss.requireDeferredStore()
	if err == nil {
		err = iss.deps.DeferredTransactions.Update(ctx, transactionID, func(cur *DeferredTransactionRecord) error {
			clientID = cur.ClientID
			if err := iss.checkPending(*cur); err != nil {
				return err
			}
			cur.Status = DeferredTransactionDenied
			return nil
		})
	}
	iss.audit(ctx, AuditEventDenyDeferredCredential, clientID, err)
	return err
}

// pendingDeferredTransaction returns transactionID's record if it's
// still pending.
func (iss *Issuer) pendingDeferredTransaction(ctx context.Context, transactionID string) (DeferredTransactionRecord, error) {
	if err := iss.requireDeferredStore(); err != nil {
		return DeferredTransactionRecord{}, err
	}
	record, err := iss.deps.DeferredTransactions.Get(ctx, transactionID)
	if err != nil {
		return DeferredTransactionRecord{}, fmt.Errorf("issuer: deferred transaction: %w", err)
	}
	if err := iss.checkPending(record); err != nil {
		return DeferredTransactionRecord{}, err
	}
	return record, nil
}

func (iss *Issuer) requireDeferredStore() error {
	if iss.deps.DeferredTransactions == nil {
		return fmt.Errorf("issuer: deferred issuance is not configured")
	}
	return nil
}

// checkPending refuses a record that's resolved or past its ExpiresAt.
func (iss *Issuer) checkPending(record DeferredTransactionRecord) error {
	if record.Status != DeferredTransactionPending || iss.deferredExpired(record) {
		return ErrDeferredTransactionResolved
	}
	return nil
}

// deferredExpired reports whether record has an ExpiresAt that has
// passed.
func (iss *Issuer) deferredExpired(record DeferredTransactionRecord) bool {
	return !record.ExpiresAt.IsZero() && !iss.deps.Clock.Now().Before(record.ExpiresAt)
}

// deferredClient is the AuthorizedRequest a notification_id for record
// is bound to: its client, or none for a transaction with none.
func deferredClient(record DeferredTransactionRecord) AuthorizedRequest {
	if record.ClientID == "" {
		return AuthorizedRequest{ClientIdentity: NoClientIdentity{}}
	}
	return AuthorizedRequest{ClientIdentity: KnownClientID(record.ClientID)}
}

// credentialResponseStatus is the HTTP status a Credential Response is
// sent with: 202 for a deferred one (§8.3), 200 otherwise.
func credentialResponseStatus(resp oid4vci.CredentialResponse) int {
	if resp.TransactionID != "" {
		return http.StatusAccepted
	}
	return http.StatusOK
}
