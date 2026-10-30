package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

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

// ErrDeferredKeyAttestation is returned, wrapped with the reason, by
// IssueDeferredCredential when a key attestation that attested the
// transaction's binding keys no longer verifies (it has expired, been
// revoked, or lost its trust): the transaction is denied instead of
// issued, and the Wallet's next poll receives credential_request_denied
// (§9.3).
var ErrDeferredKeyAttestation = errors.New("issuer: a key attestation behind the deferred transaction is no longer valid")

// ErrDeferredAttestationStatusUnknown is returned, wrapped with the
// reason, by IssueDeferredCredential when a key attestation's validity
// couldn't be decided now, and none is known to be invalid:
// Dependencies.AttestationStatus returned an error that didn't wrap
// ErrKeyAttestationRevoked (a Status List that couldn't be fetched,
// say), or Dependencies.AttestationVerifier one saying the signer's
// certificate revocation couldn't be decided (see AttestationVerifier).
// The transaction stays pending, so it can be issued once the status
// can be checked again, or denied with DenyDeferredCredential. Until
// then it waits at most Limits.DeferredTransactionLifetime, when it
// expires, or the attestation's exp, after which a re-check denies it.
var ErrDeferredAttestationStatusUnknown = errors.New("issuer: a key attestation behind the deferred transaction has a status that can't be checked now")

// ErrDeferredTransactionResolved is returned by IssueDeferredCredential
// and DenyDeferredCredential for a transaction that isn't pending any
// more: already issued, denied or expired.
var ErrDeferredTransactionResolved = errors.New("issuer: the deferred transaction is no longer pending")

// requireDeferral checks this Issuer can defer auth's request: it has a
// Deferred Credential Endpoint to poll and a store for the
// transactions, and auth has a Subject to bind the transaction to.
func (iss *Issuer) requireDeferral(auth AuthorizedRequest) error {
	if iss.cfg.Endpoints.DeferredCredential.IsZero() || iss.deps.DeferredTransactions == nil {
		return fmt.Errorf("issuer: request credential: deferral needs Endpoints.DeferredCredential and Dependencies.DeferredTransactions")
	}
	if auth.Subject == "" {
		return fmt.Errorf("issuer: request credential: deferral needs AuthorizedRequest.Subject to bind the transaction to")
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
	var keyAttestations []string
	for i, k := range keys {
		bindingKeys[i] = k.JWKRaw
		if k.KeyAttestation != "" && !slices.Contains(keyAttestations, k.KeyAttestation) {
			keyAttestations = append(keyAttestations, k.KeyAttestation)
		}
	}
	record := DeferredTransactionRecord{
		Owner:    iss.storeOwner(),
		ClientID: auth.ClientID(), Subject: auth.Subject, Status: DeferredTransactionPending,
		CredentialConfigurationID: configID, BindingKeys: bindingKeys, Reference: d.Reference,
		ExpiresAt:       iss.deps.Clock.Now().Add(iss.cfg.Limits.DeferredTransactionLifetime),
		KeyAttestations: keyAttestations,
	}
	if err := iss.deps.DeferredTransactions.Create(ctx, transactionID, record); err != nil {
		return oid4vci.CredentialResponse{}, fmt.Errorf("issuer: request credential: save deferred transaction: %w", err)
	}
	if err := iss.checkOwnerKept(&iss.deferredOwner, iss.deps.DeferredTransactions, func() (string, error) {
		saved, err := iss.deps.DeferredTransactions.Get(ctx, transactionID)
		return saved.Owner, err
	}); err != nil {
		// Without its Owner the record is unknown to every Issuer
		// under AssuranceProduction, and lapses unanswered.
		return oid4vci.CredentialResponse{}, fmt.Errorf("issuer: request credential: save deferred transaction: %w", err)
	}
	return oid4vci.CredentialResponse{
		TransactionID: transactionID,
		Interval:      pollIntervalSeconds(iss.cfg.Limits.DeferredIssuancePollInterval),
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
// that isn't pending, and an error wrapping ErrDeferredTransactionUnknown
// for an unknown one, or one another Credential Issuer sharing the
// store created (DeferredTransactionRecord.Owner).
//
// The key attestations the transaction's request carried
// (DeferredTransactionRecord.KeyAttestations) are verified again first,
// as of now: one that has expired, been revoked
// (ErrKeyAttestationRevoked, or certrevocation.ErrRevoked for its
// signer's certificate) or is no longer trusted denies the
// transaction, and IssueDeferredCredential returns
// ErrDeferredKeyAttestation, wrapped with the reason. Every one is
// checked: only when none is invalid does one whose status, or whose
// signer's revocation, can't be checked now leave the transaction
// pending, with ErrDeferredAttestationStatusUnknown. A key attestation's exp is when
// its keys expire too (Appendix D.1), so a Wallet Provider's must
// outlast the time a deferred transaction waits for its decision.
//
// Concurrent calls for one transaction may each build Credentials, and
// run content.PerCredential for them, but only the first to finish
// saves them; the others return ErrDeferredTransactionResolved, and
// anything their PerCredential reserved is unused.
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
	if err := iss.recheckKeyAttestations(ctx, cc, record); err != nil {
		if errors.Is(err, ErrDeferredAttestationStatusUnknown) {
			return record.ClientID, fmt.Errorf("issuer: issue deferred credential: %w", err)
		}
		if _, denyErr := iss.denyPending(ctx, transactionID); denyErr != nil {
			return record.ClientID, denyErr
		}
		return record.ClientID, fmt.Errorf("issuer: issue deferred credential: %w: %w", ErrDeferredKeyAttestation, err)
	}
	credentials, err := iss.issueBatch(ctx, cc, CredentialRequest{
		SDJWTClaims: content.SDJWTClaims, MdocClaims: content.MdocClaims, PerCredential: content.PerCredential,
	}, keys)
	if err != nil {
		return record.ClientID, err
	}
	var notificationID string
	if !iss.cfg.Endpoints.Notification.IsZero() {
		if notificationID, err = iss.IssueNotificationID(ctx, deferredClient(record)); err != nil {
			return record.ClientID, fmt.Errorf("issuer: issue deferred credential: %w", err)
		}
	}
	err = iss.deps.DeferredTransactions.Update(ctx, transactionID, func(cur *DeferredTransactionRecord) error {
		if err := iss.checkPending(*cur); err != nil {
			return err
		}
		cur.Status, cur.Credentials, cur.NotificationID = DeferredTransactionIssued, credentials, notificationID
		if !cur.ExpiresAt.IsZero() {
			cur.ExpiresAt = iss.deps.Clock.Now().Add(iss.cfg.Limits.DeferredTransactionLifetime)
		}
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
		clientID, err = iss.denyPending(ctx, transactionID)
	}
	iss.audit(ctx, AuditEventDenyDeferredCredential, clientID, err)
	return err
}

// denyPending marks the pending transaction transactionID denied, and
// returns its client. It returns ErrDeferredTransactionResolved for a
// transaction that isn't pending.
func (iss *Issuer) denyPending(ctx context.Context, transactionID string) (string, error) {
	var clientID string
	err := iss.deps.DeferredTransactions.Update(ctx, transactionID, func(cur *DeferredTransactionRecord) error {
		clientID = cur.ClientID
		if err := iss.checkPending(*cur); err != nil {
			return err
		}
		cur.Status = DeferredTransactionDenied
		return nil
	})
	return clientID, err
}

// recheckKeyAttestations verifies record's KeyAttestations again, as of
// now: each one's signature against the key
// Dependencies.AttestationVerifier resolves, by an algorithm one of
// cc's proof types accepts, its exp, and its status
// (checkAttestationStatus). The request-time checks of freshness
// (nonce, iat) and of the proofs themselves aren't repeated: they were
// met when the transaction was created.
//
// Every attestation is checked, so one no longer valid denies the
// transaction even after another whose status, or signer's trust,
// can't be decided now (trustUndecided), which alone wraps
// ErrDeferredAttestationStatusUnknown.
func (iss *Issuer) recheckKeyAttestations(ctx context.Context, cc CredentialConfiguration, record DeferredTransactionRecord) error {
	if len(record.KeyAttestations) == 0 {
		return nil
	}
	if iss.deps.AttestationVerifier == nil {
		return fmt.Errorf("this issuer has no Dependencies.AttestationVerifier to verify them with")
	}
	var algs []string
	for _, ptc := range cc.ProofTypesSupported {
		algs = append(algs, ptc.ProofSigningAlgValuesSupported...)
	}
	now := iss.deps.Clock.Now()
	var unknown error
	for i, compact := range record.KeyAttestations {
		verified, err := iss.verifyOneAttestation(ctx, compact, i, now, algs)
		if err == nil {
			if err = iss.checkAttestationStatus(ctx, verified); errors.Is(err, ErrKeyAttestationRevoked) {
				return fmt.Errorf("attestation %d: status: %w", i, err)
			}
		} else if !trustUndecided(err) {
			return err
		}
		if err != nil && unknown == nil {
			unknown = fmt.Errorf("%w: attestation %d: %w", ErrDeferredAttestationStatusUnknown, i, err)
		}
	}
	return unknown
}

// abandonDeferral denies a pending transaction whose Credential
// Response never reached the Wallet, so the deployment's business
// process gets ErrDeferredTransactionResolved instead of issuing for
// it. It's best effort: a store error leaves the transaction to expire.
func (iss *Issuer) abandonDeferral(ctx context.Context, transactionID string) {
	_ = iss.deps.DeferredTransactions.Update(ctx, transactionID, func(cur *DeferredTransactionRecord) error {
		if cur.Status == DeferredTransactionPending && iss.owns(cur.Owner) {
			cur.Status = DeferredTransactionDenied
		}
		return nil
	})
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

// checkPending refuses a record that's resolved or past its ExpiresAt,
// and, as unknown (ErrDeferredTransactionUnknown), one that isn't this
// Issuer's.
func (iss *Issuer) checkPending(record DeferredTransactionRecord) error {
	if !iss.owns(record.Owner) {
		return fmt.Errorf("issuer: deferred transaction: %w", ErrDeferredTransactionUnknown)
	}
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

// deferredOwner reports whether auth may poll record: it's the client,
// and the subject, the transaction was created for.
func deferredOwner(record DeferredTransactionRecord, auth AuthorizedRequest) bool {
	if record.ClientID != "" && auth.ClientID() != record.ClientID {
		return false
	}
	return record.Subject == "" || auth.Subject == record.Subject
}

// deferredAuthorized reports whether auth may poll record: it's
// record's owner (deferredOwner), and, §9, the access token is still
// "valid for the issuance of the Credential(s) previously requested":
// it grants the transaction's credential configuration.
func (iss *Issuer) deferredAuthorized(record DeferredTransactionRecord, auth AuthorizedRequest) bool {
	if !deferredOwner(record, auth) {
		return false
	}
	return record.CredentialConfigurationID == "" ||
		iss.grantsConfiguration(auth, record.CredentialConfigurationID, iss.cfg.CredentialConfigurationsSupported[record.CredentialConfigurationID])
}

// pollIntervalSeconds is d as §9.2's "interval": whole seconds, rounded
// up.
func pollIntervalSeconds(d time.Duration) int64 {
	return int64((d + time.Second - 1) / time.Second)
}

// deferredClient is the AuthorizedRequest a notification_id for record
// is bound to: its client, or none for a transaction with none, and its
// subject, as an immediate issuance's is. A client_id alone names a
// whole wallet solution under HAIP, not one holder.
func deferredClient(record DeferredTransactionRecord) AuthorizedRequest {
	if record.ClientID == "" {
		return AuthorizedRequest{ClientIdentity: NoClientIdentity{}, Subject: record.Subject}
	}
	return AuthorizedRequest{ClientIdentity: KnownClientID(record.ClientID), Subject: record.Subject}
}

// credentialResponseStatus is the HTTP status a Credential Response is
// sent with: 202 for a deferred one (§8.3), 200 otherwise.
func credentialResponseStatus(resp oid4vci.CredentialResponse) int {
	if resp.TransactionID != "" {
		return http.StatusAccepted
	}
	return http.StatusOK
}
