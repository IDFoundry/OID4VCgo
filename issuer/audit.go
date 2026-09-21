package issuer

import (
	"context"
	"errors"
	"time"
)

// AuditEventType is a closed set of security-significant events this
// issuer can record — the token/credential-issuance boundary
// operations, mirroring FAPIgo's own server.AuditEventType's own
// choice to audit authorization/token exchange rather than every
// endpoint (this package has no equivalent of PAR/BeginAuthorization
// to audit in the first place — RequestNonce/RequestNotification/
// CreateCredentialOffer hand out or acknowledge values, they don't
// cross a trust boundary the way exchanging a code for a token, or
// handing out a Credential, does).
type AuditEventType uint8

const (
	_ AuditEventType = iota

	// AuditEventExchangePreAuthorizedCode records the outcome of an
	// ExchangePreAuthorizedCode call.
	AuditEventExchangePreAuthorizedCode

	// AuditEventRequestCredential records the outcome of a
	// RequestCredential call.
	AuditEventRequestCredential

	// AuditEventRequestDeferredCredential records the outcome of a
	// RequestDeferredCredential call.
	AuditEventRequestDeferredCredential
)

// AuditOutcome is a closed set of outcomes for an AuditEvent.
type AuditOutcome uint8

const (
	_ AuditOutcome = iota
	AuditOutcomeSuccess
	AuditOutcomeFailure
)

// AuditEvent is a structured, security-significant event. Description
// is a short, safe summary (an ErrorCode, on failure) — never a raw
// internal error or anything that could carry a token, key or proof
// value.
type AuditEvent struct {
	Type        AuditEventType
	Time        time.Time
	ClientID    string // "" if the client could not be identified — see AuthorizedRequest.ClientID's own doc comment
	Outcome     AuditOutcome
	Description string
}

// AuditSink records AuditEvents. Under AssuranceProduction, New
// requires one to be configured — the same requirement FAPIgo's own
// server.AssuranceProduction places on server.Dependencies.Audit.
type AuditSink interface {
	Record(ctx context.Context, event AuditEvent) error
}

// audit records event via deps.Audit if configured — nil disables
// auditing entirely (rejected under AssuranceProduction, see
// checkProductionAssurance's own sibling check in assurance.go).
// Best-effort: a failure to record itself never fails the caller's own
// request — the audit trail is defense-in-depth, not the primary
// security boundary, the same stance FAPIgo's own server.audit takes.
func (iss *Issuer) audit(ctx context.Context, eventType AuditEventType, clientID string, err error) {
	if iss.deps.Audit == nil {
		return
	}
	outcome := AuditOutcomeSuccess
	description := ""
	if err != nil {
		outcome = AuditOutcomeFailure
		description = auditDescription(err)
	}
	_ = iss.deps.Audit.Record(ctx, AuditEvent{
		Type:        eventType,
		Time:        iss.deps.Clock.Now(),
		ClientID:    clientID,
		Outcome:     outcome,
		Description: description,
	})
}

// auditDescription maps err to a short, safe summary: this package's
// own *Error carries a closed ErrorCode safe to record verbatim;
// anything else (a plain fmt.Errorf, possibly wrapping a dependency's
// own internal error text) is never included as-is, since it could
// carry more detail than a security audit log should retain.
func auditDescription(err error) string {
	var issuerErr *Error
	if errors.As(err, &issuerErr) {
		return string(issuerErr.Code())
	}
	return "internal_error"
}
