package mobile

import (
	"context"
	"errors"
	"fmt"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// Issuance receives the credentials one Credential Offer offers
// (walletflow.Issuance): show Offer, then BeginAuthorization and
// CompleteAuthorization, or RedeemPreAuthorizedCode, then
// RequestCredentials; Close when done. What's deferred is polled from
// the Wallet (Wallet.PollDeferred), and survives Close and the app
// quitting.
type Issuance struct {
	s *walletflow.Issuance
}

// StartIssuance resolves the Credential Offer offerURI and fetches the
// issuer's metadata.
func (w *Wallet) StartIssuance(op *Operation, offerURI string) (*Issuance, error) {
	s, err := w.w.StartIssuance(op.context(), offerURI)
	if err != nil {
		return nil, classify(err)
	}
	return &Issuance{s: s}, nil
}

// ResumeIssuance completes an authorization begun before the app was
// suspended or relaunched: redirect is the issuer's redirect back to
// redirect_uri, the whole URL, delivered to the app. It returns the
// Issuance ready for RequestCredentials; Close it when done. A redirect
// no authorization in progress matches — not this wallet's, already
// completed, or expired — is a not_found error.
func (w *Wallet) ResumeIssuance(op *Operation, redirect string) (*Issuance, error) {
	s, err := w.w.ResumeIssuance(op.context(), redirect)
	if errors.Is(err, walletflow.ErrNoAuthorization) {
		return nil, newError(CodeNotFound, err)
	}
	if err != nil {
		return nil, classify(err)
	}
	return &Issuance{s: s}, nil
}

type offerJSON struct {
	result
	CredentialIssuer string        `json:"credential_issuer"`
	IssuerName       string        `json:"issuer_name,omitempty"`
	IssuerLogo       *logoJSON     `json:"issuer_logo,omitempty"`
	Grant            string        `json:"grant"`
	TxCode           *txCodeJSON   `json:"tx_code,omitempty"`
	Credentials      []offeredJSON `json:"credentials"`
}

type txCodeJSON struct {
	InputMode   string `json:"input_mode,omitempty"`
	Length      int    `json:"length,omitempty"`
	Description string `json:"description,omitempty"`
}

type offeredJSON struct {
	ConfigurationID string    `json:"configuration_id"`
	Format          string    `json:"format"`
	VCT             string    `json:"vct,omitempty"`
	DocType         string    `json:"doctype,omitempty"`
	Name            string    `json:"name,omitempty"`
	Description     string    `json:"description,omitempty"`
	Logo            *logoJSON `json:"logo,omitempty"`
	BackgroundColor string    `json:"background_color,omitempty"`
	TextColor       string    `json:"text_color,omitempty"`
}

// Grant values in Offer.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantPreAuthorizedCode = "pre-authorized_code"
)

// Offer returns what the offer offers: {"abi", "credential_issuer",
// "issuer_name", "issuer_logo": {"uri", "alt_text"}, "grant":
// "authorization_code" | "pre-authorized_code", "tx_code":
// {"input_mode", "length", "description"} (the PIN to ask for, if any),
// "credentials": [{"configuration_id", "format", "vct", "doctype",
// "name", "description", "logo", "background_color", "text_color"}]}.
// The display metadata is the issuer's, in the configuration's
// "locales"; a logo is https or a data: image.
func (s *Issuance) Offer() string {
	o := s.s.Offer()
	out := offerJSON{
		result: result{ABIVersion}, CredentialIssuer: o.CredentialIssuer, IssuerName: o.IssuerName,
		IssuerLogo: logoOf(o.IssuerLogo), Grant: GrantAuthorizationCode,
	}
	if o.Grant == walletflow.GrantPreAuthorizedCode {
		out.Grant = GrantPreAuthorizedCode
	}
	if o.TxCode != nil {
		out.TxCode = txCode(*o.TxCode)
	}
	for _, c := range o.Credentials {
		out.Credentials = append(out.Credentials, offeredJSON{
			ConfigurationID: c.ConfigurationID, Format: c.Format, VCT: c.VCT, DocType: c.DocType, Name: c.Name,
			Description: c.Description, Logo: logoOf(c.Logo), BackgroundColor: c.BackgroundColor, TextColor: c.TextColor,
		})
	}
	text, _ := marshal(out) // plain data: can't fail
	return text
}

func txCode(t oid4vci.TxCode) *txCodeJSON {
	return &txCodeJSON{InputMode: string(t.InputMode), Length: t.Length, Description: t.Description}
}

// BeginAuthorization sends the Pushed Authorization Request and returns
// the authorization URL to open in a browser
// (ASWebAuthenticationSession).
func (s *Issuance) BeginAuthorization(op *Operation) (string, error) {
	u, err := s.s.BeginAuthorization(op.context())
	return u, classify(err)
}

// CompleteAuthorization takes the redirect back to the wallet's
// redirect URI and gets the access token.
func (s *Issuance) CompleteAuthorization(op *Operation, redirect string) error {
	return classify(s.s.CompleteAuthorization(op.context(), redirect))
}

// RedeemPreAuthorizedCode redeems the offer's pre-authorized code with
// the PIN the holder entered ("" when the offer asks for none).
func (s *Issuance) RedeemPreAuthorizedCode(op *Operation, txCode string) error {
	return classify(s.s.RedeemPreAuthorizedCode(op.context(), txCode))
}

// failedJSON is a credential the issuer refused, or that failed the
// wallet's checks: its error's code and detail.
type failedJSON struct {
	ConfigurationID string `json:"configuration_id"`
	Code            string `json:"code"`
	Detail          string `json:"detail,omitempty"`
}

type deferredJSON struct {
	ID                   string     `json:"id"`
	CredentialIssuer     string     `json:"credential_issuer"`
	ConfigurationID      string     `json:"configuration_id"`
	IntervalSeconds      float64    `json:"interval_seconds"`
	DeferredAt           time.Time  `json:"deferred_at"`
	AccessTokenExpiresAt *time.Time `json:"access_token_expires_at,omitempty"`
}

func deferredOf(d *walletflow.Deferred) deferredJSON {
	out := deferredJSON{
		ID: d.ID(), CredentialIssuer: d.CredentialIssuer(), ConfigurationID: d.ConfigurationID(),
		IntervalSeconds: d.Interval().Seconds(), DeferredAt: d.DeferredAt(),
	}
	if t := d.AccessTokenExpiresAt(); !t.IsZero() {
		out.AccessTokenExpiresAt = &t
	}
	return out
}

// RequestCredentials requests, checks and stores every offered
// credential, and returns {"abi", "credentials": [summary],
// "deferred": [pending], "failed": [{"configuration_id", "code",
// "detail"}]}, each pending one as Wallet.Deferred lists it. A failed one
// was refused for good, or failed the wallet's checks: it doesn't hold
// up the rest. Only when nothing at all was obtained is a refusal an
// error.
// Deferred credentials are kept in the CredentialStore and polled with
// Wallet.PollDeferred, after Close too. If a request fails, call it
// again: the retry requests only the credentials not yet obtained, and
// returns everything obtained by every call (what an earlier, failed
// call stored is in the CredentialStore already).
func (s *Issuance) RequestCredentials(op *Operation) (string, error) {
	received, err := s.s.RequestCredentials(op.context())
	if err != nil {
		return "", classify(err)
	}
	deferred := make([]deferredJSON, 0, len(received.Deferred))
	for _, d := range received.Deferred {
		deferred = append(deferred, deferredOf(d))
	}
	failed := make([]failedJSON, 0, len(received.Failed))
	for _, f := range received.Failed {
		var e *Error
		_ = errors.As(classify(f.Err), &e)
		failed = append(failed, failedJSON{ConfigurationID: f.ConfigurationID, Code: e.Code, Detail: e.Detail})
	}
	return marshal(struct {
		result
		Credentials []credentialSummary `json:"credentials"`
		Deferred    []deferredJSON      `json:"deferred"`
		Failed      []failedJSON        `json:"failed"`
	}{result{ABIVersion}, summariesOf(received.Credentials), deferred, failed})
}

// Deferred credential statuses, in PollDeferred's result.
const (
	DeferredPending = "pending"
	DeferredIssued  = "issued"
)

// Deferred returns {"abi", "deferred": [{"id", "credential_issuer",
// "configuration_id", "interval_seconds", "deferred_at",
// "access_token_expires_at" (when known)}]}: the credentials issuers
// have deferred and not yet settled, oldest first — including ones from
// before the app last quit. Listing makes no network calls.
func (w *Wallet) Deferred() (string, error) {
	pending, err := w.w.Deferred(context.Background())
	if err != nil {
		return "", classify(err)
	}
	out := make([]deferredJSON, 0, len(pending))
	for _, d := range pending {
		out = append(out, deferredOf(d))
	}
	return marshal(struct {
		result
		Deferred []deferredJSON `json:"deferred"`
	}{result{ABIVersion}, out})
}

// PollDeferred asks the issuer once about the deferred credential
// deferredID names, and returns {"abi", "status": "pending" | "issued",
// "credential": summary (once issued), "interval_seconds"}. A credential
// the issuer refused is a credential_denied error; it's then no longer
// pending. The first poll after the app relaunches fetches the issuer's
// metadata.
func (w *Wallet) PollDeferred(op *Operation, deferredID string) (string, error) {
	d, err := w.deferred(deferredID)
	if err != nil {
		return "", err
	}
	stored, err := d.Poll(op.context())
	if err != nil {
		return "", classify(err)
	}
	out := struct {
		result
		Status          string             `json:"status"`
		Credential      *credentialSummary `json:"credential,omitempty"`
		IntervalSeconds float64            `json:"interval_seconds"`
	}{result: result{ABIVersion}, Status: DeferredPending, IntervalSeconds: d.Interval().Seconds()}
	if stored != nil {
		summary := summaryOf(*stored)
		out.Status, out.Credential = DeferredIssued, &summary
	}
	return marshal(out)
}

// AbandonDeferred gives up on the deferred credential deferredID names — its
// access token has expired, say, or the holder doesn't want it — and
// deletes it and its keys.
func (w *Wallet) AbandonDeferred(deferredID string) error {
	d, err := w.deferred(deferredID)
	if err != nil {
		return err
	}
	return classify(d.Abandon(context.Background()))
}

func (w *Wallet) deferred(id string) (*walletflow.Deferred, error) {
	pending, err := w.w.Deferred(context.Background())
	if err != nil {
		return nil, classify(err)
	}
	for _, d := range pending {
		if d.ID() == id {
			return d, nil
		}
	}
	return nil, newError(CodeNotFound, fmt.Errorf("no deferred credential %q", id))
}

// Close ends the issuance, deleting its keys but those its deferred
// credentials still poll with. Safe to call more than once.
func (s *Issuance) Close() error {
	err := s.s.Close(context.Background())
	if err != nil && !errors.Is(err, walletflow.ErrWrongStep) {
		return classify(err)
	}
	return nil
}
