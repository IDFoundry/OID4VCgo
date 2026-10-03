package mobile

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// Issuance receives the credentials one Credential Offer offers
// (walletflow.Issuance): show Offer, then BeginAuthorization and
// CompleteAuthorization, or RedeemPreAuthorizedCode, then
// RequestCredentials; poll what's deferred with PollDeferred; Close when
// done.
type Issuance struct {
	s *walletflow.Issuance

	mu       sync.Mutex
	deferred map[string]*walletflow.Deferred
	ids      map[*walletflow.Deferred]string
}

// StartIssuance resolves the Credential Offer offerURI and fetches the
// issuer's metadata.
func (w *Wallet) StartIssuance(op *Operation, offerURI string) (*Issuance, error) {
	s, err := w.w.StartIssuance(op.context(), offerURI)
	if err != nil {
		return nil, classify(err)
	}
	return &Issuance{s: s, deferred: map[string]*walletflow.Deferred{}, ids: map[*walletflow.Deferred]string{}}, nil
}

type offerJSON struct {
	result
	CredentialIssuer string        `json:"credential_issuer"`
	IssuerName       string        `json:"issuer_name,omitempty"`
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
	ConfigurationID string `json:"configuration_id"`
	Format          string `json:"format"`
	VCT             string `json:"vct,omitempty"`
	DocType         string `json:"doctype,omitempty"`
	Name            string `json:"name,omitempty"`
}

// Grant values in Offer.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantPreAuthorizedCode = "pre-authorized_code"
)

// Offer returns what the offer offers: {"abi", "credential_issuer",
// "issuer_name", "grant": "authorization_code" | "pre-authorized_code",
// "tx_code": {"input_mode", "length", "description"} (the PIN to ask
// for, if any), "credentials": [{"configuration_id", "format", "vct",
// "doctype", "name"}]}.
func (s *Issuance) Offer() string {
	o := s.s.Offer()
	out := offerJSON{result: result{ABIVersion}, CredentialIssuer: o.CredentialIssuer, IssuerName: o.IssuerName, Grant: GrantAuthorizationCode}
	if o.Grant == walletflow.GrantPreAuthorizedCode {
		out.Grant = GrantPreAuthorizedCode
	}
	if o.TxCode != nil {
		out.TxCode = txCode(*o.TxCode)
	}
	for _, c := range o.Credentials {
		out.Credentials = append(out.Credentials, offeredJSON{
			ConfigurationID: c.ConfigurationID, Format: c.Format, VCT: c.VCT, DocType: c.DocType, Name: c.Name,
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

type deferredJSON struct {
	ID              string  `json:"id"`
	ConfigurationID string  `json:"configuration_id"`
	IntervalSeconds float64 `json:"interval_seconds"`
}

// RequestCredentials requests, checks and stores every offered
// credential, and returns {"abi", "credentials": [summary],
// "deferred": [{"id", "configuration_id", "interval_seconds"}]}. A
// deferred credential's id is unique across issuances. If a request
// fails, call it again: the retry requests only the credentials not yet
// obtained, and returns everything obtained by every call (what an
// earlier, failed call stored is in the CredentialStore already).
func (s *Issuance) RequestCredentials(op *Operation) (string, error) {
	received, err := s.s.RequestCredentials(op.context())
	s.register(received.Deferred)
	if err != nil {
		return "", classify(err)
	}
	s.mu.Lock()
	deferred := make([]deferredJSON, 0, len(received.Deferred))
	for _, d := range received.Deferred {
		deferred = append(deferred, deferredJSON{ID: s.ids[d], ConfigurationID: d.ConfigurationID(), IntervalSeconds: d.Interval().Seconds()})
	}
	s.mu.Unlock()
	return marshal(struct {
		result
		Credentials []credentialSummary `json:"credentials"`
		Deferred    []deferredJSON      `json:"deferred"`
	}{result{ABIVersion}, summariesOf(received.Credentials), deferred})
}

// register gives each deferred credential not yet registered a random
// ID, so it can be polled — including one from a call that failed.
func (s *Issuance) register(deferred []*walletflow.Deferred) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range deferred {
		if _, ok := s.ids[d]; ok {
			continue
		}
		id, err := randomID()
		if err != nil {
			continue
		}
		s.ids[d], s.deferred[id] = id, d
	}
}

// randomID is a random 128-bit identifier.
func randomID() (string, error) {
	var b [16]byte
	if _, err := (randReader{}).Read(b[:]); err != nil {
		return "", err
	}
	return "deferred-" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Deferred credential statuses, in PollDeferred's result.
const (
	DeferredPending = "pending"
	DeferredIssued  = "issued"
)

// PollDeferred asks the issuer once about deferredID, and returns
// {"abi", "status": "pending" | "issued", "credential": summary (once
// issued), "interval_seconds"}. A credential the issuer refused is a
// credential_denied error.
func (s *Issuance) PollDeferred(op *Operation, deferredID string) (string, error) {
	s.mu.Lock()
	d, ok := s.deferred[deferredID]
	s.mu.Unlock()
	if !ok {
		return "", newError(CodeNotFound, fmt.Errorf("no deferred credential %q", deferredID))
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

// Close ends the issuance, deleting its keys: deferred credentials can
// no longer be polled. Safe to call more than once.
func (s *Issuance) Close() error {
	err := s.s.Close(context.Background())
	if err != nil && !errors.Is(err, walletflow.ErrWrongStep) {
		return classify(err)
	}
	return nil
}
