//go:build mobiletest

package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// goCredentialStore is a CredentialStore in memory, as the app's would
// be.
type goCredentialStore struct {
	mu        sync.Mutex
	records   map[string][]byte
	order     []string
	ephemeral bool // says it isn't Durable
}

func newGoCredentialStore() *goCredentialStore {
	return &goCredentialStore{records: map[string][]byte{}}
}

func (s *goCredentialStore) Durable() bool { return !s.ephemeral }

func (s *goCredentialStore) Put(id string, record []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[id]; !ok {
		s.order = append(s.order, id)
	}
	s.records[id] = record
	return nil
}

func (s *goCredentialStore) Get(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records[id], nil
}

func (s *goCredentialStore) List() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]json.RawMessage, 0, len(s.order))
	for _, id := range s.order {
		if r, ok := s.records[id]; ok {
			all = append(all, r)
		}
	}
	return json.Marshal(all)
}

func (s *goCredentialStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, id)
	return nil
}

type harness struct {
	env   *TestEnv
	keys  *goKeyStore
	creds *goCredentialStore
	w     *Wallet
}

func newHarness(t *testing.T, deferIssuance bool) harness {
	t.Helper()
	env, err := StartTestEnv(deferIssuance)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	h := harness{env: env, keys: newGoKeyStore(), creds: newGoCredentialStore()}
	if h.w, err = NewWallet(env.ConfigJSON(), h.keys, h.creds, env.Provider()); err != nil {
		t.Fatal(err)
	}
	return h
}

func decode[T any](t *testing.T, text string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		t.Fatalf("%v: %s", err, text)
	}
	return v
}

type summary struct {
	ID, Format, DocType, VCT, CredentialIssuer string
}

func (h harness) receive(t *testing.T) []summary {
	t.Helper()
	offer, err := h.env.AuthorizationCodeOffer()
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.w.StartIssuance(NewOperation(0), offer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	o := decode[struct {
		ABI         int
		Grant       string
		Credentials []struct {
			ConfigurationID string `json:"configuration_id"`
		}
	}](t, s.Offer())
	if o.ABI != ABIVersion || o.Grant != GrantAuthorizationCode || len(o.Credentials) != 2 {
		t.Fatalf("Offer = %s", s.Offer())
	}
	authURL, err := s.BeginAuthorization(NewOperation(0))
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := h.env.Approve(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteAuthorization(NewOperation(0), redirect); err != nil {
		t.Fatal(err)
	}
	out, err := s.RequestCredentials(NewOperation(0))
	if err != nil {
		t.Fatal(err)
	}
	got := decode[struct {
		Credentials []summary
		Deferred    []json.RawMessage
	}](t, out)
	if len(got.Credentials) != 2 || len(got.Deferred) != 0 {
		t.Fatalf("RequestCredentials = %s", out)
	}
	return got.Credentials
}

func TestSessions_IssueThenPresent(t *testing.T) {
	h := newHarness(t, false)
	received := h.receive(t)

	list := decode[struct{ Credentials []summary }](t, mustText(t)(h.w.Credentials()))
	// The two credentials, and the refresh grant both use.
	if len(list.Credentials) != 2 || len(h.creds.records) != 3 {
		t.Fatalf("Credentials = %+v; store holds %d", list, len(h.creds.records))
	}
	// The two holder keys and the instance key the refresh grant keeps:
	// Close deleted the DPoP key.
	if len(h.keys.keys) != 3 {
		t.Errorf("keys held = %d, want 3", len(h.keys.keys))
	}

	sdjwt := checkPresentation(t, h, received)

	checkClaims(t, h, received)

	if err := h.w.DeleteCredential(sdjwt); err != nil {
		t.Fatal(err)
	}
	if err := h.w.DeleteCredential(sdjwt); code(err) != CodeNotFound {
		t.Errorf("deleting it again: %v", err)
	}

	checkOrphan(t, h, received)
	if !IsTestBuild() {
		t.Error("IsTestBuild = false in the mobiletest build")
	}
}

// checkPresentation presents the SD-JWT VC from received, chosen among
// the candidates for a request that takes either format, and returns
// its ID.
func checkPresentation(t *testing.T, h harness, received []summary) string {
	t.Helper()
	req := decode[struct{ ID, Link string }](t, mustText(t)(h.env.Request("")))
	p, err := h.w.StartPresentation(NewOperation(0), req.Link)
	if err != nil {
		t.Fatal(err)
	}
	if v := decode[struct{ Name string }](t, p.Verifier()); v.Name == "" {
		t.Errorf("Verifier = %s", p.Verifier())
	}
	req2 := decode[struct {
		Queries []struct {
			QueryID     string `json:"query_id"`
			Multiple    bool
			Credentials []summary
		}
		CredentialSets []struct {
			Options  [][]string
			Required bool
		} `json:"credential_sets"`
	}](t, p.Queries())
	if len(req2.Queries) != 2 || req2.Queries[0].Multiple || len(req2.CredentialSets) != 1 || !req2.CredentialSets[0].Required {
		t.Fatalf("Queries = %s", p.Queries())
	}
	if def := mustText(t)(p.DefaultSelection()); !strings.Contains(def, `"selection":{"`) {
		t.Errorf("DefaultSelection = %s", def)
	}
	var sdjwt string
	for _, c := range received {
		if c.Format == "dc+sd-jwt" {
			sdjwt = c.ID
		}
	}
	if _, err := p.Preview(`{"pid":["` + sdjwt + `","` + sdjwt + `"]}`); code(err) != CodeInvalidSelection {
		t.Errorf("Preview with two for a query that takes one: %v", err)
	}
	chosen := `{"pid":["` + sdjwt + `"]}`
	preview := mustText(t)(p.Preview(chosen))
	if !strings.Contains(preview, `"claims":[["family_name"]]`) {
		t.Errorf("Preview = %s", preview)
	}
	presented := decode[struct {
		QueryIDs []string `json:"query_ids"`
	}](t, mustText(t)(p.Respond(NewOperation(0), chosen)))
	if len(presented.QueryIDs) != 1 || presented.QueryIDs[0] != "pid" {
		t.Errorf("Respond = %+v", presented)
	}
	result := decode[struct {
		Status string
		Claims map[string]any
	}](t, mustText(t)(h.env.RequestResult(req.ID)))
	if result.Status != "done" || result.Claims["family_name"] != "Doe" {
		t.Errorf("verifier = %+v", result)
	}
	if _, err := p.Respond(NewOperation(0), chosen); code(err) != CodeWrongStep {
		t.Errorf("Respond twice: %v", err)
	}
	return sdjwt
}

// checkClaims checks each received credential's claims, for display.
func checkClaims(t *testing.T, h harness, received []summary) {
	t.Helper()
	keys := decode[struct {
		KeyIDs []string `json:"key_ids"`
	}](t, mustText(t)(h.w.HolderKeyIDs()))
	if len(keys.KeyIDs) != len(received)+1 {
		t.Errorf("HolderKeyIDs = %v, want one per credential and the refresh grant's instance key", keys.KeyIDs)
	}
	for _, id := range keys.KeyIDs {
		if _, ok := h.keys.keys[id]; !ok {
			t.Errorf("HolderKeyIDs lists %q, which the key store doesn't hold", id)
		}
	}
	for _, c := range received {
		detail := decode[struct {
			ID               string
			HolderKeyPresent *bool `json:"holder_key_present"`
			Claims           map[string]any
		}](t, mustText(t)(h.w.Credential(c.ID)))
		if detail.ID != c.ID || detail.HolderKeyPresent == nil || !*detail.HolderKeyPresent {
			t.Errorf("Credential(%s) = %+v", c.ID, detail)
		}
		family := detail.Claims["family_name"]
		if c.Format == "mso_mdoc" {
			ns, _ := detail.Claims["org.example.test.1"].(map[string]any)
			family = ns["family_name"]
		}
		if family != "Doe" {
			t.Errorf("%s claims = %v", c.Format, detail.Claims)
		}
	}
	if _, err := h.w.Credential("no-such"); code(err) != CodeNotFound {
		t.Errorf("Credential of an unknown ID: %v", err)
	}
}

// checkOrphan checks that a credential whose holder key is gone is
// listed as such.
func checkOrphan(t *testing.T, h harness, received []summary) {
	t.Helper()
	var mdocCred summary
	for _, c := range received {
		if c.Format == "mso_mdoc" {
			mdocCred = c
		}
	}
	var keyID string
	for _, raw := range h.creds.records {
		var r credentialRecord
		if err := json.Unmarshal(raw, &r); err == nil && r.ID == mdocCred.ID {
			keyID = r.HolderKeyID
		}
	}
	if err := h.keys.DeleteKey(keyID); err != nil {
		t.Fatal(err)
	}
	listed := decode[struct {
		Credentials []struct {
			HolderKeyPresent *bool `json:"holder_key_present"`
		}
	}](t, mustText(t)(h.w.Credentials()))
	if len(listed.Credentials) != 1 || listed.Credentials[0].HolderKeyPresent == nil || *listed.Credentials[0].HolderKeyPresent {
		t.Errorf("after its key was deleted: %+v", listed)
	}
}

func TestSessions_PreAuthorizedCode(t *testing.T) {
	h := newHarness(t, false)
	offer, err := h.env.PreAuthorizedOffer("123456")
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.w.StartIssuance(NewOperation(0), offer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	o := decode[struct {
		Grant  string
		TxCode *struct{ Length int } `json:"tx_code"`
	}](t, s.Offer())
	if o.Grant != GrantPreAuthorizedCode || o.TxCode == nil || o.TxCode.Length != 6 {
		t.Fatalf("Offer = %s", s.Offer())
	}
	if _, err := s.BeginAuthorization(NewOperation(0)); code(err) != CodeWrongStep {
		t.Errorf("BeginAuthorization: %v", err)
	}
	if err := s.RedeemPreAuthorizedCode(NewOperation(0), "000000"); code(err) != CodeProtocol || !strings.HasPrefix(err.Error(), "[protocol:invalid_grant] ") {
		t.Errorf("a wrong PIN: %v", err)
	}
	if err := s.RedeemPreAuthorizedCode(NewOperation(0), "123456"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestCredentials(NewOperation(0)); err != nil {
		t.Fatal(err)
	}
}

// deferTwo receives the test issuer's two credentials, both deferred,
// closes the issuance, and returns the wallet's pending ones' IDs.
func (h harness) deferTwo(t *testing.T) []string {
	t.Helper()
	offer, err := h.env.AuthorizationCodeOffer()
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.w.StartIssuance(NewOperation(0), offer)
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := s.BeginAuthorization(NewOperation(0))
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := h.env.Approve(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteAuthorization(NewOperation(0), redirect); err != nil {
		t.Fatal(err)
	}
	got := decode[struct {
		Deferred []struct {
			ID              string
			IntervalSeconds float64 `json:"interval_seconds"`
		}
	}](t, mustText(t)(s.RequestCredentials(NewOperation(0))))
	if len(got.Deferred) != 2 || got.Deferred[0].IntervalSeconds <= 0 || got.Deferred[0].ID == got.Deferred[1].ID || len(got.Deferred[0].ID) < 20 {
		t.Fatalf("deferred = %+v", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return []string{got.Deferred[0].ID, got.Deferred[1].ID}
}

// pending lists w's pending deferred credentials' IDs.
func pending(t *testing.T, w *Wallet) []string {
	t.Helper()
	got := decode[struct{ Deferred []struct{ ID string } }](t, mustText(t)(w.Deferred()))
	ids := make([]string, 0, len(got.Deferred))
	for _, d := range got.Deferred {
		ids = append(ids, d.ID)
	}
	return ids
}

// Deferred credentials survive the issuance closing and the app
// relaunching: a new Wallet over the same stores lists and polls them,
// and the key sweep keeps their keys.
func TestSessions_Deferred(t *testing.T) {
	h := newHarness(t, true)
	ids := h.deferTwo(t)

	relaunched, err := NewWallet(h.env.ConfigJSON(), h.keys, h.creds, h.env.Provider())
	if err != nil {
		t.Fatal(err)
	}
	if got := pending(t, relaunched); len(got) != 2 {
		t.Fatalf("pending after a relaunch = %v, want %v", got, ids)
	}
	if held := decode[struct{ Credentials []summary }](t, mustText(t)(relaunched.Credentials())); len(held.Credentials) != 0 {
		t.Errorf("pending ones listed as credentials: %+v", held)
	}
	if keys := decode[struct {
		KeyIDs []string `json:"key_ids"`
	}](t, mustText(t)(relaunched.HolderKeyIDs())); len(keys.KeyIDs) != 4 {
		t.Errorf("keys in use = %v, want two holder keys, the DPoP key and the refresh grant's instance key", keys.KeyIDs)
	}

	poll := func(id string) (string, error) { return relaunched.PollDeferred(NewOperation(0), id) }
	if st := decode[struct{ Status string }](t, mustText(t)(poll(ids[0]))); st.Status != DeferredPending {
		t.Errorf("before a decision: %+v", st)
	}
	h.env.Decide(true)
	issued := decode[struct {
		Status     string
		Credential *summary
	}](t, mustText(t)(poll(ids[0])))
	if issued.Status != DeferredIssued || issued.Credential == nil || issued.Credential.ID == "" {
		t.Errorf("after approval: %+v", issued)
	}
	h.env.Decide(false)
	if _, err := poll(ids[1]); code(err) != CodeCredentialDenied {
		t.Errorf("after denial: %v", err)
	}
	if got := pending(t, relaunched); len(got) != 0 {
		t.Errorf("still pending once settled: %v", got)
	}
	if len(h.keys.keys) != 2 {
		t.Errorf("keys held = %d, want the issued credential's and its refresh grant's instance key", len(h.keys.keys))
	}
	if _, err := poll("no-such"); code(err) != CodeNotFound {
		t.Errorf("an unknown deferred credential: %v", err)
	}
}

func TestSessions_AbandonDeferred(t *testing.T) {
	h := newHarness(t, true)
	for _, id := range h.deferTwo(t) {
		if err := h.w.AbandonDeferred(id); err != nil {
			t.Fatal(err)
		}
	}
	if got := pending(t, h.w); len(got) != 0 || len(h.keys.keys) != 0 {
		t.Errorf("after abandoning: pending %v, %d keys; want none", got, len(h.keys.keys))
	}
	if err := h.w.AbandonDeferred("no-such"); code(err) != CodeNotFound {
		t.Errorf("abandoning an unknown one: %v", err)
	}
}

func TestSessions_DeclineAndNoMatch(t *testing.T) {
	h := newHarness(t, false)
	req := decode[struct{ ID, Link string }](t, mustText(t)(h.env.Request("mso_mdoc")))
	p, err := h.w.StartPresentation(NewOperation(0), req.Link)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Queries(), `"credentials":[]`) {
		t.Errorf("Queries with nothing held = %s", p.Queries())
	}
	if _, err := p.DefaultSelection(); code(err) != CodeNoMatchingCredential {
		t.Errorf("DefaultSelection: %v", err)
	}
	if _, err := p.Respond(NewOperation(0), `{"mdl":["no-such"]}`); code(err) != CodeInvalidSelection {
		t.Errorf("Respond with an unknown credential: %v", err)
	}
	if _, err := p.Preview("not json"); code(err) != CodeInvalidInput {
		t.Errorf("Preview with a bad selection: %v", err)
	}
	if _, err := p.Decline(NewOperation(0)); err != nil {
		t.Fatal(err)
	}
	if r := decode[struct {
		LastError string `json:"last_error"`
	}](t, mustText(t)(h.env.RequestResult(req.ID))); !strings.Contains(r.LastError, "access_denied") {
		t.Errorf("verifier after Decline = %+v", r)
	}
}

func TestSessions_Cancel(t *testing.T) {
	h := newHarness(t, false)
	offer, err := h.env.AuthorizationCodeOffer()
	if err != nil {
		t.Fatal(err)
	}
	op := NewOperation(0)
	op.Cancel()
	if _, err := h.w.StartIssuance(op, offer); code(err) != CodeCancelled {
		t.Errorf("a cancelled StartIssuance: %v", err)
	}
	// A timeout is the service not answering in time: network, which
	// can be retried — not the holder cancelling.
	if _, err := h.w.StartIssuance(NewOperation(1), offer); err != nil && code(err) != CodeNetwork {
		t.Errorf("a timed-out StartIssuance: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
}

func TestNewWallet_RefusesBadConfiguration(t *testing.T) {
	ks, cs := newGoKeyStore(), newGoCredentialStore()
	for name, cfg := range map[string]string{
		"not JSON":         "{",
		"bad issuer roots": `{"issuer_roots": "not PEM"}`,
		"bad verifier":     `{"verifier_roots": "not PEM"}`,
		"bad copy policy":  `{"copy_policy": "sometimes"}`,
	} {
		if _, err := NewWallet(cfg, ks, cs, nil); code(err) != CodeInvalidInput {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := NewWallet("{}", nil, cs, nil); code(err) != CodeInvalidInput {
		t.Errorf("no key store: %v", err)
	}
	w, err := NewWallet("{}", ks, cs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.StartIssuance(NewOperation(0), "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Fo"); code(err) != CodeProtocol {
		t.Errorf("issuing without issuer settings: %v", err)
	}
	if _, err := w.StartPresentation(NewOperation(0), "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fv.example%2Fr"); err == nil {
		t.Error("presenting without verifier_roots succeeded")
	}
}

func mustText(t *testing.T) func(string, error) string {
	return func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
}

// The redirect completes an authorization begun before the app quit: a
// relaunched Wallet over the same stores resumes it and receives the
// credentials. A redirect matching nothing is not_found.
func TestSessions_ResumeIssuance(t *testing.T) {
	h := newHarness(t, false)
	offer, err := h.env.AuthorizationCodeOffer()
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.w.StartIssuance(NewOperation(0), offer)
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := s.BeginAuthorization(NewOperation(0))
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := h.env.Approve(authURL)
	if err != nil {
		t.Fatal(err)
	}
	// The app quits, s with it.
	relaunched, err := NewWallet(h.env.ConfigJSON(), h.keys, h.creds, h.env.Provider())
	if err != nil {
		t.Fatal(err)
	}
	if keys := decode[struct {
		KeyIDs []string `json:"key_ids"`
	}](t, mustText(t)(relaunched.HolderKeyIDs())); len(keys.KeyIDs) != 2 {
		t.Errorf("keys in use = %v, want the authorization's instance and DPoP keys", keys.KeyIDs)
	}
	if held := decode[struct{ Credentials []summary }](t, mustText(t)(relaunched.Credentials())); len(held.Credentials) != 0 {
		t.Errorf("the authorization is listed as a credential: %+v", held)
	}
	resumed, err := relaunched.ResumeIssuance(NewOperation(0), redirect)
	if err != nil {
		t.Fatalf("ResumeIssuance: %v", err)
	}
	got := decode[struct{ Credentials []summary }](t, mustText(t)(resumed.RequestCredentials(NewOperation(0))))
	if len(got.Credentials) != 2 {
		t.Errorf("received %+v, want 2 credentials", got)
	}
	if err := resumed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := relaunched.ResumeIssuance(NewOperation(0), redirect); code(err) != CodeNotFound {
		t.Errorf("the redirect again: %v", err)
	}
}

// Without development, receiving credentials needs durable stores.
func TestSessions_ProductionNeedsDurableStores(t *testing.T) {
	h := newHarness(t, false)
	var cfg map[string]any
	if err := json.Unmarshal([]byte(h.env.ConfigJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["development"] = false
	raw, _ := json.Marshal(cfg)
	creds := newGoCredentialStore()
	creds.ephemeral = true
	w, err := NewWallet(string(raw), h.keys, creds, h.env.Provider())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.StartIssuance(NewOperation(0), "openid-credential-offer://?credential_offer=%7B%7D"); err == nil || !strings.Contains(err.Error(), "Durable") {
		t.Errorf("StartIssuance with a store that isn't durable: %v", err)
	}
}

// A received credential's summary carries the issuer's display metadata
// and its expiry; CheckStatus reads its status, and sees a revocation.
func TestSessions_DisplayAndStatus(t *testing.T) {
	h := newHarness(t, false)
	held := h.receive(t)
	type summaryWithDisplay struct {
		ID      string
		Display struct {
			IssuerName string `json:"issuer_name"`
			Name       string
			Logo       *struct{ URI string }
		}
		ValidUntil *time.Time `json:"valid_until"`
		Status     *struct{ Value string }
	}
	list := decode[struct{ Credentials []summaryWithDisplay }](t, mustText(t)(h.w.Credentials()))
	for _, c := range list.Credentials {
		if c.Display.IssuerName != walletflowtest.IssuerName || c.Display.Name == "" || c.Display.Logo == nil ||
			c.ValidUntil == nil || !c.ValidUntil.After(time.Now()) || c.Status != nil {
			t.Errorf("summary = %+v", c)
		}
	}
	check := func(id string) string {
		got := decode[summaryWithDisplay](t, mustText(t)(h.w.CheckStatus(NewOperation(0), id)))
		if got.Status == nil {
			return ""
		}
		return got.Status.Value
	}
	if v := check(held[0].ID); v != "valid" {
		t.Errorf("status = %q, want valid", v)
	}
	h.env.Revoke()
	if v := check(held[0].ID); v != "invalid" {
		t.Errorf("status after Revoke = %q, want invalid", v)
	}
	if _, err := h.w.CheckStatus(NewOperation(0), "no-such"); code(err) != CodeNotFound {
		t.Errorf("an unknown credential: %v", err)
	}
}

// From an issuer offering batches, the wallet holds copies of each
// credential, keeps every copy's key, and each presentation uses a
// fresh copy; the copies survive a relaunch.
func TestSessions_Batch(t *testing.T) {
	env, err := StartBatchTestEnv(false, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	h := harness{env: env, keys: newGoKeyStore(), creds: newGoCredentialStore()}
	if h.w, err = NewWallet(env.ConfigJSON(), h.keys, h.creds, env.Provider()); err != nil {
		t.Fatal(err)
	}
	received := h.receive(t)
	type copies struct {
		ID, Format string
		Copies     int `json:"copies"`
		CopiesLeft int `json:"copies_left"`
	}
	list := func(w *Wallet) []copies {
		return decode[struct{ Credentials []copies }](t, mustText(t)(w.Credentials())).Credentials
	}
	for _, c := range list(h.w) {
		if c.Copies != 3 || c.CopiesLeft != 3 {
			t.Errorf("%s: %d copies, %d left; want 3 and 3", c.Format, c.Copies, c.CopiesLeft)
		}
	}
	if keys := decode[struct {
		KeyIDs []string `json:"key_ids"`
	}](t, mustText(t)(h.w.HolderKeyIDs())); len(keys.KeyIDs) != 7 {
		t.Errorf("keys in use = %d, want every copy's and the refresh grant's instance key: 7", len(keys.KeyIDs))
	}
	sdjwt := checkPresentation(t, h, received)
	relaunched, err := NewWallet(env.ConfigJSON(), h.keys, h.creds, env.Provider())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range list(relaunched) {
		want := 3
		if c.ID == sdjwt {
			want = 2
		}
		if c.CopiesLeft != want {
			t.Errorf("%s after one presentation: %d left, want %d", c.Format, c.CopiesLeft, want)
		}
	}
}

// A credential received with a refresh token is refreshable: refreshing
// it replaces its copies, unused again, under the same ID, also after a
// relaunch, until the grant is revoked (reissue_required). The grant's
// record goes with the last credential using it.
func TestSessions_Refresh(t *testing.T) {
	env, err := StartBatchTestEnv(false, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	h := harness{env: env, keys: newGoKeyStore(), creds: newGoCredentialStore()}
	if h.w, err = NewWallet(env.ConfigJSON(), h.keys, h.creds, env.Provider()); err != nil {
		t.Fatal(err)
	}
	received := h.receive(t)
	type refreshable struct {
		ID          string
		Refreshable bool `json:"refreshable"`
		CopiesLeft  int  `json:"copies_left"`
	}
	for _, c := range decode[struct{ Credentials []refreshable }](t, mustText(t)(h.w.Credentials())).Credentials {
		if !c.Refreshable {
			t.Errorf("%s isn't refreshable", c.ID)
		}
	}
	sdjwt := checkPresentation(t, h, received)
	refresh := func(w *Wallet) refreshable {
		out := decode[struct {
			Credential refreshable
			Deferred   *struct{ ID string }
		}](t, mustText(t)(w.RefreshCredential(NewOperation(0), sdjwt)))
		if out.Deferred != nil || out.Credential.ID != sdjwt {
			t.Fatalf("RefreshCredential = %+v", out)
		}
		return out.Credential
	}
	if c := refresh(h.w); c.CopiesLeft != 3 || !c.Refreshable {
		t.Errorf("refreshed = %+v, want 3 copies left", c)
	}
	relaunched, err := NewWallet(env.ConfigJSON(), h.keys, h.creds, env.Provider())
	if err != nil {
		t.Fatal(err)
	}
	if c := refresh(relaunched); c.CopiesLeft != 3 {
		t.Errorf("refreshed after a relaunch = %+v", c)
	}

	env.RevokeGrants()
	if _, err := relaunched.RefreshCredential(NewOperation(0), sdjwt); code(err) != CodeReissueRequired {
		t.Errorf("after the grant was revoked: %v, want reissue_required", err)
	}
	if _, err := relaunched.RefreshCredential(NewOperation(0), "no-such"); code(err) != CodeNotFound {
		t.Errorf("an unknown credential: %v", err)
	}
	for _, c := range received {
		if err := relaunched.DeleteCredential(c.ID); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.creds.records) != 0 || len(h.keys.keys) != 0 {
		t.Errorf("after deleting both: %d records, %d keys; want none", len(h.creds.records), len(h.keys.keys))
	}
}

// A pending deferred credential's refresh grant and the credential it
// replaces survive the record.
func TestDeferredStore_KeepsGrantAndReplaces(t *testing.T) {
	ctx := context.Background()
	s := deferredStore{newGoCredentialStore()}
	p := walletflow.PendingDeferred{ID: "d", ConfigurationID: "c", AccessToken: fapi.NewSecret("at"), GrantID: "g", Replaces: "old"}
	if err := s.PutDeferred(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListDeferred(ctx)
	if err != nil || len(got) != 1 || got[0].GrantID != "g" || got[0].Replaces != "old" {
		t.Errorf("ListDeferred = %+v, %v", got, err)
	}
}

// Per Verifier, the same Verifier is shown the same copy again, and its
// candidates say it has seen the credential; a record keeps that
// across a relaunch.
func TestSessions_CopyPolicyPerVerifier(t *testing.T) {
	env, err := StartBatchTestEnv(false, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	var cfg map[string]any
	if err := json.Unmarshal([]byte(env.ConfigJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["copy_policy"] = "per_verifier"
	raw, _ := json.Marshal(cfg)
	h := harness{env: env, keys: newGoKeyStore(), creds: newGoCredentialStore()}
	if h.w, err = NewWallet(string(raw), h.keys, h.creds, env.Provider()); err != nil {
		t.Fatal(err)
	}
	var sdjwt string
	for _, c := range h.receive(t) {
		if c.Format == "dc+sd-jwt" {
			sdjwt = c.ID
		}
	}
	type candidate struct {
		ShownToVerifier *bool `json:"shown_to_verifier"`
		LinkableHere    *bool `json:"linkable_here"`
	}
	present := func(w *Wallet) candidate {
		req := decode[struct{ ID, Link string }](t, mustText(t)(h.env.Request("dc+sd-jwt")))
		p, err := w.StartPresentation(NewOperation(0), req.Link)
		if err != nil {
			t.Fatal(err)
		}
		q := decode[struct {
			Queries []struct{ Credentials []candidate }
		}](t, p.Queries())
		if _, err := p.Respond(NewOperation(0), `{"pid":["`+sdjwt+`"]}`); err != nil {
			t.Fatal(err)
		}
		return q.Queries[0].Credentials[0]
	}
	if c := present(h.w); c.ShownToVerifier == nil || *c.ShownToVerifier || c.LinkableHere == nil || *c.LinkableHere {
		t.Errorf("first presentation's candidate = %+v; want not shown, not linkable", c)
	}
	relaunched, err := NewWallet(string(raw), h.keys, h.creds, env.Provider())
	if err != nil {
		t.Fatal(err)
	}
	if c := present(relaunched); c.ShownToVerifier == nil || !*c.ShownToVerifier || *c.LinkableHere {
		t.Errorf("second presentation's candidate = %+v; want shown to this Verifier, not linkable", c)
	}
	type summary struct {
		ID         string
		CopiesLeft int  `json:"copies_left"`
		Linkable   bool `json:"linkable"`
	}
	for _, c := range decode[struct{ Credentials []summary }](t, mustText(t)(relaunched.Credentials())).Credentials {
		if c.ID == sdjwt && (c.CopiesLeft != 2 || c.Linkable) {
			t.Errorf("after two presentations to one Verifier: %+v; want 2 copies left, not linkable", c)
		}
	}
}

// TestStartPresentation_UntrustedVerifier: a request signed by a
// Verifier whose certificate doesn't chain to verifier_roots is
// untrusted_verifier, not a generic protocol error.
func TestStartPresentation_UntrustedVerifier(t *testing.T) {
	env, err := StartTestEnv(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	var cfg map[string]any
	if err := json.Unmarshal([]byte(env.ConfigJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	// Another CA: the issuer's.
	cfg["verifier_roots"] = cfg["issuer_roots"]
	raw, _ := json.Marshal(cfg)
	w, err := NewWallet(string(raw), newGoKeyStore(), newGoCredentialStore(), env.Provider())
	if err != nil {
		t.Fatal(err)
	}
	req := decode[struct{ ID, Link string }](t, mustText(t)(env.Request("dc+sd-jwt")))
	if _, err := w.StartPresentation(NewOperation(0), req.Link); code(err) != CodeUntrustedVerifier {
		t.Errorf("StartPresentation from an untrusted verifier: %v, want %s", err, CodeUntrustedVerifier)
	}
}

// TestStartPresentation_Registration: a registered Verifier's
// registration and what a request asks beyond it reach the app; an
// unregistered Verifier's is "none".
func TestStartPresentation_Registration(t *testing.T) {
	h := newHarness(t, false)
	h.receive(t)
	type reg struct {
		Status, Name, Purpose, Registrar string
		PrivacyPolicy                    string  `json:"privacy_policy"`
		Claims                           [][]any `json:"claims"`
	}
	type query struct {
		QueryID         string  `json:"query_id"`
		Unregistered    [][]any `json:"unregistered"`
		UnregisteredAll bool    `json:"unregistered_all"`
	}
	start := func(link string) (reg, []query) {
		t.Helper()
		p, err := h.w.StartPresentation(NewOperation(0), link)
		if err != nil {
			t.Fatal(err)
		}
		v := decode[struct{ Registration reg }](t, p.Verifier())
		q := decode[struct{ Queries []query }](t, p.Queries())
		return v.Registration, q.Queries
	}

	within := decode[struct{ ID, Link string }](t, mustText(t)(h.env.RegisteredRequest("dc+sd-jwt", "")))
	r, qs := start(within.Link)
	if r.Status != "verified" || r.Name == "" || r.Purpose != "Testing" || r.Registrar == "" || r.PrivacyPolicy == "" || len(r.Claims) != 2 {
		t.Errorf("registration = %+v", r)
	}
	if len(qs) != 1 || len(qs[0].Unregistered) != 0 || qs[0].UnregisteredAll {
		t.Errorf("within the registration: %+v", qs)
	}

	over := decode[struct{ ID, Link string }](t, mustText(t)(h.env.RegisteredRequest("dc+sd-jwt", "given_name")))
	_, qs = start(over.Link)
	if len(qs) != 1 || len(qs[0].Unregistered) != 1 || fmt.Sprint(qs[0].Unregistered[0]) != "[given_name]" {
		t.Errorf("beyond the registration: %+v", qs)
	}

	plain := decode[struct{ ID, Link string }](t, mustText(t)(h.env.Request("dc+sd-jwt")))
	if r, qs := start(plain.Link); r.Status != "none" || r.Name != "" || len(qs) != 1 || qs[0].Unregistered == nil {
		t.Errorf("an unregistered Verifier: %+v, %+v", r, qs)
	}
}
