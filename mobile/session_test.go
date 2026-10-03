//go:build mobiletest

package mobile

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// goCredentialStore is a CredentialStore in memory, as the app's would
// be.
type goCredentialStore struct {
	mu      sync.Mutex
	records map[string][]byte
	order   []string
}

func newGoCredentialStore() *goCredentialStore {
	return &goCredentialStore{records: map[string][]byte{}}
}

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
	if len(list.Credentials) != 2 || len(h.creds.records) != 2 {
		t.Fatalf("Credentials = %+v; store holds %d", list, len(h.creds.records))
	}
	// Only the two holder keys remain: Close deleted the instance and
	// DPoP keys.
	if len(h.keys.keys) != 2 {
		t.Errorf("keys held = %d, want 2", len(h.keys.keys))
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
	cands := decode[struct {
		Queries []struct {
			QueryID     string `json:"query_id"`
			Credentials []summary
		}
	}](t, p.Candidates())
	if len(cands.Queries) != 2 {
		t.Fatalf("Candidates = %s", p.Candidates())
	}
	var sdjwt string
	for _, c := range received {
		if c.Format == "dc+sd-jwt" {
			sdjwt = c.ID
		}
	}
	chosen := `["` + sdjwt + `"]`
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
	if len(keys.KeyIDs) != len(received) {
		t.Errorf("HolderKeyIDs = %v, want one per credential", keys.KeyIDs)
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

func TestSessions_Deferred(t *testing.T) {
	h := newHarness(t, true)
	offer, err := h.env.AuthorizationCodeOffer()
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.w.StartIssuance(NewOperation(0), offer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
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
	if len(got.Deferred) != 2 || got.Deferred[0].IntervalSeconds <= 0 {
		t.Fatalf("deferred = %+v", got)
	}
	poll := func(id string) (string, error) { return s.PollDeferred(NewOperation(0), id) }
	if st := decode[struct{ Status string }](t, mustText(t)(poll(got.Deferred[0].ID))); st.Status != DeferredPending {
		t.Errorf("before a decision: %+v", st)
	}
	h.env.Decide(true)
	issued := decode[struct {
		Status     string
		Credential *summary
	}](t, mustText(t)(poll(got.Deferred[0].ID)))
	if issued.Status != DeferredIssued || issued.Credential == nil || issued.Credential.ID == "" {
		t.Errorf("after approval: %+v", issued)
	}
	h.env.Decide(false)
	if _, err := poll(got.Deferred[1].ID); code(err) != CodeCredentialDenied {
		t.Errorf("after denial: %v", err)
	}
	if got.Deferred[0].ID == got.Deferred[1].ID || !strings.HasPrefix(got.Deferred[0].ID, "deferred-") || len(got.Deferred[0].ID) < 20 {
		t.Errorf("deferred IDs %q and %q aren't distinct random IDs", got.Deferred[0].ID, got.Deferred[1].ID)
	}
	if _, err := poll("no-such"); code(err) != CodeNotFound {
		t.Errorf("an unknown deferred credential: %v", err)
	}
}

func TestSessions_DeclineAndNoMatch(t *testing.T) {
	h := newHarness(t, false)
	req := decode[struct{ ID, Link string }](t, mustText(t)(h.env.Request("mso_mdoc")))
	p, err := h.w.StartPresentation(NewOperation(0), req.Link)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Candidates(), `"queries":[]`) {
		t.Errorf("Candidates with nothing held = %s", p.Candidates())
	}
	if _, err := p.Respond(NewOperation(0), ""); code(err) != CodeNoMatchingCredential {
		t.Errorf("Respond: %v", err)
	}
	if _, err := p.Preview("not json"); code(err) != CodeInvalidInput {
		t.Errorf("Preview with bad IDs: %v", err)
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
	if _, err := h.w.StartIssuance(NewOperation(1), offer); err != nil && code(err) != CodeCancelled {
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
