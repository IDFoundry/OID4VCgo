//go:build mobiletest

package mobile

import (
	"strings"
	"testing"
)

// A reader asking for two documents (RequestDocuments) gets both from
// RespondDocuments in one response, and HandleMessage reports each;
// CheckStatus checks both. Malformed answers are invalid_input, and an
// answer the request doesn't allow is invalid_selection, with the
// request still standing.
func TestSessions_ProximityRespondDocuments(t *testing.T) {
	reader := newTestReader(t)
	h := newHarness(t, false).withReaderRoots(t, reader)
	offer, err := h.env.MultiDocumentOffer()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, c := range h.receiveOffer(t, offer) {
		ids[c.DocType] = c.ID
	}
	one, two := ids["org.example.test.1"], ids["org.example.test.2"]
	if one == "" || two == "" {
		t.Fatalf("received %v", ids)
	}
	cfg, ks := readerConfig(t, h, &reader, map[string]any{"status": "check"})
	rd, err := NewProximityReader(cfg, ks)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := h.w.StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	s, err := rd.Start(decode[struct {
		QRCode string `json:"qr_code"`
	}](t, holder.Engagement()).QRCode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestDocuments(`[{"doctype": "org.example.test.1", "elements": {}, "extra": 1}]`); code(err) != CodeInvalidInput {
		t.Errorf("an unknown member: %v, want %s", err, CodeInvalidInput)
	}
	req, err := s.RequestDocuments(`[
		{"doctype": "org.example.test.1", "elements": {"org.example.test.1": ["family_name"]}},
		{"doctype": "org.example.test.2", "elements": {"org.example.test.2": ["family_name", "given_name"]}}]`)
	if err != nil {
		t.Fatal(err)
	}
	if ev := decode[proximityEvent](t, holder.HandleMessage(NewOperation(0), sent(t, decode[struct{ Send string }](t, req).Send))); ev.Event != "request" {
		t.Fatalf("holder: %+v", ev)
	}
	if got := decode[struct {
		Documents []struct {
			DocType string `json:"doctype"`
		}
	}](t, holder.Request()).Documents; len(got) != 2 {
		t.Fatalf("the holder sees %d documents, want 2", len(got))
	}

	for name, tc := range map[string]struct {
		answers string
		want    string
	}{
		"not an array":   {`{`, CodeInvalidInput},
		"unknown member": {`[{"document": 0, "credential_id": "` + one + `", "elements": [], "nope": true}]`, CodeInvalidInput},
		"no document":    {`[{"credential_id": "` + one + `", "elements": [["org.example.test.1","family_name"]]}]`, CodeInvalidInput},
		"none":           {`[]`, CodeInvalidSelection},
		"answered twice": {`[{"document": 0, "credential_id": "` + one + `", "elements": [["org.example.test.1","family_name"]]}, {"document": 0, "credential_id": "` + one + `", "elements": [["org.example.test.1","family_name"]]}]`, CodeInvalidSelection},
		"unrequested":    {`[{"document": 0, "credential_id": "` + one + `", "elements": [["org.example.test.1","given_name"]]}]`, CodeInvalidSelection},
	} {
		if _, err := holder.RespondDocuments(NewOperation(0), tc.answers); code(err) != tc.want {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
	}

	out, err := holder.RespondDocuments(NewOperation(0), `[
		{"document": 1, "credential_id": "`+two+`", "elements": [["org.example.test.2","given_name"]]},
		{"document": 0, "credential_id": "`+one+`", "elements": [["org.example.test.1","family_name"]]}]`)
	if err != nil {
		t.Fatal(err)
	}
	presented := decode[struct {
		Send                string
		Linkable            bool
		LinkableCredentials []string `json:"linkable_credentials"`
	}](t, out)
	if presented.Linkable || presented.LinkableCredentials == nil || len(presented.LinkableCredentials) != 0 {
		t.Errorf("RespondDocuments = %s, want linkable false and linkable_credentials []", out)
	}
	got := decode[struct {
		Event     string
		Documents []struct {
			DocType string `json:"doctype"`
			Claims  map[string]map[string]any
		}
	}](t, s.HandleMessage(sent(t, presented.Send)))
	if got.Event != "verified" || len(got.Documents) != 2 {
		t.Fatalf("HandleMessage = %+v", got)
	}
	if d := got.Documents[0]; d.DocType != "org.example.test.1" || d.Claims["org.example.test.1"]["family_name"] != "Doe" || len(d.Claims["org.example.test.1"]) != 1 {
		t.Errorf("document 0 = %+v", d)
	}
	if d := got.Documents[1]; d.DocType != "org.example.test.2" || d.Claims["org.example.test.2"]["given_name"] != "Jane" || len(d.Claims["org.example.test.2"]) != 1 {
		t.Errorf("document 1 = %+v", d)
	}
	status := decode[struct {
		Status   string
		Statuses []string
	}](t, mustText(t)(s.CheckStatus(NewOperation(0))))
	if status.Status != "valid" || strings.Join(status.Statuses, ",") != "valid,valid" {
		t.Errorf("CheckStatus = %+v", status)
	}
}
