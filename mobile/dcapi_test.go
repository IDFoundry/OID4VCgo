//go:build mobiletest

package mobile

import (
	"encoding/json"
	"testing"
)

const dcapiOrigin = "https://verifier.mobile.example"

type dcapiRequest struct{ ID, Protocol, Data, Origin string }

// An OpenID4VP request over the DC API, signed or not and for either
// format, is answered across the boundary as an app would: Verifier
// names the origin, Respond hands back the response's data, which the
// page verifies, and the candidate is recorded as shown to the origin.
func TestDCAPIPresentation(t *testing.T) {
	h := newHarness(t, false)
	h.receive(t)
	for _, tc := range []struct {
		format string
		signed bool
	}{{"dc+sd-jwt", true}, {"mso_mdoc", true}, {"dc+sd-jwt", false}} {
		t.Run(tc.format+map[bool]string{true: " signed", false: " unsigned"}[tc.signed], func(t *testing.T) {
			r := decode[dcapiRequest](t, mustText(t)(h.env.DCAPIRequest(tc.format, dcapiOrigin, tc.signed)))
			p, err := h.w.StartDCAPIPresentation(NewOperation(0), r.Protocol, []byte(r.Data), r.Origin)
			if err != nil {
				t.Fatal(err)
			}
			v := decode[struct {
				ClientID    string `json:"client_id"`
				Name        string
				Origin      string
				ResponseURI string `json:"response_uri"`
			}](t, p.Verifier())
			if v.Origin != dcapiOrigin || v.ResponseURI != "" || (tc.signed && v.Name == "") || (!tc.signed && v.ClientID != "") {
				t.Errorf("Verifier = %s", p.Verifier())
			}
			sel := mustText(t)(p.DefaultSelection())
			var s struct {
				Selection map[string][]string
			}
			if err := json.Unmarshal([]byte(sel), &s); err != nil {
				t.Fatal(err)
			}
			selection, _ := json.Marshal(s.Selection)
			out := decode[struct {
				QueryIDs      []string `json:"query_ids"`
				DCAPIResponse string   `json:"dcapi_response"`
			}](t, mustText(t)(p.Respond(NewOperation(0), string(selection))))
			if len(out.QueryIDs) != 1 || out.DCAPIResponse == "" {
				t.Fatalf("Respond = %+v", out)
			}
			result := decode[struct {
				Status, Error string
				Claims        map[string]any
			}](t, mustText(t)(h.env.DCAPIResult(r.ID, out.DCAPIResponse)))
			if result.Status != "done" {
				t.Fatalf("the page got %+v", result)
			}
		})
	}
	// The origin has now been shown the SD-JWT VC.
	r := decode[dcapiRequest](t, mustText(t)(h.env.DCAPIRequest("dc+sd-jwt", dcapiOrigin, true)))
	p, err := h.w.StartDCAPIPresentation(NewOperation(0), r.Protocol, []byte(r.Data), r.Origin)
	if err != nil {
		t.Fatal(err)
	}
	q := decode[struct {
		Queries []struct {
			Credentials []struct {
				ShownToVerifier bool `json:"shown_to_verifier"`
			}
		}
	}](t, p.Queries())
	if len(q.Queries) != 1 || len(q.Queries[0].Credentials) != 1 || !q.Queries[0].Credentials[0].ShownToVerifier {
		t.Errorf("Queries = %s, want the credential shown to the origin before", p.Queries())
	}
	declined := decode[struct {
		DCAPIResponse string `json:"dcapi_response"`
	}](t, mustText(t)(p.Decline(NewOperation(0))))
	if result := decode[struct{ Status, Error string }](t, mustText(t)(h.env.DCAPIResult(r.ID, declined.DCAPIResponse))); result.Error != "access_denied" {
		t.Errorf("the page got %+v for a refusal, want access_denied", result)
	}
}

// A request that isn't one, or comes with no origin, is refused.
func TestDCAPIPresentation_Garbled(t *testing.T) {
	h := newHarness(t, false)
	if _, err := h.w.StartDCAPIPresentation(NewOperation(0), "openid4vp-v1-signed", []byte(`{"request":"not.a.jws"}`), dcapiOrigin); err == nil {
		t.Fatal("a garbled request was opened")
	}
	if _, err := h.w.StartDCAPIPresentation(NewOperation(0), "openid4vp-v1-signed", []byte(`{}`), ""); code(err) == "" {
		t.Fatalf("no origin: %v", err)
	}
}

// require_signed_dcapi_requests refuses an unsigned request as
// untrusted_verifier, and still opens a signed one.
func TestDCAPIPresentation_RequireSigned(t *testing.T) {
	h := newHarness(t, false)
	var cfg map[string]any
	if err := json.Unmarshal([]byte(h.env.ConfigJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["require_signed_dcapi_requests"] = true
	text, _ := json.Marshal(cfg)
	w, err := NewWallet(string(text), h.keys, h.creds, h.env.Provider())
	if err != nil {
		t.Fatal(err)
	}
	unsigned := decode[dcapiRequest](t, mustText(t)(h.env.DCAPIRequest("dc+sd-jwt", dcapiOrigin, false)))
	if _, err := w.StartDCAPIPresentation(NewOperation(0), unsigned.Protocol, []byte(unsigned.Data), unsigned.Origin); code(err) != CodeUntrustedVerifier {
		t.Errorf("an unsigned request: %v, want %s", err, CodeUntrustedVerifier)
	}
	signed := decode[dcapiRequest](t, mustText(t)(h.env.DCAPIRequest("dc+sd-jwt", dcapiOrigin, true)))
	if _, err := w.StartDCAPIPresentation(NewOperation(0), signed.Protocol, []byte(signed.Data), signed.Origin); err != nil {
		t.Errorf("a signed request: %v", err)
	}
}
