package verifierapp_test

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// status GETs page's status endpoint as c, checking it's never cached
// and carries only the coarse fields.
func (c *dcapiClient) status(page string) (int, map[string]any) {
	c.t.Helper()
	resp := c.do(http.MethodGet, page+"/status", "", nil)
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		c.t.Errorf("status Cache-Control = %q, want no-store", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		c.t.Errorf("status Content-Type = %q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		c.t.Fatalf("status body %s: %v", body, err)
	}
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"expires_in", "rejected", "state"}) {
		c.t.Errorf("status carries %v, want only state, rejected and expires_in", keys)
	}
	return resp.StatusCode, out
}

// The status endpoint follows the request: waiting, a rejected answer
// noted, then answered — without ever carrying what was disclosed.
func TestRequestStatus_Transitions(t *testing.T) {
	iss := newDCAPIIssuer(t)
	c := newDCAPIApp(t, iss)
	answer := openID4VPAnswerer(t, c, iss)
	page := c.startPage(verifierapp.ScenarioAge)

	code, st := c.status(page)
	if code != http.StatusOK || st["state"] != "waiting" || st["rejected"] != false {
		t.Fatalf("a new request: %d %v, want waiting", code, st)
	}
	if left, _ := st["expires_in"].(float64); left <= 0 || left > 600 {
		t.Errorf("expires_in = %v, want within the request's lifetime", st["expires_in"])
	}

	c.askInBrowser(page)
	if status, _ := c.postResponseAs(page, wallet.DCAPIProtocolSigned, answer("https://attacker.example")); status != http.StatusBadRequest {
		t.Fatalf("an answer bound to another origin: status %d, want 400", status)
	}
	if _, st = c.status(page); st["state"] != "waiting" || st["rejected"] != true {
		t.Errorf("after a rejected answer: %v, want still waiting, rejected", st)
	}

	if status, body := c.postResponseAs(page, wallet.DCAPIProtocolSigned, answer(dcapiOrigin)); status != http.StatusNoContent {
		t.Fatalf("response: status %d: %s", status, body)
	}
	if _, st = c.status(page); st["state"] != "answered" {
		t.Errorf("after the answer: %v, want answered", st)
	}
	resp := c.do(http.MethodGet, page+"/status", "", nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	for _, leak := range []string{"age_over_18", "Sale", "mso_mdoc", "valid"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("the status carries %q: %s", leak, body)
		}
	}
}

// Another browser, like an unknown request, gets "ended" and a 404:
// nothing about the page's request.
func TestRequestStatus_OnlyThePagesBrowser(t *testing.T) {
	c := newDCAPIApp(t, newDCAPIIssuer(t))
	page := c.startPage(verifierapp.ScenarioAge)
	other := &dcapiClient{t: t, srv: c.srv}
	for _, tc := range []struct {
		name string
		c    *dcapiClient
		page string
	}{{"another browser", other, page}, {"an unknown request", c, "/demo/requests/no-such-request"}} {
		code, st := tc.c.status(tc.page)
		if code != http.StatusNotFound || st["state"] != "ended" || st["rejected"] != false || st["expires_in"] != float64(0) {
			t.Errorf("%s: %d %v, want 404 ended", tc.name, code, st)
		}
	}
}

// The waiting page polls its status, falls back to refreshing without
// JavaScript, and announces changes in a live region.
func TestRequestPage_Waiting(t *testing.T) {
	c := newDCAPIApp(t, newDCAPIIssuer(t))
	page := c.pageText(c.startPage(verifierapp.ScenarioAge))
	for _, want := range []string{
		`"/status"`, `<noscript><meta http-equiv="refresh" content="2"></noscript>`, `aria-live="polite"`,
		"Choose how to respond", "Scan with a phone", "Use a wallet on this device", "Use this browser's ID",
		`id="dcapi" disabled`, "<summary>For the demo CLI wallet</summary>", `id="copy-link"`, `id="expiry"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the waiting page lacks %q", want)
		}
	}
	if strings.Contains(page, "location.reload(); }, 2000") {
		t.Error("the waiting page still reloads on a timer")
	}
}
