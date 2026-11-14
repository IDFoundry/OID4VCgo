package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// issuePreAuthorized redeems a pre-authorized code offer of
// configuration id and returns the one Credential issued.
func (e offersTestEnv) issuePreAuthorized(t *testing.T, id string) string {
	t.Helper()
	offer, _ := e.offer(t, `{"grant":"pre-authorized_code","credential_configuration_ids":["`+id+`"],"by_reference":true}`)
	status, token := e.do(t, e.preAuthorizedTokenRequest(t, offer.Grants.PreAuthorizedCode.PreAuthorizedCode, nil, true))
	if status != http.StatusOK {
		t.Fatalf("token: %d %v", status, token)
	}
	now := time.Now()
	nonceResp := doJSON(t, e.client, mustRequest(t, http.MethodPost, e.cfg.Issuer+"/nonce"))
	holderKey, _ := newKeyPair(t)
	proof, err := buildCredentialProofJWT(holderKey, e.cfg.Client.ID, e.cfg.Issuer, nonceResp["c_nonce"].(string), now)
	if err != nil {
		t.Fatal(err)
	}
	accessToken, _ := token["access_token"].(string)
	cred := postCredentialRequest(t, e.client, e.cfg, e.clientKey, accessToken, now, map[string]any{
		"credential_configuration_id": id, "proofs": map[string][]string{"jwt": {proof}},
	})
	creds, _ := cred["credentials"].([]any)
	if len(creds) != 1 {
		t.Fatalf("credential response = %v, want one credential", cred)
	}
	entry, _ := creds[0].(map[string]any)
	credential, _ := entry["credential"].(string)
	return credential
}

// fetchStatusList GETs uri, asking for accept ("" for no Accept), and
// returns the token and its media type.
func (e offersTestEnv) fetchStatusList(t *testing.T, uri, accept string) ([]byte, string) {
	t.Helper()
	req := mustRequest(t, http.MethodGet, uri)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %s", uri, resp.StatusCode, body)
	}
	return body, resp.Header.Get("Content-Type")
}

// setStatus POSTs a status change to the offers listener's /status.
func (e offersTestEnv) setStatus(t *testing.T, body string) int {
	t.Helper()
	resp, err := http.Post(strings.TrimSuffix(e.offersURL, "/offers")+"/status", "application/json", strings.NewReader(body)) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestStatusLists issues an SD-JWT VC and an mdoc with
// Config.StatusLists set: each names the one list, at its format's
// URI, served signed by its format's issuer; revoking the SD-JWT VC
// through POST /status shows at once at both URIs, and the mdoc stays
// valid.
func TestStatusLists(t *testing.T) {
	mdocCfg := mdocTestConfig(t).Mdoc
	e := startOffersTestServer(t, func(c *Config) {
		c.Mdoc = mdocCfg
		c.StatusLists = &StatusListsConfig{}
	})

	sdjwt := e.issuePreAuthorized(t, e.cfg.CredentialConfigurationID)
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(strings.Split(sdjwt, "~")[0], ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Status map[string]any `json:"status"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	sdRef, err := statuslist.ParseStatusClaim(claims.Status)
	if err != nil {
		t.Fatalf("SD-JWT VC status claim %v: %v", claims.Status, err)
	}
	if sdRef.URI != e.cfg.Issuer+statusListPath {
		t.Fatalf("SD-JWT VC status uri = %q, want %q", sdRef.URI, e.cfg.Issuer+statusListPath)
	}

	raw, err := base64.RawURLEncoding.DecodeString(e.issuePreAuthorized(t, mdocCfg.CredentialConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		t.Fatal(err)
	}
	dsCert, err := conformancecert.ParseCertificatePEM(mdocCfg.CertificatePEM)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := mdoc.Verify(signed, mdocCfg.DocType, dsCert.PublicKey, oid4vci.COSEES256, mdoc.VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if verified.Status == nil || verified.Status.StatusList == nil || verified.Status.StatusList.URI != e.cfg.Issuer+mdocStatusListPath {
		t.Fatalf("mdoc status = %+v, want a status_list at %s", verified.Status, e.cfg.Issuer+mdocStatusListPath)
	}
	mdocRef := statuslist.StatusListRef{Idx: verified.Status.StatusList.Idx, URI: verified.Status.StatusList.URI}
	if mdocRef.Idx == sdRef.Idx {
		t.Fatalf("both credentials have index %d", sdRef.Idx)
	}

	issuerCert, err := e.cfg.credentialIssuerCertificate()
	if err != nil {
		t.Fatal(err)
	}
	check := func(ref statuslist.StatusListRef, cwt bool) statuslist.StatusType {
		t.Helper()
		token, mediaType := e.fetchStatusList(t, ref.URI, "")
		var status statuslist.StatusType
		if cwt {
			if mediaType != statuslist.CWTTokenMediaType {
				t.Fatalf("GET %s served %q, want a CWT", ref.URI, mediaType)
			}
			status, _, err = statuslist.CheckCWT(token, dsCert.PublicKey, oid4vci.COSEES256, ref, statuslist.VerifyOptions{})
		} else {
			if mediaType != statuslist.TokenMediaType {
				t.Fatalf("GET %s served %q, want a JWT", ref.URI, mediaType)
			}
			status, _, err = statuslist.Check(string(token), issuerCert.PublicKey, oid4vci.ES256, ref, statuslist.VerifyOptions{})
		}
		if err != nil {
			t.Fatalf("check %s index %d: %v", ref.URI, ref.Idx, err)
		}
		return status
	}
	if got := check(sdRef, false); got != statuslist.StatusValid {
		t.Fatalf("SD-JWT VC status = %v, want VALID", got)
	}
	if got := check(mdocRef, true); got != statuslist.StatusValid {
		t.Fatalf("mdoc status = %v, want VALID", got)
	}

	for name, body := range map[string]string{
		"unknown uri":    `{"uri":"https://elsewhere.example.com/statuslists/1","idx":0,"status":"INVALID"}`,
		"unknown status": `{"uri":"` + sdRef.URI + `","idx":0,"status":"REVOKED"}`,
		"unknown member": `{"uri":"` + sdRef.URI + `","idx":0,"status":"INVALID","why":"x"}`,
	} {
		if got := e.setStatus(t, body); got != http.StatusBadRequest {
			t.Errorf("%s: POST /status = %d, want 400", name, got)
		}
	}
	revoke, _ := json.Marshal(statusRequest{URI: sdRef.URI, Idx: sdRef.Idx, Status: "INVALID"})
	if got := e.setStatus(t, string(revoke)); got != http.StatusOK {
		t.Fatalf("POST /status = %d, want 200", got)
	}
	if got := check(sdRef, false); got != statuslist.StatusInvalid {
		t.Fatalf("revoked SD-JWT VC status = %v, want INVALID", got)
	}
	if got := check(statuslist.StatusListRef{Idx: sdRef.Idx, URI: mdocRef.URI}, true); got != statuslist.StatusInvalid {
		t.Fatalf("revoked index at the mdoc URI = %v, want INVALID", got)
	}
	if got := check(mdocRef, true); got != statuslist.StatusValid {
		t.Fatalf("mdoc status after revoking the SD-JWT VC = %v, want VALID", got)
	}
}

// TestValidateStatusLists refuses a StatusLists configuration
// newStatusLists couldn't use.
func TestValidateStatusLists(t *testing.T) {
	mdocCfg := mdocTestConfig(t)
	for name, tc := range map[string]struct {
		cfg     Config
		lists   StatusListsConfig
		wantErr bool
	}{
		"empty":                 {cfg: mdocCfg},
		"https origin":          {cfg: mdocCfg, lists: StatusListsConfig{BaseURL: "https://lists.example.com:8443"}},
		"base_url with a path":  {cfg: mdocCfg, lists: StatusListsConfig{BaseURL: "https://lists.example.com/x"}, wantErr: true},
		"http base_url":         {cfg: mdocCfg, lists: StatusListsConfig{BaseURL: "http://lists.example.com"}, wantErr: true},
		"mdoc signer key alone": {cfg: mdocCfg, lists: StatusListsConfig{MdocSignerKeyPEM: "x"}, wantErr: true},
		"mdoc signer, no mdoc":  {cfg: baseTestConfig(t), lists: StatusListsConfig{MdocSignerKeyPEM: "x", MdocSignerCertificatePEM: "y"}, wantErr: true},
	} {
		cfg := tc.cfg
		cfg.StatusLists = &tc.lists
		if err := validateStatusLists(cfg); (err != nil) != tc.wantErr {
			t.Errorf("%s: validateStatusLists = %v, want an error %v", name, err, tc.wantErr)
		}
	}
}
