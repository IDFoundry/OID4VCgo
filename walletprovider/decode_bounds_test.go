package walletprovider_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// A request body is refused at its bound on tokens, and a key in it is
// decoded as a JWK's members, not as raw JSON (DOS-1 of the 2026-11-18
// audit): a registration padded inside registration_key with many
// small tokens or members is refused at the bound, one with a member a
// JWK doesn't have or in another case is refused, and one with the
// members RFC 7517 registers still decodes.
func TestHandlerDecodesKeysAsJWKs(t *testing.T) {
	var log bytes.Buffer
	h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		d.Logger = slog.New(slog.NewTextHandler(&log, nil))
	})
	handler := h.p.Handler()
	register := func(key string) (int, string) {
		t.Helper()
		log.Reset()
		body := `{"challenge":"x","registration_key":` + key + `,"evidence":{"kind":"fake","data":"e30"}}`
		req := httptest.NewRequest(http.MethodPost, walletprovider.InstancesPath, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code, log.String()
	}
	var members strings.Builder
	members.WriteString(`{"kty":"EC"`)
	for i := 0; members.Len() < walletprovider.MaxRequestBytes-256; i++ {
		fmt.Fprintf(&members, `,"k%d":0`, i)
	}
	members.WriteString("}")
	for name, tc := range map[string]struct{ key, refusal string }{
		"an array":             {`[` + strings.Repeat("0,", walletprovider.MaxRequestBytes/2-256) + `0]`, `too many tokens`},
		"many members":         {members.String(), `too many tokens`},
		"a foreign member":     {`{"kty":"EC","crv":"P-256","pad":0}`, `unknown field \"pad\"`},
		"a case-folded member": {`{"kty":"EC","CRV":"P-256"}`, `names are case-sensitive`},
	} {
		code, logged := register(tc.key)
		if code != http.StatusBadRequest || !strings.Contains(logged, tc.refusal) {
			t.Errorf("%s: %d, logged %.300s; want 400 for %s", name, code, logged, tc.refusal)
		}
	}
	// A JWK with RFC 7517's other members gets past decoding, to the
	// challenge, which is unknown.
	jwk := `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"k","use":"sig","alg":"EdDSA","key_ops":["verify"],"ext":true}`
	if _, logged := register(jwk); strings.Contains(logged, "decoding") || !strings.Contains(logged, "challenge") {
		t.Errorf("a JWK with registered members: logged %.300s, want it refused for its challenge", logged)
	}
}
