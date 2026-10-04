package issuerapp_test

import (
	"bytes"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/cms"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
)

func upload(t *testing.T, env *demotest.Env, data []byte) (*http.Response, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("passport", "passport.gmrtd")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart: %v", err)
	}
	resp, err := env.HTTP.Post(env.IssuerURL+"/passport", mw.FormDataContentType(), &body)
	if err != nil {
		t.Fatalf("POST /passport: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	page, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, string(page)
}

func TestUpload_RejectsNonPassportFile(t *testing.T) {
	env := demotest.New(t, nil)
	resp, page := upload(t, env, []byte("not a passport"))
	if resp.StatusCode != http.StatusBadRequest || strings.Contains(page, "openid-credential-offer") {
		t.Errorf("status %d, want 400 and no credential offer", resp.StatusCode)
	}
}

func TestUploadPage(t *testing.T) {
	env := demotest.New(t, nil)
	resp, err := env.HTTP.Get(env.IssuerURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / status %d", resp.StatusCode)
	}
}

// TestUpload_Sample uploads a real gmrtd portable passport file through
// the web form when PASSPORT_VDC_SAMPLE points at one (outside this
// repository — see the passport package's TestVerifySample). It checks
// the page offers a credential and logs nothing from the passport.
func TestUpload_Sample(t *testing.T) {
	path := os.Getenv("PASSPORT_VDC_SAMPLE")
	if path == "" {
		t.Skip("PASSPORT_VDC_SAMPLE not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}
	env := demotest.New(t, pool)
	resp, page := upload(t, env, data)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "openid-credential-offer://") {
		t.Errorf("status %d; credential offer present: %v", resp.StatusCode, strings.Contains(page, "openid-credential-offer://"))
	}
	for _, want := range []string{"Confirmation code", `src="data:image/png;base64,`} {
		if !strings.Contains(page, want) {
			t.Errorf("offer page is missing %q", want)
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("offer page Cache-Control = %q, want no-store", resp.Header.Get("Cache-Control"))
	}
}

// TestSampleDocument offers gmrtd's sample passport from the upload
// page's button, as an ordinary passport's credentials, with the page
// saying it wasn't checked.
func TestSampleDocument(t *testing.T) {
	env := demotest.New(t, nil)
	resp, err := env.HTTP.Get(env.IssuerURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	home, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(home), `formaction="/sample"`) {
		t.Error("the upload page has no sample passport button")
	}

	resp, err = env.HTTP.PostForm(env.IssuerURL+"/sample", url.Values{"counter": {"1"}})
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /sample: status %d", resp.StatusCode)
	}
	for _, want := range []string{"Sample passport — issued without checking", "PIN:", issuerapp.MdocConfigurationID} {
		if !strings.Contains(string(page), want) && !strings.Contains(html.UnescapeString(string(page)), want) {
			t.Errorf("the offer page doesn't mention %q", want)
		}
	}
	if strings.Contains(string(page), "Passport verified") {
		t.Error("the sample's offer page says the passport is verified")
	}
	// The wallet app link is the offer itself, not html/template's
	// placeholder for a URL scheme it doesn't trust.
	if !strings.Contains(string(page), `<a href="openid-credential-offer://`) || strings.Contains(string(page), "ZgotmplZ") {
		t.Error("the offer page doesn't link the wallet app to the offer")
	}
}
