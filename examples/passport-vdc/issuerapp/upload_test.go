package issuerapp_test

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
)

func upload(t *testing.T, issuerURL string, data []byte) (*http.Response, string) {
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
	resp, err := tlsClients[issuerURL].Post(issuerURL+"/passport", mw.FormDataContentType(), &body)
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
	provider, err := walletprovider.New(providerIssuer)
	if err != nil {
		t.Fatalf("walletprovider.New: %v", err)
	}
	_, issuerURL := startIssuer(t, provider)
	resp, page := upload(t, issuerURL, []byte("not a passport"))
	if resp.StatusCode != http.StatusBadRequest || strings.Contains(page, "openid-credential-offer") {
		t.Errorf("status %d, want 400 and no credential offer", resp.StatusCode)
	}
}

func TestUploadPage(t *testing.T) {
	provider, err := walletprovider.New(providerIssuer)
	if err != nil {
		t.Fatalf("walletprovider.New: %v", err)
	}
	_, issuerURL := startIssuer(t, provider)
	resp, err := tlsClients[issuerURL].Get(issuerURL + "/")
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
	provider, err := walletprovider.New(providerIssuer)
	if err != nil {
		t.Fatalf("walletprovider.New: %v", err)
	}
	_, issuerURL := startIssuerWithMasterList(t, provider)
	resp, page := upload(t, issuerURL, data)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "openid-credential-offer://") {
		t.Errorf("status %d; credential offer present: %v", resp.StatusCode, strings.Contains(page, "openid-credential-offer://"))
	}
}
