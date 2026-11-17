package mobile

import (
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// The issuer trust options reach walletflow.Config, and the metadata
// requirements need their roots.
func TestWalletflowConfig_IssuerTrustOptions(t *testing.T) {
	ca, _ := testcert.CA(t, "metadata root")
	roots := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	wcfg, err := walletConfig(config{
		Development: true, RequireIssuerName: true, AllowForeignIss: true, IssuerMetadataRoots: roots,
		RequireSignedIssuerMetadata: true, RequireIssuerMetadataName: true, MaxIssuerMetadataAgeSeconds: 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !wcfg.RequireIssuerName || !wcfg.AllowForeignIss || wcfg.IssuerMetadataRoots == nil || !wcfg.RequireSignedIssuerMetadata ||
		!wcfg.RequireIssuerMetadataName || wcfg.MaxIssuerMetadataAge != time.Hour {
		t.Errorf("walletflow.Config = %+v", wcfg)
	}
	for name, cfg := range map[string]config{
		"signed metadata required without roots": {Development: true, RequireSignedIssuerMetadata: true},
		"a name required without roots":          {Development: true, RequireIssuerMetadataName: true},
		"a negative max age":                     {Development: true, MaxIssuerMetadataAgeSeconds: -1},
		"roots that aren't PEM":                  {Development: true, IssuerMetadataRoots: "not PEM"},
	} {
		if _, err := walletConfig(cfg); err == nil || !strings.Contains(err.Error(), "issuer_metadata") {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

// The mdoc issuer trust options reach walletflow.Config: an empty
// document type entry names the type with no roots.
func TestWalletflowConfig_MdocIssuerTrust(t *testing.T) {
	ca, _ := testcert.CA(t, "IACA")
	roots := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	wcfg, err := walletConfig(config{
		Development: true, MdocIssuerRoots: roots, MdocIssuerRequireEKU: "1.0.18013.5.1.2", CredentialIssuers: []string{"https://issuer.example"},
		MdocIssuerRootsByDocType: map[string]string{"org.iso.18013.5.1.mDL": roots, "eu.europa.ec.eudi.pid.1": ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	pid, named := wcfg.MdocIssuerRootsByDocType["eu.europa.ec.eudi.pid.1"]
	if wcfg.MdocIssuerRoots == nil || wcfg.MdocIssuerLeafPolicy == nil || wcfg.MdocIssuerRootsByDocType["org.iso.18013.5.1.mDL"] == nil || !named || pid != nil {
		t.Errorf("walletflow.Config = %+v", wcfg)
	}
	for name, cfg := range map[string]config{
		"roots that aren't PEM":         {Development: true, MdocIssuerRoots: "not PEM"},
		"a document type's that aren't": {Development: true, MdocIssuerRootsByDocType: map[string]string{"a": "not PEM"}},
		"an EKU that isn't an OID":      {Development: true, MdocIssuerRequireEKU: "x"},
	} {
		if _, err := walletConfig(cfg); err == nil || !strings.Contains(err.Error(), "mdoc_issuer") {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

// A wallet receiving credentials decides which issuers' offers it
// takes, as walletflow.New requires, in development too:
// credential_issuers; issuer_metadata_roots with
// require_signed_issuer_metadata and require_issuer_metadata_name; or
// allow_any_credential_issuer, alone.
func TestWalletflowConfig_CredentialIssuerTrust(t *testing.T) {
	ca, _ := testcert.CA(t, "root")
	roots := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
	list := []string{"https://issuer.example"}
	for name, tc := range map[string]struct {
		cfg config
		ok  bool
	}{
		"no decision":         {config{}, false},
		"credential_issuers":  {config{CredentialIssuers: list}, true},
		"an empty identifier": {config{CredentialIssuers: []string{""}}, false},
		"signed and named metadata": {config{
			IssuerMetadataRoots: roots, RequireSignedIssuerMetadata: true, RequireIssuerMetadataName: true}, true},
		"signed metadata, not named": {config{IssuerMetadataRoots: roots, RequireSignedIssuerMetadata: true}, false},
		"named metadata, not signed": {config{IssuerMetadataRoots: roots, RequireIssuerMetadataName: true}, false},
		"a list and named metadata": {config{CredentialIssuers: list,
			IssuerMetadataRoots: roots, RequireSignedIssuerMetadata: true, RequireIssuerMetadataName: true}, true},
		"any issuer":            {config{AllowAnyCredentialIssuer: true}, true},
		"any issuer and a list": {config{AllowAnyCredentialIssuer: true, CredentialIssuers: list}, false},
		"any issuer and named metadata": {config{AllowAnyCredentialIssuer: true,
			IssuerMetadataRoots: roots, RequireSignedIssuerMetadata: true, RequireIssuerMetadataName: true}, false},
	} {
		cfg := tc.cfg
		cfg.Development, cfg.IssuerRoots = true, roots
		_, err := walletConfig(cfg)
		if tc.ok && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !tc.ok && code(err) != CodeInvalidInput {
			t.Errorf("%s: %v, want invalid_input", name, err)
		}
	}
	if _, err := walletConfig(config{Development: true}); err != nil {
		t.Errorf("a wallet receiving no credentials: %v", err)
	}
}
