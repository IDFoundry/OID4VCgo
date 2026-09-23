// Command run-modules closes conformance-wallet-vp's own "driven by
// hand" gap: 13 of `oid4vp-1final-wallet-haip-test-plan`'s 14
// `direct_post.jwt` + `x509_hash` + `request_uri_signed` modules
// (confirmed against a real historical plan document, GET
// /api/plan/{id} — not guessed) were originally run live one at a
// time by hand, never as a committed, repeatable tool.
//
// -credential-format drives the exact same 14 modules under either of
// the plan's own VP1FinalWalletCredentialFormat values — "sd_jwt_vc"
// (default) or "iso_mdl" — confirmed live via GET /api/plan/{id}
// against both variant selections before writing this flag's own
// support: the module list itself is completely credential-format-
// agnostic, only the fixture credential/DCQL query/trust anchor this
// binary and this script build differ (see generateWalletVPFixtures/
// buildDCQLCredential and cmd/conformance-wallet-vp/credential.go's own
// issueFixtureMdocCredential). Completes the OID4VP Wallet role's own
// "iso_mdl direct_post.jwt" certification profile.
//
// How this binary gets driven, confirmed live (not assumed from
// conformance/wallet-vp/README.md's own "How the interaction model
// was confirmed" section alone): creating a module does NOT make the
// suite's own internal browser navigate to this binary's
// /authorize on its own — the suite logs "Redirecting to
// authorization endpoint" and then sits WAITING. The actual
// destination — this binary's own suite-network-internal URL, with
// client_id/request_uri query parameters the suite generated — is
// recorded as a structured "redirect_to" field on that same log entry
// (see internal/conformancesuite.LogEntry). This binary drives it by
// polling for that field, substituting the host-published address for
// the suite-internal one (the same "swap hostname:port, keep
// path+query" pattern conformance/verifier's own scripts already use),
// and GETting it directly — cmd/conformance-wallet-vp's own
// handleAuthorize runs the entire flow synchronously within that one
// call.
//
// A positive-behavior module (happy-flow and 5 others) completes to a
// clean FINISHED/PASSED from that alone. Every negative-test module is
// REVIEW-gated instead (the suite's own condition text: "the wallet
// should display an error, a screenshot of which must be uploaded for
// the test to transition to FINISHED") — filled the same proven way
// conformance/verifier's own scripts and
// conformance/issuer/scripts/run-fapi2sp-battery/unblock.go already
// fill one. But per conformance/wallet-vp/README.md's own established
// finding, the suite's own overall verdict on a negative-test module
// isn't the real pass/fail signal (a REVIEW grade there is expected
// regardless of whether this binary's own security check actually
// worked) — this binary's own local HTTP response to the drive GET is:
// a 200 means it presented a credential (wrong, for a negative test);
// a non-200 (with the real Go error as the body, via handleAuthorize's
// own http.Error calls) means it correctly rejected the malformed
// request before ever calling response_uri. This script grades
// negative-test modules on that local signal, not the suite's own
// REVIEW verdict.
//
// `alternate-happy-flow`'s own fragment-carrying redirect_uri (HAIP's
// alternate response variant) needs relaying real fragment content to
// the suite's own "implicit submission" URL, exactly like a real
// browser's window.location.hash + XHR POST would — this binary's own
// GET drops the fragment on the floor (fragments never transmit over
// HTTP by design), so driveOne relays it separately once it sees one.
// The exact wire shape (raw fragment text, INCLUDING the leading '#',
// POSTed as Content-Type: text/plain) was confirmed by decompiling the
// suite's own fapi-test-suite.jar (implicitCallback.html's own
// xhr.send(window.location.hash) and
// CheckUrlFragmentContainsCodeVerifier.java's own literal comparison
// against "#" + code_verifier) rather than guessed — two earlier
// guesses (a bare fragment value with no leading '#', and a
// form-encoded code_verifier=<fragment> body) both failed against the
// live suite with "URL fragment passed to redirect_uri contains more
// than the one expected entry" for exactly this reason.
//
// Usage: go run ./conformance/wallet-vp/scripts/run-modules \
//
//	-suite=https://localhost:8443/ \
//	-walletvp-base=https://localhost:19447
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

const (
	planName              = "oid4vp-1final-wallet-haip-test-plan"
	configOutPath         = "conformance/wallet-vp/oidf-config/haip.config.json"
	dockerComposeYML      = "conformance/wallet-vp/docker-compose.yml"
	restartTimeout        = 30 * time.Second
	redirectTimeout       = 15 * time.Second
	implicitSubmitTimeout = 15 * time.Second
	uploadTimeout         = 10 * time.Second
	moduleTimeout         = 30 * time.Second
	authorizePath         = "/authorize"
)

// positiveTests are driven and expected to complete cleanly on the
// first drive call alone (FINISHED/PASSED or /WARNING) — this
// binary's own local response is a 200.
var positiveTests = []string{
	"oid4vp-1final-wallet-happy-flow",
	"oid4vp-1final-wallet-alternate-happy-flow",
	"oid4vp-1final-wallet-request-uri-method-post",
	"oid4vp-1final-wallet-ignores-unusable-encryption-key",
	"oid4vp-1final-wallet-fewer-claims-than-available",
	"oid4vp-1final-wallet-optional-credential-set",
	"oid4vp-1final-wallet-no-claims-in-dcql-query",
}

// negativeTests are driven the same way, but graded on this binary's
// own local non-200 response (correctly rejected before ever calling
// response_uri) — see this file's own package doc comment for why the
// suite's own REVIEW verdict isn't the real signal here.
var negativeTests = []string{
	"oid4vp-1final-wallet-negative-test-invalid-request-object-signature",
	"oid4vp-1final-wallet-negative-test-mismatched-client-id",
	"oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post",
	"oid4vp-1final-wallet-negative-test-missing-nonce",
	"oid4vp-1final-wallet-negative-test-invalid-client-id-prefix",
	"oid4vp-1final-wallet-negative-test-unknown-transaction-data-type",
	"oid4vp-1final-wallet-negative-test-required-non-matching-credential",
}

// negativeTestExpectedErrorCode names the exact OID4VP §8.1 "error"
// value handleAuthorize's own respondWithError call must send for the
// four negativeTests entries that actually reach response_uri at all
// (the other three — invalid-request-object-signature,
// mismatched-client-id, invalid-client-id-prefix — reject locally
// before response_uri is ever contacted, so there's no error code to
// check). Without this, driveOne's own moduleResultExpected grading
// only ever checked "did some rejection happen," never which code —
// exactly the gap that let redirect-uri-with-direct-post/missing-
// nonce ship as generic "invalid_request" and unknown-transaction-
// data-type/required-non-matching-credential ship with the wrong code
// (invalid_request instead of invalid_transaction_data/access_denied)
// undetected by this script's own local-suite runs, only caught by
// driving the real hosted suite live and reading its own condition
// checks directly (EnsureInvalidTransactionDataError,
// EnsureAuthorizationEndpointErrorIsAccessDenied).
var negativeTestExpectedErrorCode = map[string]string{
	"oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post":    "invalid_request",
	"oid4vp-1final-wallet-negative-test-missing-nonce":                    "invalid_request",
	"oid4vp-1final-wallet-negative-test-unknown-transaction-data-type":    "invalid_transaction_data",
	"oid4vp-1final-wallet-negative-test-required-non-matching-credential": "access_denied",
}

// allMandatoryClaimsTest is oid4vp-1final-wallet-all-mandatory-claims
// — deliberately not in positiveTests above: unlike every other module
// in this plan, it's @VariantNotApplicable for credential_type=custom
// (the suite's own default when a plan never sets that variant, which
// this script's own main plan never did), so it isn't even reachable
// under the same plan/variant crossing the other 14 modules use — it
// needs its own plan with credential_type set to a real value
// (allMandatoryClaimsCredentialType), which makes every module in
// that plan use the suite's own built-in DCQL query for that
// credential type instead of a client-supplied one. Confirmed by
// reading the suite's own VP1FinalWalletAllMandatoryClaims.java and
// VP1FinalWalletCredentialType.java directly, not guessed — this is
// also why it was never caught by this script's own "14/14 confirmed
// live" runs: it was never driven, automated or otherwise, until
// found live against the real hosted suite.
const allMandatoryClaimsTest = "oid4vp-1final-wallet-all-mandatory-claims"

// allMandatoryClaimsCredentialType returns the
// VP1FinalWalletCredentialType variant value matching
// credentialFormat ("sd_jwt_vc" -> "eudi_pid", "iso_mdl" -> "mdl") —
// the two credential types this repo's own fixtures support, out of
// the suite's own three non-custom values (VP1FinalWalletCredentialType
// also has "photoid", which this repo doesn't implement a fixture
// for).
func allMandatoryClaimsCredentialType(credentialFormat string) string {
	if credentialFormat == "iso_mdl" {
		return "mdl"
	}
	return "eudi_pid"
}

// extractSentErrorCode finds handleAuthorize's own "Sent error
// response: <code>: <description>" response text (respondWithError's
// own respondFollowingRedirect call) and returns <code> — ok=false
// when driveBody carries no such line (every negative test that
// rejects locally before response_uri, and every positive-behavior
// module).
func extractSentErrorCode(driveBody string) (code string, ok bool) {
	const marker = "Sent error response: "
	i := strings.Index(driveBody, marker)
	if i < 0 {
		return "", false
	}
	rest := driveBody[i+len(marker):]
	colonIdx := strings.Index(rest, ": ")
	if colonIdx < 0 {
		return "", false
	}
	return rest[:colonIdx], true
}

type generatedConfig struct {
	ListenAddr                     string         `json:"listen_addr"`
	TLSCertificatePEM              string         `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM               string         `json:"tls_private_key_pem"`
	CredentialIssuerPrivateKeyPEM  string         `json:"credential_issuer_private_key_pem"`
	CredentialIssuerCertificatePEM string         `json:"credential_issuer_certificate_pem"`
	HolderPrivateKeyPEM            string         `json:"holder_private_key_pem"`
	VCT                            string         `json:"vct,omitempty"`
	Claims                         map[string]any `json:"claims,omitempty"`

	// CredentialFormat/MdocIssuerPrivateKeyPEM/MdocIssuerCertificatePEM/
	// MdocDocType/MdocNamespace/MdocClaims mirror
	// cmd/conformance-wallet-vp's own Config — see that file's own doc
	// comment. Only set when driving -credential-format iso_mdl.
	CredentialFormat         string         `json:"credential_format,omitempty"`
	MdocIssuerPrivateKeyPEM  string         `json:"mdoc_issuer_private_key_pem,omitempty"`
	MdocIssuerCertificatePEM string         `json:"mdoc_issuer_certificate_pem,omitempty"`
	MdocDocType              string         `json:"mdoc_doc_type,omitempty"`
	MdocNamespace            string         `json:"mdoc_namespace,omitempty"`
	MdocClaims               map[string]any `json:"mdoc_claims,omitempty"`
}

// planConfig is the suite's own oid4vp-1final-wallet-haip-test-plan
// test-configuration body — confirmed live against the real suite API
// (verifier_info deliberately omitted: an empty array there fails
// "Found invalid entries in verifier_info input", confirmed live —
// the field must be absent, not empty).
type planConfig struct {
	Alias       string         `json:"alias"`
	Description string         `json:"description"`
	Credential  planCredential `json:"credential"`
	Client      planClient     `json:"client"`
	Server      planServer     `json:"server"`
}

type planCredential struct {
	TrustAnchorPEM           string `json:"trust_anchor_pem"`
	StatusListTrustAnchorPEM string `json:"status_list_trust_anchor_pem"`
}

type planClient struct {
	AuthorizationEncryptedResponseEnc string   `json:"authorization_encrypted_response_enc"`
	AuthorizationEncryptedResponseAlg string   `json:"authorization_encrypted_response_alg"`
	JWKs                              jwk.Set  `json:"jwks"`
	DCQL                              planDCQL `json:"dcql"`
}

type planDCQL struct {
	Credentials []planDCQLCredential `json:"credentials"`
}

type planDCQLCredential struct {
	ID     string          `json:"id"`
	Format string          `json:"format"`
	Meta   any             `json:"meta"`
	Claims []planDCQLClaim `json:"claims"`
}

// planDCQLMeta is "dc+sd-jwt"'s own Meta shape.
type planDCQLMeta struct {
	VCTValues []string `json:"vct_values"`
}

// planDCQLMdocMeta is "mso_mdoc"'s own Meta shape (Appendix B.3.1.1) —
// planDCQLCredential.Meta's other concrete type, selected by
// credential_format rather than a shared struct, since the two formats'
// own DCQL Credential Query Meta parameters don't overlap at all
// (confirmed against dcql.NewSDJWTVCMeta/NewMdocMeta's own identical
// split).
type planDCQLMdocMeta struct {
	DoctypeValue string `json:"doctype_value"`
}

// planDCQLClaim's own Path is a single top-level claim name for
// "dc+sd-jwt" (e.g. ["given_name"]) but namespace-then-element for
// "mso_mdoc" (e.g. ["org.iso.18013.5.1","given_name"], Appendix
// B.2.4) — both fit the same []string shape, no format-specific type
// needed here.
type planDCQLClaim struct {
	Path []string `json:"path"`
}

type planServer struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}

type moduleResult struct {
	testName string
	localOK  bool // this binary's own drive call returned 200
	status   string
	result   string
	err      error
}

const (
	mdlDocType   = "org.iso.18013.5.1.mDL"
	mdlNamespace = "org.iso.18013.5.1"
)

// fixturePortraitJPEG is a minimal valid 1x1 JPEG, base64-encoded —
// shared by both fixture credentials' own image-bearing mandatory
// claim: ISO/IEC 18013-5 Table 20 requires the mdoc "portrait" data
// element be JPEG or JPEG2000 binary data (§13.4.3, base64-encoded
// since conformanceconfig.BuildMdocNameSpaceElements expects that —
// JSON has no native byte-string type), and the EUDI PID Rulebook's
// own "picture" claim is conventionally the same kind of value (plain
// base64 in this case — SD-JWT VC claims are ordinary JSON, no
// namespace-specific byte-string transform needed).
const fixturePortraitJPEG = "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDoqKKK8s9g/9k="

// fixtureClaims is the "dc+sd-jwt" fixture credential's own claim
// set — covers every mandatory EUDI PID Rulebook data element
// oid4vp-1final-wallet-all-mandatory-claims' own built-in DCQL
// query asks for under credential_type=eudi_pid (this run's own
// client-configured DCQL query, buildDCQLCredential, only ever asks
// for given_name/family_name regardless — the extra claims are simply
// held, undisclosed, for every other module), not just
// given_name/family_name — the exact same "held credential is missing
// a mandatory claim" gap this file's own mdocFixtureClaims already
// found and fixed for mso_mdoc, confirmed to apply equally here by
// reading the suite's own vp1final-wallet-eudi-pid-all-mandatory.json
// DCQL resource directly. "picture" is the one PID-Rulebook claim the
// suite itself treats as optional (a fallback claim_set omits it, and
// EnsurePidPictureClaimDisclosed is only a WARNING) — included anyway
// since holding it costs nothing.
var fixtureClaims = map[string]any{
	"given_name":        "Jean",
	"family_name":       "Dupont",
	"birthdate":         "1980-05-23",
	"place_of_birth":    map[string]any{"country": "FR", "locality": "Paris"},
	"nationalities":     []any{"FR"},
	"issuing_authority": "Conformance Test Authority",
	"issuing_country":   "FR",
	"picture":           fixturePortraitJPEG,
}

// mdocFixtureClaims is the "mso_mdoc" fixture credential's own claim
// set — unlike fixtureClaims above, this covers every ISO/IEC 18013-5
// Table 20 data element marked "M" (mandatory) for org.iso.18013.5.1.mDL,
// not just given_name/family_name: some suite modules (e.g.
// oid4vp-1final-wallet-all-mandatory-claims) query the mdoc via their
// own built-in DCQL query rather than this run's own client-configured
// one (buildDCQLCredential), and that built-in query asks for every
// mandatory element — confirmed live against the real hosted suite,
// which rejected a fixture holding only given_name/family_name with
// "no held credential satisfies this credential query". issuing_country/
// un_distinguishing_sign match generateWalletVPFixtures' own IACA
// country ("FR"; "F" is France's own UN distinguishing sign per
// ISO/IEC 18013-1:2018 Annex F). birth_date/issue_date/expiry_date are
// plain date strings here — BuildMdocNameSpaceElements wraps them in
// the required full-date CBOR tag (Table 20's own "full-date" encoding
// for all three, one consistent choice). driving_privileges follows
// §7.2.4's own DrivingPrivileges CDDL (an array of DrivingPrivilege
// maps, each needing at least "vehicle_category_code").
var mdocFixtureClaims = map[string]any{
	"given_name":             "Jean",
	"family_name":            "Dupont",
	"birth_date":             "1990-01-01",
	"issue_date":             "2024-01-01",
	"expiry_date":            "2034-01-01",
	"issuing_country":        "FR",
	"issuing_authority":      "Conformance Test Authority",
	"document_number":        "123456789",
	"portrait":               fixturePortraitJPEG,
	"un_distinguishing_sign": "F",
	"driving_privileges": []any{
		map[string]any{"vehicle_category_code": "B"},
	},
}

// generateWalletVPFixtures generates every piece of throwaway key
// material and certificate this run needs (TLS listener cert, a holder/
// device key, and either a dedicated Credential Issuer signer+cert+CA
// for "dc+sd-jwt" or an ISO/IEC 18013-5 IACA+Document Signer identity
// for "mso_mdoc" — see credentialFormat), returning the resulting
// generatedConfig plus the trust anchor certificate the suite's own
// "credential.trust_anchor_pem" needs separately (its own mdoc IACA
// trust anchor when no VICAL is configured is the very same
// certificate — confirmed against the suite's own
// AbstractVP1FinalWalletTest.java doc comment, see credential.go's own
// issueFixtureMdocCredential) — split out of main purely to keep it
// under the linter's own cognitive complexity ceiling.
func generateWalletVPFixtures(credentialFormat string) (cfg generatedConfig, trustAnchorCertPEM string, err error) {
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("conformance-wallet-vp", []string{"conformance-wallet-vp", "localhost"})
	if err != nil {
		return generatedConfig{}, "", fmt.Errorf("generate tls cert: %w", err)
	}
	holderKeyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		return generatedConfig{}, "", fmt.Errorf("generate holder key: %w", err)
	}
	cfg = generatedConfig{
		ListenAddr:          ":8443",
		TLSCertificatePEM:   tlsCertPEM,
		TLSPrivateKeyPEM:    tlsKeyPEM,
		HolderPrivateKeyPEM: holderKeyPEM,
	}

	if credentialFormat == "iso_mdl" {
		iacaCert, iacaKey, iacaCertPEM, _, iacaErr := conformancecert.GenerateMdocIACA(
			"conformance-wallet-vp-mdoc-iaca", "FR", "https://example.com/conformance-wallet-vp-mdoc-contact")
		if iacaErr != nil {
			return generatedConfig{}, "", fmt.Errorf("generate mdoc iaca: %w", iacaErr)
		}
		_, dsKeyPEM, dsCertPEM, dsErr := conformancecert.GenerateMdocDocumentSigner(
			"conformance-wallet-vp-mdoc-ds", "FR", "https://example.com/conformance-wallet-vp-mdoc-contact",
			"https://example.com/conformance-wallet-vp-mdoc.crl", iacaCert, iacaKey)
		if dsErr != nil {
			return generatedConfig{}, "", fmt.Errorf("generate mdoc document signer: %w", dsErr)
		}
		cfg.CredentialFormat = "mso_mdoc"
		cfg.MdocIssuerPrivateKeyPEM = dsKeyPEM
		cfg.MdocIssuerCertificatePEM = dsCertPEM
		cfg.MdocDocType = mdlDocType
		cfg.MdocNamespace = mdlNamespace
		cfg.MdocClaims = mdocFixtureClaims
		return cfg, iacaCertPEM, nil
	}

	_, issuerKeyPEM, issuerCertPEM, issuerCACertPEM, credErr := conformancecert.GenerateSignerAndCert(
		"conformance-wallet-vp-credential-issuer", "conformance-wallet-vp-credential-issuer-ca")
	if credErr != nil {
		return generatedConfig{}, "", fmt.Errorf("generate credential issuer key/certificate: %w", credErr)
	}
	cfg.CredentialIssuerPrivateKeyPEM = issuerKeyPEM
	cfg.CredentialIssuerCertificatePEM = issuerCertPEM
	cfg.VCT = "urn:eudi:pid:1"
	cfg.Claims = fixtureClaims
	return cfg, issuerCACertPEM, nil
}

// writeConfigAndMaybeRestart writes cfg to configOutPath and, unless
// skipDockerRestart, restarts the conformance-wallet-vp container and
// waits for it to come back up — split out of main purely to keep it
// under the linter's own cognitive complexity ceiling.
func writeConfigAndMaybeRestart(cfg generatedConfig, httpClient *http.Client, walletVPBase string, skipDockerRestart bool) error {
	cfgRaw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	// 0o644, not 0o600: this file is bind-mounted read-only into
	// conformance-wallet-vp's own container, which (like every
	// cmd/conformance-* image) runs as gcr.io/distroless/static-
	// debian12:nonroot's own fixed uid (65532) — a different uid than
	// whatever process writes this file on the host, so 0o600 leaves
	// the container itself unable to read its own config (confirmed
	// live in CI for the same pattern in conformance-verifier: "open
	// /config.json: permission denied"). Every key/cert here is
	// throwaway, freshly generated per run — never a real production
	// secret — so a host-world-readable file is an acceptable trade
	// for a working readiness check.
	if err := os.WriteFile(configOutPath, cfgRaw, 0o644); err != nil { //nolint:gosec // G306: intentionally looser than 0600 — see the comment above; a throwaway CI config a differently-uid'd container must read
		return fmt.Errorf("write %s: %w", configOutPath, err)
	}
	log.Printf("wrote %s", configOutPath)

	if skipDockerRestart {
		return nil
	}
	if err := restartContainer(); err != nil {
		return fmt.Errorf("restart conformance-wallet-vp container: %w", err)
	}
	log.Print("restarted conformance-wallet-vp container, waiting for it to come up")
	if err := waitReady(httpClient, walletVPBase); err != nil {
		return fmt.Errorf("wait for conformance-wallet-vp: %w", err)
	}
	return nil
}

// moduleResultExpected reports whether res's own outcome matches what
// this script's own combined-summary grading expects — split out of
// main purely to keep it under the linter's own cognitive complexity
// ceiling.
func moduleResultExpected(res moduleResult) bool {
	if res.err != nil {
		return false
	}
	if res.localOK && res.result != "PASSED" && res.result != "WARNING" && res.result != "REVIEW" {
		return false
	}
	if !res.localOK && res.result != "REVIEW" && res.result != "PASSED" {
		return false
	}
	return true
}

// buildDCQLCredential builds this run's own DCQL "credentials" entry —
// "dc+sd-jwt" (cfg.VCT/given_name/family_name, the plan's own default)
// or "mso_mdoc" (cfg.MdocDocType/the same two claims, namespace-prefixed)
// depending on cfg.CredentialFormat — see planDCQLCredential.Meta's own
// doc comment for why Meta itself is untyped.
func buildDCQLCredential(cfg generatedConfig) planDCQLCredential {
	if cfg.CredentialFormat == "mso_mdoc" {
		return planDCQLCredential{
			ID: "cred1", Format: "mso_mdoc",
			Meta: planDCQLMdocMeta{DoctypeValue: cfg.MdocDocType},
			Claims: []planDCQLClaim{
				{Path: []string{cfg.MdocNamespace, "given_name"}},
				{Path: []string{cfg.MdocNamespace, "family_name"}},
			},
		}
	}
	return planDCQLCredential{
		ID: "cred1", Format: "dc+sd-jwt",
		Meta:   planDCQLMeta{VCTValues: []string{cfg.VCT}},
		Claims: []planDCQLClaim{{Path: []string{"given_name"}}, {Path: []string{"family_name"}}},
	}
}

func main() {
	apiBase := flag.String("suite", "https://localhost:8443/", "OIDF conformance suite base URL")
	walletVPBase := flag.String("walletvp-base", "https://localhost:19447", "cmd/conformance-wallet-vp's own host-published base URL")
	walletVPInternalBase := flag.String("walletvp-internal-base", "https://conformance-wallet-vp:8443", "cmd/conformance-wallet-vp's own suite-network-internal base URL")
	alias := flag.String("alias", "oid4vcgo-wallet-vp", "suite plan alias")
	skipDockerRestart := flag.Bool("skip-docker-restart", false, "skip restarting the conformance-wallet-vp container after writing the new config (only safe when the container is already running with matching key material from a prior run of this exact binary)")
	credentialFormat := flag.String("credential-format", "sd_jwt_vc", "credential_format variant to drive: \"sd_jwt_vc\" (default) or \"iso_mdl\" — confirmed live that both drive the exact same 14-module list (see this file's own package doc comment), only the fixture credential/DCQL query/trust anchor differ")
	dumpPlanConfig := flag.Bool("dump-plan-config", false, "print the generated suite-side plan configuration JSON and exit instead of calling POST /api/plan — for a suite instance (e.g. the hosted certification.openid.net) whose admin API needs a login this script has no way to establish; pair with -walletvp-internal-base pointing at a real publicly-reachable URL (e.g. a cloudflared tunnel) and create the plan/module yourself through the suite's own authenticated web UI")

	var driveCfg driveOnlyConfig
	driveOnly := flag.Bool("drive-only", false, "drive a single module instance you already created out-of-band (e.g. through the suite's own web UI) instead of creating a plan/module through the admin API — needs -redirect-url; see -help for the rest")
	flag.StringVar(&driveCfg.testName, "drive-test-name", "", "the suite testName of the module instance -drive-only is driving, for labeling output only")
	flag.StringVar(&driveCfg.redirectURL, "redirect-url", "", "the client_id+request_uri authorization redirect URL shown/logged by the module you created by hand, for -drive-only")
	flag.StringVar(&driveCfg.implicitSubmitURL, "implicit-submit-url", "", "the suite's own implicit-submission URL (its log's implicit_submit.fullUrl field) for -drive-only — only needed for oid4vp-1final-wallet-alternate-happy-flow's fragment-carrying redirect_uri; runDriveOnly errors out asking for it if the drive response carries a fragment and this is empty")
	flag.BoolVar(&driveCfg.negativeTest, "negative-test", false, "grade this -drive-only run as a negative test: a non-200 local response (rejected before ever calling response_uri) is the pass condition, not a 200")
	flag.StringVar(&driveCfg.screenshotOut, "screenshot-out", "", "path to write a negative test's own evidence screenshot to (default: /tmp/<test-name>-evidence.png) — for uploading to the suite's own screenshot-REVIEW gate; only used when -negative-test is set")
	flag.BoolVar(&driveCfg.noScreenshot, "no-screenshot", false, "skip generating an evidence screenshot for a -negative-test run")
	flag.Parse()

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local conformance suite, self-signed certs throughout

	if *driveOnly {
		if err := runDriveOnly(httpClient, driveCfg); err != nil {
			log.Fatal(err)
		}
		return
	}

	cfg, trustAnchorCertPEM, err := generateWalletVPFixtures(*credentialFormat)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err := writeConfigAndMaybeRestart(cfg, httpClient, *walletVPBase, *skipDockerRestart); err != nil {
		log.Fatalf("%v", err)
	}

	clientJWK, err := generateClientJWK()
	if err != nil {
		log.Fatalf("generate plan client signing key: %v", err)
	}

	pc := buildPlanConfig(*alias, "OID4VCgo cmd/conformance-wallet-vp live run", trustAnchorCertPEM, clientJWK, buildDCQLCredential(cfg), *walletVPInternalBase+authorizePath)
	pcRaw, err := json.MarshalIndent(pc, "", "  ")
	if err != nil {
		log.Fatalf("marshal plan config: %v", err)
	}

	// allMandatoryClaimsTest needs its own plan under a real
	// credential_type variant — see that const's own doc comment for
	// why it can't share the main plan above (credential_type=custom,
	// this plan's own implicit default). A fresh client JWK per plan
	// mirrors every other plan this script already creates (client.dcql
	// is included for schema completeness even though the suite
	// ignores it under a non-custom credential_type — see
	// VP1FinalWalletCredentialType.java's own doc comment).
	amcClientJWK, err := generateClientJWK()
	if err != nil {
		log.Fatalf("generate all-mandatory-claims plan client signing key: %v", err)
	}
	amcAlias := *alias + "-all-mandatory-claims"
	amcPC := buildPlanConfig(amcAlias, "OID4VCgo cmd/conformance-wallet-vp live run (all-mandatory-claims)", trustAnchorCertPEM, amcClientJWK, buildDCQLCredential(cfg), *walletVPInternalBase+authorizePath)
	amcPCRaw, err := json.MarshalIndent(amcPC, "", "  ")
	if err != nil {
		log.Fatalf("marshal all-mandatory-claims plan config: %v", err)
	}

	if *dumpPlanConfig {
		if _, err := os.Stdout.Write(pcRaw); err != nil {
			log.Fatal(err)
		}
		fmt.Println()
		fmt.Println("\n--- all-mandatory-claims plan (credential_type=" + allMandatoryClaimsCredentialType(*credentialFormat) + ") ---")
		if _, err := os.Stdout.Write(amcPCRaw); err != nil {
			log.Fatal(err)
		}
		fmt.Println()
		return
	}

	planVariant := map[string]string{"credential_format": *credentialFormat, "response_mode": "direct_post.jwt"} //nolint:gosec // false positive: a suite variant selector value, not a credential
	planID, _, err := conformancesuite.CreatePlan(httpClient, *apiBase, planName, planVariant, pcRaw)
	if err != nil {
		log.Fatalf("create plan: %v", err)
	}
	log.Printf("created plan %s (alias %s)", planID, *alias)
	log.Printf("plan detail: %splan-detail.html?plan=%s", *apiBase, planID)

	amcPlanVariant := map[string]string{ //nolint:gosec // false positive: a suite variant selector value, not a credential
		"credential_format": *credentialFormat, "response_mode": "direct_post.jwt",
		"credential_type": allMandatoryClaimsCredentialType(*credentialFormat),
	}
	amcPlanID, _, err := conformancesuite.CreatePlan(httpClient, *apiBase, planName, amcPlanVariant, amcPCRaw)
	if err != nil {
		log.Fatalf("create all-mandatory-claims plan: %v", err)
	}
	log.Printf("created plan %s (alias %s)", amcPlanID, amcAlias)
	log.Printf("plan detail: %splan-detail.html?plan=%s", *apiBase, amcPlanID)

	moduleVariant := map[string]string{"client_id_prefix": "x509_hash", "request_method": "request_uri_signed", "vp_profile": "haip"}

	var results []moduleResult
	for _, testName := range positiveTests {
		results = append(results, driveOne(httpClient, *apiBase, *walletVPBase, planID, testName, moduleVariant, false))
	}
	for _, testName := range negativeTests {
		results = append(results, driveOne(httpClient, *apiBase, *walletVPBase, planID, testName, moduleVariant, true))
	}
	results = append(results, driveOne(httpClient, *apiBase, *walletVPBase, amcPlanID, allMandatoryClaimsTest, moduleVariant, false))

	log.Print("=== summary ===")
	allExpected := true
	for _, res := range results {
		if !moduleResultExpected(res) {
			allExpected = false
		}
		log.Printf("%-70s localOK=%-5v %s=%s %v", res.testName, res.localOK, res.status, res.result, res.err)
	}
	if !allExpected {
		log.Printf("plan detail: %splan-detail.html?plan=%s", *apiBase, planID)
		log.Printf("all-mandatory-claims plan detail: %splan-detail.html?plan=%s", *apiBase, amcPlanID)
		os.Exit(1)
	}
}

// buildPlanConfig builds the suite's own oid4vp-1final-wallet-haip-
// test-plan configuration body — shared by both plans main creates
// (the primary 14-module one and allMandatoryClaimsTest's own), which
// otherwise differed only in alias/description/client JWK.
func buildPlanConfig(alias, description, trustAnchorCertPEM string, clientJWK jwk.SetEntry, dcqlCredential planDCQLCredential, authorizationEndpoint string) planConfig {
	return planConfig{
		Alias:       alias,
		Description: description,
		Credential:  planCredential{TrustAnchorPEM: trustAnchorCertPEM, StatusListTrustAnchorPEM: trustAnchorCertPEM},
		Client: planClient{
			AuthorizationEncryptedResponseEnc: "A128GCM",
			AuthorizationEncryptedResponseAlg: "ECDH-ES",
			JWKs:                              jwk.Set{Keys: []jwk.SetEntry{clientJWK}},
			DCQL:                              planDCQL{Credentials: []planDCQLCredential{dcqlCredential}},
		},
		Server: planServer{AuthorizationEndpoint: authorizationEndpoint},
	}
}

// driveOne creates one module instance within planID for testName,
// drives it, and grades it per this file's own package doc comment:
// negativeTest modules are graded on the local drive response, not
// the suite's own overall verdict.
func driveOne(httpClient *http.Client, apiBase, walletVPBase, planID, testName string, moduleVariant map[string]string, negativeTest bool) moduleResult {
	res := moduleResult{testName: testName}

	module, err := conformancesuite.CreateModuleInstance(httpClient, apiBase, planID, testName, moduleVariant)
	if err != nil {
		res.err = fmt.Errorf("create module instance: %w", err)
		return res
	}

	redirectTo, err := pollRedirectTo(httpClient, apiBase, module.ID)
	if err != nil {
		res.err = fmt.Errorf("poll redirect_to: %w", err)
		return res
	}
	driveURL := toHostBase(redirectTo, walletVPBase)

	driveResp, err := httpClient.Get(driveURL) //nolint:gosec,noctx // driveURL comes from the suite's own log entry, a trusted local conformance-suite instance, not attacker-controlled
	if err != nil {
		res.err = fmt.Errorf("GET %s: %w", driveURL, err)
		return res
	}
	driveBody, _ := io.ReadAll(driveResp.Body)
	_ = driveResp.Body.Close()
	res.localOK = driveResp.StatusCode == http.StatusOK
	if negativeTest && res.localOK {
		log.Printf("%s: WARNING — this binary returned 200 for a negative test (should have rejected)", testName)
	}
	if wantCode, ok := negativeTestExpectedErrorCode[testName]; ok {
		gotCode, sent := extractSentErrorCode(string(driveBody))
		if !sent {
			res.err = fmt.Errorf("expected an OID4VP error response with code %q, but none was sent (body: %s)", wantCode, driveBody)
			return res
		}
		if gotCode != wantCode {
			res.err = fmt.Errorf("sent error code %q, want %q", gotCode, wantCode)
			return res
		}
	}

	// alternate-happy-flow's own fragment-carrying redirect_uri — see
	// this file's own package doc comment. cmd/conformance-wallet-vp's
	// own handleAuthorize already names the exact URL it followed
	// (fragment included) in its own response text; extract it and
	// relay it to the suite's own implicit-submission URL the same way
	// a real browser's window.location.hash + XHR POST would.
	if fragment, ok := extractFollowedFragment(string(driveBody)); ok {
		if err := relayImplicitFragment(httpClient, apiBase, module.ID, fragment); err != nil {
			res.err = fmt.Errorf("relay implicit fragment: %w", err)
			return res
		}
	}

	// Optional: only negative-test modules need this (see package doc
	// comment) — a short, non-fatal grace period, since a
	// positive-behavior module that already reached FINISHED/PASSED
	// never gets one.
	if entry, ok := pollUpload(httpClient, apiBase, module.ID, uploadTimeout); ok {
		if err := postPlaceholder(httpClient, apiBase, module.ID, entry); err != nil {
			res.err = fmt.Errorf("fill upload placeholder: %w", err)
			return res
		}
	}

	status, result, err := conformancesuite.WaitUntilFinished(httpClient, apiBase, module.ID, moduleTimeout)
	res.status, res.result = status, result
	if err != nil {
		res.err = fmt.Errorf("wait until finished: %w", err)
	}
	return res
}

// pollRedirectTo polls moduleID's own log until a "redirect_to" field
// appears — see this file's own package doc comment for what this is
// and why it's needed instead of the suite driving the flow on its
// own.
func pollRedirectTo(httpClient *http.Client, apiBase, moduleID string) (string, error) {
	deadline := time.Now().Add(redirectTimeout)
	for {
		entries, err := conformancesuite.FetchModuleLog(httpClient, apiBase, moduleID)
		if err == nil {
			for _, e := range entries {
				if e.RedirectTo != "" {
					return e.RedirectTo, nil
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no redirect_to appeared within %s", redirectTimeout)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// extractFollowedFragment finds cmd/conformance-wallet-vp's own
// "Followed redirect_uri: <url>" response text and returns that URL's
// own fragment, INCLUDING the leading '#' — Go's net/url strips it
// from URL.Fragment, but the suite's own
// CheckUrlFragmentContainsCodeVerifier.java compares the submitted
// value literally against "#" + code_verifier, so this works from the
// raw string instead of a parsed URL to match exactly. Returns
// ok=false for a redirect_uri with no fragment (every module besides
// alternate-happy-flow) — nothing to relay.
func extractFollowedFragment(driveBody string) (fragment string, ok bool) {
	const marker = "Followed redirect_uri: "
	i := strings.Index(driveBody, marker)
	if i < 0 {
		return "", false
	}
	rest := driveBody[i+len(marker):]
	if end := strings.Index(rest, "</p>"); end >= 0 {
		rest = rest[:end]
	}
	fragIdx := strings.IndexByte(rest, '#')
	if fragIdx < 0 {
		return "", false
	}
	return rest[fragIdx:], true
}

// relayImplicitFragment polls moduleID's own log for the suite's
// "Created random implicit submission URL" entry (the same
// ImplicitSubmit.FullURL mechanism
// conformance/issuer/scripts/run-fapi2sp-battery/unblock.go already
// uses for a different stuck-point), then POSTs fragment there — raw
// text, Content-Type: text/plain — completing the same round trip the
// suite's own implicitCallback.html JS performs
// (xhr.send(window.location.hash) with an identical Content-type
// header) for a real browser.
func relayImplicitFragment(httpClient *http.Client, apiBase, moduleID, fragment string) error {
	fullURL, err := pollImplicitSubmitURL(httpClient, apiBase, moduleID)
	if err != nil {
		return err
	}
	return postFragment(httpClient, fullURL, fragment)
}

// pollImplicitSubmitURL polls moduleID's own log until a
// "Created random implicit submission URL" entry appears, mirroring
// pollRedirectTo's own polling shape.
func pollImplicitSubmitURL(httpClient *http.Client, apiBase, moduleID string) (string, error) {
	deadline := time.Now().Add(implicitSubmitTimeout)
	for {
		entries, err := conformancesuite.FetchModuleLog(httpClient, apiBase, moduleID)
		if err == nil {
			for _, e := range entries {
				if e.ImplicitSubmit != nil && e.ImplicitSubmit.FullURL != "" {
					return e.ImplicitSubmit.FullURL, nil
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no implicit submission URL appeared within %s", implicitSubmitTimeout)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// pollUpload polls moduleID's own log for an "upload" placeholder for
// up to timeout, returning ok=false (not an error) if none appears —
// unlike pollRedirectTo, a missing upload placeholder is the expected
// outcome for every positive-behavior module.
func pollUpload(httpClient *http.Client, apiBase, moduleID string, timeout time.Duration) (placeholder string, ok bool) {
	deadline := time.Now().Add(timeout)
	for {
		entries, err := conformancesuite.FetchModuleLog(httpClient, apiBase, moduleID)
		if err == nil {
			for _, e := range entries {
				if e.Upload != "" {
					return e.Upload, true
				}
			}
		}
		if time.Now().After(deadline) {
			return "", false
		}
		time.Sleep(300 * time.Millisecond)
	}
}

const placeholderPNGDataURI = "data:image/png;base64," +
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAA" +
	"AAYAAjCB0C8AAAAASUVORK5CYII="

func postPlaceholder(httpClient *http.Client, apiBase, moduleID, placeholder string) error {
	url := fmt.Sprintf("%sapi/log/%s/images/%s", apiBase, moduleID, placeholder)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(placeholderPNGDataURI))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	return nil
}

// toHostBase replaces redirectTo's own suite-network-internal
// scheme+host with hostBase, keeping path+query unchanged — the same
// "swap hostname:port" pattern conformance/verifier's own scripts
// already use.
func toHostBase(redirectTo, hostBase string) string {
	idx := strings.Index(redirectTo, authorizePath)
	if idx == -1 {
		return redirectTo
	}
	return hostBase + redirectTo[idx:]
}

// generateClientJWK builds the suite's own emulated-Verifier signing
// key: a fresh EC P-256 key plus a single self-signed leaf cert as its
// own "x5c" entry — confirmed live that this (unlike
// conformance/verifier's own client certificate) doesn't need a
// separate issuing CA; the suite doesn't independently x5c-chain-
// validate this specific key.
func generateClientJWK() (jwk.SetEntry, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return jwk.SetEntry{}, fmt.Errorf("generate key: %w", err)
	}
	certPEM, err := conformancecert.SelfSignedCertPEMForKey("oid4vcgo-wallet-vp-test-verifier-client", key)
	if err != nil {
		return jwk.SetEntry{}, fmt.Errorf("self-signed cert: %w", err)
	}
	cert, err := conformancecert.ParseCertificatePEM(certPEM)
	if err != nil {
		return jwk.SetEntry{}, fmt.Errorf("parse cert: %w", err)
	}
	privJWK, err := jwk.MarshalPrivate(key)
	if err != nil {
		return jwk.SetEntry{}, fmt.Errorf("marshal private jwk: %w", err)
	}
	return jwk.SetEntry{
		JWK: privJWK,
		Kid: "wallet-vp-test-client-sig", Use: "sig", Alg: "ES256",
		X5C: []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}, nil
}

func restartContainer() error {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("find docker: %w", err)
	}
	cmd := exec.Command(dockerPath, "compose", "-f", dockerComposeYML, "up", "-d", "--build", "--force-recreate") //nolint:gosec // dockerPath comes from exec.LookPath, args are fixed literals
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// waitReady polls walletVPBase until it responds or restartTimeout
// elapses. On a timeout it dumps the container's own logs to stderr —
// a connection refused/timeout here means the container itself never
// bound its port, and without its own stdout/stderr nothing in
// run-all.sh's own output says why (confirmed missing: a real CI run's
// own captured logs showed only the polling timeout, nothing from the
// container itself, on a failure that turned out to be reproducible on
// every run).
func waitReady(httpClient *http.Client, walletVPBase string) error {
	deadline := time.Now().Add(restartTimeout)
	for {
		resp, err := httpClient.Get(walletVPBase + authorizePath)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		if time.Now().After(deadline) {
			dumpContainerLogs()
			return fmt.Errorf("did not become ready within %s: %w", restartTimeout, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// dumpContainerLogs prints dockerComposeYML's own containers' logs to
// stderr — best-effort, since a caller already has a real error to
// report regardless of whether this succeeds.
func dumpContainerLogs() {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return
	}
	cmd := exec.Command(dockerPath, "compose", "-f", dockerComposeYML, "logs", "--no-color", "--tail=200") //nolint:gosec // dockerPath comes from exec.LookPath, args are fixed literals
	out, runErr := cmd.CombinedOutput()
	log.Printf("container logs (%s):\n%s", dockerComposeYML, out)
	if runErr != nil {
		log.Printf("docker compose logs: %v", runErr)
	}
}
