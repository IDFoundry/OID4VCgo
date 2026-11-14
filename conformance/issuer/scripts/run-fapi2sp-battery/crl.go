package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
)

// crlListenAddr is cmd/conformance-issuer's https listener for the
// test CAs' CRLs, inside its container; crlPort the port its
// distribution points name, on the issuer's own host on the suite
// network, so the issuer fetches them over the network like any other
// distribution point's.
const (
	crlListenAddr = ":8444"
	crlPort       = "8444"
)

// signer is a signing key and the leaf certificate a test CA issued
// for it.
type signer struct {
	key     *ecdsa.PrivateKey
	leafPEM string
}

// issuerPKI is the CAs the suite's Wallet Attestations and key
// attestations are certified under, which cmd/conformance-issuer
// trusts and checks for revocation: attesterCA, whose CRL revokes
// revokedAttester's certificate, attesterStaleCA, whose distribution
// point serves only an expired CRL, so none of its certificates can be
// checked, and keyAttestationCA.
type issuerPKI struct {
	attesterCA, attesterStaleCA, keyAttestationCA *conformancecrl.Authority

	attester, keyAttestation           signer
	revokedAttester, uncheckedAttester signer

	trust     *conformancecrl.Trust
	publisher *conformancecrl.Publisher
}

func newIssuerPKI(issuerBaseURL string, attesterURI *url.URL) (*issuerPKI, error) {
	u, err := url.Parse(issuerBaseURL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("issuer base url %q has no host for the crl distribution points", issuerBaseURL)
	}
	host := net.JoinHostPort(u.Hostname(), crlPort)
	p := &issuerPKI{}
	for _, ca := range []struct {
		dst  **conformancecrl.Authority
		name string
	}{
		{&p.attesterCA, "run-fapi2sp-battery-attester-ca"},
		{&p.attesterStaleCA, "run-fapi2sp-battery-attester-stale-ca"},
		{&p.keyAttestationCA, "run-fapi2sp-battery-key-attestation-ca"},
	} {
		if *ca.dst, err = conformancecrl.NewAuthority(ca.name, conformancecrl.URL(host, ca.name)); err != nil {
			return nil, fmt.Errorf("generate %s: %w", ca.name, err)
		}
	}
	attesterURIs := []*url.URL{attesterURI}
	issue := func(ca *conformancecrl.Authority, cn string, uris []*url.URL) (signer, error) {
		key, leaf, err := ca.IssueKey(cn, uris)
		if err != nil {
			return signer{}, fmt.Errorf("issue %s: %w", cn, err)
		}
		return signer{key: key, leafPEM: leaf.CertPEM}, nil
	}
	if p.attester, err = issue(p.attesterCA, "run-fapi2sp-battery-attester-leaf", attesterURIs); err != nil {
		return nil, err
	}
	if p.revokedAttester, err = issue(p.attesterCA, "run-fapi2sp-battery-attester-revoked", attesterURIs); err != nil {
		return nil, err
	}
	if p.uncheckedAttester, err = issue(p.attesterStaleCA, "run-fapi2sp-battery-attester-unchecked", attesterURIs); err != nil {
		return nil, err
	}
	if p.keyAttestation, err = issue(p.keyAttestationCA, "run-fapi2sp-battery-key-attestation-leaf", nil); err != nil {
		return nil, err
	}
	revoked, err := conformancecert.ParseCertificatePEM(p.revokedAttester.leafPEM)
	if err != nil {
		return nil, err
	}
	attesterCRL, err := p.attesterCA.CRL(revoked)
	if err != nil {
		return nil, err
	}
	staleCRL, err := p.attesterStaleCA.ExpiredCRL()
	if err != nil {
		return nil, err
	}
	keyAttestationCRL, err := p.keyAttestationCA.CRL()
	if err != nil {
		return nil, err
	}
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM(u.Hostname(), []string{u.Hostname()})
	if err != nil {
		return nil, fmt.Errorf("generate crl publisher tls cert: %w", err)
	}
	p.publisher = &conformancecrl.Publisher{
		ListenAddr: crlListenAddr, TLSCertificatePEM: tlsCertPEM, TLSPrivateKeyPEM: tlsKeyPEM,
		CRLs: map[string]string{
			p.attesterCA.Path(): attesterCRL, p.attesterStaleCA.Path(): staleCRL, p.keyAttestationCA.Path(): keyAttestationCRL,
		},
	}
	p.trust = &conformancecrl.Trust{
		DistributionPoints: []conformancecrl.DistributionPoint{
			p.attesterCA.DistributionPoint(), p.attesterStaleCA.DistributionPoint(), p.keyAttestationCA.DistributionPoint(),
		},
		TLSTrustAnchorsPEM: tlsCertPEM,
	}
	return p, nil
}

// crlControl is a negative control of cmd/conformance-issuer's
// revocation check of Wallet Attestation signers: happy-flow, under a
// plan whose Client Attestations attester signs, which the
// Authorization Server must refuse at PAR with the error response
// code and description name. The suite stops the module there
// (INTERRUPTED=FAILED); its log, which records the PAR response, must
// hold that error, or the control fails.
type crlControl struct {
	name        string
	attester    signer
	code        string
	description string
}

func (p *issuerPKI) controls() []crlControl {
	return []crlControl{
		{name: "attester certificate revoked", attester: p.revokedAttester, code: "invalid_client", description: "attester certificate is revoked"},
		{name: "attester CA without a current CRL", attester: p.uncheckedAttester, code: "server_error", description: "failed to check the attester certificate's revocation status"},
	}
}

// controlKey is the summary name a control is reported under, and
// lib.sh's exceptions name.
func controlKey(c crlControl) string { return "crl control: " + c.name }

// runCRLControl creates a plan for c and drives its plain happy-flow
// (runModule), which must end FAILED, finished or interrupted, with
// the PAR response c names in the module's log. It reports
// CONTROL=REFUSED when it does (conformance/scripts/lib.sh expects
// that), and an ERROR line otherwise.
func runCRLControl(httpClient *http.Client, cfg runModuleConfig, r *run, credentialFormat, proofTypeHint, planName string, planVariant map[string]string, happyFlow map[string]string, c crlControl) string {
	planConfig, err := buildPlanConfigWithAttester(r, credentialFormat, proofTypeHint, c.attester.key, c.attester.leafPEM)
	if err != nil {
		return "ERROR: build plan config: " + err.Error()
	}
	planID, _, err := conformancesuite.CreatePlan(httpClient, cfg.apiBase, planName, planVariant, planConfig)
	if err != nil {
		return "ERROR: create plan: " + err.Error()
	}
	cfg.planID = planID
	outcome := runModule(httpClient, cfg, happyFlowTestName, happyFlow)
	if !strings.HasPrefix(outcome, "FINISHED=FAILED") && !strings.HasPrefix(outcome, "INTERRUPTED=FAILED") {
		return "ERROR: " + outcome + ", want FAILED, refused at PAR"
	}
	moduleID := moduleIDOf(outcome)
	refused, err := loggedErrorResponse(httpClient, cfg.apiBase, moduleID, c.code, c.description)
	if err != nil {
		return "ERROR: fetch module log: " + err.Error() + moduleSuffix(cfg.apiBase, moduleID)
	}
	if !refused {
		return fmt.Sprintf("ERROR: %s, but its log holds no %s %q error response: not refused for the attester certificate's revocation%s", strings.SplitN(outcome, " ", 2)[0], c.code, c.description, moduleSuffix(cfg.apiBase, moduleID))
	}
	return fmt.Sprintf("CONTROL=REFUSED: %s %q (the suite reports %s)", c.code, c.description, outcome)
}

// moduleIDOf is the module id moduleSuffix wrote into outcome.
func moduleIDOf(outcome string) string {
	_, rest, ok := strings.Cut(outcome, "(module ")
	if !ok {
		return ""
	}
	id, _, _ := strings.Cut(rest, ",")
	return id
}

// loggedErrorResponse reports whether moduleID's log records an error
// response with code and description, as the suite logs the endpoint
// responses it parses.
func loggedErrorResponse(httpClient *http.Client, apiBase, moduleID, code, description string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, apiBase+"api/log/"+url.PathEscape(moduleID), nil)
	if err != nil {
		return false, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		body, status, err := conformancesuite.Do(httpClient, req)
		if err == nil && status == http.StatusOK {
			var entries []struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}
			if err := json.Unmarshal(body, &entries); err != nil {
				return false, fmt.Errorf("parse module log: %w", err)
			}
			for _, e := range entries {
				if e.Error == code && e.ErrorDescription == description {
					return true, nil
				}
			}
			return false, nil
		}
		if time.Now().After(deadline) {
			if err == nil {
				err = fmt.Errorf("status %d", status)
			}
			return false, err
		}
		time.Sleep(500 * time.Millisecond)
	}
}
