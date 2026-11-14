package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// crlListenAddr is cmd/conformance-wallet-vp's https listener for the
// test CAs' CRLs, inside its container, and crlHost where the wallet
// fetches them: its own name on the suite network, so the fetch goes
// over the network like any other distribution point's.
const (
	crlListenAddr = ":8444"
	crlHost       = "conformance-wallet-vp:8444"
)

// verifierPKI is the CAs the suite's emulated Verifier signs Request
// Objects under, which the wallet trusts and checks for revocation: ca,
// whose CRL revokes revoked's certificate, and stale, whose
// distribution point serves only an expired CRL, so none of its
// certificates can be checked.
type verifierPKI struct {
	ca, stale *conformancecrl.Authority
	// revoked and unchecked are client signing keys whose certificates
	// ca revoked, and stale issued: the negative controls'.
	revoked, unchecked jwk.SetEntry
}

// newVerifierPKI builds the Verifier CAs and the wallet's trust in
// them into cfg: its trust anchors, the CRLs its process publishes
// over https (CRLPublisher), and the revocation check against them
// (VerifierCRL).
func newVerifierPKI(cfg *generatedConfig) (verifierPKI, error) {
	ca, err := conformancecrl.NewAuthority("oid4vcgo-wallet-vp-test-verifier-ca", conformancecrl.URL(crlHost, "verifier-ca"))
	if err != nil {
		return verifierPKI{}, fmt.Errorf("generate verifier CA: %w", err)
	}
	stale, err := conformancecrl.NewAuthority("oid4vcgo-wallet-vp-test-verifier-stale-ca", conformancecrl.URL(crlHost, "verifier-stale-ca"))
	if err != nil {
		return verifierPKI{}, fmt.Errorf("generate stale verifier CA: %w", err)
	}
	pki := verifierPKI{ca: ca, stale: stale}
	revoked, revokedLeaf, err := generateClientJWK(ca)
	if err != nil {
		return verifierPKI{}, fmt.Errorf("generate revoked client signing key: %w", err)
	}
	pki.revoked = revoked
	if pki.unchecked, _, err = generateClientJWK(stale); err != nil {
		return verifierPKI{}, fmt.Errorf("generate stale-CA client signing key: %w", err)
	}
	crl, err := ca.CRL(revokedLeaf)
	if err != nil {
		return verifierPKI{}, err
	}
	expired, err := stale.ExpiredCRL()
	if err != nil {
		return verifierPKI{}, err
	}
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("conformance-wallet-vp", []string{"conformance-wallet-vp"})
	if err != nil {
		return verifierPKI{}, fmt.Errorf("generate crl publisher tls cert: %w", err)
	}
	cfg.VerifierTrustAnchorsPEM = ca.CertPEM + stale.CertPEM
	cfg.CRLPublisher = &conformancecrl.Publisher{
		ListenAddr: crlListenAddr, TLSCertificatePEM: tlsCertPEM, TLSPrivateKeyPEM: tlsKeyPEM,
		CRLs: map[string]string{ca.Path(): crl, stale.Path(): expired},
	}
	cfg.VerifierCRL = &conformancecrl.Trust{
		DistributionPoints: []conformancecrl.DistributionPoint{ca.DistributionPoint(), stale.DistributionPoint()},
		TLSTrustAnchorsPEM: tlsCertPEM,
	}
	return pki, nil
}

// crlControl is a negative control of the wallet's revocation check:
// happy-flow, under a plan whose Verifier signs with clientJWK, which
// the wallet must refuse before answering, for the reason refusal
// names (every part of it, as expectation.refusal).
type crlControl struct {
	name      string
	clientJWK jwk.SetEntry
	refusal   []string
}

// untrustedVerifierRevocation is how the wallet's refusal of a
// Request Object whose certificate chain fails its revocation check
// begins.
const untrustedVerifierRevocation = "untrusted verifier: wallet: verifier certificate: certchain: revocation: no verified path passes it: "

func (p verifierPKI) controls() []crlControl {
	return []crlControl{
		{name: "verifier certificate revoked", clientJWK: p.revoked, refusal: []string{
			untrustedVerifierRevocation + "certrevocation: certificate is revoked",
		}},
		{name: "verifier CA without a current CRL", clientJWK: p.unchecked, refusal: []string{
			untrustedVerifierRevocation + "certchain: revocation couldn't be decided: certrevocation: no current CRL from the certificate's issuer",
		}},
	}
}

// controlTestName is the module each control drives: one the wallet
// presents in when it trusts the Verifier.
const controlTestName = "oid4vp-1final-wallet-happy-flow"

// driveCRLControl creates a plan for c, drives its happy-flow and
// grades the wallet's answer: it must refuse, naming c.refusal. The
// suite, which can't know the certificate is revoked, waits for a
// presentation that never comes, so its verdict isn't the control's:
// the module is stopped once graded.
func driveCRLControl(httpClient *http.Client, apiBase, walletVPBase, alias, trustAnchorCertPEM, authorizationEndpoint string, cfg generatedConfig, planVariant, moduleVariant map[string]string, c crlControl) (res moduleResult) {
	exp := expectation{action: actionRefused, result: "not graded", refusal: c.refusal}
	res = moduleResult{testName: "crl control: " + c.name, expected: exp}
	pc := buildPlanConfig(alias+"-crl-"+strings.ReplaceAll(c.name, " ", "-"), "OID4VCgo cmd/conformance-wallet-vp CRL control: "+c.name, trustAnchorCertPEM, c.clientJWK, buildDCQLCredential(cfg), authorizationEndpoint)
	pcRaw, err := json.Marshal(pc)
	if err != nil {
		res.err = err
		return res
	}
	planID, _, err := conformancesuite.CreatePlan(httpClient, apiBase, planName, planVariant, pcRaw)
	if err != nil {
		res.err = fmt.Errorf("create plan: %w", err)
		return res
	}
	module, err := conformancesuite.CreateModuleInstance(httpClient, apiBase, planID, controlTestName, moduleVariant)
	if err != nil {
		res.err = fmt.Errorf("create module instance: %w", err)
		return res
	}
	res.moduleID = module.ID
	defer func() {
		if err := conformancesuite.StopModule(httpClient, apiBase, module.ID); err != nil && res.err == nil {
			res.err = fmt.Errorf("stop module: %w", err)
		}
		res.status, res.result = "STOPPED", "not graded"
	}()
	redirectTo, err := pollRedirectTo(httpClient, apiBase, module.ID)
	if err != nil {
		res.err = fmt.Errorf("poll redirect_to: %w", err)
		return res
	}
	driveURL := toHostBase(redirectTo, walletVPBase)
	driveResp, err := httpClient.Get(driveURL) //nolint:gosec,noctx // driveURL comes from the suite's own log entry, a trusted local conformance-suite instance
	if err != nil {
		res.err = fmt.Errorf("GET %s: %w", driveURL, err)
		return res
	}
	driveBody, _ := io.ReadAll(driveResp.Body)
	_ = driveResp.Body.Close()
	res.action = directPostAction(driveResp.StatusCode == http.StatusOK, string(driveBody))
	if res.action != actionRefused {
		res.err = fmt.Errorf("the wallet %s, want %s", res.action, actionRefused)
		return res
	}
	res.refusal = strings.TrimSpace(string(driveBody))
	res.err = checkRefusal(c.refusal, res.refusal)
	return res
}
