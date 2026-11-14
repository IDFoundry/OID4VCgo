package conformanceverifier

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// crlListenAddr is cmd/conformance-verifier's https listener for the
// test CAs' CRLs, inside its container, and crlHost where it fetches
// them: its own name on the suite network, so the fetch goes over the
// network like any other distribution point's.
const (
	crlListenAddr = ":8444"
	crlHost       = verifierService + ":8444"
)

// issuerPKI is the CAs the suite's "Signing JWK" is certified under in
// the "dc+sd-jwt" runs, the key it signs credentials and Status List
// Tokens with: ca, whose CRL revokes the revoked control key's
// certificate, and stale, whose distribution point serves only an
// expired CRL, so none of its certificates can be checked.
type issuerPKI struct {
	ca, stale *conformancecrl.Authority
	// signing, revoked and unchecked are signing JWKs with an x5c
	// chain: the runs' own, and the negative controls'.
	signing, revoked, unchecked jwk.SetEntry
	crl, expired                string
}

func newIssuerPKI(cn, caCN string) (*issuerPKI, error) {
	ca, err := conformancecrl.NewAuthority(caCN, conformancecrl.URL(crlHost, "credential-issuer-ca"))
	if err != nil {
		return nil, fmt.Errorf("generate credential issuer CA: %w", err)
	}
	stale, err := conformancecrl.NewAuthority(caCN+"-stale", conformancecrl.URL(crlHost, "credential-issuer-stale-ca"))
	if err != nil {
		return nil, fmt.Errorf("generate stale credential issuer CA: %w", err)
	}
	p := &issuerPKI{ca: ca, stale: stale}
	if p.signing, _, err = signingJWK(ca, cn); err != nil {
		return nil, err
	}
	var revokedLeaf conformancecrl.Leaf
	if p.revoked, revokedLeaf, err = signingJWK(ca, cn+"-revoked"); err != nil {
		return nil, err
	}
	if p.unchecked, _, err = signingJWK(stale, cn+"-unchecked"); err != nil {
		return nil, err
	}
	if p.crl, err = ca.CRL(revokedLeaf.Cert); err != nil {
		return nil, err
	}
	if p.expired, err = stale.ExpiredCRL(); err != nil {
		return nil, err
	}
	return p, nil
}

// signingJWK is a fresh signing key with a leaf certificate ca issued
// for it as its x5c.
func signingJWK(ca *conformancecrl.Authority, cn string) (jwk.SetEntry, conformancecrl.Leaf, error) {
	key, leaf, err := ca.IssueKey(cn, nil)
	if err != nil {
		return jwk.SetEntry{}, conformancecrl.Leaf{}, fmt.Errorf("generate credential issuer key/certificate: %w", err)
	}
	priv, err := jwk.MarshalPrivate(key)
	if err != nil {
		return jwk.SetEntry{}, conformancecrl.Leaf{}, fmt.Errorf("encode credential issuer private key: %w", err)
	}
	return jwk.SetEntry{JWK: priv, Alg: "ES256", X5C: []string{base64.StdEncoding.EncodeToString(leaf.Cert.Raw)}}, leaf, nil
}

// configureCRL has cfg trust p's CAs, publish their CRLs over https
// and check every issuer and status list signer certificate against
// them (cmd/conformance-verifier's issuer_crl).
func (p *issuerPKI) configureCRL(cfg *Config) error {
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM(verifierService, []string{verifierService})
	if err != nil {
		return fmt.Errorf("generate crl publisher tls cert: %w", err)
	}
	anchors := p.ca.CertPEM + p.stale.CertPEM
	cfg.CredentialIssuerTrustAnchorsPEM = anchors
	cfg.StatusListTrustAnchorsPEM = anchors
	cfg.CRLPublisher = &conformancecrl.Publisher{
		ListenAddr: crlListenAddr, TLSCertificatePEM: tlsCertPEM, TLSPrivateKeyPEM: tlsKeyPEM,
		CRLs: map[string]string{p.ca.Path(): p.crl, p.stale.Path(): p.expired},
	}
	cfg.IssuerCRL = &conformancecrl.Trust{
		DistributionPoints: []conformancecrl.DistributionPoint{p.ca.DistributionPoint(), p.stale.DistributionPoint()},
		TLSTrustAnchorsPEM: tlsCertPEM,
	}
	return nil
}

// CRLControl is a negative control of the Verifier's revocation check:
// happy-flow, under a plan whose credentials the suite signs with
// signingJWK, which the Verifier must refuse for the reason Refusal
// names (every part of it).
type CRLControl struct {
	Name       string
	signingJWK jwk.SetEntry
	Refusal    []string
}

// issuerRevocationRefusal is the result page's reason line for a
// credential whose issuer certificate chain fails the revocation check.
var issuerRevocationRefusal = "reason: " + string(verifier.ReasonUntrustedIssuer)

func (p *issuerPKI) controls() []CRLControl {
	const prefix = "resolve issuer key: certchain: revocation: no verified path passes it: "
	return []CRLControl{
		{Name: "issuer certificate revoked", signingJWK: p.revoked, Refusal: []string{
			issuerRevocationRefusal, prefix + "certrevocation: certificate is revoked",
		}},
		{Name: "issuer CA without a current CRL", signingJWK: p.unchecked, Refusal: []string{
			issuerRevocationRefusal, prefix + "certchain: revocation couldn't be decided: certrevocation: no current CRL from the certificate's issuer",
		}},
	}
}

// controlTestName is the module each control drives: one the Verifier
// accepts when it trusts the issuer.
const controlTestName = "oid4vp-1final-verifier-happy-flow"

// DriveCRLControls drives each of setup's CRL controls: happy-flow,
// under a plan of its own whose credentials are signed under the
// control's certificate. The Verifier must refuse the presentation,
// for the reason the control names; the suite's verdict isn't the
// control's (it can't know the certificate is revoked), so it's
// recorded, not graded. A run with none (the "mso_mdoc" runs, whose
// issuer is the suite's own) drives none.
func DriveCRLControls(setup SetupResult, moduleVariant map[string]string) []ModuleResult {
	var results []ModuleResult
	for _, c := range setup.Controls {
		res := driveCRLControl(setup, moduleVariant, c)
		log.Printf("%s: %s", res.TestName, res.line())
		results = append(results, res)
	}
	return results
}

func driveCRLControl(setup SetupResult, moduleVariant map[string]string, c CRLControl) ModuleResult {
	name := "crl control: " + c.Name
	pc := setup.planConfig
	pc.Alias += "-crl-" + strings.ReplaceAll(c.Name, " ", "-")
	pc.Description += " (CRL control: " + c.Name + ")"
	pc.Credential.SigningJWK = c.signingJWK
	pcRaw, err := json.Marshal(pc)
	if err != nil {
		return ModuleResult{TestName: name, Err: err}
	}
	planID, _, err := conformancesuite.CreatePlan(setup.HTTPClient, setup.APIBase, PlanName, setup.planVariant, pcRaw)
	if err != nil {
		return ModuleResult{TestName: name, Err: fmt.Errorf("create plan: %w", err)}
	}
	res, _ := driveModule(setup, planID, controlTestName, moduleVariant)
	res.TestName = name
	res.Expected = RefuseControl
	if res.Err == nil {
		res.Err = gradeControl(c.Refusal, res.VerifierOutcome, res.VerifierRefusal)
	}
	return res
}

// gradeControl checks the Verifier refused, for the reason want names.
func gradeControl(want []string, verifierOutcome, refusal string) error {
	if verifierOutcome != outcomeFailed {
		return fmt.Errorf("the verifier's result page reports %q, want %q", verifierOutcome, outcomeFailed)
	}
	if len(want) == 0 {
		return errors.New("the control names no refusal")
	}
	return checkRefusal(want, refusal)
}
