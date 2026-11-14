package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
)

// walletCRL is the CAs the suite's emulated Credential Issuer signs
// SD-JWT VCs (credential.signing_jwk) and their Token Status Lists
// (server.jwks) under, which the wallet trusts and checks for
// revocation against the CRLs this process publishes over https on a
// loopback listener, at the distribution points their certificates
// name: credentialCA, whose CRL revokes revokedSigner's certificate,
// staleCA, whose distribution point serves only an expired CRL, so
// none of its certificates can be checked, and statusCA. The suite's
// mdocs are signed under its own IACA, which publishes no CRL this
// wallet could fetch: they aren't checked.
type walletCRL struct {
	ln                         net.Listener
	credentialCA, statusCA     *conformancecrl.Authority
	staleCA                    *conformancecrl.Authority
	tlsCertPEM, tlsKeyPEM      string
	revokedSigner, staleSigner signerCert
	revocation                 certrevocation.Checker
}

// signerCert is a signing key and the leaf certificate a test CA
// issued for it.
type signerCert struct {
	key     *ecdsa.PrivateKey
	leafPEM string
}

func newWalletCRL() (*walletCRL, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("crl publisher listen: %w", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	host := net.JoinHostPort("localhost", port)
	c := &walletCRL{ln: ln}
	for _, ca := range []struct {
		dst  **conformancecrl.Authority
		name string
	}{
		{&c.credentialCA, "oid4vcgo-wallet-credential-issuer-ca"},
		{&c.statusCA, "oid4vcgo-wallet-status-list-ca"},
		{&c.staleCA, "oid4vcgo-wallet-credential-issuer-stale-ca"},
	} {
		if *ca.dst, err = conformancecrl.NewAuthority(ca.name, conformancecrl.URL(host, ca.name)); err != nil {
			_ = ln.Close()
			return nil, fmt.Errorf("generate %s: %w", ca.name, err)
		}
	}
	if c.tlsCertPEM, c.tlsKeyPEM, err = conformancecert.SelfSignedPEM("localhost", []string{"localhost"}); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("generate crl publisher tls cert: %w", err)
	}
	if c.revokedSigner, err = issueSigner(c.credentialCA, "oid4vcgo-wallet-credential-issuer-revoked"); err != nil {
		_ = ln.Close()
		return nil, err
	}
	if c.staleSigner, err = issueSigner(c.staleCA, "oid4vcgo-wallet-credential-issuer-unchecked"); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return c, nil
}

func issueSigner(ca *conformancecrl.Authority, cn string) (signerCert, error) {
	key, leaf, err := ca.IssueKey(cn, nil)
	if err != nil {
		return signerCert{}, fmt.Errorf("issue %s: %w", cn, err)
	}
	return signerCert{key: key, leafPEM: leaf.CertPEM}, nil
}

// start publishes the CAs' CRLs — credentialCA's revoking
// revokedSigner — and starts the wallet's Refresher against them,
// keeping its checker as revocation.
func (c *walletCRL) start(ctx context.Context) error {
	revoked, err := conformancecert.ParseCertificatePEM(c.revokedSigner.leafPEM)
	if err != nil {
		return err
	}
	credentialCRL, err := c.credentialCA.CRL(revoked)
	if err != nil {
		return err
	}
	statusCRL, err := c.statusCA.CRL()
	if err != nil {
		return err
	}
	expired, err := c.staleCA.ExpiredCRL()
	if err != nil {
		return err
	}
	pub := conformancecrl.Publisher{
		TLSCertificatePEM: c.tlsCertPEM, TLSPrivateKeyPEM: c.tlsKeyPEM,
		CRLs: map[string]string{c.credentialCA.Path(): credentialCRL, c.statusCA.Path(): statusCRL, c.staleCA.Path(): expired},
	}
	if err := pub.ServeOn(c.ln, func(err error) { log.Printf("crl publisher: %v", err) }); err != nil {
		return err
	}
	trust := conformancecrl.Trust{
		DistributionPoints: []conformancecrl.DistributionPoint{
			c.credentialCA.DistributionPoint(), c.statusCA.DistributionPoint(), c.staleCA.DistributionPoint(),
		},
		TLSTrustAnchorsPEM: c.tlsCertPEM,
	}
	crls, err := trust.Start(ctx, log.Printf)
	if err != nil {
		return err
	}
	c.revocation = crls
	log.Printf("checking credential issuer and status list signer certificates for revocation against %d CRL distribution points on %s", len(trust.DistributionPoints), c.ln.Addr())
	return nil
}

// crlControl is a negative control of the wallet's revocation check of
// the credential issuer's certificate: the credential issuance module,
// immediate and plain, under a plan whose credentials the suite signs
// with signer's key. The wallet must refuse the credential it's issued
// with an error wrapping want; the suite, which expects it kept, isn't
// graded.
type crlControl struct {
	name   string
	signer signerCert
	want   error
}

func (c *walletCRL) controls() []crlControl {
	return []crlControl{
		{name: "credential issuer certificate revoked", signer: c.revokedSigner, want: certrevocation.ErrRevoked},
		{name: "credential issuer CA without a current CRL", signer: c.staleSigner, want: certrevocation.ErrNoCurrentCRL},
	}
}

// controlKey is the summary name a control is reported under.
func controlKey(c crlControl) string { return "crl control: " + c.name }

// runCRLControls drives each of crl's controls, each under a plan of
// its own, returning their summary lines by controlKey. A control
// holds when the wallet refused the credential for its reason: its
// line reads CONTROL=REFUSED, which conformance/scripts/lib.sh expects.
func runCRLControls(ctx context.Context, runner moduleRunner, crl *walletCRL, planName string, planVariant map[string]string, modules []conformancesuite.PlanModule) map[string]string {
	var variant map[string]string
	for _, m := range modules {
		if m.TestModule == testNameCredentialIssuance && m.Variant["vci_credential_issuance_mode"] == "immediate" && m.Variant["vci_credential_encryption"] == "plain" {
			variant = m.Variant
		}
	}
	out := make(map[string]string)
	for _, c := range crl.controls() {
		key := controlKey(c)
		log.Printf("--- %s ---", key)
		out[key] = runCRLControl(ctx, runner, planName, planVariant, variant, c)
		log.Printf("%s: %s", key, out[key])
	}
	return out
}

func runCRLControl(ctx context.Context, runner moduleRunner, planName string, planVariant, variant map[string]string, c crlControl) string {
	if variant == nil {
		return "ERROR: the plan lists no immediate, plain credential issuance module to drive the control with"
	}
	signingJWK, err := privateJWKWithX5C(c.signer.key, c.signer.leafPEM)
	if err != nil {
		return "ERROR: " + err.Error()
	}
	planConfig, err := runner.WalletRun.planConfigWith(signingJWK)
	if err != nil {
		return "ERROR: " + err.Error()
	}
	planID, _, err := conformancesuite.CreatePlan(runner.HTTPClient, runner.APIBase, planName, planVariant, planConfig)
	if err != nil {
		return "ERROR: create plan: " + err.Error()
	}
	module, err := conformancesuite.CreateModuleInstance(runner.HTTPClient, runner.APIBase, planID, testNameCredentialIssuance, variant)
	if err != nil {
		return "ERROR: create module instance: " + err.Error()
	}
	moduleRef := " (module " + module.ID + ", " + runner.APIBase + "api/log/" + module.ID + ")"
	if err := conformancesuite.WaitUntilWaiting(runner.HTTPClient, runner.APIBase, module.ID, 10*time.Second); err != nil {
		return "ERROR: wait for module ready: " + err.Error() + moduleRef
	}
	driverErr := runner.driveModule(ctx, module, 1, false, nil)
	suite := "the suite reports " + suiteVerdict(runner, module.ID)
	switch {
	case driverErr == nil:
		return "ERROR: the wallet kept a credential it must refuse (" + suite + ")" + moduleRef
	case !errors.Is(driverErr, c.want) || !strings.Contains(driverErr.Error(), "issuer certificate"):
		return fmt.Sprintf("ERROR: the wallet refused the credential with %q, want its issuer certificate refused with %q (%s)%s", driverErr, c.want, suite, moduleRef)
	}
	return fmt.Sprintf("CONTROL=REFUSED: %v (%s, not graded)%s", driverErr, suite, moduleRef)
}

// suiteVerdict is moduleID's status=result once it settles, stopping
// it if it's still waiting for a wallet that has given up.
func suiteVerdict(runner moduleRunner, moduleID string) string {
	status, result, err := conformancesuite.WaitUntilFinished(runner.HTTPClient, runner.APIBase, moduleID, 15*time.Second)
	if err == nil {
		return status + "=" + result
	}
	if stopErr := conformancesuite.StopModule(runner.HTTPClient, runner.APIBase, moduleID); stopErr != nil {
		return "unfinished (" + err.Error() + "; stop: " + stopErr.Error() + ")"
	}
	return "unfinished, stopped"
}
