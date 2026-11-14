package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// issuerTrust is what the wallet trusts the suite's emulated Credential
// Issuer's credentials by, configured out of band as a deployment's
// wallet is: the CA that issued the SD-JWT VC signing certificate this
// run gave the suite (credential.signing_jwk), the suite's own mdoc
// IACA root for mdocs, which it signs with a document signer of its own
// whatever signing_jwk says, and the CA of the key it signs SD-JWT VC
// Token Status Lists with (server.jwks). A credential the suite issues
// is kept only once it verifies under them (verifyCredentials).
type issuerTrust struct {
	sdJWTRoots      *x509.CertPool
	mdocRoots       *x509.CertPool
	statusListRoots *x509.CertPool
	httpClient      *http.Client
	// revocation checks the SD-JWT VC issuer's and its status list
	// signer's certificates against their CAs' CRLs (crl.go); nil
	// checks none. The suite's mdoc IACA publishes no CRL.
	revocation certrevocation.Checker
}

// suiteIACARootPath is where the suite serves the IACA root its mdoc
// document signer certificates, and its CWT status list signer's,
// chain to (the suite's own config-field catalog: "configure that
// certificate as a trust anchor in the verifier or wallet under
// test").
const suiteIACARootPath = "/mdoc-iaca-root.pem"

// newIssuerTrust builds run's issuerTrust, fetching the suite's IACA
// root from suiteBase over httpClient, which pins the suite's TLS
// certificate.
func newIssuerTrust(ctx context.Context, run *walletRun, suiteBase string, httpClient *http.Client) (issuerTrust, error) {
	sdJWTRoots, err := certPool(run.credentialIssuerCAPEM)
	if err != nil {
		return issuerTrust{}, fmt.Errorf("credential issuer ca: %w", err)
	}
	statusListRoots, err := certPool(run.statusListCAPEM)
	if err != nil {
		return issuerTrust{}, fmt.Errorf("status list ca: %w", err)
	}
	iacaPEM, err := fetchSuiteIACARoot(ctx, httpClient, suiteBase)
	if err != nil {
		return issuerTrust{}, err
	}
	mdocRoots, err := certPool(iacaPEM)
	if err != nil {
		return issuerTrust{}, fmt.Errorf("suite iaca root: %w", err)
	}
	return issuerTrust{sdJWTRoots: sdJWTRoots, mdocRoots: mdocRoots, statusListRoots: statusListRoots, httpClient: httpClient}, nil
}

// fetchSuiteIACARoot GETs the suite's IACA root from suiteBase's origin.
func fetchSuiteIACARoot(ctx context.Context, httpClient *http.Client, suiteBase string) (string, error) {
	base, err := url.Parse(suiteBase)
	if err != nil {
		return "", fmt.Errorf("parse suite url: %w", err)
	}
	target := (&url.URL{Scheme: base.Scheme, Host: base.Host, Path: suiteIACARootPath}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch suite iaca root: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("fetch suite iaca root: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch suite iaca root: %s answered %d", target, res.StatusCode)
	}
	return string(body), nil
}

// certPool is every certificate in pemText, of which there must be at
// least one.
func certPool(pemText string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemText)) {
		return nil, errors.New("holds no PEM certificate")
	}
	return pool, nil
}

// verifyCredentials checks every credential the Credential Issuer
// returned before the wallet would keep it: wallet.VerifyIssuedCredential
// (its signature and certificate chain under trust, its type and
// validity, and its binding to one of
// holders, each holder key binding exactly one credential), then, when
// it references a Token Status List, that its status there is VALID.
func verifyCredentials(ctx context.Context, trust issuerTrust, conf oid4vci.CredentialConfigurationMetadata, credentials []oid4vci.IssuedCredential, holders []crypto.PublicKey) error {
	unbound := append([]crypto.PublicKey(nil), holders...)
	for i, ic := range credentials {
		verified, holder, err := verifyBound(ctx, trust, conf, ic.Credential, unbound)
		if err != nil {
			return fmt.Errorf("credential %d: %w", i, err)
		}
		unbound = append(unbound[:holder], unbound[holder+1:]...)
		if err := checkStatus(ctx, trust, ic.Credential, verified); err != nil {
			return fmt.Errorf("credential %d: status: %w", i, err)
		}
	}
	return nil
}

// verifyBound verifies credential against each of holders until one
// binds it, returning its index.
func verifyBound(ctx context.Context, trust issuerTrust, conf oid4vci.CredentialConfigurationMetadata, credential string, holders []crypto.PublicKey) (wallet.VerifiedIssuedCredential, int, error) {
	// No CredentialIssuer binding (off by default; OID4VCI 1.0 §14.4
	// leaves it to the Wallet): the suite's SD-JWT VCs name their iss
	// without the trailing "/" its metadata's credential_issuer has, so
	// the two never match by simple string comparison. The trust anchors
	// are this run's alone, so they bind the credential to the suite.
	params := wallet.VerifyIssuedCredentialParams{Configuration: conf, Credential: credential, IssuerRoots: trust.sdJWTRoots, IssuerRevocation: trust.revocation}
	if conf.Format == mdoc.CredentialFormat {
		params.IssuerRevocation = nil
		// Its document signer's own profile (mdoc.DefaultDocumentSignerPolicy,
		// IssuerLeafPolicy's default for an mdoc) under the suite's IACA.
		params.IssuerRoots = trust.mdocRoots
	}
	if len(holders) == 0 {
		return wallet.VerifiedIssuedCredential{}, 0, errors.New("more credentials than holder keys proved")
	}
	var errs []error
	for i, h := range holders {
		params.HolderKey = h
		verified, err := wallet.VerifyIssuedCredential(ctx, params)
		if err == nil {
			return verified, i, nil
		}
		errs = append(errs, err)
	}
	return wallet.VerifiedIssuedCredential{}, 0, errors.Join(errs...)
}

// checkStatus checks a verified credential's Token Status List entry is
// VALID, when it has one: an SD-JWT VC's list signed under
// trust.statusListRoots, whose only certificate is the suite's own list
// signer's; an mdoc's under the CA that signed its document signer, as
// ISO/IEC 18013-5 §12.3.6.2 has it (mdoc.StatusTrust). A status naming
// a mechanism this wallet can't check is refused, not taken as none.
func checkStatus(ctx context.Context, trust issuerTrust, credential string, verified wallet.VerifiedIssuedCredential) error {
	if verified.UnrecognizedStatus {
		return errors.New("the credential's status names no mechanism this wallet can check")
	}
	if verified.StatusList == nil {
		return nil
	}
	checker := statuslist.Checker{
		Fetcher: statuslist.Fetcher{HTTP: trust.httpClient, AllowLoopback: true},
		Roots:   trust.statusListRoots,
		Options: statuslist.VerifyOptions{UnboundSigner: statuslist.AnyListSigner, Revocation: trust.revocation},
	}
	if verified.StatusListCWT {
		checker.Options.Revocation = nil
		var err error
		if checker, err = mdocStatusChecker(checker, trust, credential); err != nil {
			return err
		}
	}
	return checker.RequireValid(ctx, *verified.StatusList, verified.StatusListCWT)
}

// mdocStatusChecker is checker for an mdoc's revocation list: the
// certificate its MSO's status names, or else a signer under the CA
// that signed its document signer (mdoc.StatusTrust).
func mdocStatusChecker(checker statuslist.Checker, trust issuerTrust, credential string) (statuslist.Checker, error) {
	raw, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil {
		return checker, err
	}
	issuerSigned, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		return checker, err
	}
	status, path, err := mdoc.IssuerAuthStatus(issuerSigned)
	if err != nil {
		return checker, err
	}
	var ref *mdoc.StatusListRef
	if status != nil {
		ref = status.StatusList
	}
	signerTrust, err := mdoc.StatusTrust(ref, path)
	if err != nil {
		return checker, err
	}
	checker.Roots = trust.mdocRoots
	checker.Options.UnboundSigner = signerTrust.LeafPolicy
	if signerTrust.Roots != nil {
		checker.Roots = signerTrust.Roots
		checker.Options.UnboundSigner = statuslist.AnyListSigner
	}
	return checker, nil
}
