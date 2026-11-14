package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

// What OID4VCgo's issuer issues the wallet in the issued-credential
// cases: the EUDI PID in both formats, as the fixtures are, under
// configurations of its own.
const (
	issuedSDJWTConfigurationID = "eu.europa.ec.eudi.pid_vc_sd_jwt"
	issuedMdocConfigurationID  = "eu.europa.ec.eudi.pid_mso_mdoc"
	// issuedClientID is the wallet's client_id at the issuer, which the
	// Wallet Provider's attestations name.
	issuedClientID = "oid4vcgo-eudi-verifier-interop-wallet"
	// issuedAttesterIssuer is the Wallet Provider's identifier, every
	// attestation's iss (run-verifier.sh starts it with it).
	issuedAttesterIssuer = "https://wallet-provider.eudi.test"
	// issuedRedirectURI is the wallet's native redirect URI, which the
	// issuer registers; the pre-authorized code flow never uses it.
	issuedRedirectURI = "eu.europa.ec.euidi://authorization"
	issuedSubject     = "eudi-verifier-interop-subject"
)

// issuedClaims are the PID claims the issuer issues, in both formats:
// its SD-JWT VC claims are strings.
var issuedClaims = map[string]string{
	"given_name":        "Jean",
	"family_name":       "Dupont",
	"birth_date":        "1990-01-01",
	"issuing_country":   "FR",
	"issuing_authority": "OID4VCgo interop test authority",
}

// issuerConfig is the subset of cmd/conformance-issuer's Config setup
// writes; run-verifier.sh adds its listener, the Wallet Provider's
// trust and its production setup.
type issuerConfig struct {
	Issuer                            string                        `json:"issuer"`
	TLSCertificatePEM                 string                        `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM                  string                        `json:"tls_private_key_pem"`
	Client                            issuerClient                  `json:"client"`
	CredentialIssuerSigningKeyPEM     string                        `json:"credential_issuer_signing_key_pem"`
	CredentialIssuerCertificatePEM    string                        `json:"credential_issuer_certificate_pem"`
	CredentialRequestDecryptionKeyPEM string                        `json:"credential_request_decryption_key_pem"`
	VCT                               string                        `json:"vct"`
	Claims                            map[string]string             `json:"claims"`
	Scope                             string                        `json:"scope"`
	CredentialConfigurationID         string                        `json:"credential_configuration_id"`
	DefaultSubject                    string                        `json:"default_subject"`
	Mdoc                              *conformanceconfig.MdocConfig `json:"mdoc"`
	StatusLists                       statusListsConfig             `json:"status_lists"`
	DPoPNonces                        bool                          `json:"dpop_nonces"`
}

type statusListsConfig struct {
	BaseURL string `json:"base_url"`
}

type issuerClient struct {
	ID                     string   `json:"id"`
	ApplicationType        string   `json:"application_type"`
	RedirectURIs           []string `json:"redirect_uris"`
	ExpectedAttesterIssuer string   `json:"expected_attester_issuer"`
}

// issuedFiles makes OID4VCgo's issuer for the issued-credential cases,
// at issuerURL (-issued-issuer), its status lists at statusURL
// (-issued-status-url), and what vpholder checks its credentials and
// the verifier against:
//
//	issued-issuer.json          cmd/conformance-issuer's config, but its listener and the Wallet Provider
//	issued-issuer-ca.pem        the CA its SD-JWT VC signer chains to
//	issued-iaca.pem             the IACA its Document Signer chains to
//	issued-issuer-tls-cert.pem  its TLS certificate, self-signed for both URLs' hosts
//	holder-crl-publisher.json   the CRLs vpholder publishes on loopback, at crlHost: both CAs' and the verifier's
//	holder-crl-trust.json       their distribution points, which vpholder checks against
//
// Its SD-JWT VC signer and Document Signer are issued by CAs of their
// own, which publish CRLs at crlHost (the CRL publisher run-verifier.sh's
// wallets run, at CRL_PORT): walletflow at production assurance checks
// both, and the status list signer, against them. The verifier fetches
// its status lists at statusURL, where it reaches the issuer, and trusts
// its TLS certificate as it trusts serve's.
func issuedFiles(files map[string][]byte, issuerURL, statusURL, crlHost string) error {
	u, err := httpsOrigin("-issued-issuer", issuerURL)
	if err != nil {
		return err
	}
	status, err := httpsOrigin("-issued-status-url", statusURL)
	if err != nil {
		return err
	}
	issuerCA, err := conformancecrl.NewAuthority("oid4vcgo-eudi-interop-issued-issuer-ca", conformancecrl.URL(crlHost, "issued-issuer-ca"))
	if err != nil {
		return fmt.Errorf("issued issuer ca: %w", err)
	}
	signerKey, signer, err := issuerCA.IssueKey("oid4vcgo-eudi-interop-issued-issuer", []*url.URL{u})
	if err != nil {
		return fmt.Errorf("issued issuer: %w", err)
	}
	signerKeyPEM, err := conformancecert.ECKeyPEM(signerKey)
	if err != nil {
		return err
	}
	iacaCert, iacaKey, iacaPEM, _, err := conformancecert.GenerateMdocIACA("oid4vcgo-eudi-interop-issued-iaca", "FR", contactURI)
	if err != nil {
		return fmt.Errorf("issued iaca: %w", err)
	}
	iaca, err := conformancecrl.Wrap(iacaCert, iacaKey, conformancecrl.URL(crlHost, "issued-iaca"))
	if err != nil {
		return fmt.Errorf("issued iaca: %w", err)
	}
	_, dsKeyPEM, dsCertPEM, err := conformancecert.GenerateMdocDocumentSigner("oid4vcgo-eudi-interop-issued-ds", "FR", contactURI, iaca.URL, iacaCert, iacaKey)
	if err != nil {
		return fmt.Errorf("issued document signer: %w", err)
	}
	decryptionKeyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		return err
	}
	hosts := []string{u.Hostname()}
	if status.Hostname() != u.Hostname() {
		hosts = append(hosts, status.Hostname())
	}
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM(u.Hostname(), hosts)
	if err != nil {
		return fmt.Errorf("issued issuer tls certificate: %w", err)
	}
	mdocClaims := make(map[string]any, len(issuedClaims))
	for k, v := range issuedClaims {
		mdocClaims[k] = v
	}
	cfg := issuerConfig{
		Issuer: issuerURL, TLSCertificatePEM: tlsCertPEM, TLSPrivateKeyPEM: tlsKeyPEM,
		Client: issuerClient{
			ID: issuedClientID, ApplicationType: "native", RedirectURIs: []string{issuedRedirectURI},
			ExpectedAttesterIssuer: issuedAttesterIssuer,
		},
		CredentialIssuerSigningKeyPEM: signerKeyPEM, CredentialIssuerCertificatePEM: signer.CertPEM,
		CredentialRequestDecryptionKeyPEM: decryptionKeyPEM,
		VCT:                               pidVCT, Claims: issuedClaims, Scope: issuedSDJWTConfigurationID,
		CredentialConfigurationID: issuedSDJWTConfigurationID, DefaultSubject: issuedSubject,
		Mdoc: &conformanceconfig.MdocConfig{
			CredentialConfigurationID: issuedMdocConfigurationID, DocType: pidDocType, Namespace: pidNamespace,
			Claims: mdocClaims, Scope: issuedMdocConfigurationID,
			SignerKeyPEM: dsKeyPEM, CertificatePEM: dsCertPEM, TrustAnchorCertificatePEM: iacaPEM,
		},
		StatusLists: statusListsConfig{BaseURL: statusURL},
		DPoPNonces:  true,
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	files["issued-issuer.json"] = raw
	files["issued-issuer-ca.pem"] = []byte(issuerCA.CertPEM)
	files["issued-iaca.pem"] = []byte(iacaPEM)
	files["issued-issuer-tls-cert.pem"] = []byte(tlsCertPEM)
	return holderCRLFiles(files, crlHost, issuerCA, iaca)
}

// httpsOrigin parses the flag name's value, an https origin.
func httpsOrigin(name, origin string) (*url.URL, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" {
		return nil, fmt.Errorf("%s %q isn't an https origin", name, origin)
	}
	return u, nil
}

// holderCRLFiles writes vpholder's CRL publisher and trust: the issued
// issuer's two CAs' current CRLs and the verifier CA's
// (verifierCRLFiles'), on loopback at crlHost's port, under the CRL
// publisher's TLS certificate.
func holderCRLFiles(files map[string][]byte, crlHost string, cas ...*conformancecrl.Authority) error {
	_, port, err := net.SplitHostPort(crlHost)
	if err != nil {
		return fmt.Errorf("-crl-host %q: %w", crlHost, err)
	}
	pub := conformancecrl.Publisher{
		ListenAddr:        net.JoinHostPort("127.0.0.1", port),
		TLSCertificatePEM: string(files["crl-tls-cert.pem"]), TLSPrivateKeyPEM: string(files["crl-tls-key.pem"]),
		CRLs: map[string]string{string(files["verifier-ca-crl-path.txt"]): string(files["verifier-ca-crl.pem"])},
	}
	trust := conformancecrl.Trust{
		DistributionPoints: []conformancecrl.DistributionPoint{{
			URL: string(files["verifier-ca-crl-url.txt"]), IssuerPEM: string(files["verifier-ca.pem"]),
		}},
		TLSTrustAnchorsPEM: string(files["crl-tls-cert.pem"]),
	}
	for _, ca := range cas {
		current, err := ca.CRL()
		if err != nil {
			return err
		}
		pub.CRLs[ca.Path()] = current
		trust.DistributionPoints = append(trust.DistributionPoints, ca.DistributionPoint())
	}
	for name, v := range map[string]any{"holder-crl-publisher.json": pub, "holder-crl-trust.json": trust} {
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		files[name] = raw
	}
	return nil
}
