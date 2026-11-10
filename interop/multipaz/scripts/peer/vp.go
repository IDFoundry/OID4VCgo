package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// pidVCT is the SD-JWT VC PID's type, as Multipaz's sample PID has it.
const pidVCT = "urn:eudi:pid:1"

// loopback is where the verifiers listen: IPv4's.
var loopback = net.IPv4(127, 0, 0, 1)

// ca is a CA certificate and its key.
type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// vpState is the OpenID4VP side: the TLS certificate the driver's
// Verifier and cmd/conformance-verifier serve, the latter's Access
// Certificate, and the verifiers started.
type vpState struct {
	verifierBinary string
	dir            string

	tlsCertPEM, tlsKeyPEM string
	tlsRoots              *x509.CertPool
	access                readerKey
	mpzIACAPEM, otherPEM  string

	started int
	procs   []*exec.Cmd
}

// setupVP makes the TLS certificate (for localhost, under a CA of its
// own: go-tls-ca.pem, tls-cert.pem, tls-key.pem, the key PKCS #8 for
// the driver), the verifiers' Access Certificate under OID4VCgo's reader
// CA, and an SD-JWT VC PID in the holder's store, under the IACA.
func (p *peer) setupVP(dir string, iaca, readerCA, other ca) error {
	p.vp.dir = dir
	tlsCA, tlsCAKey, err := newCA("OID4VCgo Multipaz interop TLS CA")
	if err != nil {
		return err
	}
	leaf, leafKey, err := issue(&x509.Certificate{
		Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{loopback, net.IPv6loopback}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, tlsCA, tlsCAKey)
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return err
	}
	p.vp.tlsCertPEM = certPEM(leaf)
	if p.vp.tlsKeyPEM, err = conformancecert.ECKeyPEM(leafKey); err != nil {
		return err
	}
	p.vp.tlsRoots = x509.NewCertPool()
	p.vp.tlsRoots.AddCert(tlsCA)
	for name, content := range map[string]string{
		"go-tls-ca.pem": certPEM(tlsCA), "tls-cert.pem": p.vp.tlsCertPEM,
		"tls-key.pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return err
		}
	}

	cert, key, err := issue(&x509.Certificate{
		Subject: pkix.Name{CommonName: "OID4VCgo Multipaz interop verifier", Country: []string{"US"}}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, readerCA.cert, readerCA.key)
	if err != nil {
		return err
	}
	p.vp.access = readerKey{key: key, chain: []*x509.Certificate{cert, readerCA.cert}}
	p.vp.otherPEM = certPEM(other.cert)
	raw, err := os.ReadFile(filepath.Join(dir, "mpz-iaca.pem")) // #nosec G304 -- the driver's own file
	if err != nil {
		return err
	}
	p.vp.mpzIACAPEM = string(raw)
	return p.issuePID(iaca)
}

// issuePID puts an SD-JWT VC PID in the holder's store, signed under
// iaca, bound to a key from its key store.
func (p *peer) issuePID(iaca ca) error {
	ctx := context.Background()
	signer, signerKey, err := issue(&x509.Certificate{
		Subject:  pkix.Name{CommonName: "OID4VCgo Multipaz interop PID issuer", Country: []string{"US"}},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, iaca.cert, iaca.key)
	if err != nil {
		return err
	}
	k, err := p.keys.NewKey(ctx, walletflow.KeyPurposeHolder)
	if err != nil {
		return err
	}
	jwk, err := attestation.AttestedKey(k.Public())
	if err != nil {
		return err
	}
	now := time.Now()
	exp := now.Add(24 * time.Hour).Unix()
	claims := map[string]any{"family_name": "Mustermann", "given_name": "Erika", "birthdate": "1971-09-01"}
	additional := map[string]any{}
	for name, value := range claims {
		additional[name] = sdjwtvc.SD(value)
	}
	credential, _, err := sdjwtvc.Issue(signerKey, oid4vci.ES256, sdjwtvc.Claims{
		VCT: pidVCT, Iss: "https://oid4vcgo.example", Exp: &exp,
		CNF: map[string]any{"jwk": json.RawMessage(jwk)}, Additional: additional,
	}, sdjwtvc.IssueOptions{IssuerCertificate: signer})
	if err != nil {
		return err
	}
	return p.store.Put(ctx, walletflow.StoredCredential{ // #nosec G101 -- the PID just issued above, not a secret
		ID: "pid", CredentialIssuer: "https://oid4vcgo.example", ConfigurationID: "pid", Format: "dc+sd-jwt", VCT: pidVCT,
		Credential: credential, HolderKeyID: k.ID(), Claims: claims, ReceivedAt: now, ValidUntil: time.Unix(exp, 0),
	})
}

// verifierConfig is cmd/conformance-verifier's Config, as far as the
// run uses it.
type verifierConfig struct {
	ListenAddr                      string   `json:"listen_addr"`
	BaseURL                         string   `json:"base_url"`
	TLSCertificatePEM               string   `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM                string   `json:"tls_private_key_pem"`
	ClientCertificatePEM            string   `json:"client_certificate_pem"`
	ClientPrivateKeyPEM             string   `json:"client_private_key_pem"`
	CredentialFormat                string   `json:"credential_format,omitempty"`
	CredentialIssuerTrustAnchorsPEM string   `json:"credential_issuer_trust_anchors_pem,omitempty"`
	VCT                             string   `json:"vct,omitempty"`
	Claims                          []string `json:"claims,omitempty"`
	Doctype                         string   `json:"doctype,omitempty"`
	Namespace                       string   `json:"namespace,omitempty"`
	MdocClaims                      []string `json:"mdoc_claims,omitempty"`
	MdocTrustAnchorPEM              string   `json:"mdoc_trust_anchor_pem,omitempty"`
	DCAPIOrigins                    []string `json:"dc_api_origins,omitempty"`
}

// verifierStart starts cmd/conformance-verifier asking for req.Format,
// trusting the driver's IACA (req.Trust "mpz") or a CA it never issued
// under ("other"), its Digital Credentials API requests for req.Origin.
func (p *peer) verifierStart(req request) (reply, error) {
	if p.vp.verifierBinary == "" {
		return reply{}, errors.New("no -verifier binary")
	}
	anchor := p.vp.mpzIACAPEM
	if req.Trust == "other" {
		anchor = p.vp.otherPEM
	}
	port, err := freePort()
	if err != nil {
		return reply{}, err
	}
	key, err := conformancecert.ECKeyPEM(p.vp.access.key)
	if err != nil {
		return reply{}, err
	}
	base := "https://localhost:" + strconv.Itoa(port)
	cfg := verifierConfig{
		ListenAddr: net.JoinHostPort(loopback.String(), strconv.Itoa(port)), BaseURL: base,
		TLSCertificatePEM: p.vp.tlsCertPEM, TLSPrivateKeyPEM: p.vp.tlsKeyPEM,
		ClientCertificatePEM: certPEM(p.vp.access.chain[0]), ClientPrivateKeyPEM: key,
		DCAPIOrigins: []string{req.Origin},
	}
	switch req.Format {
	case "dc+sd-jwt":
		cfg.VCT, cfg.Claims, cfg.CredentialIssuerTrustAnchorsPEM = pidVCT, []string{"family_name", "given_name"}, anchor
	case "mso_mdoc":
		cfg.CredentialFormat, cfg.Doctype, cfg.Namespace = "mso_mdoc", docType, nameSpace
		cfg.MdocClaims, cfg.MdocTrustAnchorPEM = requested, anchor
	default:
		return reply{}, fmt.Errorf("unknown format %q", req.Format)
	}
	p.vp.started++
	name := fmt.Sprintf("verifier-%d", p.vp.started)
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return reply{}, err
	}
	config := filepath.Join(p.vp.dir, name+".json")
	if err := os.WriteFile(config, raw, 0o600); err != nil {
		return reply{}, err
	}
	return reply{BaseURL: base}, p.vp.spawn(name, p.vp.verifierBinary, config, cfg.ListenAddr)
}

// stop stops the verifiers started.
func (s *vpState) stop() {
	for _, cmd := range s.procs {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

// presentingWallet is the holder's walletflow wallet for OpenID4VP,
// trusting Verifiers under the driver's reader CA (verifierCA "mpz")
// or a CA it never issued under ("other"), and the driver's TLS
// certificate, which is the peer's.
func (p *peer) presentingWallet(verifierCA string) (*walletflow.Wallet, error) {
	roots := p.mpzReaderCA
	if verifierCA == "other" {
		roots = p.otherRoots
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: p.vp.tlsRoots, MinVersion: tls.VersionTLS12},
	}}
	return walletflow.New(walletflow.Config{
		Development: true, VerifierTrust: wallet.X5CVerifierRoots{Roots: roots},
	}, walletflow.Dependencies{Keys: p.keys, Credentials: p.store, HTTP: client})
}

// walletPresent answers a Verifier's openid4vp: request (req.Request)
// with the held credentials it asks for, cross-device.
func (p *peer) walletPresent(ctx context.Context, req request) (reply, error) {
	w, err := p.presentingWallet(req.VerifierCA)
	if err != nil {
		return reply{}, err
	}
	pres, err := w.StartPresentation(ctx, req.Request)
	if err != nil {
		return reply{}, err
	}
	return respond(ctx, pres)
}

// walletDCAPI answers an OpenID4VP request over the Digital Credentials
// API (req.Protocol, req.Data, from req.Origin).
func (p *peer) walletDCAPI(ctx context.Context, req request) (reply, error) {
	w, err := p.presentingWallet(req.VerifierCA)
	if err != nil {
		return reply{}, err
	}
	pres, err := w.StartDCAPIPresentation(ctx, req.Protocol, []byte(req.Data), req.Origin)
	if err != nil {
		return reply{}, err
	}
	return respond(ctx, pres)
}

// respond answers pres with its default selection: the holder consents
// to what's asked.
func respond(ctx context.Context, pres *walletflow.Presentation) (reply, error) {
	rep := reply{Verifier: pres.Verifier().ClientID}
	sel, err := pres.DefaultSelection(ctx)
	if err != nil {
		return rep, err
	}
	presented, err := pres.Respond(ctx, sel)
	if err != nil {
		return rep, err
	}
	rep.QueryIDs, rep.Data = presented.QueryIDs, string(presented.DCAPIResponse)
	return rep, nil
}

// freePort is a TCP port free on loopback just now.
func freePort() (int, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(loopback.String(), "0"))
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
