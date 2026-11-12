package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// Who attests the wallets: for Multipaz's wallet, at OID4VCgo's issuer,
// and for walletflow, at Multipaz's.
const (
	mpzAttesterIssuer = "https://wallet-provider.multipaz-interop.example"
	goAttesterIssuer  = "https://wallet-provider.oid4vcgo-interop.example"
	// goClientID is walletflow's client_id at Multipaz's issuer.
	goClientID = "oid4vcgo-multipaz-interop-wallet"
)

// vciState is the OpenID4VCI side: the binaries the peer runs, and
// walletflow's Wallet Provider.
type vciState struct {
	setupIssuerBinary, issuerBinary string
	provider                        *provider
}

// signer is a key and its certificate, leaf first, CA last.
type signer struct {
	key   *ecdsa.PrivateKey
	chain []*x509.Certificate
}

// newSigner is a key whose certificate, under a CA of its own, names
// issuer as its common name and its URI.
func newSigner(issuer, caName string) (signer, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return signer{}, err
	}
	key, _, certPEMs, caPEM, err := conformancecert.GenerateSignerAndCert(issuer, caName, u)
	if err != nil {
		return signer{}, err
	}
	leaf, err := conformancecert.ParseCertificatePEM(certPEMs)
	if err != nil {
		return signer{}, err
	}
	ca, err := conformancecert.ParseCertificatePEM(caPEM)
	if err != nil {
		return signer{}, err
	}
	return signer{key: key, chain: []*x509.Certificate{leaf, ca}}, nil
}

// issuerStart runs interop/eudi/scripts/setup-issuer and starts
// cmd/conformance-issuer with its config, on loopback ports of its own,
// trusting Wallet Attestations from an attester the peer makes for
// Multipaz's wallet (its certificate's common name is its issuer, as
// Multipaz names the iss of the attestations it signs), whose key also
// signs the Key Attestations it trusts: Multipaz's local wallet backend
// signs both with one key. The attester's key and certificate, and an
// untrusted one's, go to dir as mpz-attester-{key,cert}.pem and
// mpz-other-attester-{key,cert}.pem; setup-issuer's own files to
// dir/issuer-files. It answers with the issuer's base URL and its
// files' directory.
func (p *peer) issuerStart() (reply, error) {
	if p.vci.setupIssuerBinary == "" || p.vci.issuerBinary == "" {
		return reply{}, errors.New("no -setup-issuer or -issuer binary")
	}
	port, err := freePort()
	if err != nil {
		return reply{}, err
	}
	offersPort, err := freePort()
	if err != nil {
		return reply{}, err
	}
	files := filepath.Join(p.vp.dir, "issuer-files")
	if err := os.MkdirAll(files, 0o700); err != nil {
		return reply{}, err
	}
	setup := exec.Command(p.vci.setupIssuerBinary, "-out", files, "-port", strconv.Itoa(port), "-offers-port", strconv.Itoa(offersPort)) // #nosec G204 -- the operator's own binary
	if out, err := setup.CombinedOutput(); err != nil {
		return reply{}, fmt.Errorf("setup-issuer: %w: %s", err, out)
	}

	attester, err := newSigner(mpzAttesterIssuer, "Multipaz interop wallet provider CA")
	if err != nil {
		return reply{}, err
	}
	other, err := newSigner(mpzAttesterIssuer, "Multipaz interop untrusted wallet provider CA")
	if err != nil {
		return reply{}, err
	}
	for name, s := range map[string]signer{"mpz-attester": attester, "mpz-other-attester": other} {
		if err := writeSigner(p.vp.dir, name, s); err != nil {
			return reply{}, err
		}
	}
	keyJWK, err := attestation.AttestedKey(attester.key.Public())
	if err != nil {
		return reply{}, err
	}

	path := filepath.Join(files, "issuer.json")
	raw, err := os.ReadFile(path) // #nosec G304 -- setup-issuer's own output
	if err != nil {
		return reply{}, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return reply{}, err
	}
	client, _ := cfg["client"].(map[string]any)
	keyAttestation, _ := cfg["key_attestation"].(map[string]any)
	if client == nil || keyAttestation == nil {
		return reply{}, errors.New("issuer.json has no client or key_attestation")
	}
	client["expected_attester_issuer"] = mpzAttesterIssuer
	client["attester_trust_anchors_pem"] = certPEM(attester.chain[len(attester.chain)-1])
	keyAttestation["trusted_jwk"] = json.RawMessage(keyJWK)
	if raw, err = json.MarshalIndent(cfg, "", "  "); err != nil {
		return reply{}, err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return reply{}, err
	}
	addr, _ := cfg["listen_addr"].(string)
	issuer, _ := cfg["issuer"].(string)
	if err := p.vp.spawn("issuer", p.vci.issuerBinary, path, addr); err != nil {
		return reply{}, err
	}
	return reply{BaseURL: issuer, Data: files}, nil
}

// writeSigner writes s's key (PKCS #8) and its certificate chain to
// dir as name-key.pem and name-cert.pem.
func writeSigner(dir, name string, s signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(s.key)
	if err != nil {
		return err
	}
	var chain []byte
	for _, c := range s.chain {
		chain = append(chain, certPEM(c)...)
	}
	if err := os.WriteFile(filepath.Join(dir, name+"-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name+"-cert.pem"), chain, 0o600)
}

// walletReceive redeems req.Request, a pre-authorized code offer from
// Multipaz's issuer (with req.Msg its tx_code, if any), as walletflow
// under HAIP, attested by the peer's Wallet Provider: by its trusted
// attester, or with req.Trust "other", one Multipaz's issuer doesn't
// trust. The credentials must chain to req.Data, the issuer's root.
func (p *peer) walletReceive(ctx context.Context, req request) (reply, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(req.Data)) {
		return reply{}, errors.New("no issuer root")
	}
	prov := p.vci.provider
	if req.Trust == "other" {
		prov = prov.other
	}
	// Through a recorder, of what the issuer sent (observe.go).
	rec := newRecorder(&http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: p.vp.tlsRoots, MinVersion: tls.VersionTLS12},
	})
	client := &http.Client{Timeout: 30 * time.Second, Transport: rec}
	w, err := walletflow.New(walletflow.Config{
		Development: true, ClientID: goClientID, IssuerRoots: roots, IssuanceProfile: walletflow.ProfileHAIP,
	}, walletflow.Dependencies{Keys: p.keys, Credentials: walletflow.NewMemoryCredentialStore(), HTTP: client, Provider: prov})
	if err != nil {
		return reply{}, err
	}
	s, err := w.StartIssuance(ctx, req.Request)
	if err != nil {
		return reply{}, fmt.Errorf("offer: %w", err)
	}
	defer func() { _ = s.Close(ctx) }()
	if err := s.RedeemPreAuthorizedCode(ctx, req.Msg); err != nil {
		return reply{Observed: rec.snapshot()}, fmt.Errorf("token: %w", err)
	}
	got, err := s.RequestCredentials(ctx)
	if err != nil {
		return reply{Observed: rec.snapshot()}, fmt.Errorf("credential: %w", err)
	}
	rep := reply{Observed: rec.snapshot()}
	for _, f := range got.Failed {
		return rep, fmt.Errorf("credential %s refused: %w", f.ConfigurationID, f.Err)
	}
	claims := map[string]any{}
	for _, c := range got.Credentials {
		rep.QueryIDs = append(rep.QueryIDs, c.Format+" "+c.ConfigurationID)
		for name := range c.Claims {
			claims[name] = true
		}
	}
	rep.Claims = claims
	return rep, nil
}

// provider is walletflow's Wallet Provider: it attests whatever it's
// asked to, as the peer's attester, whose CA Multipaz's issuer trusts
// (go-attester-ca.pem); other is one under a CA it doesn't.
type provider struct {
	signer signer
	other  *provider
}

func newProvider(dir string) (*provider, error) {
	trusted, err := newSigner(goAttesterIssuer, "OID4VCgo interop wallet provider CA")
	if err != nil {
		return nil, err
	}
	untrusted, err := newSigner(goAttesterIssuer, "OID4VCgo interop untrusted wallet provider CA")
	if err != nil {
		return nil, err
	}
	ca := trusted.chain[len(trusted.chain)-1]
	if err := os.WriteFile(filepath.Join(dir, "go-attester-ca.pem"), []byte(certPEM(ca)), 0o600); err != nil {
		return nil, err
	}
	return &provider{signer: trusted, other: &provider{signer: untrusted}}, nil
}

func (p *provider) header() attestation.Header {
	return attestation.Header{X5C: []string{base64.StdEncoding.EncodeToString(p.signer.chain[0].Raw)}}
}

// WalletAttestation implements walletflow.WalletProvider.
func (p *provider) WalletAttestation(_ context.Context, clientID string, instanceKey crypto.PublicKey) (string, error) {
	now := time.Now()
	return attestation.IssueWalletAttestation(p.signer.key, oid4vci.ES256, p.header(), attestation.WalletAttestationClaims{
		Issuer: goAttesterIssuer, Subject: clientID, InstanceKey: instanceKey,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
}

// KeyAttestation implements walletflow.WalletProvider.
func (p *provider) KeyAttestation(_ context.Context, _ crypto.PublicKey, keys []*ecdsa.PublicKey, nonce string) (string, error) {
	attested := make([]json.RawMessage, 0, len(keys))
	for _, k := range keys {
		raw, err := attestation.AttestedKey(k)
		if err != nil {
			return "", err
		}
		attested = append(attested, raw)
	}
	now := time.Now()
	exp := now.Add(5 * time.Minute).Unix()
	return attestation.Issue(p.signer.key, oid4vci.ES256, p.header(), attestation.Claims{
		Issuer: goAttesterIssuer, IssuedAt: now.Unix(), ExpiresAt: &exp, Nonce: nonce, AttestedKeys: attested,
	})
}

var _ walletflow.WalletProvider = (*provider)(nil)

// spawn starts binary with -config config, logging to dir/name.log,
// and waits for it to listen on addr.
func (s *vpState) spawn(name, binary, config, addr string) error {
	logFile, err := os.Create(filepath.Join(s.dir, name+".log")) // #nosec G304 -- in the run's own directory
	if err != nil {
		return err
	}
	cmd := exec.Command(binary, "-config", config) // #nosec G204 -- the operator's own binary
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		return err
	}
	s.procs = append(s.procs, cmd)
	for range 100 {
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s didn't start; see %s.log", name, filepath.Join(s.dir, name))
}
