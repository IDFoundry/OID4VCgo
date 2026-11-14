// Package conformancecrl gives the conformance and interop harnesses a
// certificate authority that publishes real CRLs, and the relying-party
// side that checks against them, so the runs against independent
// implementations exercise certificate revocation rather than decline
// it with certrevocation.NoCheck.
//
// A driver makes an Authority per CA whose certificates the other side
// presents to OID4VCgo (a verifier's request object signer, a
// credential issuer, an attester): each certificate it issues names the
// Authority's https CRL distribution point, and its CRL lists the
// certificates the driver revoked. A Publisher serves those CRLs over
// https; Trust, in the binary under test, fetches them through a
// certrevocation.Refresher with production's settings — https only,
// each distribution point bound to its CA, a missing or stale list
// refusing the certificate — so a revoked certificate is refused with
// certrevocation.ErrRevoked and one whose CA has no current list with
// certrevocation.ErrNoCurrentCRL.
//
// What isn't production's: the distribution points are on the Docker
// network or loopback, which Trust's client is allowed to dial for the
// hosts its distribution points name (production dials public
// addresses only), and their TLS certificate chains to a harness CA
// (TLSTrustAnchorsPEM) rather than the system roots. Throwaway key
// material only, never for production use.
package conformancecrl

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/certrevocation"
)

// ContentType is the media type RFC 2585 §4.2 registers for a
// DER-encoded CRL, which a Publisher answers with.
const ContentType = "application/pkix-crl"

const (
	// crlValidity is a current CRL's nextUpdate after its thisUpdate:
	// longer than any run.
	crlValidity = 7 * 24 * time.Hour
	// backdate keeps a current CRL's thisUpdate, and a certificate's
	// notBefore, in the past for a relying party whose clock runs a
	// little behind.
	backdate = time.Hour
)

// Authority is a throwaway CA whose CRL is published at URL, an https
// distribution point every certificate it issues names.
type Authority struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM string
	// URL is the CA's CRL distribution point.
	URL string

	mu     sync.Mutex
	serial int64
	crlNum int64
}

// NewAuthority generates a self-signed EC P-256 CA, commonName, whose
// CRL is published at crlURL (an https URL).
func NewAuthority(commonName, crlURL string) (*Authority, error) {
	u, err := url.Parse(crlURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("conformancecrl: CRL distribution point %q isn't an https URL", crlURL)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-backdate),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		CRLDistributionPoints: []string{crlURL},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{
		Cert: cert, Key: key, URL: crlURL,
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}, nil
}

// Wrap is an Authority for a CA certificate made elsewhere (an ISO/IEC
// 18013-5 IACA, say), whose CRL is published at crlURL: its key usage
// must allow signing CRLs. Certificates it issued itself, naming
// crlURL as their distribution point, are its caller's to make; Issue
// makes plain leaves.
func Wrap(cert *x509.Certificate, key *ecdsa.PrivateKey, crlURL string) (*Authority, error) {
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, fmt.Errorf("conformancecrl: %s can't sign CRLs", cert.Subject)
	}
	return &Authority{
		Cert: cert, Key: key, URL: crlURL,
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}, nil
}

// randomSerial is a positive 64-bit serial number.
func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
}

// Leaf is a certificate an Authority issued.
type Leaf struct {
	Cert    *x509.Certificate
	CertPEM string
}

// Issue issues a leaf certificate for pub, commonName, naming a.URL as
// its CRL distribution point. uris become its URI subject alternative
// names (an attester certificate names its attester this way); dnsNames
// its DNS ones (an x509_san_dns verifier's).
func (a *Authority) Issue(commonName string, pub crypto.PublicKey, uris []*url.URL, dnsNames ...string) (Leaf, error) {
	a.mu.Lock()
	a.serial++
	serial := big.NewInt(a.serial + 1000)
	a.mu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-backdate),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		URIs:                  uris,
		DNSNames:              dnsNames,
		CRLDistributionPoints: []string{a.URL},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, pub, a.Key)
	if err != nil {
		return Leaf{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Leaf{}, err
	}
	return Leaf{Cert: cert, CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, nil
}

// IssueKey generates an EC P-256 key and issues a leaf for it (see
// Issue).
func (a *Authority) IssueKey(commonName string, uris []*url.URL, dnsNames ...string) (*ecdsa.PrivateKey, Leaf, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, Leaf{}, err
	}
	leaf, err := a.Issue(commonName, &key.PublicKey, uris, dnsNames...)
	return key, leaf, err
}

// CRL is a's current CRL, PEM-encoded: thisUpdate an hour ago,
// nextUpdate a week later, revoking revoked (certificates a issued).
func (a *Authority) CRL(revoked ...*x509.Certificate) (string, error) {
	thisUpdate := time.Now().Add(-backdate).UTC().Truncate(time.Second)
	return a.crl(thisUpdate, thisUpdate.Add(crlValidity), revoked)
}

// ExpiredCRL is a CRL a signed whose nextUpdate has passed: a
// distribution point serving only this has no current list, so a
// relying party has none for a's certificates.
func (a *Authority) ExpiredCRL() (string, error) {
	thisUpdate := time.Now().Add(-3 * 24 * time.Hour).UTC().Truncate(time.Second)
	return a.crl(thisUpdate, thisUpdate.Add(24*time.Hour), nil)
}

func (a *Authority) crl(thisUpdate, nextUpdate time.Time, revoked []*x509.Certificate) (string, error) {
	a.mu.Lock()
	a.crlNum++
	number := big.NewInt(a.crlNum)
	a.mu.Unlock()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, c := range revoked {
		if !bytesEqual(c.RawIssuer, a.Cert.RawSubject) {
			return "", fmt.Errorf("conformancecrl: %s wasn't issued by %s", c.Subject, a.Cert.Subject)
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: c.SerialNumber, RevocationTime: thisUpdate.Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: number, ThisUpdate: thisUpdate, NextUpdate: nextUpdate, RevokedCertificateEntries: entries,
	}, a.Cert, a.Key)
	if err != nil {
		return "", fmt.Errorf("conformancecrl: create crl: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// DistributionPoint is a's distribution point, bound to a's
// certificate, for Trust.
func (a *Authority) DistributionPoint() DistributionPoint {
	return DistributionPoint{URL: a.URL, IssuerPEM: a.CertPEM}
}

// Path is the path of a's CRL distribution point, the key a Publisher
// serves its CRL under.
func (a *Authority) Path() string {
	u, _ := url.Parse(a.URL)
	return u.Path
}

// URL is the CRL distribution point https://host/crl/name.crl.
func URL(host, name string) string {
	return (&url.URL{Scheme: "https", Host: host, Path: "/crl/" + name + ".crl"}).String()
}

// Publisher serves CRLs over https: the distribution points of the
// harness's Authorities.
type Publisher struct {
	// ListenAddr is the https listener's address.
	ListenAddr string `json:"listen_addr"`
	// TLSCertificatePEM and TLSPrivateKeyPEM are its TLS certificate,
	// naming the host the distribution points do, and key.
	TLSCertificatePEM string `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM  string `json:"tls_private_key_pem"`
	// CRLs maps each distribution point's path to the PEM CRL served
	// there. A path not in it answers 404.
	CRLs map[string]string `json:"crls"`
}

// Handler serves p's CRLs, DER-encoded, as ContentType.
func (p Publisher) Handler() (http.Handler, error) {
	lists := make(map[string][]byte, len(p.CRLs))
	for path, pemText := range p.CRLs {
		block, _ := pem.Decode([]byte(pemText))
		if block == nil || block.Type != "X509 CRL" {
			return nil, fmt.Errorf("conformancecrl: crls[%q] holds no PEM X509 CRL", path)
		}
		if _, err := x509.ParseRevocationList(block.Bytes); err != nil {
			return nil, fmt.Errorf("conformancecrl: crls[%q]: %w", path, err)
		}
		lists[path] = block.Bytes
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		der, ok := lists[r.URL.Path]
		if r.Method != http.MethodGet || !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		_, _ = w.Write(der)
	}), nil
}

// Start listens on p.ListenAddr and serves p over https in a
// goroutine, calling fail with the error if serving stops. It returns
// once the listener is bound, so a Trust started after it can fetch.
func (p Publisher) Start(fail func(error)) error {
	ln, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return fmt.Errorf("conformancecrl: publisher listen: %w", err)
	}
	if err := p.ServeOn(ln, fail); err != nil {
		_ = ln.Close()
		return err
	}
	return nil
}

// ServeOn serves p over https on ln, in a goroutine, as Start does: for
// a listener bound before the distribution points could name its port.
func (p Publisher) ServeOn(ln net.Listener, fail func(error)) error {
	handler, err := p.Handler()
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair([]byte(p.TLSCertificatePEM), []byte(p.TLSPrivateKeyPEM))
	if err != nil {
		return fmt.Errorf("conformancecrl: publisher tls key pair: %w", err)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	go func() { fail(srv.ServeTLS(ln, "", "")) }()
	return nil
}

// DistributionPoint is a CRL distribution point a relying party
// fetches, bound to the CA whose CRL it serves.
type DistributionPoint struct {
	URL       string `json:"url"`
	IssuerPEM string `json:"issuer_pem"`
}

// Trust is the CRL checking a binary under test does: the distribution
// points of the CAs it trusts, fetched over https from the hosts they
// name, whose TLS certificates chain to TLSTrustAnchorsPEM.
type Trust struct {
	DistributionPoints []DistributionPoint `json:"distribution_points"`
	TLSTrustAnchorsPEM string              `json:"tls_trust_anchors_pem"`
}

// Configured reports whether t names any distribution point.
func (t *Trust) Configured() bool { return t != nil && len(t.DistributionPoints) > 0 }

// Refresher builds the certrevocation.Refresher t configures: https
// only (RequireHTTPS), each URL bound to its CA (URLIssuers), over a
// fapihttp client that may dial only the hosts the distribution points
// name on a private or loopback address.
func (t Trust) Refresher(onError func(url string, err error)) (*certrevocation.Refresher, error) {
	if len(t.DistributionPoints) == 0 {
		return nil, errors.New("conformancecrl: no distribution points")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(t.TLSTrustAnchorsPEM)) {
		return nil, errors.New("conformancecrl: tls_trust_anchors_pem holds no certificate")
	}
	urls := make([]string, 0, len(t.DistributionPoints))
	var issuers []*x509.Certificate
	bound := make(map[string]*x509.Certificate, len(t.DistributionPoints))
	var hosts []string
	for i, dp := range t.DistributionPoints {
		issuer, err := parseCertificatePEM(dp.IssuerPEM)
		if err != nil {
			return nil, fmt.Errorf("conformancecrl: distribution_points[%d].issuer_pem: %w", i, err)
		}
		u, err := url.Parse(dp.URL)
		if err != nil {
			return nil, fmt.Errorf("conformancecrl: distribution_points[%d].url: %w", i, err)
		}
		urls = append(urls, dp.URL)
		issuers = append(issuers, issuer)
		bound[dp.URL] = issuer
		hosts = append(hosts, u.Hostname())
	}
	tc := fapihttp.RecommendedTransportConfig()
	tc.RootCAs = roots
	tc.AllowedPrivateHosts = hosts
	tc.AllowedLoopbackHosts = hosts
	for _, h := range hosts {
		if h == "localhost" || isLoopbackIP(h) {
			tc.AllowLoopbackHosts = true
		}
	}
	client, err := fapihttp.NewClient(tc)
	if err != nil {
		return nil, fmt.Errorf("conformancecrl: http client: %w", err)
	}
	client.Timeout = 15 * time.Second
	return certrevocation.NewRefresher(certrevocation.RefresherConfig{
		URLs: urls, Issuers: issuers, URLIssuers: bound,
		RequireHTTPS: true, HTTPClient: client, OnError: onError,
	})
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// Start builds t's Refresher, fetches every distribution point once —
// a failure is logged, not fatal: a CA left without a current list
// has its certificates refused with certrevocation.ErrNoCurrentCRL,
// as production does — and keeps the lists current until ctx ends. It
// returns the Checker to verify against.
func (t Trust) Start(ctx context.Context, logf func(format string, args ...any)) (certrevocation.CRLs, error) {
	onError := func(u string, err error) { logf("crl: %s: %v", u, err) }
	r, err := t.Refresher(onError)
	if err != nil {
		return certrevocation.CRLs{}, err
	}
	if err := r.Refresh(ctx); err != nil {
		logf("crl: initial fetch: %v", err)
	}
	go r.Run(ctx)
	return r.Checker(), nil
}

func parseCertificatePEM(pemText string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("holds no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
