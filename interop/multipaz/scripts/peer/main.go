// Command peer is OID4VCgo's side of interop/multipaz/run.sh: the
// Multipaz driver (../../driver) starts it and exchanges ISO/IEC 18013-5,
// ISO/IEC TS 18013-7 Annex C and OpenID4VP messages with it, one JSON
// object per line on stdin, each answered by one on stdout. For
// OpenID4VP (vp.go) it is also walletflow's wallet, and starts
// cmd/conformance-verifier (-verifier) as the driver's cases ask.
//
// It is a holder, walletflow's in-person and org-iso-mdoc presentations
// holding an mDL from its own IACA, and a reader, proximity's
// ReaderSession and mdocdcapi's Verifier, authenticating with its own
// reader CA. At start it writes those two CAs to -dir (go-iaca.pem,
// go-reader-ca.pem) and trusts the driver's (mpz-iaca.pem,
// mpz-reader-ca.pem), and, for the controls, a CA it never issues under
// (go-other-ca.pem); then it prints {"ready": true}.
//
// Usage: go run ./interop/multipaz/scripts/peer -dir DIR -verifier BINARY
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

const (
	docType   = "org.iso.18013.5.1.mDL"
	nameSpace = "org.iso.18013.5.1"
	// repoURL is the certificates' contact and CRL base.
	repoURL = "https://github.com/IDFoundry/OID4VCgo"
)

// requested are the elements the readers ask for; the holder's mDL has
// these and more, so an answer disclosing anything else is an error.
var requested = []string{"family_name", "given_name", "age_over_18"}

// request is one line from the driver: Op names it, the rest are its
// arguments.
type request struct {
	Op string `json:"op"`
	// Msg is a session message, base64url.
	Msg string `json:"msg,omitempty"`
	// QR is the holder's engagement, as its QR code reads.
	QR string `json:"qr,omitempty"`
	// MAC asks the holder to authenticate with deviceMac.
	MAC bool `json:"mac,omitempty"`
	// Trust names the reader's issuer roots: "mpz", or "other".
	Trust string `json:"trust,omitempty"`
	// ReaderCA names the CA the reader's certificate is from: "go", or
	// "other"; an org-iso-mdoc request with none is unsigned.
	ReaderCA string `json:"reader_ca,omitempty"`
	// Data and Origin are an org-iso-mdoc request's, as a page passes
	// them to the platform; Response its answer's data.response.
	Data     string `json:"data,omitempty"`
	Origin   string `json:"origin,omitempty"`
	Response string `json:"response,omitempty"`

	// OpenID4VP's: the credential format a verifier asks for ("dc+sd-jwt"
	// or "mso_mdoc"), a Verifier's request (an openid4vp: link, or a DC
	// API request's data with its Protocol), and the CA the wallet
	// trusts Verifiers under ("mpz" or "other").
	Format     string `json:"format,omitempty"`
	Request    string `json:"request,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	VerifierCA string `json:"verifier_ca,omitempty"`
}

// reply is the answer to one request: Error says why it failed.
type reply struct {
	Ready bool   `json:"ready,omitempty"`
	Error string `json:"error,omitempty"`

	QR   string `json:"qr,omitempty"`
	Send string `json:"send,omitempty"`
	// Ended is the holder's session being over; Reader its view of who
	// asked (proximity.ReaderStatus, or the org-iso-mdoc reader's name).
	Ended  bool   `json:"ended,omitempty"`
	Reader string `json:"reader,omitempty"`

	// What a reader verified.
	Claims     map[string]any `json:"claims,omitempty"`
	DeviceAuth string         `json:"device_auth,omitempty"`
	Issuer     string         `json:"issuer,omitempty"`

	Data string `json:"data,omitempty"`

	// OpenID4VP's: a started verifier's base URL, and what a wallet
	// answered and whom.
	BaseURL  string   `json:"base_url,omitempty"`
	QueryIDs []string `json:"query_ids,omitempty"`
	Verifier string   `json:"verifier,omitempty"`
}

func main() {
	dir := flag.String("dir", "", "where to write the peer's CAs and read the driver's")
	verifierBinary := flag.String("verifier", "", "cmd/conformance-verifier's binary, for the OpenID4VP cases")
	flag.Parse()
	if *dir == "" {
		log.Fatal("-dir is required")
	}
	p, err := newPeer(*dir, *verifierBinary)
	if err != nil {
		log.Fatal(err)
	}
	out := json.NewEncoder(os.Stdout)
	if err := out.Encode(reply{Ready: true}); err != nil {
		log.Fatal(err)
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 8<<20)
	for in.Scan() {
		var req request
		var rep reply
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			rep = reply{Error: err.Error()}
		} else {
			rep = p.handle(req)
		}
		if err := out.Encode(rep); err != nil {
			log.Fatal(err)
		}
	}
	p.vp.stop()
	if err := in.Err(); err != nil {
		log.Fatal(err)
	}
}

// peer is the holder and the reader, and what each trusts.
type peer struct {
	keys  *agreeingKeyStore
	store *walletflow.MemoryCredentialStore
	mdlID string

	readerCAs   map[string]readerKey
	mpzIACA     *x509.CertPool
	mpzReaderCA *x509.CertPool
	otherRoots  *x509.CertPool

	holder  *walletflow.ProximityPresentation
	reader  *proximity.ReaderSession
	pending *mdocdcapi.Pending

	// OpenID4VP's: see vp.go.
	vp vpState
}

// readerKey is a reader authentication key and its chain.
type readerKey struct {
	key   *ecdsa.PrivateKey
	chain []*x509.Certificate
}

func newPeer(dir, verifierBinary string) (*peer, error) {
	iaca, iacaKey, iacaPEM, _, err := conformancecert.GenerateMdocIACA("OID4VCgo Multipaz interop IACA", "US", repoURL)
	if err != nil {
		return nil, err
	}
	dsKey, _, dsPEM, err := conformancecert.GenerateMdocDocumentSigner("OID4VCgo Multipaz interop DS", "US",
		repoURL, repoURL+"/crl", iaca, iacaKey)
	if err != nil {
		return nil, err
	}
	ds, err := conformancecert.ParseCertificatePEM(dsPEM)
	if err != nil {
		return nil, err
	}
	readerCA, readerCAKey, err := newCA("OID4VCgo Multipaz interop reader CA")
	if err != nil {
		return nil, err
	}
	other, otherKey, err := newCA("OID4VCgo Multipaz interop other CA")
	if err != nil {
		return nil, err
	}
	p := &peer{keys: &agreeingKeyStore{keys: map[string]*agreeingKey{}}, store: walletflow.NewMemoryCredentialStore(), readerCAs: map[string]readerKey{}, vp: vpState{verifierBinary: verifierBinary}}
	for name, ca := range map[string]struct {
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
	}{"go": {readerCA, readerCAKey}, "other": {other, otherKey}} {
		k, err := readerLeaf("OID4VCgo Multipaz interop reader", ca.cert, ca.key)
		if err != nil {
			return nil, err
		}
		p.readerCAs[name] = k
	}
	if err := p.issueMDL(dsKey, ds); err != nil {
		return nil, err
	}
	if err := p.setupVP(dir, ca{iaca, iacaKey}, ca{readerCA, readerCAKey}, ca{other, otherKey}); err != nil {
		return nil, err
	}
	for name, content := range map[string]string{"go-iaca.pem": iacaPEM, "go-reader-ca.pem": certPEM(readerCA), "go-other-ca.pem": certPEM(other)} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return nil, err
		}
	}
	if p.mpzIACA, err = readPool(filepath.Join(dir, "mpz-iaca.pem")); err != nil {
		return nil, err
	}
	if p.mpzReaderCA, err = readPool(filepath.Join(dir, "mpz-reader-ca.pem")); err != nil {
		return nil, err
	}
	p.otherRoots = x509.NewCertPool()
	p.otherRoots.AddCert(other)
	return p, nil
}

// issueMDL puts an mDL in the holder's store, bound to a key from its
// key store, as walletflow would after issuance.
func (p *peer) issueMDL(dsKey *ecdsa.PrivateKey, ds *x509.Certificate) error {
	ctx := context.Background()
	k, err := p.keys.NewKey(ctx, walletflow.KeyPurposeHolder)
	if err != nil {
		return err
	}
	now := time.Now().Truncate(time.Second)
	claims := map[string]any{
		"family_name": "Mustermann", "given_name": "Erika", "birth_date": "1971-09-01",
		"issuing_country": "US", "document_number": "OID4VCGO-1", "age_over_18": true, "age_over_21": true,
	}
	issued, err := mdoc.Issue(dsKey, oid4vci.COSEES256, mdoc.Claims{
		DocType: docType, NameSpaces: map[string]map[string]any{nameSpace: claims},
		DeviceKey: k.Public().(*ecdsa.PublicKey),
		Signed:    now.Add(-time.Minute), ValidFrom: now.Add(-time.Minute), ValidUntil: now.Add(24 * time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
	if err != nil {
		return err
	}
	raw, err := issued.Marshal()
	if err != nil {
		return err
	}
	p.mdlID = "mdl"
	return p.store.Put(ctx, walletflow.StoredCredential{ // #nosec G101 -- the mDL just issued above, not a secret
		ID: p.mdlID, CredentialIssuer: "https://oid4vcgo.example", ConfigurationID: "mdl",
		Format: "mso_mdoc", DocType: docType, Credential: base64.RawURLEncoding.EncodeToString(raw),
		HolderKeyID: k.ID(), Claims: map[string]any{nameSpace: claims}, ReceivedAt: now, ValidUntil: now.Add(24 * time.Hour),
	})
}

// wallet is the holder's walletflow wallet, trusting the driver's
// reader CA.
func (p *peer) wallet(mac bool) (*walletflow.Wallet, error) {
	auth := walletflow.ProximityDeviceSignature
	if mac {
		auth = walletflow.ProximityDeviceMACPreferred
	}
	return walletflow.New(walletflow.Config{
		Development: true, MdocReaderRoots: p.mpzReaderCA, MdocReaderLeafPolicy: mdocdcapi.RequireReaderAuthenticationEKU,
		MdocReaderRevocation: certrevocation.NoCheck{}, ProximityDeviceAuth: auth,
	}, walletflow.Dependencies{Keys: p.keys, Credentials: p.store})
}

func (p *peer) handle(req request) reply {
	rep, err := p.do(req)
	if err != nil {
		rep.Error = err.Error()
	}
	return rep
}

func (p *peer) do(req request) (reply, error) {
	ctx := context.Background()
	switch req.Op {
	case "holder_start":
		return p.holderStart(ctx, req)
	case "holder_message":
		return p.holderMessage(ctx, req)
	case "reader_start":
		return p.readerStart(ctx, req)
	case "reader_response":
		return p.readerResponse(ctx, req)
	case "dcapi_answer":
		return p.dcapiAnswer(ctx, req)
	case "dcapi_request":
		return p.dcapiRequest(ctx, req)
	case "dcapi_verify":
		return p.dcapiVerify(ctx, req)
	case "verifier_start":
		return p.verifierStart(req)
	case "wallet_present":
		return p.walletPresent(ctx, req)
	case "wallet_dcapi":
		return p.walletDCAPI(ctx, req)
	}
	return reply{}, fmt.Errorf("unknown op %q", req.Op)
}

func (p *peer) holderStart(ctx context.Context, req request) (reply, error) {
	w, err := p.wallet(req.MAC)
	if err != nil {
		return reply{}, err
	}
	if p.holder, err = w.StartProximityPresentation(); err != nil {
		return reply{}, err
	}
	return reply{QR: p.holder.QRCode()}, nil
}

func (p *peer) holderMessage(ctx context.Context, req request) (reply, error) {
	// A request is answered at once, with every requested element
	// the mDL has: the holder consents to all of it.
	msg, err := decode(req.Msg)
	if err != nil {
		return reply{}, err
	}
	ev := p.holder.HandleMessage(ctx, msg)
	rep := reply{Send: encode(ev.Send), Ended: ev.Ended, Reader: p.holder.Reader().Status.String()}
	if ev.Err != nil {
		return rep, ev.Err
	}
	if !ev.Request {
		return rep, nil
	}
	r := p.holder.Requests()[0]
	presented, err := p.holder.Respond(ctx, 0, p.mdlID, pairs(r.Elements))
	if err != nil {
		return rep, err
	}
	rep.Send, rep.Ended = encode(presented.Send), true
	return rep, nil
}

func (p *peer) readerStart(ctx context.Context, req request) (reply, error) {
	roots := p.mpzIACA
	if req.Trust == "other" {
		roots = p.otherRoots
	}
	auth := p.readerCAs["go"]
	var err error
	p.reader, err = proximity.NewReaderSession(req.QR,
		proximity.WithAssurance(verifier.AssuranceProduction),
		proximity.WithIssuerRootsByDocType(map[string]*x509.CertPool{docType: roots}),
		proximity.WithAnyIssuerForAnyType(),
		proximity.WithIssuerRevocation(certrevocation.NoCheck{}),
		proximity.WithNoStatusCheck(),
		proximity.WithReaderAuth(auth.key, auth.chain),
		proximity.WithMaxClockSkew(5*time.Minute),
	)
	if err != nil {
		return reply{}, err
	}
	msg, err := p.reader.Establishment(docType, map[string][]string{nameSpace: requested})
	return reply{Send: encode(msg)}, err
}

func (p *peer) readerResponse(ctx context.Context, req request) (reply, error) {
	msg, err := decode(req.Msg)
	if err != nil {
		return reply{}, err
	}
	v, err := p.reader.Verify(ctx, msg, x509.NewCertPool(), time.Time{})
	if err != nil {
		return reply{}, err
	}
	auth := "signature"
	if v.DeviceAuth == mdoc.DeviceAuthMAC {
		auth = "mac"
	}
	return reply{Claims: flatten(v.Claims), DeviceAuth: auth, Issuer: v.IssuerCN}, nil
}

func (p *peer) dcapiAnswer(ctx context.Context, req request) (reply, error) {
	w, err := p.wallet(false)
	if err != nil {
		return reply{}, err
	}
	pres, err := w.StartMdocPresentation(ctx, []byte(req.Data), req.Origin)
	if err != nil {
		return reply{}, err
	}
	rep := reply{}
	if c := pres.Reader(); c != nil {
		rep.Reader = c.Subject.CommonName
	}
	r := pres.Requests()[0]
	presented, err := pres.Respond(ctx, 0, p.mdlID, pairs(r.Elements))
	if err != nil {
		return rep, err
	}
	rep.Data = string(mdocdcapi.ResponseData(presented.EncryptedResponse))
	return rep, nil
}

func (p *peer) dcapiRequest(ctx context.Context, req request) (reply, error) {
	elements := map[string]bool{}
	for _, e := range requested {
		elements[e] = false
	}
	var readers []mdocdcapi.ReaderKey
	if auth, ok := p.readerCAs[req.ReaderCA]; ok {
		readers = append(readers, mdocdcapi.ReaderKey{Signer: auth.key, Chain: auth.chain})
	}
	r, err := mdocdcapi.BuildRequest(mdocdcapi.RequestParams{
		Origin: req.Origin, DocType: docType, Elements: map[string]map[string]bool{nameSpace: elements}, Readers: readers,
	})
	if err != nil {
		return reply{}, err
	}
	data, err := json.Marshal(r.Data)
	p.pending = &r.Pending
	return reply{Data: string(data)}, err
}

func (p *peer) dcapiVerify(ctx context.Context, req request) (reply, error) {
	if p.pending == nil {
		return reply{}, errors.New("no request pending")
	}
	pending := *p.pending
	p.pending = nil
	roots := p.mpzIACA
	if req.Trust == "other" {
		roots = p.otherRoots
	}
	v, err := mdocdcapi.VerifyResponse(ctx, mdocdcapi.VerifyParams{
		Pending: pending, Response: req.Response,
		IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}},
		Assurance:  verifier.AssuranceProduction, Origins: []string{pending.Origin},
		AnyIssuerForAnyType: true, NoStatusCheck: true,
	})
	if err != nil {
		return reply{}, err
	}
	return reply{Claims: flatten(v.NameSpaces)}, nil
}

// pairs are elements as [namespace, identifier] pairs.
func pairs(elements []walletflow.MdocElement) [][2]string {
	out := make([][2]string, 0, len(elements))
	for _, e := range elements {
		out = append(out, [2]string{e.Namespace, e.Identifier})
	}
	return out
}

// flatten is namespace → element → value as namespace/element → value.
func flatten(ns map[string]map[string]any) map[string]any {
	out := map[string]any{}
	for n, elements := range ns {
		for e, v := range elements {
			if t, ok := v.(time.Time); ok {
				v = t.Format(time.RFC3339)
			}
			out[n+"/"+e] = fmt.Sprint(v)
		}
	}
	return out
}

func encode(b []byte) string {
	if b == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// agreeingKeyStore is walletflow.MemoryKeyStore with keys that can also
// agree a key (proximity.KeyAgreer), as a phone's key store does, for
// deviceMac.
type agreeingKeyStore struct {
	mu   sync.Mutex
	keys map[string]*agreeingKey
}

type agreeingKey struct {
	*ecdsa.PrivateKey
	id string
}

func (k *agreeingKey) ID() string { return k.id }

// Agree implements proximity.KeyAgreer: ECDH with peer, Z.
func (k *agreeingKey) Agree(peer *ecdsa.PublicKey) ([]byte, error) {
	priv, err := k.ECDH()
	if err != nil {
		return nil, err
	}
	pub, err := peer.ECDH()
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

var _ proximity.KeyAgreer = (*agreeingKey)(nil)

func (s *agreeingKeyStore) NewKey(context.Context, walletflow.KeyPurpose) (walletflow.Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := &agreeingKey{PrivateKey: priv, id: fmt.Sprintf("key%d", len(s.keys)+1)}
	s.keys[k.id] = k
	return k, nil
}

func (s *agreeingKeyStore) Key(_ context.Context, id string) (walletflow.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, ok := s.keys[id]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("key %q: %w", id, walletflow.ErrNotFound)
}

func (s *agreeingKeyStore) DeleteKey(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, id)
	return nil
}

// newCA is a self-signed P-256 CA, valid for a day.
func newCA(commonName string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return issue(&x509.Certificate{
		Subject: pkix.Name{CommonName: commonName, Country: []string{"US"}},
		IsCA:    true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, nil)
}

// readerLeaf is a reader authentication certificate (ISO/IEC 18013-5
// Annex B) under ca, with its key; its chain ends at ca.
func readerLeaf(commonName string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (readerKey, error) {
	cert, key, err := issue(&x509.Certificate{
		Subject:            pkix.Name{CommonName: commonName, Country: []string{"US"}},
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{proximity.ReaderAuthenticationEKU},
	}, ca, caKey)
	return readerKey{key: key, chain: []*x509.Certificate{cert, ca}}, err
}

// issue is tmpl's certificate under parent (self-signed when nil), for
// a fresh P-256 key, valid for a day.
func issue(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

func certPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

// readPool is a PEM file's certificates.
func readPool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the driver's own file
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return p, nil
}
