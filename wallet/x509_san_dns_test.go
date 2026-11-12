package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// sanDNSName is the Verifier's DNS name in these tests: the host of
// the request fixture's response_uri, https://verifier.example.com/response.
const sanDNSName = "verifier.example.com"

const sanDNSClientID = "x509_san_dns:" + sanDNSName

// sanDNSLeaf issues a Verifier leaf under f's CA with the given
// subject alternative names, and returns it with its key.
func sanDNSLeaf(t *testing.T, f requestFixture, tmpl x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	tmpl.Subject = pkix.Name{CommonName: "x509_san_dns test verifier"}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	return testcert.Issue(t, &tmpl, f.caCert, f.caKey)
}

// sanDNSRequest is f's Request Object signed by key with leaf in x5c,
// its client_id clientID and its payload otherwise changed by mutate.
func sanDNSRequest(t *testing.T, f requestFixture, key *ecdsa.PrivateKey, leaf *x509.Certificate, clientID string, mutate func(map[string]any)) string {
	t.Helper()
	return f.sign(t, key, func(h map[string]any) { h["x5c"] = x5cOfCerts(leaf) }, func(p map[string]any) {
		p["client_id"] = clientID
		if mutate != nil {
			mutate(p)
		}
	})
}

// parseSANDNS parses object, launched with clientID, as an opted-in
// Wallet trusting trust would.
func parseSANDNS(object, clientID string, trust wallet.VerifierTrust) (wallet.AuthorizationRequest, error) {
	return wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: object, ClientID: clientID, VerifierTrust: trust, AcceptX509SANDNS: true,
	})
}

// An x509_san_dns request signed by a chain-trusted leaf with that
// dNSName, answered at a response_uri on that name, is accepted, and
// the presentation is bound to the full prefixed client_id (OpenID4VP
// 1.0 §5.9.3, §14.8): the SD-JWT VC Key Binding JWT's aud and the mdoc
// SessionTranscript's handover client_id.
func TestParseAuthorizationRequest_X509SANDNSAccepted(t *testing.T) {
	f := newRequestFixture(t)
	leaf, key := sanDNSLeaf(t, f, x509.Certificate{DNSNames: []string{"other.example.com", sanDNSName}})
	for name, mutate := range map[string]func(map[string]any){
		"response_uri on the name":        nil,
		"response_uri with a port":        func(p map[string]any) { p["response_uri"] = "https://verifier.example.com:8443/response" },
		"response_uri host in other case": func(p map[string]any) { p["response_uri"] = "https://Verifier.Example.COM/response" },
	} {
		t.Run(name, func(t *testing.T) {
			req, err := parseSANDNS(sanDNSRequest(t, f, key, leaf, sanDNSClientID, mutate), sanDNSClientID, f.trust)
			if err != nil {
				t.Fatal(err)
			}
			if req.ClientID != sanDNSClientID || !req.VerifierCertificate.Equal(leaf) {
				t.Fatalf("ClientID %q, certificate %v; want %q and the signing leaf", req.ClientID, req.VerifierCertificate.Subject, sanDNSClientID)
			}
		})
	}

	// The dNSName is compared without regard to case (RFC 4343).
	upper := "x509_san_dns:VERIFIER.example.com"
	if _, err := parseSANDNS(sanDNSRequest(t, f, key, leaf, upper, nil), upper, f.trust); err != nil {
		t.Errorf("%s: %v", upper, err)
	}

	// The Wallet's own Config.AcceptX509SANDNS reaches the same check.
	roots := x509.NewCertPool()
	roots.AddCert(f.caCert)
	w := newSANDNSWallet(t, wallet.X5CVerifierRoots{Roots: roots})
	if _, err := w.ParseAuthorizationRequest(sanDNSRequest(t, f, key, leaf, sanDNSClientID, nil), sanDNSClientID, ""); err != nil {
		t.Errorf("(*Wallet).ParseAuthorizationRequest: %v", err)
	}

	sdjwt := newHeldSDJWTVC(t)
	vpToken := presentIdentityCredential(t, sdjwt, sanDNSClientID, "")
	assertPresentedSDJWTVC(t, vpToken["identity_credential"][0], sdjwt, sanDNSClientID, "nonce-1")

	m := testmdoc.Issue(t)
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	presented, err := wallet.PresentMdoc(heldMdoc(t, m), wallet.PresentMdocParams{
		Audience: sanDNSClientID, Nonce: "nonce-1",
		ResponseURI: "https://verifier.example.com/response", ResponseEncryptionKey: &encKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("PresentMdoc: %v", err)
	}
	transcript, err := oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: sanDNSClientID, Nonce: "nonce-1",
		ResponseURI: "https://verifier.example.com/response", ResponseEncryptionJWKThumbprint: testmdoc.ResponseEncryptionThumbprint(t, encKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPresentedMdoc(t, presented, m, transcript)
}

// Each x509_san_dns request below breaks one of OpenID4VP 1.0
// §5.9.3's rules, and is refused for it, with this error.
func TestParseAuthorizationRequest_X509SANDNSRefused(t *testing.T) {
	f := newRequestFixture(t)
	leaf, key := sanDNSLeaf(t, f, x509.Certificate{DNSNames: []string{sanDNSName}})
	ip := net.IPv4(192, 0, 2, 1)
	ipURI, err := url.Parse("https://" + sanDNSName)
	if err != nil {
		t.Fatal(err)
	}
	// The name only as an IP address or URI subject alternative name,
	// never as a dNSName.
	nonDNSLeaf, nonDNSKey := sanDNSLeaf(t, f, x509.Certificate{IPAddresses: []net.IP{ip}, URIs: []*url.URL{ipURI}})
	otherCA, otherCAKey := testcert.CA(t, "unrelated CA")
	untrustedLeaf, untrustedKey := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "untrusted verifier"}, DNSNames: []string{sanDNSName},
	}, otherCA, otherCAKey)
	ipClientID := "x509_san_dns:" + ip.String()

	const prefix = "wallet: parse authorization request: "
	for name, tc := range map[string]struct {
		object   string
		clientID string
		trust    wallet.VerifierTrust
		opt      bool
		want     string
		wantIs   error
	}{
		"no dNSName matches": {
			object: sanDNSRequest(t, f, key, leaf, "x509_san_dns:other.example.com", nil), clientID: "x509_san_dns:other.example.com", opt: true,
			want: prefix + `client_id "x509_san_dns:other.example.com": "other.example.com" is not a dNSName subject alternative name of the x5c leaf (dNSNames ["verifier.example.com"])`,
		},
		"the name only as a URI SAN": {
			object: sanDNSRequest(t, f, nonDNSKey, nonDNSLeaf, sanDNSClientID, nil), clientID: sanDNSClientID, opt: true,
			want: prefix + `client_id "x509_san_dns:verifier.example.com": "verifier.example.com" is not a dNSName subject alternative name of the x5c leaf (dNSNames [])`,
		},
		"an IP address SAN as the name": {
			object: sanDNSRequest(t, f, nonDNSKey, nonDNSLeaf, ipClientID, nil), clientID: ipClientID, opt: true,
			want: prefix + fmt.Sprintf(`client_id %q: %q isn't a DNS name`, ipClientID, ip.String()),
		},
		"a wildcard name": {
			object: sanDNSRequest(t, f, key, leaf, "x509_san_dns:*.example.com", nil), clientID: "x509_san_dns:*.example.com", opt: true,
			want: prefix + `client_id "x509_san_dns:*.example.com": "*.example.com" isn't a DNS name`,
		},
		"an empty name": {
			object: sanDNSRequest(t, f, key, leaf, "x509_san_dns:", nil), clientID: "x509_san_dns:", opt: true,
			want: prefix + `client_id "x509_san_dns:": "" isn't a DNS name`,
		},
		"an unsigned request": {
			object: unsignedRequestObject(t, f, leaf), clientID: sanDNSClientID, opt: true,
			want: prefix + "signature verification failed: jose: unsupported algorithm \"none\"",
		},
		"a chain to no trusted anchor": {
			object: sanDNSRequest(t, f, untrustedKey, untrustedLeaf, sanDNSClientID, nil), clientID: sanDNSClientID, opt: true,
			want:   prefix + "untrusted verifier: wallet: verifier certificate: certchain: certificate chain does not verify against a trusted root: x509: certificate signed by unknown authority",
			wantIs: wallet.ErrUntrustedVerifier,
		},
		"NoVerifierTrust": {
			object: sanDNSRequest(t, f, key, leaf, sanDNSClientID, nil), clientID: sanDNSClientID, opt: true, trust: wallet.NoVerifierTrust{},
			want:   prefix + `untrusted verifier: client_id "x509_san_dns:verifier.example.com": x509_san_dns needs the x5c chain verified to trust anchors, which NoVerifierTrust doesn't do`,
			wantIs: wallet.ErrUntrustedVerifier,
		},
		"response_uri on another host": {
			object: sanDNSRequest(t, f, key, leaf, sanDNSClientID, func(p map[string]any) { p["response_uri"] = "https://elsewhere.example.org/response" }), clientID: sanDNSClientID, opt: true,
			want: prefix + `response_uri host "elsewhere.example.org" isn't "verifier.example.com", the x509_san_dns client_id's DNS name (OpenID4VP 1.0 §5.9.3)`,
		},
		"response_uri on a subdomain": {
			object: sanDNSRequest(t, f, key, leaf, sanDNSClientID, func(p map[string]any) { p["response_uri"] = "https://evil.verifier.example.com/response" }), clientID: sanDNSClientID, opt: true,
			want: prefix + `response_uri host "evil.verifier.example.com" isn't "verifier.example.com", the x509_san_dns client_id's DNS name (OpenID4VP 1.0 §5.9.3)`,
		},
		"the payload's client_id is another name of the leaf": {
			object: sanDNSRequest(t, f, key, leaf, "x509_san_dns:other.example.com", nil), clientID: sanDNSClientID, opt: true,
			want: prefix + `payload client_id "x509_san_dns:other.example.com" does not match "x509_san_dns:verifier.example.com"`,
		},
		"not opted in": {
			object: sanDNSRequest(t, f, key, leaf, sanDNSClientID, nil), clientID: sanDNSClientID,
			want: prefix + fmt.Sprintf(`client_id %q does not match x5c leaf's own x509_hash %q`, sanDNSClientID, x509HashOf(leaf)),
		},
	} {
		t.Run(name, func(t *testing.T) {
			trust := tc.trust
			if trust == nil {
				trust = f.trust
			}
			_, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
				RequestObject: tc.object, ClientID: tc.clientID, VerifierTrust: trust, AcceptX509SANDNS: tc.opt,
			})
			if err == nil || err.Error() != tc.want {
				t.Fatalf("ParseAuthorizationRequest = %v,\nwant %s", err, tc.want)
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("error %v doesn't wrap %v", err, tc.wantIs)
			}
			var rejected *wallet.RequestRejectedError
			if errors.As(err, &rejected) {
				t.Errorf("refused with a RequestRejectedError, answered at response_uri: %v", err)
			}
		})
	}
}

// unsignedRequestObject is f's request with an x509_san_dns client_id
// and leaf in x5c, but unsigned: alg none, no signature.
func unsignedRequestObject(t *testing.T, f requestFixture, leaf *x509.Certificate) string {
	t.Helper()
	header := map[string]any{"alg": "none", "typ": "oauth-authz-req+jwt", "x5c": x5cOfCerts(leaf)}
	payload := map[string]any{}
	for k, v := range f.payload {
		payload[k] = v
	}
	payload["client_id"] = sanDNSClientID
	enc := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return enc(header) + "." + enc(payload) + "."
}

// newSANDNSWallet is a development Wallet opted in to x509_san_dns,
// trusting trust.
func newSANDNSWallet(t *testing.T, trust wallet.VerifierTrust) *wallet.Wallet {
	t.Helper()
	w, err := wallet.New(sanDNSConfig(trust), wallet.Dependencies{Clock: wallet.ClockFunc(time.Now)})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func sanDNSConfig(trust wallet.VerifierTrust) wallet.Config {
	return wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: oid4vci.ES256,
		Fetch:         fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: time.Second},
		VerifierTrust: trust, AcceptX509SANDNS: true,
	}
}

// New refuses AcceptX509SANDNS without a VerifierTrust that verifies
// the chain to anchors: the name alone binds the request to nothing.
func TestNew_X509SANDNSNeedsTrustAnchors(t *testing.T) {
	const want = "wallet: config: accept_x509_san_dns needs a VerifierTrust that verifies the x5c chain to trust anchors: X5CVerifierRoots with Roots, or another VerifierTrust, never NoVerifierTrust or none"
	var nilRoots *wallet.X5CVerifierRoots
	for name, trust := range map[string]wallet.VerifierTrust{
		"none":                        nil,
		"NoVerifierTrust":             wallet.NoVerifierTrust{},
		"*NoVerifierTrust":            &wallet.NoVerifierTrust{},
		"X5CVerifierRoots, no Roots":  wallet.X5CVerifierRoots{},
		"*X5CVerifierRoots, no Roots": &wallet.X5CVerifierRoots{},
		"nil *X5CVerifierRoots":       nilRoots,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := wallet.New(sanDNSConfig(trust), wallet.Dependencies{Clock: wallet.ClockFunc(time.Now)}); err == nil || err.Error() != want {
				t.Fatalf("New = %v, want %s", err, want)
			}
		})
	}
	roots := x509.NewCertPool()
	newSANDNSWallet(t, &wallet.X5CVerifierRoots{Roots: roots})
}

// Over the DC API, a signed or multi-signed x509_san_dns request is
// bound to the leaf's dNSName and chain as in the redirect flow, but
// not to the origin: OpenID4VP 1.0 §5.9.3's FQDN rule "applies unless
// the interaction is using the DC API", where expected_origins binds
// the request to the calling origin instead (Appendix A.2). An unsigned
// request's client_id, x509_san_dns or not, is ignored.
func TestParseDCAPIRequestData_X509SANDNS(t *testing.T) {
	forms := newDCAPIForms(t)
	ca, caKey := testcert.CA(t, "dc api x509_san_dns CA")
	// A name unrelated to the origin, testDCAPIOrigin.
	leaf, key := testcert.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "dc api verifier"}, DNSNames: []string{"rp.example.net"}}, ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	trust := wallet.X5CVerifierRoots{Roots: roots}
	const clientID = "x509_san_dns:rp.example.net"

	signed := func(t *testing.T, clientID string) json.RawMessage {
		t.Helper()
		f := requestFixture{payload: forms.claims, header: map[string]any{"typ": "oauth-authz-req+jwt"}}
		raw, err := json.Marshal(map[string]string{"request": sanDNSRequest(t, f, key, leaf, clientID, nil)})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	parse := func(protocol string, data json.RawMessage, opt bool) (wallet.AuthorizationRequest, error) {
		return wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
			Protocol: protocol, Data: data, Origin: testDCAPIOrigin, VerifierTrust: trust, AcceptX509SANDNS: opt,
		})
	}

	for name, data := range map[string]struct {
		protocol string
		data     json.RawMessage
	}{
		"signed":       {wallet.DCAPIProtocolSigned, signed(t, clientID)},
		"multi-signed": {wallet.DCAPIProtocolMultiSigned, forms.multiSigned(t, nil, signer{key: key, cert: leaf, clientID: clientID})},
	} {
		t.Run(name, func(t *testing.T) {
			req, err := parse(data.protocol, data.data, true)
			if err != nil {
				t.Fatal(err)
			}
			if req.ClientID != clientID || req.Origin != testDCAPIOrigin || !req.VerifierCertificate.Equal(leaf) {
				t.Fatalf("request = %+v", req)
			}
			forms.answer(t, req)

			if _, err := parse(data.protocol, data.data, false); err == nil {
				t.Error("not opted in: accepted")
			}
		})
	}

	// Not opted in, or not the leaf's name: refused with the redirect
	// flow's errors.
	notHash := fmt.Sprintf(`wallet: parse dc api request: client_id %q does not match x5c leaf's own x509_hash %q`, clientID, x509HashOf(leaf))
	if _, err := parse(wallet.DCAPIProtocolSigned, signed(t, clientID), false); err == nil || err.Error() != notHash {
		t.Errorf("signed, not opted in: %v, want %s", err, notHash)
	}
	noName := `wallet: parse dc api request: client_id "x509_san_dns:other.example.net": "other.example.net" is not a dNSName subject alternative name of the x5c leaf (dNSNames ["rp.example.net"])`
	if _, err := parse(wallet.DCAPIProtocolSigned, signed(t, "x509_san_dns:other.example.net"), true); err == nil || err.Error() != noName {
		t.Errorf("signed, another name: %v, want %s", err, noName)
	}
	multiNoName := `wallet: parse dc api request: no signature verifies: signature 0: client_id "x509_san_dns:other.example.net": "other.example.net" is not a dNSName subject alternative name of the x5c leaf (dNSNames ["rp.example.net"])`
	if _, err := parse(wallet.DCAPIProtocolMultiSigned, forms.multiSigned(t, nil, signer{key: key, cert: leaf, clientID: "x509_san_dns:other.example.net"}), true); err == nil || err.Error() != multiNoName {
		t.Errorf("multi-signed, another name: %v, want %s", err, multiNoName)
	}

	req, err := parse(wallet.DCAPIProtocolUnsigned, forms.unsigned(t, func(c map[string]any) { c["client_id"] = clientID }), true)
	if err != nil {
		t.Fatal(err)
	}
	if req.ClientID != "" || req.VerifierCertificate != nil {
		t.Errorf("unsigned request with an x509_san_dns client_id: %+v, want it identified by its origin alone", req)
	}

	// The Wallet's own Config.AcceptX509SANDNS reaches the DC API too.
	w := newSANDNSWallet(t, trust)
	if _, err := w.ParseDCAPIRequestData(wallet.DCAPIProtocolSigned, signed(t, clientID), testDCAPIOrigin); err != nil {
		t.Errorf("(*Wallet).ParseDCAPIRequestData: %v", err)
	}
}
