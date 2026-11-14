package main

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

func chain(t *testing.T, f files, name string) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	rest := f[name]
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		t.Fatalf("%s holds no certificate", name)
	}
	return certs
}

func roots(t *testing.T, f files, name string) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(f[name]) {
		t.Fatalf("%s holds no certificate", name)
	}
	return p
}

func TestGenerate(t *testing.T) {
	const issuer = "https://localhost:19443/pid-issuer"
	f, err := generate(issuer, "https://host.docker.internal:19445", defaultCRLHost)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tls-ca.pem", "haproxy.pem", "keycloak-cert.pem", "serve-cert.pem", "serve-key.pem", "iaca.pem",
		"metadata-ca.pem", "wallet-provider-ca.pem", "other-ca.pem", "wrprc.jws", "statuslist.jwt", "statuslist-signer.cert.der",
		"statuslist-signer.key.pem", "status-issuer.txt", "wallet-provider-status-list.txt"} {
		if len(f[name]) == 0 {
			t.Errorf("no %s", name)
		}
	}
	for _, alias := range []string{"pid-mdoc", "pid-sdjwt", "access-certificate", "request-encryption", "nonce-encryption", "wallet-attestation", "key-attestation"} {
		if !strings.Contains(string(f[alias+".key.pem"]), "BEGIN PRIVATE KEY") {
			t.Errorf("%s.key.pem isn't PKCS #8", alias)
		}
	}

	verify := func(name, rootsFile string, usage ...x509.ExtKeyUsage) *x509.Certificate {
		t.Helper()
		c := chain(t, f, name)
		if len(usage) == 0 {
			usage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}
		if _, err := c[0].Verify(x509.VerifyOptions{Roots: roots(t, f, rootsFile), KeyUsages: usage}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		return c[0]
	}
	if leaf := verify("pid-sdjwt.chain.pem", "iaca.pem"); leaf.URIs[0].String() != issuer {
		t.Errorf("the SD-JWT VC signer names %v", leaf.URIs)
	}
	ds := verify("pid-mdoc.chain.pem", "iaca.pem")
	if err := mdoc.DefaultDocumentSignerPolicy(ds, nil); err != nil {
		t.Errorf("document signer: %v", err)
	}
	if ds.Subject.Country[0] != issuingCountry {
		t.Errorf("document signer country %v", ds.Subject.Country)
	}
	if leaf := verify("access-certificate.chain.pem", "metadata-ca.pem"); leaf.URIs[0].String() != issuer {
		t.Errorf("the Access Certificate names %v", leaf.URIs)
	}
	verify("haproxy-cert.pem", "tls-ca.pem", x509.ExtKeyUsageServerAuth)
	if c := verify("serve-cert.pem", "tls-ca.pem", x509.ExtKeyUsageServerAuth); !strings.Contains(strings.Join(c.DNSNames, ","), "host.docker.internal") {
		t.Errorf("serve's certificate names %v", c.DNSNames)
	}
	for _, name := range []string{"request-encryption.chain.pem", "nonce-encryption.chain.pem"} {
		if c := chain(t, f, name)[0]; c.KeyUsage != x509.KeyUsageKeyAgreement {
			t.Errorf("%s key usage %v", name, c.KeyUsage)
		}
	}

	sl, err := x509.ParseCertificate(f["statuslist-signer.cert.der"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sl.Verify(x509.VerifyOptions{Roots: roots(t, f, "iaca.pem"), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("status list signer: %v", err)
	}
	if got := string(f["status-issuer.txt"]); sl.URIs[0].String() != got || got != "https://localhost:19443/token_status_list" {
		t.Errorf("status issuer %q, signer names %v", got, sl.URIs)
	}

	uri := string(f["wallet-provider-status-list.txt"])
	if uri != "https://host.docker.internal:19445/statuslists/jwt" {
		t.Fatalf("wallet provider status list %q", uri)
	}
	for idx, want := range []statuslist.StatusType{statuslist.StatusValid, statuslist.StatusInvalid} {
		got, _, err := statuslist.CheckX5C(string(f["statuslist.jwt"]), roots(t, f, "wallet-provider-ca.pem"),
			statuslist.StatusListRef{Idx: uint64(idx), URI: uri}, statuslist.VerifyOptions{UnboundSigner: statuslist.AnyListSigner})
		if err != nil || got != want {
			t.Errorf("index %d: %v, %v", idx, got, err)
		}
	}
}

func TestGenerateRefusesBadURLs(t *testing.T) {
	if _, err := generate("http://localhost/pid-issuer", "https://host.docker.internal:1", defaultCRLHost); err == nil {
		t.Error("an http issuer URL was accepted")
	}
	if _, err := generate("https://localhost/pid-issuer", "host.docker.internal", defaultCRLHost); err == nil {
		t.Error("a serve URL with no scheme was accepted")
	}
}
