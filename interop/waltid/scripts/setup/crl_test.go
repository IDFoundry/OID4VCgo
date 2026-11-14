package main

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

// TestRunWritesCRLs checks setup names the CA's distribution point in
// Issuer2's and Verifier2's certificates and writes a publisher for
// each CRL set the wallet's -crl-set takes, and the trust checking
// against it.
func TestRunWritesCRLs(t *testing.T) {
	ca, err := newCA("test CA")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	put := func(name, content string) { files[name] = content }
	url := conformancecrl.URL("localhost:21441", "ca")
	issuers, err := issuer2Files(put, ca, ports{issuer2: 21411}, url)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := verifier2File(put, ca, ports{verifier2: 21412}, url)
	if err != nil {
		t.Fatal(err)
	}
	if err := crlFiles(put, ca, url, 21441, issuers, verifier); err != nil {
		t.Fatal(err)
	}
	for _, set := range []string{"current", "revoked-issuer", "revoked-verifier", "expired"} {
		var pub conformancecrl.Publisher
		if err := json.Unmarshal([]byte(files["crl-publisher-"+set+".json"]), &pub); err != nil {
			t.Fatalf("%s: %v", set, err)
		}
		if _, err := pub.Handler(); err != nil || len(pub.CRLs) != 1 {
			t.Errorf("%s: %v, %d CRLs", set, err, len(pub.CRLs))
		}
	}
	var trust conformancecrl.Trust
	if err := json.Unmarshal([]byte(files["crl-trust.json"]), &trust); err != nil || len(trust.DistributionPoints) != 1 || trust.DistributionPoints[0].URL != url {
		t.Errorf("crl-trust.json: %v, %+v", err, trust)
	}
	for _, p := range append(issuers, verifier) {
		cert, err := conformancecert.ParseCertificatePEM(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(cert.CRLDistributionPoints) != 1 || cert.CRLDistributionPoints[0] != url {
			t.Errorf("%s names %v, want [%s]", cert.Subject, cert.CRLDistributionPoints, url)
		}
	}
}
