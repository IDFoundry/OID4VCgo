package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

// crlFiles writes what OID4VCgo's wallet needs to publish the CA's CRL
// over https on localhost:port, at crlURL, the distribution point
// Issuer2's and Verifier2's certificates name, and check them against
// it: crl-trust.json, its revocation check (conformancecrl.Trust), and
// one publisher per CRL, crl-publisher-SET.json
// (conformancecrl.Publisher), which scripts/wallet's -crl-set picks:
//
//   - current: revoking nothing;
//   - revoked-issuer: revoking Issuer2's SD-JWT VC and mdoc signers;
//   - revoked-verifier: revoking Verifier2's Access Certificate;
//   - expired: past its nextUpdate, so the wallet has no current list.
func crlFiles(put func(name, content string), ca authority, crlURL string, port int, issuer2Leaves []string, verifier2Leaf string) error {
	auth, err := conformancecrl.Wrap(ca.cert, ca.key, crlURL)
	if err != nil {
		return err
	}
	parse := func(pems ...string) ([]*x509.Certificate, error) {
		var certs []*x509.Certificate
		for _, p := range pems {
			c, err := conformancecert.ParseCertificatePEM(p)
			if err != nil {
				return nil, err
			}
			certs = append(certs, c)
		}
		return certs, nil
	}
	issuers, err := parse(issuer2Leaves...)
	if err != nil {
		return err
	}
	verifiers, err := parse(verifier2Leaf)
	if err != nil {
		return err
	}
	lists := map[string]string{}
	for set, revoked := range map[string][]*x509.Certificate{"current": nil, "revoked-issuer": issuers, "revoked-verifier": verifiers} {
		if lists[set], err = auth.CRL(revoked...); err != nil {
			return err
		}
	}
	if lists["expired"], err = auth.ExpiredCRL(); err != nil {
		return err
	}
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("localhost", []string{"localhost"})
	if err != nil {
		return fmt.Errorf("crl publisher tls certificate: %w", err)
	}
	trust := conformancecrl.Trust{
		DistributionPoints: []conformancecrl.DistributionPoint{auth.DistributionPoint()},
		TLSTrustAnchorsPEM: tlsCertPEM,
	}
	if err := putJSON(put, "crl-trust.json", trust); err != nil {
		return err
	}
	for set, list := range lists {
		pub := conformancecrl.Publisher{
			ListenAddr:        net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			TLSCertificatePEM: tlsCertPEM, TLSPrivateKeyPEM: tlsKeyPEM,
			CRLs: map[string]string{auth.Path(): list},
		}
		if err := putJSON(put, "crl-publisher-"+set+".json", pub); err != nil {
			return err
		}
	}
	return nil
}

func putJSON(put func(name, content string), name string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	put(name, string(raw))
	return nil
}
