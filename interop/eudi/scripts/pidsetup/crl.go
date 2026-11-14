package main

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

// defaultCRLHost is -crl-host's default: run-pid-issuer.sh's CRL_PORT.
const defaultCRLHost = "localhost:19446"

// crlFiles writes what pidwallet needs to publish the IACA's and the
// metadata CA's CRLs over https and check the issuer's certificates
// against them: crl-trust.json, its revocation check
// (conformancecrl.Trust), and one publisher per set of lists,
// crl-publisher-SET.json (conformancecrl.Publisher), which pidwallet's
// -crl-set picks:
//
//   - current: both CAs' lists current, revoking nothing;
//   - revoked: the IACA's revoking the Document Signer's and the SD-JWT
//     VC signer's certificates, for the control the wallet must refuse
//     the credential in;
//   - expired: the IACA's past its nextUpdate, so the wallet has no
//     current list for the issuer's certificates.
//
// The metadata CA's list is current in every set, so each control
// fails only at the credential.
func crlFiles(f files, crlHost string, iaca, metadataCA *conformancecrl.Authority, dsPEM, sdjwtPEM string) error {
	host, _, err := net.SplitHostPort(crlHost)
	if err != nil {
		return fmt.Errorf("-crl-host %q: %w", crlHost, err)
	}
	ds, err := conformancecert.ParseCertificatePEM(dsPEM)
	if err != nil {
		return err
	}
	sdjwt, err := conformancecert.ParseCertificatePEM(sdjwtPEM)
	if err != nil {
		return err
	}
	iacaCurrent, err := iaca.CRL()
	if err != nil {
		return err
	}
	iacaRevoking, err := iaca.CRL(ds, sdjwt)
	if err != nil {
		return err
	}
	iacaExpired, err := iaca.ExpiredCRL()
	if err != nil {
		return err
	}
	metadataCurrent, err := metadataCA.CRL()
	if err != nil {
		return err
	}
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM(host, []string{host})
	if err != nil {
		return fmt.Errorf("crl publisher tls certificate: %w", err)
	}
	trust := conformancecrl.Trust{
		DistributionPoints: []conformancecrl.DistributionPoint{iaca.DistributionPoint(), metadataCA.DistributionPoint()},
		TLSTrustAnchorsPEM: tlsCertPEM,
	}
	if err := putJSON(f, "crl-trust.json", trust); err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(crlHost)
	for set, iacaList := range map[string]string{"current": iacaCurrent, "revoked": iacaRevoking, "expired": iacaExpired} {
		pub := conformancecrl.Publisher{
			ListenAddr: net.JoinHostPort("127.0.0.1", port), TLSCertificatePEM: tlsCertPEM, TLSPrivateKeyPEM: tlsKeyPEM,
			CRLs: map[string]string{iaca.Path(): iacaList, metadataCA.Path(): metadataCurrent},
		}
		if err := putJSON(f, "crl-publisher-"+set+".json", pub); err != nil {
			return err
		}
	}
	return nil
}

func putJSON(f files, name string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f[name] = raw
	return nil
}
