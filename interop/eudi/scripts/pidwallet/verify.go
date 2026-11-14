package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// verifyAll checks each credential as walletflow does on receipt
// (wallet.VerifyIssuedCredential: signature under the IACA, the
// signer's role, the issuer it names, validity, holder binding to one
// of holders), then its status list entry, recording what it found.
// It reports whether every credential passed verification; the status
// found is only recorded.
func verifyAll(ctx context.Context, env *environment, conf oid4vci.CredentialConfigurationMetadata, credentialIssuer string,
	credentials []oid4vci.IssuedCredential, holders []*ecdsa.PrivateKey, res *result) bool {
	ok := true
	for i, ic := range credentials {
		report := credentialReport{Format: conf.Format}
		verified, err := verifyOne(ctx, env, conf, credentialIssuer, ic.Credential, holders)
		if err != nil {
			report.VerifyError = err.Error()
			res.Credentials = append(res.Credentials, report)
			if ok {
				res.fail("verify", fmt.Errorf("credential %d: %w", i, err))
			}
			ok = false
			continue
		}
		// The script decides whether the status is what the case
		// expects.
		res.Credentials = append(res.Credentials, verifiedReport(ctx, env, conf, ic.Credential, verified))
	}
	return ok
}

// verifiedReport is what the wallet found of a verified credential,
// its status list entry checked.
func verifiedReport(ctx context.Context, env *environment, conf oid4vci.CredentialConfigurationMetadata, credential string,
	verified wallet.VerifiedIssuedCredential) credentialReport {
	report := credentialReport{Format: conf.Format, Verified: true, Claims: claimNames(verified.Claims), Status: "absent"}
	if verified.IssuerCertificate != nil {
		report.Signer = verified.IssuerCertificate.Subject.CommonName
	}
	report.Issuer, _ = verified.Claims["iss"].(string)
	if !verified.ValidUntil.IsZero() {
		report.ValidUntil = verified.ValidUntil.UTC().Format(time.RFC3339)
	}
	ref := verified.StatusList
	if ref == nil {
		return report
	}
	report.StatusURI, report.StatusIdx, report.Status = ref.URI, ref.Idx, ""
	status, err := checkStatus(ctx, env, conf, credential, verified)
	if err != nil {
		report.StatusError = err.Error()
	} else {
		report.Status = status.String()
	}
	return report
}

// verifyOne verifies credential against each of holders until one
// binds it.
func verifyOne(ctx context.Context, env *environment, conf oid4vci.CredentialConfigurationMetadata, credentialIssuer, credential string,
	holders []*ecdsa.PrivateKey) (wallet.VerifiedIssuedCredential, error) {
	params := wallet.VerifyIssuedCredentialParams{
		Configuration: conf, Credential: credential, IssuerRoots: env.issuerRoots, IssuerRevocation: env.revocation,
		RequireIssuerName: true, CredentialIssuer: credentialIssuer, Now: time.Now(),
	}
	if conf.Format == "mso_mdoc" {
		// A Document Signer's own profile, as walletflow checks an mdoc
		// under mdoc-specific roots.
		params.IssuerLeafPolicy = mdoc.DefaultDocumentSignerPolicy
		params.RequireIssuerName = false
		params.CredentialIssuer = ""
	}
	var errs []error
	for _, h := range holders {
		params.HolderKey = &h.PublicKey
		verified, err := wallet.VerifyIssuedCredential(ctx, params)
		if err == nil {
			return verified, nil
		}
		errs = append(errs, err)
	}
	return wallet.VerifiedIssuedCredential{}, errors.Join(errs...)
}

// checkStatus checks a verified credential's status list entry, with
// the signer trust walletflow's CheckStatus applies: for an SD-JWT VC, a
// list signed by its issuer or by a certificate under the IACA naming
// the issuer's Status Issuer; for an mdoc, one under the CA that signed
// its Document Signer (ISO/IEC 18013-5 §12.3.6), a CWT that must carry
// exp (§12.3.6.3).
func checkStatus(ctx context.Context, env *environment, conf oid4vci.CredentialConfigurationMetadata, credential string,
	verified wallet.VerifiedIssuedCredential) (statuslist.StatusType, error) {
	checker := statuslist.Checker{
		Fetcher: statuslist.Fetcher{HTTP: env.statusHTTP, AllowLoopback: true},
		Roots:   env.issuerRoots,
		Options: statuslist.VerifyOptions{Revocation: env.revocation},
	}
	if conf.Format == "mso_mdoc" {
		raw, err := base64.RawURLEncoding.DecodeString(credential)
		if err != nil {
			return 0, err
		}
		issuerSigned, err := mdoc.UnmarshalIssuerSigned(raw)
		if err != nil {
			return 0, err
		}
		status, path, err := mdoc.IssuerAuthStatus(issuerSigned)
		if err != nil {
			return 0, err
		}
		var ref *mdoc.StatusListRef
		if status != nil {
			ref = status.StatusList
		}
		trust, err := mdoc.StatusTrust(ref, path)
		if err != nil {
			return 0, err
		}
		if trust.Roots != nil {
			checker.Roots = trust.Roots
			checker.Options.UnboundSigner = statuslist.AnyListSigner
		} else {
			checker.Options.UnboundSigner = trust.LeafPolicy
		}
	} else {
		iss, _ := verified.Claims["iss"].(string)
		var issuerKey any
		if verified.IssuerCertificate != nil {
			issuerKey = verified.IssuerCertificate.PublicKey
		}
		statusIssuer := env.statusIssuer
		checker.Options.UnboundSigner = func(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
			if certchain.SameKey(leaf.PublicKey, issuerKey) || certchain.CheckIssuerName(leaf, iss) == nil ||
				certchain.CheckIssuerName(leaf, statusIssuer) == nil {
				return nil
			}
			return fmt.Errorf("the status list's signer is neither %q nor its Status Issuer %q", iss, statusIssuer)
		}
	}
	status, _, err := checker.Check(ctx, *verified.StatusList, verified.StatusListCWT)
	return status, err
}

// revokeFirst revokes the first credential's status list entry at the
// status list service (its /set endpoint, with the service's API key)
// and checks the entry again.
func revokeFirst(ctx context.Context, env *environment, conf oid4vci.CredentialConfigurationMetadata, credentials []oid4vci.IssuedCredential,
	holders []*ecdsa.PrivateKey, credentialIssuer string, res *result) error {
	verified, err := verifyOne(ctx, env, conf, credentialIssuer, credentials[0].Credential, holders)
	if err != nil {
		return err
	}
	ref := verified.StatusList
	if ref == nil {
		return errors.New("the credential has no status list entry")
	}
	set, err := url.Parse(ref.URI)
	if err != nil {
		return err
	}
	set.Path, set.RawQuery = "/token_status_list/set", ""
	form := url.Values{"uri": {ref.URI}, "idx": {strconv.FormatUint(ref.Idx, 10)}, "status": {"1"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, set.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Api-Key", env.o.revokeAPIKey)
	resp, err := env.statusHTTP.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the status list service answered %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	status, err := checkStatus(ctx, env, conf, credentials[0].Credential, verified)
	if err != nil {
		res.StatusAfterRevoke = "error: " + err.Error()
		return nil
	}
	res.StatusAfterRevoke = status.String()
	return nil
}

// claimNames are a credential's claim names, sorted: an mdoc's as
// namespace/element.
func claimNames(claims map[string]any) []string {
	var names []string
	for k, v := range claims {
		if inner, ok := v.(map[string]any); ok && strings.Contains(k, ".") {
			for e := range inner {
				names = append(names, k+"/"+e)
			}
			continue
		}
		names = append(names, k)
	}
	slices.Sort(names)
	return names
}
