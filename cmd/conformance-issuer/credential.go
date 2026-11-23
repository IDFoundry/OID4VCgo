package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	fapires "github.com/idfoundry/fapigo/resource"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/issuer/fapiresource"
)

// issuedCredentialLifetime bounds an issued credential's own "exp"
// claim — HAIP/SD-JWT VC §11.2.3's own RECOMMENDED (not required) way
// to limit a credential's validity, confirmed live as something the
// OIDF conformance suite's own log flags as a WARNING when absent. See
// sdjwtvc.RoundedExp's own doc comment for why the actual exp value is
// day-rounded, not this value added to the raw issuance instant.
const issuedCredentialLifetime = 365 * 24 * time.Hour

// nonceHandler serves the OID4VCI Nonce Endpoint (§7) with
// requestNonce, an issuer's RequestNonce — not a protected resource
// (issuer.RequestNonce's own doc comment), so no resource.Verifier
// check here. Its callers are anonymous: an error is logged, and they
// get only server_error, never its text (a store's error can name its
// database, host or user).
func nonceHandler(requestNonce func(context.Context) (issuer.NonceResult, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := requestNonce(r.Context())
		if err != nil {
			log.Printf("nonce endpoint: %v", err)
			issuer.WriteError(w, err)
			return
		}
		result.WriteJSON(w)
	}
}

// mdocClaimsForRequest builds this request's own *mdoc.Claims from
// nameSpaces (cfg.Mdoc.Claims, precomputed once by credentialHandler —
// nil when cfg.Mdoc is unset, in which case this returns nil too) and
// docType, with a Signed/ValidFrom/ValidUntil validity window spanning
// lifetime from the start of today's own UTC day, not the raw issuance
// instant — the same RFC 9901 §10.1 anti-linkability reasoning
// sdjwtvc.RoundedExp's own doc comment explains for SD-JWT VC's "exp",
// applying equally here (confirmed live: the OIDF suite's own
// VCIEnsureCredentialTimeClaimsNotLinkable check flags mdoc's MSO
// validityInfo signed/validFrom/validUntil the same way it flags
// SD-JWT VC's iat/exp/nbf). Day-granularity rounding means every
// credential issued on the same calendar day carries identical
// Signed/ValidFrom values, closing that channel.
func mdocClaimsForRequest(docType string, nameSpaces map[string]map[string]interface{}, lifetime time.Duration) *mdoc.Claims {
	if nameSpaces == nil {
		return nil
	}
	signed, validFrom, validUntil := mdoc.RoundedValidity(time.Now(), lifetime)
	return &mdoc.Claims{
		DocType: docType, NameSpaces: nameSpaces,
		Signed: signed, ValidFrom: validFrom, ValidUntil: validUntil,
	}
}

// credentialHandler serves the Credential Endpoint (§8) with
// issuer.CredentialHandler, checking access tokens with
// resourceVerifier through issuer/fapiresource. What it issues is fixed
// by cfg — issuer.Issuer has no user database of its own
// (CredentialRequest.SDJWTClaims' own doc comment), so this binary's
// own static test data stands in for one — narrowed to the claims the
// token's authorization detail asks for (req.AuthorizedClaims): the
// issuer issues whatever Prepare sets.
func credentialHandler(iss *issuer.Issuer, resourceVerifier *fapires.Verifier, credentialURL *url.URL, cfg Config) (http.Handler, error) {
	content, err := credentialContentFor(cfg)
	if err != nil {
		return nil, err
	}
	tokens, err := fapiresource.New(resourceVerifier)
	if err != nil {
		return nil, err
	}
	return iss.CredentialHandler(issuer.CredentialHandlerConfig{
		URL: credentialURL, Tokens: tokens,
		Prepare: func(_ context.Context, _ issuer.Grant, req *issuer.CredentialRequest) (func(bool), error) {
			if cfg.Deferred {
				reference, err := deferralReference(req.AuthorizedClaims)
				if err != nil {
					return nil, err
				}
				req.Defer = &issuer.Deferral{Reference: reference}
				return nil, nil
			}
			sdjwtClaims, mdocClaims := content()
			sdjwtClaims, mdocClaims, err := iss.NarrowToAuthorizedClaims(req.ResolvedConfigurationID, req.AuthorizedClaims, sdjwtClaims, mdocClaims)
			if err != nil {
				return nil, err
			}
			req.SDJWTClaims, req.MdocClaims = sdjwtClaims, mdocClaims
			if cfg.lists != nil {
				req.PerBatch = cfg.lists.perBatch
			}
			return nil, nil
		},
	})
}

// deferralReference is the Deferral.Reference carrying authorized, a
// deferred request's AuthorizedClaims, to the Deferred Credential
// Endpoint's Resolve: a DeferredTransactionRecord doesn't keep them,
// and this binary keeps no state of its own beside its stores. "" when
// every claim is authorized.
func deferralReference(authorized []oid4vci.ClaimsDescription) (string, error) {
	if len(authorized) == 0 {
		return "", nil
	}
	raw, err := json.Marshal(authorized)
	if err != nil {
		return "", fmt.Errorf("deferred authorized claims: %w", err)
	}
	return string(raw), nil
}

// referencedClaims is the AuthorizedClaims deferralReference carried
// in reference.
func referencedClaims(reference string) ([]oid4vci.ClaimsDescription, error) {
	if reference == "" {
		return nil, nil
	}
	var authorized []oid4vci.ClaimsDescription
	if err := json.Unmarshal([]byte(reference), &authorized); err != nil {
		return nil, fmt.Errorf("deferred authorized claims: %w", err)
	}
	return authorized, nil
}

// credentialContentFor returns what this binary issues, fixed by cfg:
// both SDJWTClaims and MdocClaims (the latter nil when cfg.Mdoc is
// unset) — the issuer uses whichever the requested configuration's
// format needs.
func credentialContentFor(cfg Config) (func() (*sdjwtvc.Claims, *mdoc.Claims), error) {
	additional := sdjwtAdditionalClaims(cfg.Claims)
	mdocNameSpaceElements, mdocDocType, err := mdocNameSpaceElementsFor(cfg.Mdoc)
	if err != nil {
		return nil, fmt.Errorf("mdoc claims: %w", err)
	}
	return func() (*sdjwtvc.Claims, *mdoc.Claims) {
		exp := sdjwtvc.RoundedExp(time.Now(), issuedCredentialLifetime)
		return &sdjwtvc.Claims{VCT: cfg.VCT, Exp: &exp, Additional: additional},
			mdocClaimsForRequest(mdocDocType, mdocNameSpaceElements, issuedCredentialLifetime)
	}, nil
}

// deferredPath is the Deferred Credential Endpoint's path
// under the Credential Issuer's identifier.
const deferredPath = "/deferred_credential"

// deferredCredentialHandler serves the Deferred Credential Endpoint
// (§9) with issuer.DeferredCredentialHandler, issuing a pending
// transaction on the Wallet's first poll: this binary has no business
// process to wait for, and the OIDF suite polls only once.
func deferredCredentialHandler(iss *issuer.Issuer, resourceVerifier *fapires.Verifier, cfg Config) (http.Handler, error) {
	endpoint, err := url.Parse(cfg.Issuer + deferredPath)
	if err != nil {
		return nil, fmt.Errorf("deferred credential endpoint URL: %w", err)
	}
	content, err := credentialContentFor(cfg)
	if err != nil {
		return nil, err
	}
	tokens, err := fapiresource.New(resourceVerifier)
	if err != nil {
		return nil, err
	}
	return iss.DeferredCredentialHandler(issuer.DeferredCredentialHandlerConfig{
		ProtectedEndpointConfig: issuer.ProtectedEndpointConfig{URL: endpoint, Tokens: tokens},
		Resolve: func(ctx context.Context, _ issuer.Grant, transactionID string, tx issuer.DeferredTransactionRecord) error {
			authorized, err := referencedClaims(tx.Reference)
			if err != nil {
				return err
			}
			sdjwtClaims, mdocClaims := content()
			sdjwtClaims, mdocClaims, err = iss.NarrowToAuthorizedClaims(tx.CredentialConfigurationID, authorized, sdjwtClaims, mdocClaims)
			var refused *issuer.Error
			switch {
			case errors.As(err, &refused):
				// None of the claims the token authorizes is in this
				// credential.
				return iss.DenyDeferredCredential(ctx, transactionID)
			case err != nil:
				return err
			}
			issuance := issuer.DeferredIssuance{SDJWTClaims: sdjwtClaims, MdocClaims: mdocClaims}
			if cfg.lists != nil {
				issuance.PerBatch = cfg.lists.perBatch
			}
			return iss.IssueDeferredCredential(ctx, transactionID, issuance)
		},
	})
}

// notificationPath is the Notification Endpoint's path under the
// Credential Issuer's identifier.
const notificationPath = "/notification"

// notificationHandler serves the Notification Endpoint (§11) with
// issuer.NotificationEndpointHandler, checking access tokens with
// resourceVerifier the same way credentialHandler does.
func notificationHandler(iss *issuer.Issuer, resourceVerifier *fapires.Verifier, cfg Config) (http.Handler, error) {
	endpoint, err := url.Parse(cfg.Issuer + notificationPath)
	if err != nil {
		return nil, fmt.Errorf("notification endpoint URL: %w", err)
	}
	tokens, err := fapiresource.New(resourceVerifier)
	if err != nil {
		return nil, err
	}
	return iss.NotificationEndpointHandler(issuer.ProtectedEndpointConfig{URL: endpoint, Tokens: tokens})
}

// sdjwtAdditionalClaims builds credentialHandler's own precomputed
// SD-JWT "Additional" claim map (every entry selectively disclosable)
// from claims — extracted out of credentialHandler itself purely to
// keep that function's own cognitive complexity low.
func sdjwtAdditionalClaims(claims map[string]string) map[string]any {
	additional := make(map[string]any, len(claims))
	for name, value := range claims {
		additional[name] = sdjwtvc.SD(value)
	}
	return additional
}

// mdocNameSpaceElementsFor builds credentialHandler's own precomputed
// mso_mdoc namespace/data-element map from cfg (nil when cfg is unset,
// in which case serveCredentialRequest's own mdocClaimsForRequest call
// always returns a nil *mdoc.Claims too) — extracted out of
// credentialHandler itself purely to keep that function's own
// cognitive complexity low. The actual Table 20 full-date/portrait
// transform lives in conformanceconfig.BuildMdocNameSpaceElements,
// shared with cmd/conformance-wallet-vp's own identical need to build
// a real mdoc fixture credential.
func mdocNameSpaceElementsFor(cfg *conformanceconfig.MdocConfig) (nameSpaces map[string]map[string]interface{}, docType string, err error) {
	if cfg == nil {
		return nil, "", nil
	}
	nameSpaces, err = conformanceconfig.BuildMdocNameSpaceElements(cfg.Namespace, cfg.Claims)
	if err != nil {
		return nil, "", err
	}
	return nameSpaces, cfg.DocType, nil
}
