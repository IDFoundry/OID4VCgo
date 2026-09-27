package wallet

import (
	"errors"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// AuthorizationPlan is how a Wallet obtains, through the Authorization
// Code Flow, the credentials a Credential Offer offers: which
// Authorization Server to use and what to ask it for.
type AuthorizationPlan struct {
	// AuthorizationServer is the Authorization Server's issuer
	// identifier — pass it to FetchAuthorizationServerMetadata.
	AuthorizationServer string

	// Scopes are the scopes of the offered Credential Configurations,
	// in offer order without duplicates — pass them to
	// BuildAuthorizationRequest (HAIP 1.0 §4.1, §4.3: every Credential
	// Configuration has a scope, and the Wallet requests by scope).
	Scopes []string

	// IssuerState is the offer's issuer_state, or "" — BuildAuthorizationRequest
	// sends it on.
	IssuerState string
}

// PlanAuthorization works out the AuthorizationPlan for offer, whose
// Credential Issuer's metadata is metadata (FetchCredentialIssuerMetadata).
//
// The Authorization Server (OID4VCI 1.0 §12.2.4, §4.1.1) is the
// Credential Issuer itself when its metadata lists no
// authorization_servers; the one it lists; or, when it lists several,
// the one the offer's authorization_code grant names — which must be
// one of them. An offer that names a server the metadata doesn't list,
// or names none when several are listed, is refused.
//
// Every offered configuration must be in metadata with a scope. An
// offer with grants but no authorization_code grant (e.g. only
// pre-authorized_code) is refused: see RequestPreAuthorizedCodeToken
// for that flow.
func PlanAuthorization(offer oid4vci.CredentialOffer, metadata oid4vci.Metadata) (AuthorizationPlan, error) {
	// metadata must be the offering issuer's own, as
	// FetchCredentialIssuerMetadata checks it names the issuer it was
	// fetched for (§12.2.4): its authorization servers and scopes are
	// what this plan trusts.
	if metadata.CredentialIssuer.String() != offer.CredentialIssuer {
		return AuthorizationPlan{}, fmt.Errorf("wallet: plan authorization: metadata is for issuer %q, but the offer is from %q", metadata.CredentialIssuer.String(), offer.CredentialIssuer)
	}
	var grant *oid4vci.GrantAuthorizationCode
	if offer.Grants != nil {
		if offer.Grants.AuthorizationCode == nil {
			return AuthorizationPlan{}, errors.New("wallet: plan authorization: the offer has no authorization_code grant")
		}
		grant = offer.Grants.AuthorizationCode
	}
	plan := AuthorizationPlan{}
	if grant != nil {
		plan.IssuerState = grant.IssuerState
	}
	var err error
	if plan.AuthorizationServer, err = selectAuthorizationServer(offer.CredentialIssuer, grant, metadata.AuthorizationServers); err != nil {
		return AuthorizationPlan{}, fmt.Errorf("wallet: plan authorization: %w", err)
	}
	seen := map[string]bool{}
	for _, id := range offer.CredentialConfigurationIDs {
		conf, ok := metadata.CredentialConfigurationsSupported[id]
		if !ok {
			return AuthorizationPlan{}, fmt.Errorf("wallet: plan authorization: offered configuration %q isn't in the issuer's metadata", id)
		}
		if conf.Scope == "" {
			return AuthorizationPlan{}, fmt.Errorf("wallet: plan authorization: offered configuration %q has no scope", id)
		}
		if !seen[conf.Scope] {
			seen[conf.Scope] = true
			plan.Scopes = append(plan.Scopes, conf.Scope)
		}
	}
	if len(plan.Scopes) == 0 {
		return AuthorizationPlan{}, errors.New("wallet: plan authorization: the offer offers no credential configuration")
	}
	return plan, nil
}

func selectAuthorizationServer(credentialIssuer string, grant *oid4vci.GrantAuthorizationCode, servers []fapi.URL) (string, error) {
	named := ""
	if grant != nil {
		named = grant.AuthorizationServer
	}
	if len(servers) == 0 {
		if named != "" && named != credentialIssuer {
			return "", fmt.Errorf("the offer names authorization server %q, but the issuer lists none", named)
		}
		return credentialIssuer, nil
	}
	for _, as := range servers {
		if named == "" && len(servers) == 1 {
			return as.String(), nil
		}
		if as.String() == named {
			return named, nil
		}
	}
	if named == "" {
		return "", fmt.Errorf("the issuer lists %d authorization servers and the offer doesn't name one", len(servers))
	}
	return "", fmt.Errorf("the offer names authorization server %q, which the issuer doesn't list", named)
}

// ClientEndpoints converts m to what fapigo/client.Config needs: the
// Authorization Server's issuer identifier and its authorization, token
// and pushed authorization request endpoints. opts apply to every URL
// (e.g. fapi.AllowLoopbackHTTP() for local development).
func (m AuthorizationServerMetadata) ClientEndpoints(opts ...fapi.URLOption) (fapi.URL, client.Endpoints, error) {
	issuer, err := fapi.ParseIssuerURL(m.Issuer, opts...)
	if err != nil {
		return fapi.URL{}, client.Endpoints{}, fmt.Errorf("wallet: authorization server issuer: %w", err)
	}
	var endpoints client.Endpoints
	for name, field := range map[string]struct {
		raw string
		dst *fapi.URL
	}{
		"authorization_endpoint":                {m.AuthorizationEndpoint, &endpoints.Authorization},
		"token_endpoint":                        {m.TokenEndpoint, &endpoints.Token},
		"pushed_authorization_request_endpoint": {m.PushedAuthorizationRequestEndpoint, &endpoints.PushedAuthorizationRequest},
	} {
		if *field.dst, err = fapi.ParseEndpointURL(field.raw, opts...); err != nil {
			return fapi.URL{}, client.Endpoints{}, fmt.Errorf("wallet: authorization server %s: %w", name, err)
		}
	}
	return issuer, endpoints, nil
}
