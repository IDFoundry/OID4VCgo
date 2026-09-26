package issuer

import (
	"fmt"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
)

// validateCredentialOffer checks o against oid4vci.CredentialOffer's
// own structural requirements (§4.1.1) and, additionally, against what
// this issuer's own cfg actually supports: every ID in
// CredentialConfigurationIDs must be known to it, and a grant's
// authorization_server is allowed only when cfg advertises more than
// one AuthorizationServers entry, and must then be one of them
// (§4.1.1: "MUST NOT be used otherwise").
func validateCredentialOffer(o oid4vci.CredentialOffer, cfg Config) error {
	if err := o.Validate(); err != nil {
		return err
	}
	for _, id := range o.CredentialConfigurationIDs {
		if _, ok := cfg.CredentialConfigurationsSupported[id]; !ok {
			return fmt.Errorf("credential_configuration_ids contains unknown id %q", id)
		}
	}
	if o.Grants == nil {
		return nil
	}
	if o.Grants.AuthorizationCode != nil {
		if err := checkGrantAuthorizationServer(o.Grants.AuthorizationCode.AuthorizationServer, cfg.AuthorizationServers); err != nil {
			return fmt.Errorf("grants.authorization_code.%w", err)
		}
	}
	if o.Grants.PreAuthorizedCode != nil {
		if err := checkGrantAuthorizationServer(o.Grants.PreAuthorizedCode.AuthorizationServer, cfg.AuthorizationServers); err != nil {
			return fmt.Errorf("grants[%q].%w", "urn:ietf:params:oauth:grant-type:pre-authorized_code", err)
		}
	}
	return nil
}

// checkGrantAuthorizationServer applies §4.1.1's rule for a grant's
// authorization_server against this issuer's advertised servers.
func checkGrantAuthorizationServer(value string, servers []fapi.URL) error {
	if value == "" {
		return nil
	}
	if len(servers) < 2 {
		return fmt.Errorf("authorization_server must not be set: this issuer's metadata does not advertise multiple authorization_servers")
	}
	for _, s := range servers {
		if s.String() == value {
			return nil
		}
	}
	return fmt.Errorf("authorization_server %q is not one of this issuer's authorization_servers", value)
}
