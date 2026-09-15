package issuer

import (
	"fmt"

	"github.com/idfoundry/oid4vcigo"
)

// validateCredentialOffer checks o against oid4vci.CredentialOffer's
// own structural requirements (§4.1.1) and, additionally, against what
// this issuer's own cfg actually supports: every ID in
// CredentialConfigurationIDs must be known to it, and neither grant's
// own AuthorizationServer may be set, since this issuer's Metadata
// doesn't advertise multiple authorization_servers yet (see
// ARCHITECTURE.md).
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
	const noMultiAS = "authorization_server must not be set: this issuer's metadata does not advertise multiple authorization_servers"
	if o.Grants.AuthorizationCode != nil && o.Grants.AuthorizationCode.AuthorizationServer != "" {
		return fmt.Errorf("grants.authorization_code.%s", noMultiAS)
	}
	if o.Grants.PreAuthorizedCode != nil && o.Grants.PreAuthorizedCode.AuthorizationServer != "" {
		return fmt.Errorf("grants[%q].%s", "urn:ietf:params:oauth:grant-type:pre-authorized_code", noMultiAS)
	}
	return nil
}
