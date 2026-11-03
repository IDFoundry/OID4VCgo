package issuer

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
)

// cloneConfig is cfg with every map, slice and pointer New validated
// copied, so neither the caller changing its Config afterwards nor a
// caller changing what Metadata returns changes the policy the Issuer
// enforces (a configuration's proof types, say). Signers' keys and
// certificates are shared: they aren't policy New could have checked
// differently.
func cloneConfig(cfg Config) Config {
	cfg.AuthorizationServers = slices.Clone(cfg.AuthorizationServers)
	cfg.CredentialConfigurationsSupported = cloneConfigurations(cfg.CredentialConfigurationsSupported)
	cfg.Display = cloneDisplays(cfg.Display)
	if cfg.RequestEncryption != nil {
		r := *cfg.RequestEncryption
		r.Keys = slices.Clone(r.Keys)
		r.EncValuesSupported = slices.Clone(r.EncValuesSupported)
		r.ZipValuesSupported = slices.Clone(r.ZipValuesSupported)
		cfg.RequestEncryption = &r
	}
	if cfg.ResponseEncryption != nil {
		r := *cfg.ResponseEncryption
		r.EncValuesSupported = slices.Clone(r.EncValuesSupported)
		r.ZipValuesSupported = slices.Clone(r.ZipValuesSupported)
		cfg.ResponseEncryption = &r
	}
	if cfg.BatchCredentialIssuance != nil {
		b := *cfg.BatchCredentialIssuance
		cfg.BatchCredentialIssuance = &b
	}
	return cfg
}

func cloneConfigurations(in map[string]CredentialConfiguration) map[string]CredentialConfiguration {
	if in == nil {
		return nil
	}
	out := make(map[string]CredentialConfiguration, len(in))
	for id, c := range in {
		out[id] = cloneConfiguration(c)
	}
	return out
}

func cloneConfiguration(c CredentialConfiguration) CredentialConfiguration {
	c.CryptographicBindingMethodsSupported = slices.Clone(c.CryptographicBindingMethodsSupported)
	c.CredentialSigningAlgValuesSupported = slices.Clone(c.CredentialSigningAlgValuesSupported)
	c.CredentialSigningAlgValuesSupportedCOSE = slices.Clone(c.CredentialSigningAlgValuesSupportedCOSE)
	c.ProofTypesSupported = cloneProofTypes(c.ProofTypesSupported)
	c.CredentialMetadata = cloneCredentialMetadata(c.CredentialMetadata)
	c.TypeMetadata = cloneTypeMetadata(c.TypeMetadata)
	return c
}

func cloneProofTypes(in map[string]oid4vci.ProofTypeConfiguration) map[string]oid4vci.ProofTypeConfiguration {
	if in == nil {
		return nil
	}
	out := make(map[string]oid4vci.ProofTypeConfiguration, len(in))
	for id, p := range in {
		p.ProofSigningAlgValuesSupported = slices.Clone(p.ProofSigningAlgValuesSupported)
		if p.KeyAttestationsRequired != nil {
			r := *p.KeyAttestationsRequired
			r.KeyStorage = slices.Clone(r.KeyStorage)
			r.UserAuthentication = slices.Clone(r.UserAuthentication)
			p.KeyAttestationsRequired = &r
		}
		out[id] = p
	}
	return out
}

func cloneCredentialMetadata(in *oid4vci.CredentialMetadata) *oid4vci.CredentialMetadata {
	if in == nil {
		return nil
	}
	out := oid4vci.CredentialMetadata{Display: slices.Clone(in.Display), Claims: slices.Clone(in.Claims)}
	for i, d := range out.Display {
		if d.Logo != nil {
			logo := *d.Logo
			out.Display[i].Logo = &logo
		}
		if d.BackgroundImage != nil {
			image := *d.BackgroundImage
			out.Display[i].BackgroundImage = &image
		}
	}
	for i, c := range out.Claims {
		// A path's elements are strings, nulls and integers: copying the
		// slice copies them.
		out.Claims[i].Path = slices.Clone(c.Path)
		out.Claims[i].Display = slices.Clone(c.Display)
		if c.Mandatory != nil {
			mandatory := *c.Mandatory
			out.Claims[i].Mandatory = &mandatory
		}
	}
	return &out
}

func cloneDisplays(in []oid4vci.Display) []oid4vci.Display {
	out := slices.Clone(in)
	for i, d := range out {
		if d.Logo != nil {
			logo := *d.Logo
			out[i].Logo = &logo
		}
	}
	return out
}

func cloneTypeMetadata(in *sdjwtvc.TypeMetadata) *sdjwtvc.TypeMetadata {
	if in == nil {
		return nil
	}
	out := *in
	out.Display = slices.Clone(in.Display)
	for i, d := range out.Display {
		if d.Rendering != nil {
			rendering := make(map[string]json.RawMessage, len(d.Rendering))
			for k, v := range maps.All(d.Rendering) {
				rendering[k] = bytes.Clone(v)
			}
			out.Display[i].Rendering = rendering
		}
	}
	out.Claims = slices.Clone(in.Claims)
	for i, c := range out.Claims {
		out.Claims[i].Path = slices.Clone(c.Path)
		out.Claims[i].Display = slices.Clone(c.Display)
	}
	return &out
}
