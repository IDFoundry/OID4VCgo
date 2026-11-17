package issuerapp

// WithExtraResources has the Authorization Server accept resources
// besides the Credential Issuer, as one serving other Credential
// Issuers too does.
func WithExtraResources(resources ...string) func(*Config) {
	return func(cfg *Config) { cfg.extraResources = resources }
}
