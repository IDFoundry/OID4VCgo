package walletflowtest

// WithExtraResources has the Authorization Server accept resources
// besides the Credential Issuer, as one serving other Credential
// Issuers too does.
func WithExtraResources(opts Options, resources ...string) Options {
	opts.extraResources = resources
	return opts
}
