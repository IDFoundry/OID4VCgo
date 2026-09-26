package wallet

// AssuranceLevel gates how strict New's own validation is — the same
// mechanism issuer.AssuranceLevel and FAPIgo's own
// server.AssuranceLevel/client.AssuranceLevel use, mirrored here so a
// deployment has the same lever on the wallet side it already has on
// the issuer side.
type AssuranceLevel uint8

const (
	_ AssuranceLevel = iota

	// AssuranceDevelopment permits a configuration meant for local
	// development only — most importantly Config.Fetch.AllowLoopbackHTTP.
	AssuranceDevelopment

	// AssuranceProduction rejects a Config.Fetch with AllowLoopbackHTTP
	// set: fapihttp documents that option as existing for local
	// development only, and it lets this Wallet's own unauthenticated
	// fetches (a by-reference Credential Offer, the Nonce Endpoint, a
	// request_uri Request Object) go over plain http:// — the same
	// reasoning FAPIgo's own server.AssuranceProduction applies to an
	// endpoint URL parsed with fapi.AllowLoopbackHTTP.
	//
	// Config.Fetch.AllowedPrivateHosts is deliberately not rejected: it
	// is an explicit, named allow-list for a fixed deployment topology
	// (e.g. a Wallet backend reaching an internal Credential Issuer),
	// not a development switch, and every other SSRF check still
	// applies to an allowed host.
	AssuranceProduction
)
