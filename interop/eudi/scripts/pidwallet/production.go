package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/internal/prodwallet"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// The -assurance levels. Under production the wallet is set up as a
// deployment sets it up, every engine:
//
//   - walletflow at production assurance (Config.Development false),
//     building its own HTTP client (Dependencies.HTTP nil), its keys,
//     credentials and pending authorizations in sqlstore's sealed
//     stores (internal/prodwallet), which it requires to receive
//     credentials;
//   - the core engine's wallet.Wallet and fapigo/client at
//     AssuranceProduction, over fapihttp.NewClient's client, the
//     client's sessions in fapigo/sqlstore's store and its instance
//     and DPoP keys in sqlstore's KeyStore, which declares their
//     custody, and status lists fetched through that client.
//
// Each of those dials public addresses only, and the private ones of
// the hosts -allowed-private-host names, follows no redirect and
// verifies TLS against the system roots: run-pid-issuer.sh runs the
// wallet in a container on interop/prodnet.sh's network, where the
// stack is, names the stack's host, and gives it the run's TLS CA as
// those roots. The holder's
// sign-in at Keycloak (login) is the holder's browser, not the wallet,
// and keeps env.http. Every certificate is still checked against the
// IACA's and the metadata CA's CRLs (startCRL), and trust is as strict
// as at development.
const (
	assuranceDevelopment = "development"
	assuranceProduction  = "production"
)

// productionTimeout bounds each request of the core engine's client.
const productionTimeout = 30 * time.Second

// startProduction opens the stores in o.store and builds production's
// HTTP client.
func (env *environment) startProduction() error {
	stores, err := prodwallet.Open(env.o.store)
	if err != nil {
		return fmt.Errorf("-store: %w", err)
	}
	tc := fapihttp.RecommendedTransportConfig()
	tc.AllowedPrivateHosts = env.o.allowedPrivateHosts
	client, err := fapihttp.NewClient(tc)
	if err != nil {
		_ = stores.Close()
		return err
	}
	client.Timeout = productionTimeout
	env.production, env.stores, env.prodHTTP = true, stores, client
	return nil
}

// productionStatusFetcher is the core engine's status list Fetcher in
// production: statuslist's own client, public addresses only, the
// system's TLS roots; or, with -allowed-private-host, as walletflow
// fetches then, production's hardened client used as it is
// (UncheckedTransport), its dial-time policy allowing those hosts'
// private addresses alone, where statuslist's own policy can allow only
// every private address or none.
func (env *environment) productionStatusFetcher() statuslist.Fetcher {
	if len(env.o.allowedPrivateHosts) == 0 {
		return statuslist.Fetcher{}
	}
	client := *env.prodHTTP
	client.Transport = hardenedTransport{env.prodHTTP.Transport}
	return statuslist.Fetcher{HTTP: &client, UncheckedTransport: true}
}

// hardenedTransport hides fapihttp.NewClient's transport from
// statuslist.Fetcher's *http.Transport check, so it keeps its own
// dialer.
type hardenedTransport struct{ http.RoundTripper }

// walletHTTP is the core engine's client for the wallet and
// fapigo/client: production's, or the recording one.
func (env *environment) walletHTTP() *http.Client {
	if env.production {
		return env.prodHTTP
	}
	return env.http
}
