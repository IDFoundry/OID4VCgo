package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/internal/prodwallet"
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
//     custody, and status lists fetched by statuslist's own client.
//
// Each of those dials public addresses only, follows no redirect and
// verifies TLS against the system roots: run-pid-issuer.sh runs the
// wallet in a container on interop/prodnet.sh's network, where the
// stack is, and gives it the run's TLS CA as those roots. The holder's
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
	client, err := fapihttp.NewClient(fapihttp.RecommendedTransportConfig())
	if err != nil {
		_ = stores.Close()
		return err
	}
	client.Timeout = productionTimeout
	env.production, env.stores, env.prodHTTP = true, stores, client
	return nil
}

// walletHTTP is the core engine's client for the wallet and
// fapigo/client: production's, or the recording one.
func (env *environment) walletHTTP() *http.Client {
	if env.production {
		return env.prodHTTP
	}
	return env.http
}
