// Package prodwallet gives the interop and conformance harnesses'
// wallets the durable stores walletflow requires at production
// assurance (walletflow.Config.Development false): sqlstore's sealed
// SQLite stores, as a wallet running on a server keeps its keys,
// credentials and pending authorizations.
//
// sqlstore is a module of its own that this one doesn't require, so
// Open works only in a binary built with the conformance_production
// tag, in a Go workspace holding this module and ./sqlstore:
//
//	go work init . ./sqlstore
//	go build -tags conformance_production ./interop/...
//
// Built without it, Open returns ErrNotBuilt.
//
// A production leg runs the wallet with nothing else changed from
// production: Dependencies.HTTP nil, so walletflow builds its own
// hardened client, which dials public addresses only and follows no
// redirect, and verifies TLS against the system roots. Two things
// about where it runs aren't production's, and the harness scripts
// that run it (interop/prodnet.sh) document them: the other side's
// services are on a Docker network whose subnet is global unicast
// space, internal (no route out), so that their addresses are public
// ones to that client; and the system roots are the run's TLS CA,
// through SSL_CERT_FILE. Throwaway key material only, never for
// production use.
package prodwallet

import "errors"

// ErrNotBuilt is Open's error in a binary built without the
// conformance_production tag.
var ErrNotBuilt = errors.New("prodwallet: built without the conformance_production build tag, which needs a Go workspace holding this module and ./sqlstore (go work init . ./sqlstore)")
