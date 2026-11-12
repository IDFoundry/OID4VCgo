//go:build !conformance_production

package main

import "errors"

// newProductionBackend refuses Config.Production in a binary built
// without the conformance_production build tag: the production setup's
// stores are sqlstore's and fapigo/sqlstore's, separate modules this
// one doesn't require (see production.go).
func newProductionBackend(Config) (backend, error) {
	return nil, errors.New("config: production is set, but this binary was built without the conformance_production build tag, which needs a Go workspace holding this module and ./sqlstore (go work init . ./sqlstore; see conformance/issuer/README.md)")
}
