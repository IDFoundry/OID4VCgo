//go:build !conformance_production

package main

import (
	"errors"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// openProductionStore refuses Config.Production in a binary built
// without the conformance_production build tag: the production store
// is sqlstore's, a separate module this one doesn't require (see
// production.go).
func openProductionStore(ProductionConfig) (verifier.TransactionStore, error) {
	return nil, errors.New("config: production is set, but this binary was built without the conformance_production build tag, which needs a Go workspace holding this module and ./sqlstore (go work init . ./sqlstore; see conformance/verifier/README.md)")
}
