//go:build !conformance_production

package main

import "errors"

// openStores fails in a binary built without the conformance_production
// tag: the provider's stores are sqlstore's, a module of its own (see
// stores_production.go).
func openStores(string) (stores, error) {
	return stores{}, errors.New("this binary was built without the conformance_production build tag, which needs a Go workspace holding this module and ./sqlstore (interop/production.sh's build_production)")
}
