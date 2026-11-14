//go:build !conformance_production

package prodwallet

// Built reports whether Open works in this binary.
const Built = false

// Open returns ErrNotBuilt: this binary was built without the
// conformance_production tag.
func Open(string) (*Stores, error) { return nil, ErrNotBuilt }
