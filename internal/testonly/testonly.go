// Package testonly marks stand-ins that accept what anyone can forge,
// such as walletprovidertest.FakeVerifier, so that a constructor under
// a production assurance level can refuse them without an exported
// method or field saying so.
package testonly

// Marker marks a stand-in that embeds it, under an unexported alias so
// the field stays out of the stand-in's API. Its method is unexported,
// so only an embedded Marker gives a type that method: Is finds it on
// the stand-in, and on any type that embeds the stand-in.
type Marker struct{}

func (Marker) acceptsForgeries() {
	// Empty: having the method is the mark.
}

// Marked is implemented only by a marked stand-in, or by a type
// embedding one. The stand-in's package asserts it (var _ Marked =
// T{...}), so the mark can't be lost unnoticed.
type Marked interface{ acceptsForgeries() }

// Is reports whether v is a marked stand-in, or embeds one.
func Is(v any) bool {
	_, ok := v.(Marked)
	return ok
}
