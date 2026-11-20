package testonly

import "testing"

type (
	// standIn is marked as a stand-in package's type is.
	standIn struct{ marker }
	marker  = Marker
	// wrapper embeds a stand-in, by value and by pointer.
	wrapper    struct{ standIn }
	ptrWrapper struct{ *standIn }
	// unmarked holds a stand-in without embedding it.
	unmarked struct{ inner standIn }
)

func TestIs(t *testing.T) {
	for _, c := range []struct {
		name string
		v    any
		want bool
	}{
		{"stand-in", standIn{}, true},
		{"pointer to a stand-in", &standIn{}, true},
		{"embedding a stand-in", wrapper{}, true},
		{"embedding a pointer to a stand-in", ptrWrapper{&standIn{}}, true},
		{"holding a stand-in in a named field", unmarked{inner: standIn{}}, false},
		{"nil", nil, false},
		{"another value", "fake", false},
	} {
		if got := Is(c.v); got != c.want {
			t.Errorf("%s: Is = %v, want %v", c.name, got, c.want)
		}
	}
}
