package jose

import "testing"

// TypeIs compares media types case-insensitively in ASCII only, with
// "application/" implied.
func TestTypeIs(t *testing.T) {
	for _, tc := range []struct {
		typ, want string
		is        bool
	}{
		{"dc+sd-jwt", "dc+sd-jwt", true},
		{"DC+SD-JWT", "dc+sd-jwt", true},
		{"application/kb+jwt", "kb+jwt", true},
		{"Application/KB+JWT", "kb+jwt", true},
		{"kb+jwt", "dc+sd-jwt", false},
		{"\u212Ab+jwt", "kb+jwt", false},       // KELVIN SIGN
		{"dc+\u017Fd-jwt", "dc+sd-jwt", false}, // LATIN SMALL LETTER LONG S
		{"", "kb+jwt", false},
	} {
		if got := TypeIs(tc.typ, tc.want); got != tc.is {
			t.Errorf("TypeIs(%q, %q) = %v, want %v", tc.typ, tc.want, got, tc.is)
		}
	}
}
