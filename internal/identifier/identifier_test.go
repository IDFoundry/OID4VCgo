package identifier

import "testing"

func TestCheck(t *testing.T) {
	for s, ok := range map[string]bool{
		"org.iso.18013.5.1":       true,
		"age_over_18":             true,
		"":                        false,
		"age_over_18\nRetain: no": false,
		"family\u202ename":        false,
		"\u2066isolated\u2069":    false,
		"age_over_18\u2028Retain": false,
		"age_over_18\u2029Retain": false,
		"family\u200bname":        false,
		"family_name\u2060":       false,
		"\ufeffportrait":          false,
		"family_name\U000e0041":   false,
		"family\u00adname":        false,
		"family\u200dname":        false,
		"\xff\xfe":                false,
		string(make([]byte, 300)): false,
	} {
		if err := Check(s); (err == nil) != ok {
			t.Errorf("Check(%q) = %v", s, err)
		}
	}
}
