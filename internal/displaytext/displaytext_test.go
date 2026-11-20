package displaytext

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Text reaches the holder without control, line separator or invisible
// format characters, and bounded, the joiners that scripts and emoji
// need aside.
func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"Example Bank":     "Example Bank",
		"Pay\u202egnp.exe": "Paygnp.exe",
		"line\nbreak\x00":  "line break",
		"  \u2066Isolated\u2069 \u200fmark\u200e ":         "Isolated mark",
		"Bank\u2028Verified by the State\u2029":            "Bank Verified by the State",
		"\ufeffEx\u200bam\u2060ple\u00ad Bank":             "Example Bank",
		"Bank\U000e0041\U000e0042\U000e007f":               "Bank",
		"\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645": "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645",
		"\U0001f469\u200d\U0001f4bb Coders":                "\U0001f469\u200d\U0001f4bb Coders",
		"bad\xffbyte":                                      "badbyte",
		// Invisible letters and symbols that aren't format characters.
		"Bank\u3164\u3164Verified":            "BankVerified",
		"\u115f\u1160Bank\uffa0":              "Bank",
		"Bank\u2800\u2800\u2800":              "Bank",
		"Ba\u034fnk\u17b4\u17b5":              "Bank",
		"\ud55c\uad6d\uc740\ud589 Korea Bank": "\ud55c\uad6d\uc740\ud589 Korea Bank",
		// Variation selectors, emoji's among them: invisible, and a
		// run of them can carry text.
		"Example Bank\ufe0f\ufe0e\U000e0100":   "Example Bank",
		"\U0001f469\ufe0f Bank":                "\U0001f469 Bank",
		"\u845b\U000e0101 Bank":                "\u845b Bank",
		"\u1820\u180b\u1821\u180f":             "\u1820\u1821",
		"Bank" + strings.Repeat("\ufe00", 300): "Bank",
	} {
		if got := Clean(in, 200); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := Clean(strings.Repeat("\u00e9", 500), 200); utf8.RuneCountInString(got) != 200 {
		t.Errorf("kept %d runes, want 200", utf8.RuneCountInString(got))
	}
}

// Every variation selector, all 260, is dropped.
func TestClean_VariationSelectors(t *testing.T) {
	n := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !unicode.Is(unicode.Variation_Selector, r) {
			continue
		}
		n++
		if got := Clean("a"+string(r)+"b", 10); got != "ab" {
			t.Errorf("Clean kept %U: %q", r, got)
		}
	}
	if n != 260 {
		t.Errorf("%d variation selectors, want 260", n)
	}
}

// Shorten cleans as Clean does, and marks text it cut short.
func TestShorten(t *testing.T) {
	for in, want := range map[string]string{
		"denied\u2028INFO forged": "denied INF\u2026",
		"short\u200b":             "short",
		"exactly10!\u200b":        "exactly10!",
		"eleven runes":            "eleven run\u2026",
	} {
		if got := Shorten(in, 10); got != want {
			t.Errorf("Shorten(%q) = %q, want %q", in, got, want)
		}
	}
}
