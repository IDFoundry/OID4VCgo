package displaytext

import (
	"strings"
	"testing"
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
	} {
		if got := Clean(in, 200); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := Clean(strings.Repeat("\u00e9", 500), 200); utf8.RuneCountInString(got) != 200 {
		t.Errorf("kept %d runes, want 200", utf8.RuneCountInString(got))
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
