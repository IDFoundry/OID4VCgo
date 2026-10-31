package displaytext

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzClean checks Clean and Shorten on arbitrary text and limits:
// their output is UTF-8 with no control, line or paragraph separator,
// or format character but the zero-width joiner and non-joiner, and no
// surrounding space; it holds at most limit runes (Shorten's one more,
// its ellipsis, only when it cut the text); and cleaning it again
// changes nothing.
func FuzzClean(f *testing.F) {
	for _, seed := range []string{
		"Example Bank", "Pay\u202egnp.exe", "line\nbreak\x00", "  \u2066Isolated\u2069 \u200fmark\u200e ",
		"Bank\u2028Verified\u2029", "\ufeffEx\u200bam\u2060ple\u00ad", "Bank\U000e0041\U000e007f",
		"\u0645\u06cc\u200c\u062e", "\U0001f469\u200d\U0001f4bb", "bad\xffbyte", "\ufffd", "a \u0085 b", "\t\r\n",
		strings.Repeat("\u00e9", 40), "x\u2026",
	} {
		f.Add(seed, uint8(16))
	}
	f.Add("", uint8(0))
	f.Add("abc", uint8(0))
	f.Fuzz(func(t *testing.T, s string, limit8 uint8) {
		limit := int(limit8)
		clean := Clean(s, limit)
		checkShown(t, s, clean)
		if n := utf8.RuneCountInString(clean); n > limit {
			t.Fatalf("Clean(%q, %d) = %q, %d runes", s, limit, clean, n)
		}
		if again := Clean(clean, limit); again != clean {
			t.Fatalf("Clean(%q, %d) = %q, which cleans again to %q", s, limit, clean, again)
		}

		short := Shorten(s, limit)
		if short != clean && short != clean+"\u2026" {
			t.Fatalf("Shorten(%q, %d) = %q, Clean = %q", s, limit, short, clean)
		}
		if n := utf8.RuneCountInString(short); n > limit+1 {
			t.Fatalf("Shorten(%q, %d) = %q, %d runes", s, limit, short, n)
		}
		if again := Shorten(short, limit); again != short {
			t.Fatalf("Shorten(%q, %d) = %q, which shortens again to %q", s, limit, short, again)
		}
	})
}

// checkShown fails t if out, Clean's output for in, holds anything
// Clean's documentation says it removes.
func checkShown(t *testing.T, in, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Fatalf("Clean(%q) = %q, not UTF-8", in, out)
	}
	if strings.TrimSpace(out) != out {
		t.Fatalf("Clean(%q) = %q, with surrounding space", in, out)
	}
	for _, r := range out {
		switch {
		case r == utf8.RuneError:
			t.Fatalf("Clean(%q) = %q, with U+FFFD", in, out)
		case unicode.IsControl(r), unicode.In(r, unicode.Zl, unicode.Zp):
			t.Fatalf("Clean(%q) = %q, with %U", in, out, r)
		case unicode.Is(unicode.Cf, r) && r != '\u200c' && r != '\u200d':
			t.Fatalf("Clean(%q) = %q, with the format character %U", in, out, r)
		}
	}
}
