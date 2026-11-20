// Package displaytext fits text from another party, such as an issuer's
// display name or a certificate's common name, to show the holder.
package displaytext

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Clean is s fit to show the holder: control characters and line and
// paragraph separators become spaces, so the text stays on the lines
// the app gives it, format characters are dropped, and at most limit
// runes are kept, trimmed of surrounding space. Format characters (Cf)
// are invisible: the bidirectional formatting ones can make text read
// other than it is, and the rest (zero-width space, word joiner, byte
// order mark, soft hyphen, tag characters) can hide text or break it
// where the app doesn't expect. The zero-width joiner and non-joiner
// stay: scripts such as Persian and Devanagari, and emoji sequences,
// need them to render right, and they join or part neighbouring
// characters without hiding or reordering any. The invisible letters
// and marks Unicode lists as default ignorable outside Cf (Hangul
// fillers U+115F, U+1160, U+3164 and U+FFA0, the combining grapheme
// joiner, Khmer's inherent vowels) are dropped too, as is the blank
// braille pattern U+2800, which shows as nothing: each could pad a name
// with blank space that isn't a space. So are the variation selectors
// (U+FE00–U+FE0F, U+E0100–U+E01EF and Mongolian's free variation
// selectors): each only picks a glyph for the character before it and
// shows as nothing itself, so a run of them can carry text no one sees,
// or set apart a name that looks the same as another. An emoji then
// shows in its default presentation.
func Clean(s string, limit int) string {
	text, _ := clean(s, limit)
	return text
}

// Shorten is Clean, ending text it cut short with "…", for an error or
// log line whose reader should know there was more.
func Shorten(s string, limit int) string {
	text, cut := clean(s, limit)
	if cut {
		return text + "…"
	}
	return text
}

// clean is Clean, also reporting whether it cut s short.
func clean(s string, limit int) (text string, cut bool) {
	var b strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case r == utf8.RuneError, isHiddenFormat(r), isInvisible(r):
			continue
		case unicode.IsControl(r), unicode.In(r, unicode.Zl, unicode.Zp):
			r = ' '
		}
		if n == limit {
			return strings.TrimSpace(b.String()), true
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String()), false
}

// isHiddenFormat reports whether r is a format character (Cf) other than
// the zero-width non-joiner and joiner: among them the bidirectional
// embeddings, overrides, isolates and marks.
func isHiddenFormat(r rune) bool {
	return r != '\u200c' && r != '\u200d' && unicode.Is(unicode.Cf, r)
}

// isInvisible reports whether r is a character that isn't a format
// character but shows as nothing: default ignorable (Unicode's
// Other_Default_Ignorable_Code_Point: the Hangul fillers among them), a
// variation selector, or the blank braille pattern.
func isInvisible(r rune) bool {
	return r == '\u2800' || unicode.In(r, unicode.Other_Default_Ignorable_Code_Point, unicode.Variation_Selector)
}
