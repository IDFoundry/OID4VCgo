package mdocdcapi

import "testing"

// The wallet takes only a serialized origin: a bare "?" or "#", which
// url.Parse leaves no query or fragment for, is refused too.
func TestCheckOrigin(t *testing.T) {
	for _, origin := range []string{"https://shop.example", "https://shop.example:8443", "http://localhost:8080"} {
		if err := checkOrigin(origin); err != nil {
			t.Errorf("%q: %v", origin, err)
		}
	}
	for _, origin := range []string{
		"", "shop.example", "https://shop.example/", "https://shop.example/app",
		"https://shop.example?x=1", "https://shop.example?", "https://shop.example#x", "https://shop.example#",
		"https://u@shop.example", "https:shop.example",
	} {
		if err := checkOrigin(origin); err == nil {
			t.Errorf("%q: accepted", origin)
		}
	}
}
