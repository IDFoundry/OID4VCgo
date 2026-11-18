package webwallet

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// The consent page shows everything an option discloses: the claims
// asked for, those the credential discloses whatever is asked for, and
// those the verifier says it will keep; and it says "only" just when
// the claims asked for are all.
func TestConsent_ShowsAlwaysDisclosedAndRetained(t *testing.T) {
	render := func(o walletapp.Option) string {
		t.Helper()
		var b strings.Builder
		if err := consentTemplate.Execute(&b, consentPage{ID: "x", VerifierName: "V", Options: optionsFor([]walletapp.Option{o}, nil)}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	page := render(walletapp.Option{Ref: "option-0", Format: "dc+sd-jwt",
		Claims:          [][]string{{"family_name"}},
		AlwaysDisclosed: [][]string{{"nationalities", "0"}, {"address", "*", "country"}},
	})
	for _, want := range []string{"It will see:", "always shows", "<code>nationalities › 0</code>", "<code>address › * › country</code>", "<code>family_name</code>"} {
		if !strings.Contains(page, want) {
			t.Errorf("the consent page lacks %q", want)
		}
	}
	if strings.Contains(page, "It will see only") {
		t.Error("the consent page says the verifier sees only the claims asked for, beside claims always disclosed")
	}

	page = render(walletapp.Option{Ref: "option-0", Format: "mso_mdoc",
		Claims:   [][]string{{"org.iso.23220.1", "family_name"}, {"org.iso.23220.1", "portrait"}},
		Retained: [][]string{{"org.iso.23220.1", "portrait"}},
	})
	for _, want := range []string{"It will see only:", "It says it will keep:"} {
		if !strings.Contains(page, want) {
			t.Errorf("the mdoc consent page lacks %q", want)
		}
	}
	if strings.Contains(page, "always shows") {
		t.Error("the mdoc consent page lists claims always disclosed, with none")
	}
}
