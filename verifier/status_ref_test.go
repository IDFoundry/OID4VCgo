package verifier_test

import (
	"math"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

func TestVerifiedCredential_StatusListRef(t *testing.T) {
	const uri = "https://issuer.example/statuslists/1"
	cases := map[string]struct {
		vc              verifier.VerifiedCredential
		want            statuslist.StatusListRef
		wantCWT, wantOK bool
		wantErr         bool
	}{
		"sd-jwt with status": {
			vc:   verifier.VerifiedCredential{Claims: map[string]any{"status": map[string]any{"status_list": map[string]any{"idx": float64(7), "uri": uri}}}},
			want: statuslist.StatusListRef{Idx: 7, URI: uri}, wantOK: true,
		},
		"sd-jwt without status": {vc: verifier.VerifiedCredential{Claims: map[string]any{"vct": "x"}}},
		"sd-jwt malformed status": {
			vc:      verifier.VerifiedCredential{Claims: map[string]any{"status": map[string]any{"status_list": "nope"}}},
			wantErr: true,
		},
		"mdoc with status": {
			vc:   verifier.VerifiedCredential{MdocStatus: &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 9, URI: uri}}},
			want: statuslist.StatusListRef{Idx: 9, URI: uri}, wantCWT: true, wantOK: true,
		},
		"mdoc status without a list": {vc: verifier.VerifiedCredential{MdocStatus: &mdoc.Status{}}},
		"mdoc index beyond int range": {
			vc:   verifier.VerifiedCredential{MdocStatus: &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: math.MaxUint64, URI: uri}}},
			want: statuslist.StatusListRef{Idx: math.MaxUint64, URI: uri}, wantCWT: true, wantOK: true,
		},
	}
	for name, c := range cases {
		ref, cwt, ok, err := c.vc.StatusListRef()
		if (err != nil) != c.wantErr || ok != c.wantOK || cwt != c.wantCWT || ref != c.want {
			t.Errorf("%s: StatusListRef = %+v, cwt %v, ok %v, err %v", name, ref, cwt, ok, err)
		}
	}
}
