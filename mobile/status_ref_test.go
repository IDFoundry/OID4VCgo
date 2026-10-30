package mobile

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
)

// Both of an MSO's revocation mechanisms reach the app: an identifier
// list doesn't look like no status at all.
func TestStatusRefOf(t *testing.T) {
	if got := statusRefOf(nil); got != nil {
		t.Errorf("no status: %+v", got)
	}
	list := statusRefOf(&mdoc.Status{StatusList: &mdoc.StatusListRef{URI: "https://status.example/1", Idx: 7, Certificate: []byte{1}}})
	if list == nil || list.Type != "status_list" || list.Idx != 7 || list.Certificate != "AQ==" {
		t.Errorf("status list: %+v", list)
	}
	ids := statusRefOf(&mdoc.Status{IdentifierList: &mdoc.IdentifierListRef{ID: []byte{0xab}, URI: "https://status.example/ids"}})
	if ids == nil || ids.Type != "identifier_list" || ids.URI != "https://status.example/ids" || ids.ID != "qw==" || ids.Certificate != "" {
		t.Errorf("identifier list: %+v", ids)
	}
	if unknown := statusRefOf(&mdoc.Status{}); unknown == nil || unknown.Type != "unknown" {
		t.Errorf("a status naming no known mechanism: %+v", unknown)
	}
}
