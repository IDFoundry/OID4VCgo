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
	if list == nil || list.Type != "status_list" || list.Idx != 7 || list.Certificate != "AQ==" || list.IdentifierList != nil {
		t.Errorf("status list: %+v", list)
	}
	idsRef := &mdoc.IdentifierListRef{ID: []byte{0xab}, URI: "https://status.example/ids"}
	ids := statusRefOf(&mdoc.Status{IdentifierList: idsRef})
	if ids == nil || ids.Type != "identifier_list" || ids.URI != "https://status.example/ids" || ids.ID != "qw==" || ids.Certificate != "" || ids.IdentifierList != nil {
		t.Errorf("identifier list: %+v", ids)
	}
	// Naming both, the identifier list, which may revoke the document
	// while the status list says valid, isn't hidden.
	both := statusRefOf(&mdoc.Status{StatusList: &mdoc.StatusListRef{URI: "https://status.example/1", Idx: 7}, IdentifierList: idsRef})
	if both == nil || both.Type != "status_list" || both.IdentifierList == nil || both.IdentifierList.Type != "identifier_list" || both.IdentifierList.ID != "qw==" {
		t.Errorf("both: %+v", both)
	}
	if unknown := statusRefOf(&mdoc.Status{}); unknown == nil || unknown.Type != "unknown" {
		t.Errorf("a status naming no known mechanism: %+v", unknown)
	}
}
