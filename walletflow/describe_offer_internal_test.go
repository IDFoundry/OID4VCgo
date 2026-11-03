package walletflow

import (
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// A tx_code's description reaches the PIN prompt cleaned, as every
// issuer text is: no bidi overrides or line breaks to reorder or hide
// what's around it. The offer itself is left as it was.
func TestDescribeOffer_CleansTxCodeDescription(t *testing.T) {
	tx := &oid4vci.TxCode{Length: 6, Description: "Enter‮ the code\nyour bank sent"}
	offer := oid4vci.CredentialOffer{
		CredentialIssuer: "https://issuer.example",
		Grants:           &oid4vci.Grants{PreAuthorizedCode: &oid4vci.GrantPreAuthorizedCode{PreAuthorizedCode: "c", TxCode: tx}},
	}
	o := describeOffer(offer, oid4vci.Metadata{}, GrantPreAuthorizedCode, nil)
	if o.TxCode == nil || o.TxCode.Description != "Enter the code your bank sent" || o.TxCode.Length != 6 {
		t.Errorf("TxCode = %+v", o.TxCode)
	}
	if tx.Description != "Enter‮ the code\nyour bank sent" {
		t.Error("the offer's own tx_code was changed")
	}
}
