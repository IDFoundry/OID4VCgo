package walletapp

import (
	"context"
	"errors"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// PINApprover is an Approver that can also supply a pre-authorized
// offer's PIN (tx_code, OID4VCI 1.0 §4.1.1): the wallet redeems such an
// offer at the token endpoint with the PIN, with no browser approval.
type PINApprover interface {
	PIN(ctx context.Context, txCode oid4vci.TxCode) (string, error)
}

// PIN implements PINApprover with Code.
func (h HeadlessApprover) PIN(context.Context, oid4vci.TxCode) (string, error) {
	if h.Code == "" {
		return "", errors.New("walletapp: the offer needs a PIN")
	}
	return h.Code, nil
}
