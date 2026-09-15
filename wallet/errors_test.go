package wallet_test

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcigo/wallet"
)

func TestError_Error(t *testing.T) {
	withDescription := &wallet.Error{HTTPStatus: 400, Code: "invalid_proof", Description: "proof is expired"}
	if !strings.Contains(withDescription.Error(), "invalid_proof") || !strings.Contains(withDescription.Error(), "proof is expired") {
		t.Errorf("Error() = %q, want it to mention code and description", withDescription.Error())
	}

	withoutDescription := &wallet.Error{HTTPStatus: 400, Code: "invalid_proof"}
	if !strings.Contains(withoutDescription.Error(), "invalid_proof") {
		t.Errorf("Error() = %q, want it to mention code", withoutDescription.Error())
	}
}
