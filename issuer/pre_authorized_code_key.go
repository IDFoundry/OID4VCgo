package issuer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// preAuthorizedCodeKey is what Dependencies.PreAuthorizedCodes keeps
// code under for the Credential Issuer owner: SHA-256 of the two,
// base64url-encoded. The code is a bearer credential, so a store, or a
// leak of it, never holds one a Wallet could redeem; a lookup by the
// key finds the record as the code itself would. Bound to owner too, a
// code one Credential Issuer issued is unknown to every other sharing
// its store, before any of its record is read: no other Issuer can
// spend it, or count a wrong tx_code against it.
func preAuthorizedCodeKey(owner, code string) string {
	h := sha256.New()
	for _, part := range []string{owner, code} {
		// Length-prefixed, so no two pairs hash alike.
		_, _ = fmt.Fprintf(h, "%d:%s", len(part), part) // a hash.Hash never fails to write
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// txCodeHash is what a PreAuthorizedCodeRecord keeps of code's
// Transaction Code: HMAC-SHA256 of txCode keyed by code itself,
// base64url-encoded, or "" for none. A Transaction Code is a short PIN,
// so a plain hash of it would be reversed by trying every PIN; keyed by
// the 256-bit code, which the store holds only a hash of, it can't be
// without the code.
func txCodeHash(code, txCode string) string {
	if txCode == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(code))
	mac.Write([]byte(txCode)) // a hash.Hash never fails to write
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
