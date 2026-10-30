package issuer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// preAuthorizedCodeKey is what Dependencies.PreAuthorizedCodes keeps
// code under: SHA-256 of the code, base64url-encoded. The code is a
// bearer credential, so a store, or a leak of it, never holds one a
// Wallet could redeem; a lookup by the code's hash finds the record as
// the code itself would.
func preAuthorizedCodeKey(code string) string {
	sum := sha256.Sum256([]byte(code))
	return base64.RawURLEncoding.EncodeToString(sum[:])
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
