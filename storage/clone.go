package storage

import "github.com/idfoundry/oid4vcigo/issuer"

// cloneStrings returns a deep copy of s. A Go slice header copies by
// value but shares its backing array, so simply assigning a
// stored/returned struct is not enough to keep a store's records
// independent of whatever the caller does with its own copy
// afterward — every slice or pointer-bearing value that crosses a
// store's Store/Get boundary must be cloned, in both directions, or a
// caller's later mutation could silently corrupt another caller's
// already-returned value or the store's own internal record.
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s...)
}

// cloneIssuedCredentials returns a deep copy of c — see cloneStrings'
// own doc comment for why. issuer.IssuedCredential has no reference
// fields of its own, so copying the slice is enough.
func cloneIssuedCredentials(c []issuer.IssuedCredential) []issuer.IssuedCredential {
	if c == nil {
		return nil
	}
	return append([]issuer.IssuedCredential(nil), c...)
}

// cloneCredentialOffer returns a deep copy of o, including its Grants
// pointer chain — see cloneStrings' own doc comment for why. Every
// field Grants and its own two grant types carry is a plain scalar, so
// copying each pointed-to struct by value is enough once the pointers
// themselves are no longer shared.
func cloneCredentialOffer(o issuer.CredentialOffer) issuer.CredentialOffer {
	o.CredentialConfigurationIDs = cloneStrings(o.CredentialConfigurationIDs)
	o.Grants = cloneGrants(o.Grants)
	return o
}

func cloneGrants(g *issuer.Grants) *issuer.Grants {
	if g == nil {
		return nil
	}
	out := *g
	if g.AuthorizationCode != nil {
		authCode := *g.AuthorizationCode
		out.AuthorizationCode = &authCode
	}
	if g.PreAuthorizedCode != nil {
		preAuth := *g.PreAuthorizedCode
		if g.PreAuthorizedCode.TxCode != nil {
			txCode := *g.PreAuthorizedCode.TxCode
			preAuth.TxCode = &txCode
		}
		out.PreAuthorizedCode = &preAuth
	}
	return &out
}
