// Package identifierlist implements ISO/IEC 18013-5 §12.3.6.4's
// identifier list, a profile of the Token Status List CWT (package
// statuslist; §12.3.6.3's Status List Token rules apply) with typ
// application/identifierlist+cwt and, in place of status_list, a set of
// the identifiers of revoked MSOs at claim 65530. An MSO points at one
// with its status.identifier_list element
// (credential/mdoc.IdentifierListRef), and is revoked when its id is on
// the list.
//
// IssueToken signs a list, and Publisher serves one over HTTP. A list
// hosted as a static file must be served with
// "Content-Type: application/identifierlist+cwt" (MediaType), or
// Checker refuses it. Check and Checker verify a list and report
// whether an identifier is on it; a verifier.StatusPolicy
// (verifier.TransactionsConfig.Status, mdocdcapi.VerifyParams.Status,
// proximity.WithStatus) checks a presented mdoc's identifier list.
package identifierlist
