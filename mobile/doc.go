// Package mobile is OID4VCgo's gomobile boundary: the API an iOS or
// Android app calls, compiled with gomobile bind into an XCFramework or
// AAR (see MOBILE.md).
//
// The boundary is deliberately narrow and stable — strings, bools,
// integers, []byte, a few exported objects, and small callback
// interfaces the app implements — so that it can be versioned
// separately from the native Go API (ABIVersion):
//
//   - Rich data crosses as JSON. Every JSON result is an object carrying
//     "abi", the ABIVersion it was written for.
//   - Errors cross as text beginning with a stable code in brackets —
//     "[invalid_input] …" — which the app's wrapper parses (see Error).
//   - Calls block. The app calls from a background thread, never the
//     main thread; a callback into the app runs on that same thread.
//   - A call that waits on the network takes an Operation the app can
//     Cancel from another thread, since no context.Context crosses the
//     boundary.
//   - A callback that can fail returns []byte or nothing besides its
//     error: one returning a string isn't a throwing Swift method.
//
// The API, ABIVersion 12, is documented call by call in ABI.md. NewWallet
// takes a JSON configuration and the app's KeyStore, CredentialStore and
// WalletProvider; StartIssuance and StartPresentation return the
// walletflow sessions, step by step, each step taking an Operation.
// Over the Digital Credentials API, StartDCAPIPresentation answers
// OpenID4VP and StartMdocPresentation org-iso-mdoc. In person,
// StartProximityPresentation is the holder and NewProximityReader the
// reader: bytes in and out, with the BLE transport left to the app.
// CheckKeyStore exercises a KeyStore as the wallet will.
package mobile
