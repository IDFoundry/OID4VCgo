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
//   - A long call takes an Operation the app can Cancel from another
//     thread, since no context.Context crosses the boundary.
//
// This first version is the boundary's feasibility spike (MOBILE.md
// Phase 1): request-link parsing (JSON out), a DPoP proof signed by a
// key the app holds (a callback into the app), and a cancellable fetch.
package mobile
