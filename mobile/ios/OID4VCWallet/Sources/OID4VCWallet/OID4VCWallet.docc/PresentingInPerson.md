# Presenting in person

Share an mdoc with a reader nearby over Bluetooth, or be the reader,
with ISO/IEC 18013-5 device retrieval.

## Overview

In person, the holder shows a QR code and the reader scans it: the
code carries the holder's ephemeral key and how to reach it over
Bluetooth LE. The two devices then exchange encrypted messages over
GATT. The package carries the Bluetooth side itself: your app shows or
scans the QR code, follows the session's states, and asks the holder.

Engagement is by QR code only. NFC engagement (a tap instead of the
code) is in OID4VCgo's Kotlin library, not this package: an iOS holder
can't answer a reader's tap, and an iOS reader can't tap a holder. An
Android reader or holder that offers both still works with this
package over the QR code.

Both sides need `NSBluetoothAlwaysUsageDescription` in the app's
Info.plist. Keep the app in the foreground during a session: neither
side keeps one going while the app is suspended. A session answers one
request. Bluetooth failures are ``ProximityError``s; protocol failures
are ``WalletError``s.

### Share as the holder

``Wallet/startProximityPresentation(timeouts:modes:)`` returns a
``ProximityPresentation`` whose ``ProximityPresentation/qrCode`` you
show. It offers both ``ProximityBLEMode``s by default: it advertises
for the reader and scans for it at once, until a reader connects
either way (a reader offered both should connect in central client
mode). Pass `modes` to offer one. It then reports
``ProximityPresentation/State/requestReceived(_:)`` with who is asking
and what: ask the holder, then respond or decline.

```swift
import Foundation
import OID4VCWallet
import Security

/// What the holder agreed to share: a requested document, the held
/// mdoc to answer it with, and the elements to disclose.
struct InPersonAnswer {
    let document: Int
    let credentialID: String
    let elements: [MdocPresentation.Element]
}

/// Shares an mdoc in person. `showQRCode` displays the code; `consent`
/// shows the reader's request and returns the holder's answer, or nil
/// to decline. Returns whether the copy shared had been seen by another
/// Verifier, or nil when nothing was shared.
func shareInPerson(wallet: Wallet, showQRCode: (String) -> Void,
                   consent: (ProximityPresentation.Request) async -> InPersonAnswer?) async throws -> Bool? {
    let session = try wallet.startProximityPresentation()
    showQRCode(session.qrCode)
    for await state in session.states {
        switch state {
        case .requestReceived(let request):
            guard let answer = await consent(request) else {
                await session.decline()
                return nil
            }
            // The holder key signs now: Face ID, if the key store asks.
            do {
                return try await session.respond(document: answer.document, credentialID: answer.credentialID,
                                                 elements: answer.elements)
            } catch {
                // Nothing was sent (Face ID cancelled, say), and the
                // request stands: end the session rather than leave the
                // reader waiting. A consent screen may offer to try again.
                await session.decline()
                throw error
            }
        case .failed(let error):
            throw error
        case let state where state.isFinal:
            return nil
        default:
            continue
        }
    }
    return nil
}
```

Show ``ProximityPresentation/Request/reader`` on the consent screen. A
reader that signs its request (reader authentication) is named, and
``ProximityReaderIdentity/Status/trusted`` when its certificate chains
to ``WalletConfiguration/mdocReaderRoots``. An unsigned request could
come from anyone who scanned the code. As over the Digital Credentials
API, ``WalletConfiguration/requireTrustedMdocReader`` ends a session
from any other reader before the holder sees it.

### Several documents at once

A reader may ask for several documents in one request: an mDL, a photo
ID and a payment credential, say, each a
``ProximityPresentation/Request/documents`` entry. Answer any of them in
one response with ``ProximityPresentation/respond(answers:)``, a
``MdocPresentation/Answer`` each; a document left out isn't in the
response. It returns ``ProximityPresentation/Responded``:
``ProximityPresentation/Responded/linkable`` whether any copy shared
had been seen by another Verifier, and
``ProximityPresentation/Responded/linkableCredentials`` which. The same call
is on ``MdocPresentation`` for the Digital Credentials API.

Each answer's holder key signs in turn, and a ``KeychainKeyStore``
asking for user presence asks the holder once for them all: the keys
share one authentication for that call only. If the holder cancels,
nothing is sent and the request stands.

``ProximityPresentation/cancel()`` ends a session at any point, as the
holder leaves the screen, say. ``ProximityTimeouts`` sets how long it
waits: by default 60 seconds for a reader to connect, 30 for its
request, and 300 for the holder to decide. Give them as `TimeInterval`
seconds, on iOS 15 and later
(``ProximityTimeouts/init(connectSeconds:requestSeconds:idleSeconds:)``),
or as `Duration`s, on iOS 16 and later
(``ProximityTimeouts/init(connect:request:idle:)``).

### Read as the verifier

A ``ProximityReader`` needs no ``Wallet``: give it the IACAs whose
mdocs it accepts, and, to sign its requests so holders see who is
asking, a key in a ``KeyStore`` and its certificate chain, with the
reader authentication extended key usage
(``ProximityReaderConfiguration``). The reader is a production one: it
refuses (`invalidInput`) a configuration that leaves a decision open:
which IACAs issue which document types (`anyIssuerForAnyType`, or
`issuerRootsByDocType`), each role's revocation (`revocation` with
`crls`, or `noRevocationCheck` to decline), and whether a document's
revocation status is checked (`statusCheck`). `development` relaxes
this, for trying out a development issuer's documents; never ship an
app with it set. ``ProximityReader/start(qrCode:docType:elements:timeouts:)``
takes the holder's QR code and what to ask for.

```swift
/// A verified mdoc whose issuer the reader doesn't accept.
struct UnacceptedIssuer: Error {}

/// Reads an mDL's name and portrait from the holder whose QR code was
/// scanned. `mdlIACAs` are the IACAs (PEM) trusted to issue mDLs, and
/// only mDLs; `accepts` decides on the verified certificate path, leaf
/// first. Returns the verified mdoc, its status checked, or nil if the
/// holder declined.
func readInPerson(qrCode: String, mdlIACAs: String, crls: String,
                  accepts: ([SecCertificate]) -> Bool) async throws -> VerifiedMdoc? {
    let reader = try ProximityReader(configuration: ProximityReaderConfiguration(
        issuerRoots: "", issuerRootsByDocType: ["org.iso.18013.5.1.mDL": mdlIACAs],
        crls: crls, revocation: [.issuer, .status], statusCheck: .check))
    let session = try reader.start(qrCode: qrCode, docType: "org.iso.18013.5.1.mDL",
                                   elements: ["org.iso.18013.5.1": ["given_name", "family_name", "portrait"]])
    for await state in session.states {
        switch state {
        case .verified(let mdoc):
            // Its status was checked first: valid, or it names none.
            // Decide on the verified chain, not the names shown.
            guard accepts(mdoc.issuerChain) else { throw UnacceptedIssuer() }
            return mdoc
        case .failed(let error):
            // A revoked or suspended document is WalletError
            // .documentNotValid.
            throw error
        case let state where state.isFinal:
            return nil
        default:
            continue
        }
    }
    return nil
}
```

``VerifiedMdoc`` carries the disclosed elements, the document signer
and the IACA it chains to, and its validity. Decide which issuers to
accept on ``VerifiedMdoc/issuerChain``, the verified certificate path:
``VerifiedMdoc/issuer`` and ``VerifiedMdoc/trustAnchor`` are names any
document signer under a trusted IACA can choose, for display.

With `statusCheck: .check`, the session checks the document's
revocation status before it's `.verified`, as
``ProximityReaderSession/checkStatus()`` does: it closes the
connection, fetches the issuer's status list over the network, so the
reader needs a connection then, and verifies the list is signed under
the certificate the document names or the CA that signed the document
signer (ISO/IEC 18013-5 §12.3.6). Only a document that's
``MdocStatus/valid``, or names no status (``MdocStatus/noStatus``), is
`.verified`, with ``VerifiedMdoc/status`` set; any other status fails
the session with ``WalletError`` `.documentNotValid`, its
`protocolError` the status. With `.decline`, nothing checks it:
for a reader where something else stands in, which then calls
``ProximityReaderSession/checkStatus()`` itself or checks otherwise.

### Reading several documents

``ProximityReader/start(qrCode:documents:timeouts:)`` asks for several
documents in one request, a ``ProximityReader/DocumentRequest`` each,
of different types and at most eight. The holder may answer any of
them: once the session is `.verified`, whose mdoc is the first,
``ProximityReaderSession/documents`` has every document it answered, in
the response's order. Check that each one needed came back. With
`statusCheck: .check`, each document's status is checked, and any one
that isn't valid fails the session with `.documentNotValid`.

```swift
/// Asks the holder whose QR code was scanned for an mDL and a photo ID,
/// and returns the documents the holder chose to share.
func readTwo(reader: ProximityReader, qrCode: String) async throws -> [VerifiedMdoc] {
    let session = try reader.start(qrCode: qrCode, documents: [
        ProximityReader.DocumentRequest(docType: "org.iso.18013.5.1.mDL",
                                        elements: ["org.iso.18013.5.1": ["family_name", "portrait"]]),
        ProximityReader.DocumentRequest(docType: "org.iso.23220.photoid.1",
                                        elements: ["org.iso.23220.1": ["family_name", "portrait"]]),
    ])
    for await state in session.states where state.isFinal {
        if case .failed(let error) = state { throw error }
        return session.documents
    }
    return []
}
```
