# Presenting in person

Share an mdoc with a reader nearby over Bluetooth, or be the reader,
with ISO/IEC 18013-5 device retrieval.

## Overview

In person, the holder shows a QR code and the reader scans it: the
code carries the holder's ephemeral key and how to reach it over
Bluetooth LE. The two devices then exchange encrypted messages over
GATT. The package carries the Bluetooth side itself: your app shows or
scans the QR code, follows the session's states, and asks the holder.

Both sides need `NSBluetoothAlwaysUsageDescription` in the app's
Info.plist. Keep the app in the foreground during a session: neither
side keeps one going while the app is suspended. A session answers one
request. Bluetooth failures are ``ProximityError``s; protocol failures
are ``WalletError``s.

### Share as the holder

``Wallet/startProximityPresentation(timeouts:)`` returns a
``ProximityPresentation`` whose ``ProximityPresentation/qrCode`` you
show. It advertises until a reader connects, then reports
``ProximityPresentation/State/requestReceived(_:)`` with who is asking
and what: ask the holder, then respond or decline.

```swift
import Foundation
import OID4VCWallet

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
            return try await session.respond(document: answer.document, credentialID: answer.credentialID,
                                             elements: answer.elements)
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

``ProximityPresentation/cancel()`` ends a session at any point, as the
holder leaves the screen, say. ``ProximityTimeouts`` sets how long it
waits: by default 60 seconds for a reader to connect, 30 for its
request, and 300 for the holder to decide.

### Read as the verifier

A ``ProximityReader`` needs no ``Wallet``: give it the IACAs whose
mdocs it accepts, and, to sign its requests so holders see who is
asking, a key in a ``KeyStore`` and its certificate chain, with the
reader authentication extended key usage
(``ProximityReaderConfiguration``). ``ProximityReader/start(qrCode:docType:elements:timeouts:)``
takes the holder's QR code and what to ask for.

```swift
/// Reads an mDL's name and portrait from the holder whose QR code was
/// scanned. Returns the verified mdoc, or nil if the holder declined.
func readInPerson(qrCode: String, issuerRoots: String) async throws -> VerifiedMdoc? {
    let reader = try ProximityReader(configuration: ProximityReaderConfiguration(issuerRoots: issuerRoots))
    let session = try reader.start(qrCode: qrCode, docType: "org.iso.18013.5.1.mDL",
                                   elements: ["org.iso.18013.5.1": ["given_name", "family_name", "portrait"]])
    for await state in session.states {
        switch state {
        case .verified(let mdoc):
            return mdoc
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

``VerifiedMdoc`` carries the disclosed elements, the document signer
and the IACA it chains to, and its validity. Its
``VerifiedMdoc/statusList`` is unchecked: check it before relying on
the document.
