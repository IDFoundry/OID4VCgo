# Presenting in person

Share an mdoc with a reader nearby over Bluetooth, or be the reader,
with ISO/IEC 18013-5 device retrieval.

In person, the holder shows a QR code and the reader scans it: the code
carries the holder's ephemeral key and how to reach it over Bluetooth
LE. The two devices then exchange encrypted messages over GATT. The
library carries the Bluetooth side itself: your app shows or scans the
QR code, follows the session's states, and asks the holder.

The library's manifest adds the Bluetooth permissions to your app's:
on Android 11 and earlier `BLUETOOTH`, `BLUETOOTH_ADMIN` and
`ACCESS_FINE_LOCATION`, which a reader needs for scan results; from
Android 12 `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT` and
`BLUETOOTH_SCAN` (with `neverForLocation`). Request
`ProximityPermissions.holder` or `ProximityPermissions.reader` at runtime
before starting a session: without them, starting one throws a
`ProximityException` (`PermissionMissing`).

Keep the app in the foreground during a session: neither side keeps
one going while the app is in the background. A session answers one
request. Bluetooth failures are `ProximityException`s; protocol failures
are `WalletException`s. The emulator has no Bluetooth: use devices.

## Share as the holder

`Wallet.startProximityPresentation` returns a `ProximityPresentation`
whose `qrCode` you show. It offers both `ProximityBLEMode`s by default:
it advertises for the reader and scans for it at once, until a reader
connects either way (a reader offered both should connect in central
client mode). Pass `modes` to offer one, and request
`ProximityPermissions.holder(modes)` for them. Scanning makes the
default ask the holder for more than peripheral server mode alone:
`BLUETOOTH_SCAN` from Android 12, and location on Android 11 and
earlier, where Android delivers scan results only with it. An app that
would rather not ask can offer `setOf(ProximityBLEMode.PERIPHERAL_SERVER)`,
which needs neither. Then its `state` becomes
`RequestReceived`, with who is asking and what: ask the
holder, then respond or decline.

```kotlin
import android.content.Context
import dev.idfoundry.oid4vcwallet.MdocPresentation
import dev.idfoundry.oid4vcwallet.ProximityPresentation
import dev.idfoundry.oid4vcwallet.ProximityReader
import dev.idfoundry.oid4vcwallet.ProximityReaderConfiguration
import dev.idfoundry.oid4vcwallet.ProximityReaderSession
import dev.idfoundry.oid4vcwallet.VerifiedMdoc
import dev.idfoundry.oid4vcwallet.Wallet
import kotlinx.coroutines.flow.first

/** What the holder agreed to share: a requested document, the held mdoc to answer it with, and the elements to disclose. */
data class InPersonAnswer(val document: Int, val credentialID: String, val elements: List<MdocPresentation.Element>)

/**
 * Shares an mdoc in person. `showQRCode` displays the code; `consent`
 * shows the reader's request and returns the holder's answer, or null to
 * decline. Returns whether the copy shared had been seen by another
 * Verifier, or null when nothing was shared.
 */
suspend fun shareInPerson(
    context: Context,
    wallet: Wallet,
    showQRCode: (String) -> Unit,
    consent: suspend (ProximityPresentation.Request) -> InPersonAnswer?,
): Boolean? {
    val session = wallet.startProximityPresentation(context)
    showQRCode(session.qrCode)
    val state = session.state.first { it is ProximityPresentation.State.RequestReceived || it.isFinal }
    if (state is ProximityPresentation.State.Failed) throw state.error
    if (state !is ProximityPresentation.State.RequestReceived) return null
    val answer = consent(state.request)
    if (answer == null) {
        session.decline()
        return null
    }
    // The holder key signs now: the fingerprint or screen lock, if the key store asks.
    return session.respond(answer.document, answer.credentialID, answer.elements)
}
```

Show the request's `reader` on the consent screen. A reader that signs
its request (reader authentication) is named, and `Trusted` when its
certificate chains to `WalletConfiguration.mdocReaderRoots`. An
unsigned request could come from anyone who scanned the code.
`WalletConfiguration.requireTrustedMdocReader` ends a session from any
other reader before the holder sees it.

`cancel()` ends a session at any point, as the holder leaves the screen,
say. `ProximityTimeouts` sets how long it waits: by default 60 seconds
for a reader to connect, 30 for its request, and 300 for the holder to
decide.

## Read as the verifier

A `ProximityReader` needs no `Wallet`: give it the IACAs whose mdocs it
accepts, and, to sign its requests so holders see who is asking, a key
in a `KeyStore` and its certificate chain, with the reader
authentication extended key usage (`ProximityReaderConfiguration`).
`start` takes the holder's QR code and what to ask for.

```kotlin
/** Reads an mDL's name and portrait from the holder whose QR code was scanned. Returns the verified mdoc, or null if the holder declined. */
suspend fun readInPerson(context: Context, qrCode: String, issuerRoots: String): VerifiedMdoc? {
    val reader = ProximityReader(ProximityReaderConfiguration(issuerRoots = issuerRoots))
    val session = reader.start(
        context, qrCode, "org.iso.18013.5.1.mDL",
        mapOf("org.iso.18013.5.1" to listOf("given_name", "family_name", "portrait")),
    )
    return when (val state = session.state.first { it.isFinal }) {
        is ProximityReaderSession.State.Verified -> state.result
        is ProximityReaderSession.State.Failed -> throw state.error
        else -> null
    }
}
```

`VerifiedMdoc` carries the disclosed elements, the document signer and
the IACA it chains to, and its validity. Its status list reference is
unchecked: check it before relying on the document.
