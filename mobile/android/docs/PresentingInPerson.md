# Presenting in person

Share an mdoc with a reader nearby, or be the reader, with ISO/IEC
18013-5 device retrieval: engaged by a QR code or an NFC tap, then
exchanged over Bluetooth LE or NFC.

In person, the holder first gives the reader its ephemeral key and how
to reach it (engagement): a QR code the reader scans, or an NFC tap the
reader reads. The two devices then exchange encrypted messages over
Bluetooth LE GATT, or, for NFC transfer, over NFC while the phones stay
together. The library carries Bluetooth and NFC itself: your app shows
the QR code or asks for the tap, follows the session's states, and asks
the holder.

| The holder starts | The reader | Data goes over | Phones |
|---|---|---|---|
| `startProximityPresentation` | scans the QR code | Bluetooth | apart |
| `startNfcPresentation` | taps | Bluetooth | apart after the tap |
| `startNfcPresentation(nfcData = true)` | taps | NFC | together until shared |
| `startCombinedPresentation` | scans or taps, whichever comes first | Bluetooth, or NFC with `nfcData` | as above |

Every holder entry point answers with the same `ProximityPresentation.State`s
and the same `respond`/`decline`, so one consent screen serves them all.
NFC needs an `NfcEngagementService` subclass in your manifest
([NFC holder and reader](#nfc-holder-and-reader)); QR alone doesn't.

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
import android.app.Activity
import android.nfc.Tag
import dev.idfoundry.oid4vcwallet.CombinedPresentation
import dev.idfoundry.oid4vcwallet.NfcEngagementOptions
import dev.idfoundry.oid4vcwallet.NfcEngagementService
import dev.idfoundry.oid4vcwallet.NfcPresentation
import dev.idfoundry.oid4vcwallet.ProximityBLEMode
import dev.idfoundry.oid4vcwallet.ProximityDiagnostics
import dev.idfoundry.oid4vcwallet.MdocPresentation
import dev.idfoundry.oid4vcwallet.MdocStatus
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
authentication extended key usage (`ProximityReaderConfiguration`). The
reader is a production one: it refuses (`invalid_input`) a
configuration that leaves a decision open: which IACAs issue which
document types (`anyIssuerForAnyType`, or `issuerRootsByDocType`), and
each role's revocation (`revocation` with `crls`, or
`noRevocationCheck` to decline). `development` relaxes this, for trying
out a development issuer's documents; never ship an app with it set. `start` takes the holder's QR code and what to ask for.

```kotlin
/**
 * Reads an mDL's name and portrait from the holder whose QR code was scanned. Returns the verified
 * mdoc, or null if the holder declined or the mdoc isn't known to be unrevoked.
 */
suspend fun readInPerson(context: Context, qrCode: String, issuerRoots: String, crls: String): VerifiedMdoc? {
    val reader = ProximityReader(
        ProximityReaderConfiguration(
            issuerRoots = issuerRoots, crls = crls,
            revocation = listOf(ProximityReaderConfiguration.RevocationRole.ISSUER, ProximityReaderConfiguration.RevocationRole.STATUS),
            anyIssuerForAnyType = true,
        ),
    )
    val session = reader.start(
        context, qrCode, "org.iso.18013.5.1.mDL",
        mapOf("org.iso.18013.5.1" to listOf("given_name", "family_name", "portrait")),
    )
    return when (val state = session.state.first { it.isFinal }) {
        is ProximityReaderSession.State.Verified -> when (session.checkStatus()) {
            MdocStatus.Valid, MdocStatus.NoStatus -> state.result
            else -> null
        }
        is ProximityReaderSession.State.Failed -> throw state.error
        else -> null
    }
}
```

`VerifiedMdoc` carries the disclosed elements, the document signer and
the IACA it chains to, and its validity. Decide which issuers to accept
on `issuerChain`, the verified certificate path: `issuer` and
`trustAnchor` are names any document signer under a trusted IACA can
choose, for display.

The session doesn't check revocation itself: `session.checkStatus()`
does, once the session is `Verified`. It fetches the issuer's status
list over the network, so the reader needs a connection then, and
verifies the list is signed under the certificate the document names or
the CA that signed the document signer (ISO/IEC 18013-5 §12.3.6). Rely
on the document only when it's `MdocStatus.Valid` or
`MdocStatus.NoStatus`.

## NFC holder and reader

Android only. NFC engagement uses static or negotiated (TNEP) handover,
then Bluetooth LE or NFC-only retrieval. Every combination, with both
Bluetooth roles, interoperated with the independent Multipaz
implementation on physical phones, in both directions, at 6aef12e
(#659), when the APDU protocols still ran in Kotlin. They now run in Go
(`proximity/nfcapdu`), which hasn't been re-tested on phones yet. None of
this is a conformance claim: the licensed ISO/IEC 18013-5 and NFC Forum
texts haven't been reviewed against it. iOS NFC, USB readers, L2CAP and
Concurrent Channel Engagement aren't supported.

The holder answers taps through host card emulation (HCE): Android
routes the reader's commands to your app's NFC service, which hands
them to the presentation your app has started. No presentation started,
no answer. NFC needs no runtime permission; it needs NFC on, and the
device unlocked.

Declare an application subclass, for example `class IdentityNfcService :
NfcEngagementService()`, and its HCE service:

```xml
<service android:name=".IdentityNfcService" android:exported="true"
    android:permission="android.permission.BIND_NFC_SERVICE">
    <intent-filter>
        <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE" />
    </intent-filter>
    <meta-data android:name="android.nfc.cardemulation.host_apdu_service"
        android:resource="@xml/oid4vc_nfc_aids" />
</service>
```

The library declares optional NFC/HCE hardware and the NFC permission.
Its AID resource uses category `other` and requires device unlock. Retain
one `NfcPresentation` at application/view-model level. Start it with:

```kotlin
class IdentityNfcService : NfcEngagementService()

suspend fun startNfcHolder(
    context: Context, wallet: Wallet, modes: Set<ProximityBLEMode>,
): NfcPresentation {
    return wallet.startNfcPresentation(context, modes = modes)
}
// For negotiated NFC-to-BLE, pass negotiated = true.
// For static NFC-only retrieval, pass nfcData = true.
// For negotiated NFC-only, pass both nfcData = true and negotiated = true.
```

Follow `owner.presentation.state` and use the existing `respond`/`decline`
consent flow. On a resumed Activity, call
`owner.preferForeground(activity, IdentityNfcService::class.java)` and
check its Boolean result. Call `releaseForeground(activity)` on pause
and completion, and acquire preference again on every resume while the
session is still going. The platform can refuse preference; the
application should explain how to select its NFC service. Reapply it to
each new presentation.

Another wallet on the phone can register the same NFC application ID;
while your app holds the preference, taps come to it. Don't prefer again
for a session that has ended: the fingerprint or screen-lock prompt
resumes your activity after sharing, and an `onResume` that prefers
unconditionally keeps taps away from other wallets until the screen is
left. Check `state.value.isFinal` first.

`owner.close()` cancels and awaits cleanup. Starting another NFC owner
waits for the previous owner's tasks and radio resources to close.
Use `startCombinedPresentation` below to offer QR and NFC together;
do not combine two independent owners. HCE service
recreation reuses the owner. A process restart leaves it unarmed.
Repeated reads reuse the key/UUID/Hs and trigger BLE only once the whole
Hs has been read. NFC removal after BLE handover leaves BLE running.
Field loss during NFC-only retrieval ends that session; start a new one
to recover. NFC-only mode does not require Bluetooth permissions.

On the verifier, enable Android reader mode with NFC-A/NFC-B and
`FLAG_READER_SKIP_NDEF_CHECK` while the reader screen is resumed, then
start the session from a coroutine with the tag it delivers:

```kotlin
/** Arms the reader screen for a tap: `onTag` gets the holder's tag, on a binder thread. Call on resume. */
fun armNfcReader(activity: Activity, onTag: (Tag) -> Unit): Boolean {
    val adapter = android.nfc.NfcAdapter.getDefaultAdapter(activity)
    if (adapter?.isEnabled != true) return false // Ask the user to turn NFC on.
    adapter.enableReaderMode(
        activity, { tag -> onTag(tag) },
        android.nfc.NfcAdapter.FLAG_READER_NFC_A or android.nfc.NfcAdapter.FLAG_READER_NFC_B or
            android.nfc.NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
        null,
    )
    return true
}

/** Stops listening for taps: call on pause, and on leaving the reader screen. */
fun disarmNfcReader(activity: Activity) {
    android.nfc.NfcAdapter.getDefaultAdapter(activity)?.disableReaderMode(activity)
}

suspend fun startNfcReader(
    context: Context, reader: ProximityReader, tag: Tag,
    docType: String, elements: Map<String, List<String>>,
): ProximityReaderSession = reader.startFromNfc(context, tag, docType, elements)
```

The reader detects static versus negotiated handover and the selected
carrier. BLE retrieval needs `ProximityPermissions.reader` granted.
For NFC-only, keep the phones together through consent and response;
`session.usesNfcData` identifies this path. The BLE `mode` property has
meaning only when `usesNfcData` is false. Disable reader mode on pause
or after leaving the reader screen. Cancellation closes IsoDep and interrupts
blocking transceives and negotiated-handover waits; the coroutine waits for
its worker to exit. A successful handover keeps the tag open for NFC data
selection. Removing the tag after BLE selection is safe.

The APDU protocols run in Go (`proximity/nfcapdu`); Kotlin passes each
command APDU through and sends back the response. The Type 4 Tag serves
a read-only static Hs, or staged TNEP writes,
with a 32767-byte NDEF file limit and chunked NDEF records rejected.
Classic NFC-only uses short APDUs, ENVELOPE command chaining, DO53,
and GET RESPONSE with a Le-only command. It supports a 2 MiB complete
message; the controller's smaller transceive limit is applied as well.
The final ENVELOPE remains asynchronous during consent, so hardware
timeout/WTX behavior must be included in real-device validation.

The [demo wallet](https://github.com/IDFoundry/OID4VCgo/tree/main/mobile/android/DemoWallet) is a complete app on all of this. Its
presentation settings select QR, QR or NFC (combined), static or
negotiated NFC-to-BLE, or static or negotiated NFC-only, and the
Bluetooth mode, greyed out for NFC-only. Its `InPersonSession` shows one
consent flow over all three holder entry points. Reader presets offer
NFC/Bluetooth and NFC-only actions; the latter does not request
Bluetooth permissions.

## Combined QR and NFC engagement

Use one owner for a screen that displays a QR code and accepts an NFC tap:

```kotlin
suspend fun startCombinedHolder(
    context: Context, wallet: Wallet, showQr: (String) -> Unit,
): CombinedPresentation {
    val owner = wallet.startCombinedPresentation(
        context,
        nfc = NfcEngagementOptions(negotiated = false, nfcData = false),
    )
    showQr(owner.qrCode) // Empty when NFC-only is available but BLE permission is absent.
    return owner
}
// Collect owner.state, the same ProximityPresentation.State used by QR sessions.
// On RequestReceived, use owner.respond(document, credentialID, elements)
// or owner.decline(). owner.selectedEngagement records QR, NFC_BLE or NFC_DATA.
```

Hide the QR once `selectedEngagement` becomes non-null; it cannot accept another
reader after either offer has won.

Retain the owner at application/presentation scope across HCE recreation. Create
it once on entering the screen, after checking NFC availability. Reuse the
declared `NfcEngagementService` and `@xml/oid4vc_nfc_aids` manifest entry above.
The exact activity/screen calls, while that owner exists, are:

```kotlin
// Activity.onResume(), and immediately after creating an owner while resumed:
fun resumeCombinedHolder(
    owner: CombinedPresentation, activity: Activity,
    showNfcServiceSelectionInstructions: () -> Unit,
) {
    // Ended (the consent prompt resumes the activity after sharing): leave taps to other wallets.
    if (owner.state.value.isFinal) return pauseCombinedHolder(owner, activity)
    val preferred = owner.preferForeground(activity, IdentityNfcService::class.java)
    if (!preferred) showNfcServiceSelectionInstructions()
}

// Activity.onPause():
fun pauseCombinedHolder(owner: CombinedPresentation, activity: Activity) {
    owner.releaseForeground(activity)
}

// Screen exit or terminal state, from a retained coroutine that survives navigation:
suspend fun closeCombinedHolder(owner: CombinedPresentation, activity: Activity) {
    owner.releaseForeground(activity)
    owner.cancel() // Withdraw immediately, even if cleanup has to suspend.
    owner.close()  // Await tasks and radio cleanup before dropping/replacing the owner.
}
```

Do not create another owner on each resume or use a coroutine cancelled by the
screen exit to await cleanup. If creation finishes after pause, retain it and
defer foreground preference until resume. A refused foreground preference is a
Boolean result, not proof that NFC routing is available; offer service-selection
instructions and the QR alternative if present. Do not force a different wallet's
routing. Pausing releases preference; explicitly close on screen exit.

QR BLE advertising/scanning starts immediately. A completed QR BLE connection
(the State-start handshake), a complete NFC-to-BLE Hs read, or an NFC data
application SELECT after handover claims the presentation. Type 4 discovery,
reading TNEP parameters, and preparing Hr/Hs do not withdraw QR. Field loss
before Hs creation resets an uncommitted attempt for another tap; QR stays
available. Static partial reads also reset. Once negotiated Hs is produced,
field loss before its full read cancels the presentation to keep Hr/Hs frozen,
unless QR already won. A losing NFC field loss never cancels the winning QR
session. The losing offer cannot attach or be revived after commitment.
After QR wins, further NFC APDUs return `6985`. After NFC wins, QR tasks stop and
their BLE resources close before any NFC BLE transport is created. NFC BLE still
waits until the complete Hs has been read. There are never two offer advertisers
running together. For NFC data, keep the devices together through consent.

Use static handover (`NfcEngagementOptions()`, or `negotiated = false`) for
unknown readers; this is already the combined API default. Negotiated mode
requires a TNEP-capable reader to select the handover service and write Hr.
A reader that only reads the initial NDEF gets service parameters, not Hs;
there is no automatic switch to a different static transcript. Its incomplete
tap leaves QR available, but cannot establish NFC retrieval. To use such a
reader over NFC, close this owner and create a static presentation.

ISO/IEC 18013-5:2021 §6.3.2.3 permits a holder to offer either handover
method or both, and requires both on the reader; NFC Forum's
[Connection Handover overview](https://nfc-forum.org/build/specifications/connection-handover-technical-specification/)
describes them. Choose the mode explicitly: there is no silent fallback
from one to the other.

For opt-in Android lifecycle diagnostics:

```kotlin
fun enableProximityDiagnostics(enabled: Boolean) {
    ProximityDiagnostics.enabled = enabled // Turn off again after troubleshooting.
}
```

Filter logcat by `OID4VCProximity`. Events distinguish Type 4 discovery,
commitment, gate completion, NFC BLE startup with its modes, QR withdrawal
and cleanup, and an aborted attempt that retains QR. Payloads and credentials
are not logged. The default is disabled; existing app behavior is unchanged.

The offers have independent ephemeral keys, DeviceEngagements and service UUIDs.
QR uses a null Handover; NFC uses exactly `[Hs, null]` (static) or `[Hs, Hr]`
(negotiated). Selection switches the Go session before processing any request;
consent and response remain one state machine. This avoids assuming permission
to reuse one EDeviceKey across engagement mechanisms. Existing Annex D vectors
cover transcript construction; they do not establish that key reuse is permitted.

With `nfcData = true`, missing Bluetooth runtime permissions omit the QR offer
(`qrCode == ""`) and no Bluetooth transport is constructed. NFC remains armed.
A QR transport startup failure also leaves the NFC offer available until the
connection timeout. NFC-to-BLE requires Bluetooth permissions as before.

The additive method keeps the JVM descriptors and default-argument bridges of
the existing QR and NFC APIs unchanged. `CombinedPresentation` delegates the
existing state/consent flow and uses the same serialized NFC owner registry.
