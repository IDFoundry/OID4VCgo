# OID4VC demo wallet (Android)

A Jetpack Compose wallet app on the OID4VCWallet Kotlin library —
OID4VCgo's walletflow through gomobile (see [MOBILE.md](../../MOBILE.md),
Phase 8) — the Android counterpart of [the iOS demo](../../ios/DemoWallet).
It receives credentials from a Credential Offer link
(`openid-credential-offer://…`, opened from anywhere, pasted, or
scanned), and presents them in answer to a presentation request link
(`openid4vp://…`).

- **Receiving:** both grants — the issuer's pages in an Auth Tab (an
  ephemeral Custom Tab where the browser has no Auth Tabs), the
  redirect back on the app's private-use scheme; or a PIN typed in the
  app. A failure trying again may fix (the network, a wrong PIN) keeps
  the offer open with Try again. Deferred credentials wait under
  "Waiting for the issuer", polled at the issuer's interval, and
  survive the app quitting; an authorization the app was killed during
  completes when the redirect arrives.
- **Presenting:** who's asking (and its registration), the credentials
  that can answer each query, and exactly what sharing them discloses,
  previewed as the selection changes. Sharing asks for the holder's
  fingerprint, face or screen lock first, and only sharing does:
  receiving and refreshing credentials don't. The check is the app's,
  not the holder keys' own: a key requiring the holder for each use
  would ask for every Credential Request's proof too, including those
  of copies refreshed in the background
  (`AndroidKeystoreKeyStore.Options.holderUserAuthentication` describes
  the trade-off). Holder keys made before this change still ask each
  time they sign, until the credentials are received again.
- **Holding:** cards in the issuer's colours grouped by whose they are,
  with claims and portraits; status checked at launch and on demand;
  copies, refreshed without the holder once used up.
- **Keys** are Android Keystore keys (StrongBox where the device has
  it), **credentials** are encrypted files that need the device
  unlocked, and nothing of the wallet's is backed up. The app needs a
  screen lock.
- **QR codes** scan live (CameraX, ML Kit's bundled model: no Play
  services) or from an image.

## Presenting to Chrome (Digital Credentials API)

The app is a Credential Manager provider: it registers each
presentable SD-JWT VC and mdoc, with its claims, in an `OpenId4VpRegistry`
(Google's OpenID4VP matcher), so when a page in Chrome asks over the
Digital Credentials API with OpenID4VP (`openid4vp-v1-unsigned`,
`-signed` or `-multisigned`), the system's chooser offers the matching
credentials. Choosing one opens `GetCredentialActivity`: the same
consent screen as a link's request, naming the page's origin (and the
Verifier, for a signed request), and Share hands the encrypted response
back through Chrome. The origin comes from Chrome, which the app trusts
as a privileged browser (`res/raw/privileged_browsers.json`, Chrome's
entries from Google's list). It needs Google Play services.

Against the test services, open `https://127.0.0.1:8600/dcapi` in
Chrome on the device (past the certificate warning), and tap Verify:
the page shows what the test Verifier made of the answer.
Android answers over OpenID4VP, mdocs included: `org-iso-mdoc` is the iOS demo's route.
This has run on the API 37 emulator with Google Play; on a physical
device it's still to be tried (MOBILE.md's Phase 8 open items).

## Screen privacy

Both activities set `FLAG_SECURE` on their window, so the recents
screen's thumbnail, screenshots and screen recordings show nothing of a
portrait or a passport's claims. An app on the library should do the
same on every screen that shows credentials, and keep claims and QR
codes (a device engagement) out of its logs. Issuer logos are URLs the
issuer chose: fetch one once, when the holder accepts the credential,
and keep it, rather than loading it on the offer's preview (which tells
the issuer, or a tracker it names, that the offer was opened).

## Configuration

The app takes its configuration — the JSON mobile/cmd/testservices
serves at `/config` — from `demo-config.json` pushed to its external
files directory, or, in a debug build only, from the launch intent's
`config` extra, and remembers it. The other test extras (`reset`,
`offer`, `request`) are debug-only too: the main activity is exported
for its links, and a release build mustn't let any app replace its
trust roots, wipe it, or skip a link's confirmation.

```json
{"wallet": {"client_id": "…", "redirect_uri": "…", "issuer_roots": "<PEM>",
            "verifier_roots": "<PEM>", "mdoc_reader_roots": "<PEM>", "development": true},
 "provider_url": "https://…",
 "reader": {"issuer_roots": "<PEM>", "reader_chain": "<PEM>", "reader_key": "<PKCS #8 PEM>"}}
```

`reader`, optional, is reader mode's identity (below): the IACAs it
accepts, and its certificate chain and key. The key comes in the
configuration as a demo shortcut; a real reader's key is made in Android
Keystore and never leaves the device. `mdoc_reader_roots` is the CA the
wallet recognizes readers by.

With `development`, a `dev-ca.pem` pushed beside it is trusted too: the
wallet's own requests take it as `development_roots`, since Go reads only
Android's system CA files. The launch extras `reset` (delete every
credential first), `offer` and `request` (open a link) are for tests.

`provider_url` is the Wallet Provider (`HTTPWalletProvider`). With the
passport-vdc demo's, the wallet makes each instance and holder key over
an attestation challenge from the provider's `/attestation-challenge`,
so Android Keystore attests it, and sends the key's attestation chain
with its attestation requests; the provider verifies the chain before
attesting the key, and logs whether it's hardware Google vouches for.
An emulator's attestation is software, which the provider accepts
unless it runs with `-require-hardware-key-attestation`. A provider
without that endpoint (mobile/cmd/testservices) gives no challenge,
and the keys go without chains. See the passport-vdc README's
"The stand-in Wallet Provider". The iOS demo app sends no such
evidence: App Attest attests the app, not its Secure Enclave keys.

The demo requires Android 11/API 30 and compileSdk 37. Install a matching
debug APK with `adb -s <device> install -r <apk>` to preserve data when the
installed signing key matches; do not uninstall or reset an existing wallet
just to try a new build. The test-services launch helpers reset the wallet,
so use manual configuration for an existing integration.

## In person (ISO/IEC 18013-5 over QR/BLE or NFC)

The demo also offers **QR code or NFC tap, then Bluetooth**, **NFC tap and
Bluetooth**, **Negotiated NFC tap and Bluetooth**, **NFC tap and
transfer**, and **Negotiated NFC tap and transfer** in the presentation
settings. The first shows the QR code and answers a tap at the same time
(`startCombinedPresentation`): the first reader to engage gets the request,
and the other offer is withdrawn. The Bluetooth ones use the BLE mode
chosen below them in the same menu, which stays open for both choices. The
two transfer modes keep the phones together for the whole exchange and
require no Bluetooth permissions, so the menu greys out the Bluetooth modes.
The choice is kept across launches.
Reader presets offer **Tap with Bluetooth allowed**, which requests
Bluetooth permissions, and **Tap without asking for Bluetooth**, which
skips that request. Both detect the holder's selected carrier; the second
action does not force NFC-only if Bluetooth permissions were granted
previously. To test NFC-only explicitly, select NFC tap and transfer on the
holder and disable Bluetooth on both phones. The verified result reports
the actual data transport and the BLE role when applicable. Consent and
credential verification use the existing presentation flow.

Selecting either tap action opens an NFC waiting screen showing the selected
request and tap instructions. **Cancel NFC** or Back returns to the request
list and disables reader mode; leaving the Verify screen also closes it.
NFC errors show **Try again** without claiming the reader is ready.

Use two NFC-capable Android phones, unlocked with NFC enabled. The verifier
needs the credential issuer's IACA in `reader.issuer_roots`, and a reader
identity in `reader.reader_chain` / `reader.reader_key`. If the holder
requires trusted readers, put that reader's CA in its `mdoc_reader_roots`.
These are separate trust roles. Choose a preset matching the credential's
docType and namespace; custom schemas require a corresponding preset.
Import `demo-config.json` through the configuration mechanism above and
restart the app so its reader uses the new configuration. Never commit
private keys or credentials in test evidence.

Test static and negotiated BLE handover in both BLE roles, and static and
negotiated NFC-only transfer. Verify the reader identity on the holder,
consent and the disclosed claims on the verifier. Keep the phones together
through NFC-only consent/transfer; for BLE, separate after handover.
Repeat, decline, cancel, then test field loss and a fresh session. Record
device/OS and APK/SDK identifiers. Independent Multipaz tests remain a
separate interoperability gate.

`DemoNfcService` is declared with the library AIDs; one view-model owner
retains the session, and foreground preference is refreshed on resume.
See the [NFC integration guide](../docs/PresentingInPerson.md#nfc-holder-and-reader).
Emulator APDU tests do not
establish real-device Multipaz interoperability or ISO conformance.

Over the Kotlin library's `startProximityPresentation` and
`ProximityReader` ([`mobile/README.md`](../../README.md#in-person-presentation)).

**Share in person, the Present tab:** it asks for the nearby devices
permission the first time, then shows a QR code at once, and a new one
after each session; leaving the tab ends the session. A reader that scans it
connects over Bluetooth, and the app shows:
- who is asking: the reader's name and whether it's verified, its
  certificate chain on "Reader certificate";
- what it asks for, element by element, marking those the reader says
  it will keep.

"Share" sends the chosen elements after the fingerprint or screen lock
prompt; "Decline" sends nothing. Only mdocs can be shared in person.

**Bluetooth modes:** the QR code offers both ISO/IEC 18013-5 modes by
default: the phone advertises for the reader and scans for it at once,
and the reader picks (central client mode, where the holder connects to
the reader, when it supports both). Settings, "Presenting in person",
limits it to one, for trying a reader that supports only that mode. The
Verify tab's result says which mode a session used.

**Reader mode, the Verify tab:** with a `reader` in the configuration,
the Verify tab in the bottom bar offers what to ask for (a Photo
ID's or a driving licence's age, or name, photo and age; the test
services' mdoc), scans the holder's QR code, and shows what verified:
the elements, the issuer and the IACA it chains to, validity and device
authentication. Revocation isn't checked: the status list reference is
shown. An `mdoc:` link opens the Verify tab too, without the camera.

The test services give a reader (`Test Services Reader`) the wallet
recognizes; passport-vdc's demo writes its own to
`.demo-state/mdoc-reader.pem` (key, then chain) and its CA to
`mdoc-reader-ca.pem`, which `run-passport-vdc.sh` puts in the
configuration: it runs the app against the passport-vdc demo, on an
emulator or a USB-connected phone, as the iOS demo's `run-device.sh`
does on an iPhone. Use it to try an Android phone and an iPhone
together.

### Two phones, by hand

BLE doesn't run in CI: try it on two phones (two Android phones, or an
Android phone and an iPhone with the iOS demo), each configured against
the same services, Bluetooth on, screen lock set:

1. On the holder, receive the test mdoc: `curl -sk -X POST
   'https://127.0.0.1:8600/offer?pin=493536&mdoc=1'`, open the link, enter
   493536.
2. On the reader, open the Verify tab, choose "Test mdoc: name", and scan
   the holder's QR code (its Present tab).
3. The holder sees "Test Services Reader" as verified. "Share" (with the
   screen lock): the reader shows Verified, with only the shared names.
4. Again, then: "Decline" (the reader shows declined); untick an
   element (it's missing from the result); cancel on the reader while
   the holder decides (the holder shows the reader ended it); walk out of
   range mid-transfer, or turn on airplane mode (both show the
   connection lost); a reader without `reader` in its configuration (the
   holder shows an unknown reader).
5. Swap the phones' roles.

The demo doesn't log its QR code: the device engagement is for the
reader that scans it, not for anything that can read the device's log.

## UI tests, against test services

```sh
./run-ui-tests.sh            # an emulator or device, unlocked, screen lock PIN 1111
./run-ui-tests.sh present    # one test
```

`../DemoWalletUITests` is a self-instrumenting test app driving the
installed demo from outside, with UiAutomator, as the iOS demo's
XCUITests do: it quits and relaunches the app, and answers the system's
screen-lock prompt before the app shares. The script starts
`mobile/cmd/testservices`, forwards their ports into the device, pushes
their CA to the app and hands it to the tests, which reach the services'
control endpoint over it. The tests cover both grants (the authorization
code, through Chrome, and the pre-authorized code: a wrong PIN, then the
right one), refreshing copies (by hand, and by itself once every copy is
used), status and revocation, presenting
(one credential, several, per-verifier copies, a registered verifier and
a request beyond its registration, an untrusted verifier, declining),
deferred credentials (approved, denied, and approved after a relaunch),
and the scanner. For the issuer's page, the script has Chrome accept the
services' self-signed certificate by its key: it writes Chrome's command
line (`--ignore-certificate-errors-spki-list`, skipping the first-run
screens) to `/data/local/tmp/chrome-command-line`, makes Chrome the debug
app so it reads it, and removes both when done.
`../unlock-emulator.sh` gives an emulator the PIN. `UI_TEST_PORT` moves
the control endpoint off 8600; the script stops if something already
answers there.

## Against the test services

```sh
./run-test-services.sh      # an emulator running, or a device attached
```

It builds the release Go library and the app, starts
`mobile/cmd/testservices`, forwards their ports into the device, pushes
the configuration and the services' CA, and launches the app from an
empty wallet. Then make offers and requests with the services' control
endpoint, as the script's header shows.

The app links the release Go library, `../../build/release/mobile.aar`
(`../../build-aar.sh`).

Running it against the passport-vdc demo, as the iOS demo's
`run-device.sh` does, hasn't been tried on Android yet, and has no
script.
