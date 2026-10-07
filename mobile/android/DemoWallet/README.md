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
  previewed as the selection changes. Sharing has the holder key sign,
  which asks for the holder's fingerprint or screen lock.
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

## Configuration

The app takes its configuration — the JSON mobile/cmd/testservices
serves at `/config` — from the launch intent's `config` extra, or from
`demo-config.json` pushed to its external files directory, and
remembers it:

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

## In person (ISO/IEC 18013-5 over BLE)

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

Two Android emulators can do it too, over the emulator's own Bluetooth:
the holder's debug build logs its QR code's text (`adb logcat -s
DemoWallet`), and `adb -s <reader> shell am start -a
android.intent.action.VIEW -d '<mdoc:…>'` hands it to the reader.

## UI tests, against test services

```sh
./run-ui-tests.sh            # an emulator or device, unlocked, screen lock PIN 1111
./run-ui-tests.sh present    # one test
```

`../DemoWalletUITests` is a self-instrumenting test app driving the
installed demo from outside, with UiAutomator, as the iOS demo's
XCUITests do: it quits and relaunches the app, and answers the system's
screen-lock prompt when a holder key signs. The script starts
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
