# OID4VC demo wallet (iOS)

A SwiftUI wallet app on the OID4VCWallet Swift package — OID4VCgo's
walletflow through gomobile (see [MOBILE.md](../../../MOBILE.md), Phases
4 to 9). It receives credentials from a Credential Offer link
(`openid-credential-offer://…`, opened in the app, or pasted), and
presents them in answer to a presentation request link (`openid4vp://…`).
Links can be opened from anywhere, pasted, or scanned in the app. On a
device the camera scans QR codes live (VisionKit); anywhere, including
the Simulator, the app reads a QR code from a photo or screenshot.
A credential's claims show the holder's portrait as an image.
A credential the issuer defers (passport-vdc's operator review, say)
waits under "Waiting for the issuer". It's polled at the issuer's
interval, and Check again asks at once. It joins the credentials once
issued, or says it was denied. A credential still waiting when the app
quits is waited for again when it's relaunched.
For a request, it shows who's asking, which credentials can answer and
exactly what sharing them discloses. Then it shares them, with holder
keys signing (Face ID or the passcode on a device), or declines. Its keys are
Secure Enclave keys kept in the Keychain. It gets Wallet and Key
Attestations from a Wallet Provider over HTTPS (the passport-vdc demo's
API), and keeps credentials in Application Support with complete file
protection.

The Xcode project is generated from `project.yml` with
[XcodeGen](https://github.com/yonaskolb/XcodeGen) (`xcodegen`); the
generated `DemoWallet.xcodeproj` is checked in, so building needs only
Xcode. It links the release framework, `../../build/release/Mobile.xcframework`:
build it first with `../../build-xcframework.sh`. At launch it deletes
any key none of its credentials is bound to, which an issuance the app
quit in the middle of leaves behind.

## Configuration

The app takes its configuration from the `OID4VC_DEMO_CONFIG`
environment variable (`simctl launch` passes `SIMCTL_CHILD_…` variables
through), and remembers it:

```json
{"wallet": {"client_id": "…", "redirect_uri": "…", "issuer_roots": "<PEM>",
            "verifier_roots": "<PEM>", "development": true},
 "provider_url": "https://…"}
```

## In person (ISO/IEC 18013-5 over BLE)

**Share in person:** "In person" shows a QR code (iOS asks for
Bluetooth the first time). A reader that scans it connects over
Bluetooth, and the app shows who is asking (the reader's name, whether
it's verified, and its certificate chain under "Reader certificate") and
what, element by element, marking those the reader says it will keep.
"Share" sends the chosen elements after Face ID or the passcode;
"Decline" sends nothing. Only mdocs can be shared in person.

**Reader mode:** with a `reader` in the configuration (`{"issuer_roots",
"reader_chain", "reader_key"}`: the test services and the scripts here
add one), turn on "Reader mode" in the settings menu. "Verify" offers
what to ask for, scans the holder's QR code, and shows what verified.
Revocation isn't checked: the status list reference is shown. An
`mdoc:` link opens reader mode too. The reader key arrives in the
configuration as a demo shortcut; a real reader makes its key in the
Secure Enclave.

BLE needs real devices: the Simulator has no Bluetooth. Try it between
two iPhones, or an iPhone and an Android phone with the Android demo,
both against the same services, by the steps in
mobile/android/DemoWallet/README.md ("Two phones, by hand"):
`run-device.sh` here and `run-passport-vdc.sh` there both use the
passport-vdc demo.

## UI tests, against test services

```sh
./run-ui-tests.sh            # iPhone 16 Simulator
```

This starts `mobile/cmd/testservices`, an in-process HAIP issuer,
Verifier and Wallet Provider. It makes the Simulator trust their
certificate, and drives the app from an empty wallet through both
grants:

- the authorization code grant: the issuer's page in an ephemeral web
  session, redirecting back to the app's private-use scheme redirect URI
- the pre-authorized code grant: the PIN typed in the app

A wrong PIN keeps the offer open with the error, and the right one then
receives it. It also covers deferred issuance: approved, denied, and approved after
the app is quit and relaunched while the credential is pending. And it
presents: a received credential shared in answer to the
Verifier's request (the Verifier gets `family_name`), and a request the
wallet can't answer, declined. Each test launches with
`OID4VC_DEMO_RESET=1`, which deletes every credential and pending
deferred credential at launch.
`OID4VC_DEMO_OFFER` and `OID4VC_DEMO_REQUEST` open a link at launch.

## Against the passport-vdc demo

```sh
(cd ../../../examples/passport-vdc && go run ./cmd/demo)   # in another terminal
./run-passport-vdc.sh
```

Then upload a passport on the issuer page, and open its offer link in
the Simulator (`xcrun simctl openurl booted '<link>'`). For the
authorization code offer, enter the confirmation code the page shows on
the issuer's approval page. For the pre-authorized code offer, enter
its PIN in the app. Tick **Keep for refresh** when uploading and the
app gets a refresh token: once every copy of a credential has been
shared, it fetches fresh copies by itself (and **Refresh copies** does
so at any time), for 24 hours.

## On a device

On a device, holder keys require Face ID or the passcode. They don't on
the Simulator, which can't create a Secure Enclave key requiring user
presence. Face ID needs the app's `NSFaceIDUsageDescription` (in
`project.yml`): without it, iOS asks for the passcode instead.

The phone can't reach services on this Mac's loopback address, so the
passport-vdc demo's issuer, verifier and Wallet Provider go on public
HTTPS URLs through a tunnel. The web wallet stays on this Mac: it has no
login.

1. Create a Cloudflare named tunnel, with a hostname for each of the
   three, as `cloudflared.yml.example` shows. Copy it to `cloudflared.yml`
   (ignored by git) with your tunnel and domain, and run it.
2. Start the demo with those URLs, in its own state directory: the
   credentials it issues name them. From `examples/passport-vdc`:

   ```sh
   go run ./cmd/demo -state .demo-state-device \
     -issuer-url https://issuer.example.com \
     -verifier-url https://verifier.example.com \
     -provider-url https://provider.example.com
   ```

3. Install and launch the app on a connected iPhone, signed with your
   team:

   ```sh
   TEAM_ID=ABCDE12345 PROVIDER_URL=https://provider.example.com \
     STATE=../../../examples/passport-vdc/.demo-state-device ./run-device.sh
   ```

4. On the phone, open the issuer's page in Safari, upload a passport (or
   use the sample), and open the offer link. For a presentation, open the
   verifier's page on another screen and scan its QR code in the app.

### Presenting to Safari (Digital Credentials API)

The app is also an Identity Document Provider (iOS 26): when a page in
Safari asks for an mdoc over the Digital Credentials API
(`org-iso-mdoc`), iOS offers the app for the doctypes it registered —
the passport-vdc Photo ID (`org.iso.23220.photoid.1`) — and shows the
`DocumentProvider` extension's consent sheet. In the passport-vdc demo,
open a verifier scenario in Safari on the phone and choose *Verify with
an ID in this browser*. The first time a Photo ID is received, iOS asks
whether the app may provide documents.

The extension is a separate process, so the app keeps what it reads in
shared places: the credential store and configuration in the app group
`group.dev.idfoundry.oid4vcgo.demowallet`, and holder keys in the
Keychain access group `<team>.dev.idfoundry.oid4vcgo.demowallet.shared`.
Instance and DPoP keys stay in the app's own group. On a device, before
the first build, register the app group in the Apple Developer portal
(Identifiers → App Groups) and enable on both App IDs
(`dev.idfoundry.oid4vcgo.demowallet` and its `.documentprovider`) the
App Groups capability with that group and the Digital Credentials API –
Mobile Document Provider capability. `BUNDLE_ID` changes both bundle
identifiers but not the group names, which are in the entitlements files
and `Shared/SharedWallet.swift`.

The extension names the reader asking when its request is signed by a
certificate under `mdoc_reader_roots` with the ISO/IEC 18013-5 reader
authentication extended key usage (`run-device.sh` passes the
passport-vdc demo's mdoc reader CA, `mdoc-reader-ca.pem`, and sets
`mdoc_reader_require_eku`), and otherwise shows only the website's
origin. Before answering, it checks that the request iOS releases is the
one it showed: same document, same elements, same reader — and no copy
another website has seen unless the sheet said so. The sheet lists only
mdocs that can be presented (holder key here, unexpired, not revoked or
suspended as last checked), warns when the chosen one's every copy has
been shown to another website, and presents by the copy policy chosen in
the app's settings.

Known limitations, fine for the demo but not for a production wallet:

- The app and the extension each read, change and write a credential's
  record (marking a copy presented, replacing copies on refresh) under a
  lock that only spans their own process. If the app refreshes a
  credential at the moment the extension presents it, one can overwrite
  the other's change. A file lock across processes isn't the answer on
  iOS — an app suspended holding a lock in a shared container is
  terminated — so it needs writes that check the record's version.
- The extension reads the whole credential store, including refresh
  grants and pending issuances. Their keys stay in the app's own
  Keychain group, so the extension can't use them, but a production
  wallet would keep those records out of the shared container.

### In person

Not in the demo yet: the Swift package has the holder's and the
reader's sides (`startProximityPresentation`, `ProximityReader`, see
[`mobile/README.md`](../../README.md#in-person-presentation)), and the
demo's "Share in person" and reader mode are still to be built (MOBILE.md,
Phase 10). Adding them needs `NSBluetoothAlwaysUsageDescription` in the
app's Info.plist, and a device: the Simulator has no Bluetooth.

### Restricting the pages with Cloudflare Access

The demo's pages have no login of their own: through the tunnel, anyone
could upload passports or the unchecked sample, approve reviews, revoke
or forget credentials, and start requests in the demo's name. They're
all under `/demo/` on the issuer and the verifier (`/` redirects
there), and nothing else is: everything outside it is the OpenID4VCI,
OAuth and OpenID4VP surface the wallet, the phone's browser during
issuance (`/authorize`) and the verifier itself call, which must stay
open. So one Access rule per host guards them:

1. In Cloudflare Zero Trust, **Access → Applications → Add an
   application → Self-hosted**.
2. Name it, and add the public hostname `issuer.example.com` with path
   `demo` (it covers everything under `/demo/`). Add a second
   hostname, `verifier.example.com`, path `demo`.
3. Add a policy: **Allow**, with an **Emails** rule listing who may
   use the demo. The login method can be **One-time PIN**: Cloudflare
   emails a code, with no identity provider to set up.
4. Save. Don't add `provider.example.com`: the app calls it, with no
   one to log in.

Opening `https://issuer.example.com/` then asks for your email and the
code once, and the phone, which uses only the endpoints outside
`/demo/`, works as before. The Wallet Provider stays open, and attests
any caller: that alone gets no credential (an offer and its code are
still needed), but it's a stand-in, not a production service.

Run the tunnel only while you test, and stop it after.

To run from Xcode instead, set `DEVELOPMENT_TEAM` in `project.yml` and
regenerate the project; the app then needs `OID4VC_DEMO_CONFIG` in its
scheme's environment once, as `run-device.sh` builds it.
