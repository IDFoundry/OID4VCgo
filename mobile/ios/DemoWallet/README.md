# OID4VC demo wallet (iOS)

A SwiftUI wallet app on the OID4VCWallet Swift package — OID4VCgo's
walletflow through gomobile (see [MOBILE.md](../../MOBILE.md), Phases
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
Attestations from a Wallet Provider over HTTPS: on a device, over the
library's protocol with App Attest (`HttpWalletProvider`); in the
Simulator, which has no App Attest, over the passport-vdc demo's own
API, which attests any caller. It keeps credentials in Application
Support with complete file protection.

The Xcode project is generated from `project.yml` with
[XcodeGen](https://github.com/yonaskolb/XcodeGen) (`xcodegen`); the
generated `DemoWallet.xcodeproj` is checked in, so building needs only
Xcode. It links the release framework, `../../build/release/Mobile.xcframework`:
build it first with `../../build-xcframework.sh`. At launch it deletes
any key none of its credentials is bound to, which an issuance the app
quit in the middle of leaves behind.

## Screen privacy

iOS snapshots an app as it leaves the foreground, for the app switcher,
and that snapshot would show whatever was on screen: a portrait, a
passport's claims. The demo covers its window whenever the scene isn't
active (`PrivacyCover` in `DemoWalletApp.swift`), so the snapshot shows
the cover. An app on the library should do the same. Issuer logos are
URLs the issuer chose: fetch one once, when the holder accepts the
credential, and keep it, rather than loading it on the offer's preview
(which tells the issuer, or a tracker it names, that the offer was
opened).

## Configuration

The app takes its configuration from the `OID4VC_DEMO_CONFIG`
environment variable (`simctl launch` passes `SIMCTL_CHILD_…` variables
through), and remembers it:

```json
{"wallet": {"client_id": "…", "redirect_uri": "…", "issuer_roots": "<PEM>",
            "verifier_roots": "<PEM>", "development": true},
 "provider_url": "https://…"}
```

## Revocation lists

Against the passport-vdc demo, whose CAs publish Certificate Revocation
Lists, the scripts here configure the wallet to check its trust roles
against them (`revocation`: `issuer`, `status`, `verifier`,
`mdoc_reader` and `registrar`) and the reader likewise (`issuer`,
`status`), each fetching the lists from the distribution points its
roots name (`crl_distribution_points_from_roots`, over https only:
`crl_require_https`). The app calls the library's `refreshCRLs()` at
launch, on returning to the foreground once the last refresh's
`nextRefresh` has passed, and from **Settings → Revocation lists**,
which shows each distribution point's outcome (updated, unchanged or
failed, with why), when the lists were fetched and when they're next
due, and **Refresh revocation lists**. It keeps the lists it gets (the
result's `crls`) in the app group's defaults and passes them back as
`crls` at the next launch, so checks work before the first refresh, and
the document provider extension checks against them too. A new
configuration starts without them. Nothing refreshes them while the app
is closed: a shipping app would schedule `refreshCRLs()` with
`BGTaskScheduler` at `nextRefresh` (the library's
[GoingToProduction](../OID4VCWallet/Sources/OID4VCWallet/OID4VCWallet.docc/GoingToProduction.md)
guide). A list past its nextUpdate (an hour after the demo signs it)
refuses its CA's certificates until the next refresh.

Revoke the demo issuer's document signer (its **Issued credentials**
page, **Revoke document signer…**): the issuer revokes every credential
that signer signed on its status list too, as it would were the key
compromised. The wallet shows them revoked once it next checks their
status (at launch, or on demand), within the status list's one-minute
ttl, and the demo's verifier refuses a presentation of them. Refresh
the lists here too: the Verify tab refuses an mdoc that signer signed,
saying its document signer was revoked (the library's
`WalletError.isCertificateRevoked`), and the wallet checks each credential's
status again once a list changes. `checkStatus` also verifies the
issuer's certificate against the lists held, so a credential that signer
signed shows **Invalid: issuer certificate revoked** if the lists show
it before its status list does, and isn't offered ahead of others to a
verifier; once its status list revokes it, it shows **Revoked by the
issuer**, which is final. The certificate check isn't: a later list
that no longer names the certificate makes it valid again, unless its
status list has revoked it. Without a current list from its CA, a
credential shows **Unknown: revocation lists out of date** until the
lists are refreshed. Receive it again for one the new signer signs.

## In person (ISO/IEC 18013-5 over BLE)

**Share in person, the Present tab:** it shows a QR code at once (iOS
asks for Bluetooth the first time), and a new one after each session;
leaving the tab ends the session. A reader that scans it connects over
Bluetooth, and the app shows who is asking (the reader's name, whether
it's verified, and its certificate chain under "Reader certificate") and
what, element by element, marking those the reader says it will keep.
"Share" sends the chosen elements after Face ID or the passcode;
"Decline" sends nothing. Only mdocs can be shared in person. A reader
asking for several documents at once (the Verify tab's "and" presets)
gets a section per document the wallet holds, and "Share 2 documents"
sends them all in one response after one Face ID; a document with every
element unticked is left out. To hold two test mdocs, take the offer
`curl -sk -X POST 'https://127.0.0.1:8600/offer?pin=493536&mdoc=2'`.

**Bluetooth modes:** the QR code offers both ISO/IEC 18013-5 modes by
default: the phone advertises for the reader and scans for it at once,
and the reader picks (central client mode, where the holder connects to
the reader, when it supports both). Settings, "Presenting in person",
limits it to one, for trying a reader that supports only that mode. The
Verify tab's result says which mode a session used.

**Reader mode, the Verify tab:** with a `reader` in the configuration
(`{"issuer_roots", "reader_chain", "reader_key"}`: the test services and
the scripts here add one), the Verify tab in the tab bar offers what to
ask for, scans the holder's QR code, and shows what verified. It
checks the document's status list before reporting it verified, and,
with `revocation` in its `reader` configuration (the passport-vdc
scripts set it), the document signer's certificate against its IACA's
revocation list (see Revocation lists); without, that isn't checked. An
`mdoc:` link opens the Verify tab too. The reader key arrives in the
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

On a device, the app asks for Face ID or the passcode before each
presentation, and nowhere else: receiving and refreshing credentials
don't ask. The check is the app's, not the holder keys' own: a key
requiring user presence would ask for every Credential Request's proof
too, including those of the copies the app refreshes by itself
(`KeychainKeyStore.Options.holderUserPresence` describes the trade-off).
The Simulator doesn't ask. Face ID needs the app's
`NSFaceIDUsageDescription` (in `project.yml`): without it, iOS asks for
the passcode instead.

Holder keys made before this change still require user presence, and
ask whenever they sign: reset the app (`OID4VC_DEMO_RESET=1`) or receive
the credentials again.

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
     -provider-url https://provider.example.com \
     -ios-app ABCDE12345.dev.idfoundry.oid4vcgo.demowallet
   ```

   `-ios-app` is the app's App ID, your team ID and its bundle ID
   (`BUNDLE_ID` below, if you set one): the Wallet Provider then attests
   it over the library's protocol, with App Attest evidence from the
   development environment, as a development build makes, and turns
   off the demo provider's own API, which attests any caller.

3. Install and launch the app on a connected iPhone, signed with your
   team:

   ```sh
   TEAM_ID=ABCDE12345 PROVIDER_URL=https://provider.example.com \
     STATE=../../../examples/passport-vdc/.demo-state-device ./run-device.sh
   ```

   The app registers with the Wallet Provider at its first issuance: a
   registration key in the Secure Enclave and an App Attest key Apple
   attests (the provider logs the instance). Before the first build,
   enable **App Attest** on the App ID in the Apple Developer portal
   (Identifiers → the app → Capabilities), as the entitlement
   `com.apple.developer.devicecheck.appattest-environment`
   (`development`) needs. `PROVIDER_PROTOCOL=demo` uses the demo
   provider's own API instead, without App Attest: start the demo
   without `-ios-app` for it, as `-ios-app` turns that API off (`403`).

4. On the phone, open the issuer's page in Safari, upload a passport (or
   use the sample), and open the offer link. For a presentation, open the
   verifier's page on another screen and scan its QR code in the app.

A demo state directory from before the demo's CAs published CRLs gets
new CAs the first time the demo starts with it (it logs so): their old
keys weren't kept, so they can't sign a CRL. Run `run-device.sh` again,
for the app to trust the new ones, and receive the credentials again.
The same goes for the Simulator and `run-passport-vdc.sh`.

### Presenting to Safari (Digital Credentials API)

The app is also an Identity Document Provider (iOS 26): when a page in
Safari asks for an mdoc over the Digital Credentials API
(`org-iso-mdoc`), iOS offers the app for the doctypes it registered —
the passport-vdc Photo ID (`org.iso.23220.photoid.1`) — and shows the
`DocumentProvider` extension's consent sheet. In the passport-vdc demo,
open a verifier scenario in Safari on the phone and choose *Verify with
an ID in this browser*. The first time a Photo ID is received, iOS asks
whether the app may provide documents.

A page asking for several documents gets a section per document the
wallet holds, each with its own choice of credential and a switch to
leave it out, and the documents it doesn't hold are named. "Share 2"
sends them all in one response after one Face ID. iOS offers the
extension only the doctypes in its entitlement (the Photo ID here), so
for now Safari hands it one document at a time; adding a doctype means
adding it to both entitlements files and `DocumentRegistrations`, and
to the App IDs in the Apple Developer portal.

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

The demo shares in person and verifies others in person (the Verify
tab): see [In person](#in-person-isoiec-18013-5-over-ble) above, over the
Swift package's `startProximityPresentation` and `ProximityReader`
([`mobile/README.md`](../../README.md#in-person-presentation)). It needs
a device: the Simulator has no Bluetooth.

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
