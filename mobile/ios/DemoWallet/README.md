# OID4VC demo wallet (iOS)

A SwiftUI wallet app on the OID4VCWallet Swift package — OID4VCgo's
walletflow through gomobile (see [MOBILE.md](../../../MOBILE.md), Phase
4). It receives credentials from a Credential Offer link
(`openid-credential-offer://…`, opened in the app, or pasted), and
presents them in answer to a presentation request link (`openid4vp://…`).
Links can be opened from anywhere, pasted, or scanned in the app. On a
device the camera scans QR codes live (VisionKit); anywhere, including
the Simulator, the app reads a QR code from a photo or screenshot.
A credential's claims show the holder's portrait as an image.
A credential the issuer defers (passport-vdc's operator review, say)
waits under "Waiting for the issuer". It's polled at the issuer's
interval, and Check again asks at once. It joins the credentials once
issued, or says it was denied. Pending credentials are kept in memory,
so one still waiting when the app quits is lost.
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

The demo's pages have no login, and the issuer takes passport uploads:
run the tunnel only while you test, and stop it after.

To run from Xcode instead, set `DEVELOPMENT_TEAM` in `project.yml` and
regenerate the project; the app then needs `OID4VC_DEMO_CONFIG` in its
scheme's environment once, as `run-device.sh` builds it.
