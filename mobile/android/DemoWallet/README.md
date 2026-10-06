# OID4VC demo wallet (Android)

A Jetpack Compose wallet app on the OID4VCWallet Kotlin library —
OID4VCgo's walletflow through gomobile (see [MOBILE.md](../../../MOBILE.md),
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
`org-iso-mdoc` requests aren't answered on Android yet.

## Configuration

The app takes its configuration — the JSON mobile/cmd/testservices
serves at `/config` — from the launch intent's `config` extra, or from
`demo-config.json` pushed to its external files directory, and
remembers it:

```json
{"wallet": {"client_id": "…", "redirect_uri": "…", "issuer_roots": "<PEM>",
            "verifier_roots": "<PEM>", "development": true},
 "provider_url": "https://…"}
```

With `development`, a `dev-ca.pem` pushed beside it is trusted too: the
wallet's own requests take it as `development_roots`, since Go reads only
Android's system CA files. The launch extras `reset` (delete every
credential first), `offer` and `request` (open a link) are for tests.

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
control endpoint over it. The tests cover the pre-authorized code grant
(a wrong PIN, then the right one), status and revocation, presenting
(one credential, several, per-verifier copies, a registered verifier and
a request beyond its registration, an untrusted verifier, declining),
deferred credentials (approved, denied, and approved after a relaunch),
and the scanner. The authorization code grant isn't among them: the
issuer's page is Chrome's, which doesn't trust the services' CA.
`../unlock-emulator.sh` gives an emulator the PIN.

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
