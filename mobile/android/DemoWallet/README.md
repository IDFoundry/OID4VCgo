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
