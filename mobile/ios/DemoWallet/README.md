# OID4VC demo wallet (iOS)

A SwiftUI wallet app on the OID4VCMobile Swift package — OID4VCgo's
walletflow through gomobile (see [MOBILE.md](../../../MOBILE.md), Phase
4). It receives credentials from a Credential Offer link
(`openid-credential-offer://…`, opened in the app, or pasted), and
presents them in answer to a presentation request link (`openid4vp://…`).
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
Xcode. It links `../../build/Mobile.xcframework`: build it first with
`../../build-xcframework.sh`.

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

It also presents: a received credential shared in answer to the
Verifier's request (the Verifier gets `family_name`), and a request the
wallet can't answer, declined. Each test launches with
`OID4VC_DEMO_RESET=1`, which deletes every credential at launch.
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
its PIN in the app.

## On a device

Set `DEVELOPMENT_TEAM` in `project.yml`, regenerate the project, and run
from Xcode. On a device, holder keys require Face ID or the passcode.
They don't on the Simulator, which can't create a Secure Enclave key
requiring user presence.
