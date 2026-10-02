# OID4VC demo wallet (iOS)

A SwiftUI wallet app on the OID4VCMobile Swift package — OID4VCgo's
walletflow through gomobile (see [MOBILE.md](../../../MOBILE.md), Phase
4). It receives credentials from a Credential Offer link
(`openid-credential-offer://…`, opened in the app, or pasted). Its keys are
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
certificate, and drives the app: a pre-authorized offer with the PIN
typed in the app, received end to end. The authorization code test is
skipped until FAPIgo accepts the app's private-use scheme redirect URI
(see MOBILE.md).

## Against the passport-vdc demo

```sh
(cd ../../../examples/passport-vdc && go run ./cmd/demo)   # in another terminal
./run-passport-vdc.sh
```

Then upload a passport on the issuer page with the pre-authorized code
chosen, open its offer link in the Simulator (`xcrun simctl openurl
booted '<link>'`), and enter the PIN the page shows.

## On a device

Set `DEVELOPMENT_TEAM` in `project.yml`, regenerate the project, and run
from Xcode. On a device, holder keys require Face ID or the passcode.
They don't on the Simulator, which can't create a Secure Enclave key
requiring user presence.
