# Integration checklist

Every step and rule for integrating `OID4VCWallet`, in order, each with
how to check it. It's written to be followed literally: by a developer,
or by a coding assistant asked to integrate the library. The guides
explain the why; this list doesn't repeat them. When an item and a
guide disagree, the guide and [the API reference](https://idfoundry.github.io/OID4VCgo-wallet-kotlin/latest/)
are right: report the difference.

For a coding assistant: read [Getting started](GettingStarted.md) and
the guide for each feature you add before writing code. Use only the
public API those name; don't call anything under `gomobile`, and don't
reimplement a protocol the library already carries. The
[demo wallet](https://github.com/IDFoundry/OID4VCgo/tree/main/mobile/android/DemoWallet)
is a complete, working app on this library to compare against.

## 1. Every app

- [ ] The AAR is in an **app** module's `libs/` with the libraries the
  README lists, at the versions it lists. *Check:* the app builds; the
  AAR's SHA-256 matches the release's `SHA256SUMS`.
- [ ] The app refuses to run on a test build: `OID4VC.isTestBuild` is
  false in what you ship.
- [ ] Keys come from `AndroidKeystoreKeyStore`, credentials live in
  `FileCredentialStore`, and the app implements `WalletProvider` (or
  passes `null` for issuers that don't ask for attestations).
  ([Getting started](GettingStarted.md))
- [ ] The `WalletProvider` gives a fresh challenge from your backend in
  `attestationChallenge` for instance and holder keys, implements the
  `WalletAttestationRequest` and `KeyAttestationRequest` versions of
  its attestations, and sends each key's `KeyEvidence.certificateChain`
  to the backend, which verifies it as
  [Going to production](GoingToProduction.md) lists before attesting,
  and refuses a key without one. *Check:* the backend refuses a key
  made without its challenge, a key from an emulator, and a key from a
  build signed with another certificate.
- [ ] One `Wallet`, created at launch and kept for the app's life, with
  `Wallet.sweepOrphanedKeys` run before any issuance.
- [ ] Each setting in [Going to production](GoingToProduction.md)'s
  "Settings to decide" is decided and recorded.
- [ ] Trust roots are PEM in `WalletConfiguration`, each in its own
  role: `issuerRoots`, `verifierRoots`, `mdocReaderRoots` and the rest.
  Outside development, two roles whose roots may vouch for the same
  certificates (a shared anchor, or an intermediate in either) each
  need their own, distinct `*RequireEKU`, or the wallet isn't made.
  *Check:* `Wallet(...)` succeeds with your production configuration.
  ([Going to production](GoingToProduction.md))
- [ ] Errors are shown with `WalletException.description` and
  `ProximityException.description`, and retried only when the guide
  says so. ([Handling errors](HandlingErrors.md))
- [ ] Revocation, for every role whose roots you set: where your
  ecosystem's CAs publish CRLs, the role in `revocation`, its CAs' CRLs
  in `crls`, and, for a certificate pinned in the roots, its CA's
  certificate in `crlIssuers`; otherwise the role in
  `noRevocationCheck`, a deliberate decision. Fresh CRLs are fetched in
  the background and handed over with `Wallet.setCRLs` before the old
  ones expire. *Check:* `Wallet(...)` succeeds with your production
  configuration, and a certificate on a CRL is refused.
  ([Going to production](GoingToProduction.md))

## 2. Receiving credentials

- [ ] An intent filter opens `openid-credential-offer://` links in the
  app, and each goes to `Wallet.startIssuance`. Show `offer` (who is
  offering what) before going on.
- [ ] `redirectURI` uses the app's own scheme, a domain name in reverse
  order and a single slash, such as `com.example.wallet:/callback`, and
  an intent filter for that scheme. Not an https App Link, and not
  `myapp:/callback` or `com.example.wallet://callback`. *Check:*
  `Wallet(...)` succeeds with your production configuration.
- [ ] Pre-authorized code: ask for the PIN when `offer.txCode` is set,
  and ask again when `redeemPreAuthorizedCode` throws a retryable error.
  Authorization code: open `beginAuthorization()`'s URL in an Auth Tab
  (a Custom Tab where there are none), ephemeral, and pass the redirect
  to `completeAuthorization`. A redirect that arrives at a relaunched
  app goes to `Wallet.resumeIssuance`.
- [ ] `requestCredentials()`, then `close()` the issuance whatever
  happens. Show `Issuance.Result`'s received, deferred and failed
  credentials.
- [ ] Deferred credentials are polled (`Wallet.pollDeferred`) at the
  interval the issuer asks for, after relaunches too
  (`Wallet.deferredCredentials()`).
- [ ] `Wallet.checkStatus(id)` before relying on a held credential;
  show `CredentialStatus.Value.Unknown` as not checked, not as valid.
- [ ] *Check:* both grants against your issuer, including a killed
  process during sign-in; an offer from an issuer outside `issuerRoots`
  is refused. ([Receiving credentials](ReceivingCredentials.md))

## 3. Presenting from a link

- [ ] An intent filter opens `openid4vp://` links in the app, and each
  goes to `Wallet.startPresentation`. An `untrustedVerifier` error is
  shown as such, with nothing presented.
- [ ] Show `verifier` (and its `registration` when there is one), each
  query's claims and any `unregistered` ones, and what `preview` says
  would be disclosed, before the holder agrees. Then `respond`, or
  `decline`.
- [ ] Respond with the selection whose `preview` the holder saw: a
  changed selection is previewed and shown again first.
- [ ] Open `redirectURI`, when there is one, in the browser the request
  came from.
- [ ] `requestRefused` from `startPresentation`: open
  `Wallet.takeRefusalRedirect()` when it returns a URL, and tell the
  holder the request wasn't answered. Over the DC API, return a failure
  to the page. ([Handling errors](HandlingErrors.md))
- [ ] `deliveryUnknown` isn't retried: tell the holder to check with the
  Verifier.
- [ ] *Check:* a Verifier outside `verifierRoots` is refused before
  anything is shown; the Verifier receives exactly the claims the
  holder chose. ([Presenting from a link](PresentingFromALink.md))

## 4. In person, QR code (holder)

- [ ] Request `ProximityPermissions.holder(modes)` at runtime before
  `Wallet.startProximityPresentation(context, modes = modes)`. Pass
  `setOf(ProximityBLEMode.PERIPHERAL_SERVER)` to avoid asking for
  scanning (and location on Android 11 and earlier).
- [ ] Show `qrCode`; collect `state`. On `RequestReceived`, show
  `request.reader` (name, and whether `Trusted`) and the requested
  elements, then call `respond(document, credentialID, elements)` or
  `decline()`. On a final state, show the outcome.
- [ ] `cancel()` when the holder leaves the screen.
- [ ] *Check:* on two phones, a reader scanning the code gets the
  elements the holder chose, and nothing else.

## 5. In person, NFC tap (holder)

- [ ] A subclass `class IdentityNfcService : NfcEngagementService()` in
  the app, declared in the app's manifest:

  ```
  <service android:name=".IdentityNfcService" android:exported="true"
      android:permission="android.permission.BIND_NFC_SERVICE">
      <intent-filter>
          <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE" />
      </intent-filter>
      <meta-data android:name="android.nfc.cardemulation.host_apdu_service"
          android:resource="@xml/oid4vc_nfc_aids" />
  </service>
  ```

  `@xml/oid4vc_nfc_aids` comes from the library: don't copy or edit it.
  The library's manifest already adds the `NFC` permission and optional
  NFC/HCE features. *Check:* `adb shell dumpsys nfc` lists your service
  for AID `D2760000850101`.
- [ ] Check NFC is on (`NfcAdapter.getDefaultAdapter(context)?.isEnabled`)
  before starting; starting with NFC off throws `IllegalArgumentException`.
- [ ] Choose the entry point:
  - `startNfcPresentation(context, modes = modes)`: tap, then Bluetooth.
    Needs `ProximityPermissions.holder(modes)`.
  - `startNfcPresentation(context, nfcData = true)`: tap, and the data
    over NFC. No Bluetooth permissions. The phones stay together until
    shared: say so on screen.
  - `startCombinedPresentation(context, nfc = NfcEngagementOptions())`:
    show the QR code and answer a tap; the first reader wins.
  - `negotiated = true` only for readers known to support TNEP. The
    default, static handover, works with every reader.
- [ ] Keep **one** presentation at a time, held above the screen (an
  application or view-model scope) so it survives the HCE service being
  recreated. Starting another replaces it: the new one waits for the
  previous one's tasks and radio resources to close. Don't run two
  side by side; to offer QR and NFC together, use
  `startCombinedPresentation`.
- [ ] Routing, in the activity:
  - `onResume`: if the session's state isn't final, call
    `preferForeground(activity, IdentityNfcService::class.java)`; if it
    returns false, tell the holder to choose your app if Android asks
    which app should answer the tap, and offer the QR code.
  - `onPause`: `releaseForeground(activity)`.
  - On a final state: `releaseForeground(activity)`. Don't prefer again
    for that session. The fingerprint prompt resumes the activity after
    sharing; an unconditional `onResume` keeps taps away from other wallets.
- [ ] Leaving the screen: `releaseForeground`, then `cancel()`, then
  `close()` from a scope that outlives the screen, so cleanup finishes.
- [ ] The same consent flow as QR: `state`, `respond`, `decline` (on
  `NfcPresentation.presentation`, or directly on `CombinedPresentation`).
- [ ] With `startCombinedPresentation`, hide the QR code once
  `selectedEngagement` isn't null.
- [ ] *Check, on two phones:*
  - a tap, then Bluetooth: the reader gets the response, and you can
    part the phones after the tap;
  - NFC-only: the reader gets the response while the phones stay
    together, and parting them before Share ends the session as `Failed`;
  - with another wallet installed, `dumpsys nfc` shows your service as
    the preferred foreground service while presenting, and not after
    the outcome is shown.

## 6. In person, reader (verifier)

- [ ] `ProximityReader(ProximityReaderConfiguration(issuerRoots = …))`,
  plus a reader key and chain with the reader-authentication EKU if
  holders should see who's asking.
- [ ] `development` not set, with each role (`ISSUER`, `STATUS`) in
  `revocation` (with `crls`, refreshed by `setCRLs`) or
  `noRevocationCheck`, and `anyIssuerForAnyType` or
  `issuerRootsByDocType` deciding which IACAs issue which document type.
- [ ] QR: `reader.start(context, qrCode, docType, elements)` after
  `ProximityPermissions.reader` is granted.
- [ ] NFC: reader mode on the resumed reader screen with
  `FLAG_READER_NFC_A | FLAG_READER_NFC_B | FLAG_READER_SKIP_NDEF_CHECK`;
  pass the delivered `Tag` to `reader.startFromNfc(context, tag, docType,
  elements)` from a coroutine. Disable reader mode on pause and on
  leaving the screen.
- [ ] The result says how it went: `session.usesNfcData`, and the BLE
  `mode` only when that's false.
- [ ] Call `session.checkStatus()` once the session is `Verified`, and
  rely on the document only on `MdocStatus.Valid` or
  `MdocStatus.NoStatus`. Decide which issuers to accept on
  `VerifiedMdoc.issuerChain`, not on its `issuer` name.
- [ ] *Check:* both a QR holder and an NFC holder verify; an mdoc from
  an issuer outside `issuerRoots` is refused.

## 7. Before shipping

- [ ] [Going to production](GoingToProduction.md) is done, and no
  `ProximityReaderConfiguration` sets `development`.
- [ ] Interop beyond your own app: test your holder against at least
  one independent reader, and your reader against an independent holder.
  The library is tested against the Multipaz test app; a reader that
  supports only static handover needs your holder in static mode.
- [ ] `ProximityDiagnostics.enabled` is off in release builds. It logs
  lifecycle events, never credentials, under the `OID4VCProximity` tag.
