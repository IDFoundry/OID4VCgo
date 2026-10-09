# Module oid4vcwallet

Receive verifiable credentials and present them from an Android app:
over OpenID4VCI and OpenID4VP under HAIP, to Chrome's Digital
Credentials API through Credential Manager, and in person over
Bluetooth.

OID4VCWallet is the wallet side of [OID4VCgo](https://github.com/IDFoundry/OID4VCgo),
for Android 8.0 (API 26) and later. It handles SD-JWT VC and ISO mdoc
credentials:

- **Receiving** them from a Credential Offer (OpenID4VCI 1.0, HAIP 1.0),
  with the authorization code or the pre-authorized code grant, deferred
  issuance, batches of copies and refresh: [Wallet.startIssuance][dev.idfoundry.oid4vcwallet.Wallet.startIssuance].
- **Presenting** them in answer to an `openid4vp://` request
  (OpenID4VP 1.0, HAIP 1.0): [Wallet.startPresentation][dev.idfoundry.oid4vcwallet.Wallet.startPresentation]; to a page's
  Digital Credentials API request, which Credential Manager hands the
  app: [Wallet.startDCAPIPresentation][dev.idfoundry.oid4vcwallet.Wallet.startDCAPIPresentation]; and in person over Bluetooth
  (ISO/IEC 18013-5): [Wallet.startProximityPresentation][dev.idfoundry.oid4vcwallet.Wallet.startProximityPresentation], where the app
  can also be the reader: [ProximityReader][dev.idfoundry.oid4vcwallet.ProximityReader].

The protocols run in OID4VCgo's Go code, compiled into this library:
every network request, every protocol message and every check on what
comes back. Your app supplies the platform, through three interfaces:
a [KeyStore][dev.idfoundry.oid4vcwallet.KeyStore] whose keys never leave the device's secure hardware
([AndroidKeystoreKeyStore][dev.idfoundry.oid4vcwallet.AndroidKeystoreKeyStore]), a [CredentialStore][dev.idfoundry.oid4vcwallet.CredentialStore] under the device's
protection ([FileCredentialStore][dev.idfoundry.oid4vcwallet.FileCredentialStore]), and a [WalletProvider][dev.idfoundry.oid4vcwallet.WalletProvider] that attests
the wallet. It also owns the UI: every session stops where the holder
needs to decide.

Calls that wait on the network or the holder are `suspend` functions,
cancelled with their coroutine. Failures are [WalletException][dev.idfoundry.oid4vcwallet.WalletException]s, and
in-person ones over Bluetooth [ProximityException][dev.idfoundry.oid4vcwallet.ProximityException]s.

OID4VCgo is OpenID Certified for the OpenID4VCI and OpenID4VP wallet
roles under HAIP, over links. The Digital Credentials API and in-person
presentation aren't covered by that certification.

Start with [the guides](https://github.com/IDFoundry/OID4VCgo-wallet-kotlin/tree/main/docs): getting started, receiving
credentials, presenting from a link, to Chrome and in person, handling
errors, and going to production.

See also [OID4VCgo's mobile README](https://github.com/IDFoundry/OID4VCgo/tree/main/mobile),
for what each platform supports and the in-person guide, and
[the demo wallet app](https://github.com/IDFoundry/OID4VCgo/tree/main/mobile/android/DemoWallet),
a complete app on this library.

# Package dev.idfoundry.oid4vcwallet

The wallet ([Wallet], [WalletConfiguration]), its sessions ([Issuance],
[Presentation], [MdocPresentation], [ProximityPresentation]), the
reader ([ProximityReader]), the platform interfaces and their standard
implementations, and the results they return.
