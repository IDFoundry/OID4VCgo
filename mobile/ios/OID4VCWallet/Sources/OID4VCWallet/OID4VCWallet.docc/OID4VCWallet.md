# ``OID4VCWallet``

Receive verifiable credentials and present them from an iOS app: over
OpenID4VCI and OpenID4VP under HAIP, to Safari's Digital Credentials
API, and in person over Bluetooth.

## Overview

OID4VCWallet is the wallet side of [OID4VCgo](https://github.com/IDFoundry/OID4VCgo),
for iOS 16 and macOS 13 and later. It handles SD-JWT VC and ISO mdoc
credentials:

- **Receiving** them from a Credential Offer (OpenID4VCI 1.0, HAIP 1.0),
  with the authorization code or the pre-authorized code grant, deferred
  issuance, batches of copies and refresh.
- **Presenting** them in answer to an `openid4vp://` request
  (OpenID4VP 1.0, HAIP 1.0), to Safari's Digital Credentials API as an
  iOS document provider (`org-iso-mdoc`, ISO/IEC TS 18013-7), and in
  person over Bluetooth (ISO/IEC 18013-5), where the app can also be the
  reader.

The protocols run in OID4VCgo's Go code, compiled into the `Mobile`
framework this package links: every network request, every protocol
message and every check on what comes back. Your app supplies the
platform, through three protocols: a ``KeyStore`` whose keys never leave
the Secure Enclave, a ``CredentialStore`` under the device's data
protection, and a ``WalletProvider`` that attests the wallet. It also
owns the UI: every session stops where the holder needs to decide.

OID4VCgo is OpenID Certified for the OpenID4VCI and OpenID4VP wallet
roles under HAIP, over links. The Digital Credentials API and in-person
presentation aren't covered by that certification.

Start with <doc:GettingStarted>, then the article for each task.

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:HandlingErrors>
- <doc:GoingToProduction>
- ``Wallet``
- ``WalletConfiguration``
- ``WalletProvider``

### Keys and storage

- ``KeyStore``
- ``KeychainKeyStore``
- ``KeyPurpose``
- ``CredentialStore``
- ``FileCredentialStore``
- ``InMemoryCredentialStore``
- ``StoreError``

### Receiving credentials

- <doc:ReceivingCredentials>
- ``Issuance``
- ``Offer``
- ``DeferredCredential``
- ``DeferredStatus``

### Holding credentials

- ``CredentialSummary``
- ``CredentialDetail``
- ``CredentialDisplay``
- ``CredentialStatus``
- ``Logo``
- ``JSONValue``

### Presenting from a link

- <doc:PresentingFromALink>
- ``Presentation``
- ``RequestLink``

### Presenting to Safari

- <doc:PresentingToSafari>
- ``MdocPresentation``

### Presenting in person

- <doc:PresentingInPerson>
- ``ProximityPresentation``
- ``ProximityReaderIdentity``
- ``ProximityTimeouts``
- ``ProximityError``

### Reading in person

- ``ProximityReader``
- ``ProximityReaderConfiguration``
- ``ProximityReaderSession``
- ``VerifiedMdoc``

### Errors and the framework

- ``WalletError``
- ``OID4VC``
