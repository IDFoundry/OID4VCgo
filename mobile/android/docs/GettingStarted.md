# Getting started

Add the library, give the wallet its keys, its storage and a Wallet
Provider, and create it when the app starts.

A `Wallet` needs four things from your app: its configuration, a
`KeyStore` for its keys, a `CredentialStore` for what it holds, and a
`WalletProvider` that attests it to issuers. The library has standard
stores for the first two; the Wallet Provider is your backend.

## Add the library

Download `oid4vcwallet-<version>.aar` from a
[release](https://github.com/IDFoundry/OID4VCgo-wallet-kotlin/releases)
into your app module's `libs/`, check it (the release's `SHA256SUMS`,
and `gh attestation verify oid4vcwallet-<version>.aar --repo IDFoundry/OID4VCgo`),
and add it with the libraries it uses, at the versions the release's
README lists (its POM's dependencies):

```
dependencies {
    implementation(files("libs/oid4vcwallet-<version>.aar"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:…")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:…")
    implementation("androidx.annotation:annotation:…")
    implementation("androidx.credentials:credentials:…")
    implementation("androidx.credentials.registry:registry-provider:…")
    implementation("androidx.credentials.registry:registry-provider-play-services:…")
    implementation("androidx.credentials.registry:registry-digitalcredentials-openid:…")
    implementation("androidx.credentials.registry:registry-digitalcredentials-mdoc:…")
    implementation("androidx.credentials.registry:registry-digitalcredentials-sdjwtvc:…")
}
```

The AAR goes in an app module, and holds the Go library for every
Android ABI: arm64-v8a, armeabi-v7a, x86_64 and x86 (the emulator), each
linked for 16 KB memory pages. It needs Android 8.0 (API 26); holder keys that
ask for the holder's fingerprint or screen lock each time need Android
11 (API 30).

## Register the wallet

Issuers' Authorization Servers know the wallet as an OAuth client: a
client ID, and a redirect URI the browser returns the holder to. Use a
private-use scheme for it, and declare it in an intent filter on the
activity that receives the redirect.

The wallet trusts only what chains to the roots you give it, as PEM
certificates: `issuerRoots` for credentials, and `verifierRoots` for the
Verifiers it answers. A Credential Offer's issuer isn't trusted just
because it sent the offer.

## Provide the keys and the storage

`AndroidKeystoreKeyStore` keeps every key in Android Keystore: in
StrongBox where the device has it, else the TEE. A holder key — the one
a credential copy is bound to — signs when presenting, and the
Credential Request's proof when receiving or refreshing. By default it
asks for the holder's fingerprint or screen lock each time, through a
`HolderAuthenticator`: `BiometricPromptAuthenticator` shows the
system's prompt over the activity you give it. The device needs a
secure lock screen. [Going to production](GoingToProduction.md)
describes the trade-off.

`FileCredentialStore` encrypts each credential under a Keystore key that
works only while the device is unlocked, in a directory no backup
copies. The key is in the TEE; `Options.strongBox` puts it in StrongBox
where the device has it, falling back to the TEE. StrongBox makes every
record read and write several times slower, which shows when the wallet
lists credentials. A credential is useless without its holder key,
which can't leave this device. Its writes lock a file in that
directory, so processes of the app that share it — a credential
provider service in its own process, say — never both use one copy.
A `CredentialStore` of your own implements `compareAndSwap` atomically
across them too. A record the store can't read is left out of the
wallet's credentials.
`unreadableRecordIDs()` names the damaged ones, which can't be
recovered: delete each and have the holder receive that credential
again. `unsupportedRecordIDs()` names those a newer version of the app
wrote: keep them, since an update reads them.

## Connect the Wallet Provider

Issuers following HAIP accept only a wallet its Wallet Provider has
attested: a Wallet Attestation for the wallet's instance key, and a Key
Attestation for the keys a credential will be bound to. Your backend
issues them, after checking Android Key Attestation that each key is in
this device's secure hardware, made by your app.

With a backend built on OID4VCgo's `walletprovider` package, the wallet
needs no provider code of your own: `HttpWalletProvider` speaks its
protocol
([WALLET_PROVIDER.md](https://github.com/IDFoundry/OID4VCgo/blob/main/mobile/WALLET_PROVIDER.md)),
registering the installation once, with a registration key of its own,
and sending each instance and holder key's attestation chain. Give it
the URL the protocol is mounted at and a registry for its registration;
it keeps the registration key in Android Keystore, apart from the
wallet's keys:

```kotlin
import android.app.Activity
import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import dev.idfoundry.oid4vcwallet.AndroidKeystoreKeyStore
import dev.idfoundry.oid4vcwallet.BiometricPromptAuthenticator
import dev.idfoundry.oid4vcwallet.FileCredentialStore
import dev.idfoundry.oid4vcwallet.FileInstanceRegistry
import dev.idfoundry.oid4vcwallet.HttpWalletProvider
import dev.idfoundry.oid4vcwallet.Wallet
import dev.idfoundry.oid4vcwallet.WalletConfiguration

/** The Wallet Provider: OID4VCgo's `walletprovider`, mounted at /wp. */
fun oid4vcgoWalletProvider(context: Context): HttpWalletProvider =
    HttpWalletProvider("https://provider.example.com/wp", FileInstanceRegistry.standard(context))
```

It sends nothing but to that https URL, follows no redirect, times out
each connection and read, and checks each answer is for what it asked
before the wallet uses it. Its failures reach the wallet as a
retryable `network` error when the network or the provider's
availability caused them (HTTP 5xx and 429 among them), and as
`platform` when the provider refused.
[Going to production](GoingToProduction.md#the-wallet-provider) lists
what the backend checks.

### If your backend isn't OID4VCgo's walletprovider

Implement `WalletProvider` yourself, and make the checks
`HttpWalletProvider` makes:

- **Evidence:** `attestationChallenge` returns a fresh challenge from
  your backend for each instance and holder key (null for DPoP keys);
  `AndroidKeystoreKeyStore` makes the key over it, and the key reaches
  `walletAttestation` or `keyAttestation` as `KeyEvidence`. Send each
  key's `certificateChain`, and a Key Attestation's
  `KeyAttestationRequest.instanceKey`, to your backend, which verifies
  the chain as [Going to production](GoingToProduction.md#the-wallet-provider)
  lists before attesting.
- **Transport:** send only to your backend's https URL, with
  `instanceFollowRedirects = false`, a connect and a read timeout, and a
  bounded read of the answer.
- **Answers:** before returning a Wallet Attestation, check its `sub`
  is the request's `clientID` and its `cnf.jwk` the instance key;
  before returning a Key Attestation, check its `nonce` is the
  request's (absent when that's empty) and its `attested_keys` holds
  only keys you sent. The issuer verifies their signatures.
- **Errors:** throw an `IOException` for what's worth retrying — no
  connection, a timeout, HTTP 5xx or 429 — which reaches the wallet as
  a retryable `network` error. Any other exception reaches it as
  `platform`: throw a refusal as one.

## Create the wallet

Create one `Wallet` when the app starts — in your `Application`, say —
and keep it. Creating it makes no network requests. At launch, before
anything else, sweep the Keystore of keys no credential uses: an
issuance the app quit in the middle of leaves its keys behind. Each
trust role whose roots you set needs a revocation choice: checked against
the CRLs your app fetches (`revocation`), or declined
(`noRevocationCheck`); see [Going to production](GoingToProduction.md).

```kotlin
/** The app's wallet, created once. `currentActivity` is the activity the holder sees, for the biometric prompt. */
@RequiresApi(Build.VERSION_CODES.R)
class AppWallet(context: Context, currentActivity: () -> Activity?, issuerRoots: String, verifierRoots: String, crls: String) {
    private val keys = AndroidKeystoreKeyStore(authenticator = BiometricPromptAuthenticator(currentActivity))
    private val provider = oid4vcgoWalletProvider(context)

    val wallet = Wallet(
        WalletConfiguration(
            clientID = "https://wallet.example.com",
            redirectURI = "com.example.wallet:/callback",
            issuerRoots = issuerRoots,
            verifierRoots = verifierRoots,
            crls = crls,
            revocation = listOf(
                WalletConfiguration.RevocationRole.ISSUER,
                WalletConfiguration.RevocationRole.STATUS,
                WalletConfiguration.RevocationRole.VERIFIER,
            ),
        ),
        keys,
        FileCredentialStore.standard(context),
        provider,
    )

    /** Run once at launch, before any issuance. */
    suspend fun start() {
        wallet.sweepOrphanedKeys(keys)
        provider.sweepOrphanedRegistrationKeys()
    }
}
```

`AndroidKeystoreKeyStore`'s default options need Android 11 (API 30),
and it throws on API 26–29 rather than make holder keys that don't ask
for the holder. On a `minSdk` below 30, give it
`Options.forDevice()`: unchanged from API 30, and without per-use
holder authentication below it, where your app then asks for the
holder itself — `BiometricPrompt`, or the keyguard — before every
presentation, receipt and refresh.

```kotlin
/** The key store on any supported API level: below 30, the app authenticates the holder itself. */
fun appKeyStore(currentActivity: () -> Activity?): AndroidKeystoreKeyStore {
    val options = AndroidKeystoreKeyStore.Options.forDevice()
    val authenticator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) BiometricPromptAuthenticator(currentActivity) else null
    return AndroidKeystoreKeyStore(options, authenticator)
}
```

## Ship the release build

The release AAR carries the release build of the Go library. OID4VCgo's
own tests use a test build with an in-process issuer and Verifier that a
shipped app must never have; `OID4VC.isTestBuild` says which one an app
has, so it can refuse to run on the test build.

## Next

- [Receiving credentials](ReceivingCredentials.md)
- [Presenting from a link](PresentingFromALink.md)
- [Presenting to Chrome](PresentingToChrome.md)
- [Presenting in person](PresentingInPerson.md): QR code, NFC tap, or both
- [Handling errors](HandlingErrors.md)
- [Going to production](GoingToProduction.md)
- [Integration checklist](IntegrationChecklist.md): every step and rule in
  one list, for a developer or a coding assistant to follow and check

Every class and function is in [the API reference](https://idfoundry.github.io/OID4VCgo-wallet-kotlin/latest/).
