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
and add it with the libraries it uses, which the README lists:

```
dependencies {
    implementation(files("libs/oid4vcwallet-<version>.aar"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:…")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:…")
    implementation("androidx.annotation:annotation:…")
}
```

The AAR goes in an app module, and holds the Go library for arm64 and
x86_64 (the emulator). It needs Android 8.0 (API 26); holder keys that
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
a credential is bound to — signs only when presenting, and by default
asks for the holder's fingerprint or screen lock first, through a
`HolderAuthenticator`: `BiometricPromptAuthenticator` shows the
system's prompt over the activity you give it. The device needs a
secure lock screen.

`FileCredentialStore` encrypts each credential under a Keystore key that
works only while the device is unlocked, in a directory no backup
copies: a credential is useless without its holder key, which can't
leave this device.

## Implement the Wallet Provider

Issuers following HAIP accept only a wallet its Wallet Provider has
attested: a Wallet Attestation for the wallet's instance key, and a Key
Attestation for the keys a credential will be bound to. Your backend
issues them; the app passes the keys and returns its answers. A real
Wallet Provider attests only after checking evidence — Android Key
Attestation of the keys, or Play Integrity — that it's talking to your
genuine app.

```kotlin
import android.app.Activity
import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import dev.idfoundry.oid4vcwallet.AndroidKeystoreKeyStore
import dev.idfoundry.oid4vcwallet.BiometricPromptAuthenticator
import dev.idfoundry.oid4vcwallet.FileCredentialStore
import dev.idfoundry.oid4vcwallet.Wallet
import dev.idfoundry.oid4vcwallet.WalletConfiguration
import dev.idfoundry.oid4vcwallet.WalletProvider
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * Asks the app's backend for attestations. The keys are public JWKs, as
 * JSON; the answers are compact JWTs.
 */
class BackendWalletProvider(private val backend: String) : WalletProvider {
    override suspend fun walletAttestation(clientID: String, instanceKey: ByteArray): String =
        post("wallet-attestation", JSONObject()
            .put("client_id", clientID)
            .put("instance_key", JSONObject(instanceKey.decodeToString())))

    override suspend fun keyAttestation(keys: List<ByteArray>, nonce: String): String =
        post("key-attestation", JSONObject()
            .put("keys", JSONArray(keys.map { JSONObject(it.decodeToString()) }))
            .put("nonce", nonce))

    private suspend fun post(path: String, body: JSONObject): String = withContext(Dispatchers.IO) {
        val connection = URL("$backend/$path").openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.use { it.write(body.toString().toByteArray()) }
            check(connection.responseCode == 200) { "the Wallet Provider answered ${connection.responseCode}" }
            connection.inputStream.use { it.readBytes().decodeToString() }
        } finally {
            connection.disconnect()
        }
    }
}
```

An `IOException` the provider throws reaches the wallet as a retryable
`network` error; any other is `platform`.

## Create the wallet

Create one `Wallet` when the app starts — in your `Application`, say —
and keep it. Creating it makes no network requests. At launch, before
anything else, sweep the Keystore of keys no credential uses: an
issuance the app quit in the middle of leaves its keys behind.

```kotlin
/** The app's wallet, created once. `currentActivity` is the activity the holder sees, for the biometric prompt. */
@RequiresApi(Build.VERSION_CODES.R)
class AppWallet(context: Context, currentActivity: () -> Activity?, issuerRoots: String, verifierRoots: String) {
    private val keys = AndroidKeystoreKeyStore(authenticator = BiometricPromptAuthenticator(currentActivity))

    val wallet = Wallet(
        WalletConfiguration(
            clientID = "https://wallet.example.com",
            redirectURI = "com.example.wallet:/callback",
            issuerRoots = issuerRoots,
            verifierRoots = verifierRoots,
        ),
        keys,
        FileCredentialStore.standard(context),
        BackendWalletProvider("https://provider.example.com"),
    )

    /** Run once at launch, before any issuance. */
    suspend fun start() {
        wallet.sweepOrphanedKeys(keys)
    }
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
- [Presenting in person](PresentingInPerson.md)
- [Handling errors](HandlingErrors.md)
- [Going to production](GoingToProduction.md)

Every class and function is in [the API reference](https://idfoundry.github.io/OID4VCgo-wallet-kotlin/latest/).
