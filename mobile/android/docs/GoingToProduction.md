# Going to production

What a wallet needs before real holders use it.

A wallet holding real credentials is only as trustworthy as the
platform it runs on. The library enforces some of this itself: without
`WalletConfiguration.development`, receiving credentials needs a key
store and a credential store that both say they're durable, and
services on loopback addresses are refused. The rest is the app's.

## Keys and storage

- Keep `AndroidKeystoreKeyStore`'s defaults: keys in StrongBox where the
  device has it, else the TEE, usable only while the device is unlocked,
  and holder keys asking for the holder's fingerprint or screen lock
  each time they sign, through `BiometricPromptAuthenticator`. That
  needs Android 11 (API 30) and a secure lock screen.
- Decide where the holder is asked. A holder key signs when presenting,
  and the Credential Request's jwt proof when receiving or refreshing.
  With `AndroidKeystoreKeyStore.Options.holderUserAuthentication` on,
  the default, Keystore enforces the check, but receiving a credential
  asks once per copy (`WalletConfiguration.batchSize`), or once when the
  jwt proof carries a key attestation (again if the issuer refuses the
  nonce), and a refresh asks too, so it
  can't run in the background. Turned off, as the demo app does (and
  as below API 30 it must be), holder keys sign without asking, and the
  app must ask the holder itself (`BiometricPrompt`) before every
  presentation: in the app and from a link, through Credential Manager
  (the Digital Credentials API), and in person over QR, BLE or NFC. A
  path that doesn't ask presents without the holder: the check is the
  app's code, not the key.
- Use `FileCredentialStore`: each record encrypted under a Keystore key
  that works only while the device is unlocked, out of backups. The key
  is in the TEE unless `Options.strongBox` asks for StrongBox, which is
  several times slower on every record read and write;
  `keySecurityLevel()` says where it is, to check or log.
  `InMemoryCredentialStore` is for tests.
- Call `Wallet.sweepOrphanedKeys` at launch, before any issuance, so keys
  an interrupted issuance left don't accumulate.
- Make one `Wallet` per key store and credential store in each process,
  and share it for the app's life. Wallets in other processes over the
  same stores coordinate through `CredentialStore.compareAndSwap`: no
  two present the same copy as unused, complete the same authorization,
  or redeem the same refresh token. A refresh while another process
  refreshes with the same refresh token throws `unavailable` with the
  detail `refresh_in_progress`: try again later. The keys an issuance or
  refresh in progress holds are known only to its own Wallet, so sweep
  orphaned keys only while no other Wallet over the stores is receiving
  or refreshing.
- A device restored from a backup, or a new one the app moved to, has no
  holder keys: its credentials show `holderKeyPresent` as false and
  can't be presented. Delete them, and receive them again.

## The Wallet Provider

Issuers trust the wallet because its Wallet Provider attests it: a Key
Attestation's `key_storage` and `user_authentication` tell an issuer
the holder keys can't be copied off the device, and it binds
credentials to them on that word. A provider that attests whatever keys
it's sent lets a modified app, or an emulator, get credentials bound to
software keys anyone can copy. Play Integrity attests the app, not where
its keys live: it doesn't stand in for Key Attestation.

So the provider checks Android Key Attestation of each key before
attesting it:

1. **Give a challenge.** Implement `WalletProvider.attestationChallenge`:
   for `KeyPurpose.INSTANCE` and `KeyPurpose.HOLDER`, fetch a fresh,
   random, single-use challenge from your backend, which remembers it
   with an expiry: at least 16 random bytes (the library takes 1 to
   128). For `KeyPurpose.DPOP`, return null.
   `AndroidKeystoreKeyStore` makes each key over its challenge,
   so Android Keystore certifies the key, the challenge and the app
   that made it.
2. **Receive the evidence.** Implement the `WalletAttestationRequest`
   and `KeyAttestationRequest` versions of `walletAttestation` and
   `keyAttestation`, and send each key's `KeyEvidence` —
   `certificateChain`, DER, the key's certificate first — to your
   backend with its JWK.
3. **Verify the chain, on the backend.** Refuse a key whose chain is
   empty. Otherwise:
   - each certificate is signed by the next, all are within their
     validity, and the last is one of Google's hardware attestation
     roots;
   - no certificate in it is revoked or suspended in Google's
     attestation status list;
   - the first certificate's public key is the JWK being attested;
   - its key description extension (OID 1.3.6.1.4.1.11129.2.1.17)
     has the challenge you issued for this key, unused and unexpired,
     which you then consume;
   - its attestation and KeyMint security levels are
     `TrustedEnvironment` or `StrongBox`, never `Software`;
   - its hardware-enforced list has origin `GENERATED`, an EC P-256 key
     for signing, and a root of trust with `verifiedBootState`
     `Verified` and `deviceLocked` true;
   - its `attestationApplicationId` names your app's package and
     signing certificate digest.
4. **Attest only what you verified.** Claim `key_storage` and
   `user_authentication` levels the attestation supports — StrongBox
   or the TEE; user authentication only for a holder key whose
   hardware-enforced list requires it (`AndroidKeystoreKeyStore`'s
   `holderUserAuthentication`) — and never more.
5. **Keep your own signing key in an HSM,** and sign attestations with
   a certificate made for that alone: no extended key usage for TLS,
   OCSP, code signing or an mdoc role. Put that certificate and its
   intermediates in each attestation's `x5c`, never the root (HAIP 1.0
   §4.4.1): issuers on FAPIgo refuse an attestation that breaks either
   rule (`invalid_client`).

### A backend built with OID4VCgo

OID4VCgo's `walletprovider` package is such a backend:
`walletprovider/androidkey` makes the checks of step 3, and its
`Policy` the claims of step 4. `HttpWalletProvider` is its client, so
steps 1 and 2 need no code of your own (see
[Getting started](GettingStarted.md)). It speaks the package's HTTP
protocol, version 1
([WALLET_PROVIDER.md](https://github.com/IDFoundry/OID4VCgo/blob/main/mobile/WALLET_PROVIDER.md)):

- The installation registers once, at its first Wallet Attestation,
  with a *registration key* made over a `registration` challenge and
  sent with its chain. The key stays in Android Keystore under an alias
  prefix of its own (`HttpWalletProvider.registrationKeyStore()`), apart
  from the wallet's keys, so `Wallet.sweepOrphanedKeys` never deletes
  it; don't give the wallet's `AndroidKeystoreKeyStore` a prefix that
  covers `HttpWalletProvider.REGISTRATION_KEY_ALIAS_PREFIX`. The
  registration — the instance ID and the key's ID — is kept in an
  `InstanceRegistry`: `FileInstanceRegistry.standard(context)`, out of
  backups, since an instance ID is useless without its key. If either
  is lost, the next Wallet Attestation registers again, with a new key.
- Every request after registration is signed with the registration key.
- Each issuance's instance key is made over an `instance` challenge.
  Its first Wallet Attestation sends its chain; the provider records the
  key for the installation, and later ones — when a refresh needs a new
  Wallet Attestation — send the key alone.
- The holder keys of one issuance share a `holder` challenge, which
  their Key Attestation uses up. The Key Attestation names the
  issuance's instance key, so the provider gives it that key's status.
- It sends nothing but to the provider's `https` URL, follows no
  redirect, and checks each attestation is for what it asked: the
  client and instance key, the nonce and the keys sent.

Its failures reach the wallet as `WalletException`s. A provider that
can't be reached or answers HTTP 5xx or 429, or a challenge that expired
before it was used, is `network`: try again. A refusal is `platform`,
its `message` naming the protocol's error code (`evidence_rejected`,
`policy_refused`, `unknown_instance_key`, `instance_revoked`, …). On
`instance_revoked` the registration is forgotten and its key deleted:
the next issuance registers the installation again. The revoked
instance's instance keys stay its own (`instance_key_registered`), so a
credential whose refresh needs one must be received again; so must one
whose instance key was recorded by a registration the app lost. On
`instance_not_active` the instance is suspended: tell the holder, since
the provider may resume it. `invalid_signed_request` is not retried: the
device's clock may be wrong, or the provider no longer knows the
instance.

A key is attested once, when it's made, over that moment's challenge. A
key attested again later — the instance key, when a refresh needs a new
Wallet Attestation — brings the same chain: recognise a key you verified
before (by its JWK thumbprint) rather than asking for a fresh challenge.

Each issuance has an instance key of its own, and a Key Attestation
names it: `KeyAttestationRequest.instanceKey`, the key that issuance's
`walletAttestation` asked for first. Refuse one you didn't attest for
this installation, and give the Key Attestation that instance key's
status list entry, so suspending or revoking the installation withdraws
its Key Attestations along with its Wallet Attestations (the Wallet
Provider protocol's `instance_key`).

A custom `KeyStore` gives the provider no evidence unless it implements
`createKey(purpose, attestationChallenge)` and `attestationChain(id)`:
keep `AndroidKeystoreKeyStore`. The demo wallet's provider (the
passport-vdc demo's) checks a chain's signatures, key and challenge,
but accepts an emulator's software attestation unless told not to,
attests a key sent without a chain, and reads none of the key's
authorizations: it is for development only.

## Trust

- Configure only your ecosystem's roots: `issuerRoots` for credentials,
  `verifierRoots` for the Verifiers the wallet answers, and
  `registrarRoots` only for registrars, never for Verifiers or issuers,
  which could then register themselves.
- For readers, `mdocReaderRoots` with `mdocReaderRequireEKU`, and
  `requireTrustedMdocReader` where every reader must be a known one.
- Never ship with `development` set, or `developmentRoots`. A `Wallet`
  or `ProximityReader` refuses a `development` configuration
  (`invalid_input`) unless the app called `OID4VC.allowDevelopment()`:
  call it only from a debuggable build
  (`if (BuildConfig.DEBUG) OID4VC.allowDevelopment()`), so a staging
  configuration shipped by mistake fails instead of relaxing
  production's checks.
- To pin your services' certificates, set `tlsPins`: host → base64
  SHA-256 digests of a certificate's SubjectPublicKeyInfo. Pin a CA's
  key, so a leaf renewal doesn't break the app, and keep a backup pin:
  a wrong set locks the wallet out of that host until an update. Pins
  cover the SDK's own requests, not your app's, such as to your Wallet
  Provider: pin that client yourself (OkHttp's `CertificatePinner`, or
  a network security configuration).
- To refuse certificates your ecosystem's CAs have revoked, list the
  roles to check in `revocation` and give their CAs' CRLs (PEM
  `X509 CRL` blocks) in `crls`. A role listed fails closed for any CA it
  has no current CRL from, so list only roles whose CAs publish CRLs.
  Every role whose roots you set must be in `revocation` or in
  `noRevocationCheck`, which declines checking it, or the wallet isn't
  made (`invalidInput`): decline only where something else stands in
  for revocation, such as certificates too short-lived to be worth
  revoking. `issuerRoots` and the mdoc roots bring two roles, `ISSUER`
  and `STATUS` (the status lists' signers). CRLs expire at their nextUpdate: fetch fresh ones in the background
  and hand them over with `Wallet.setCRLs`, which replaces them all
  (empty text removes them) and throws `invalidInput`, keeping the old
  lists, for anything that isn't a CRL. A certificate pinned in the
  roots, such as a Verifier's leaf in `verifierRoots`, is checked
  against its CA's CRL: give that CA's certificate in `crlIssuers`, or
  it's refused. A `ProximityReader` takes the same, for its document
  signers and status lists. `Wallet.refreshCRLs` can do the fetching:
  see [Keeping revocation lists current](#keeping-revocation-lists-current).
- As a Credential Manager provider, see the open caveat in
  [Presenting to Chrome](PresentingToChrome.md).

### Keeping revocation lists current

Rather than fetching CRLs yourself, name the distribution points in
`crlDistributionPoints`, each with the certificate of the CA whose list
it serves, or set `crlDistributionPointsFromRoots` to fetch the points
your roots' self-signed CAs (IACAs, say) name for their own lists.
`Wallet.refreshCRLs` then fetches each one, keeps every list its CA
signed that is current and not older than the one held, and returns a
`CRLRefreshResult`: each point's outcome, every list now held as `crls`,
and `nextRefresh`. A failed point keeps its list, so a refresh never
makes things worse. Fetches go to public addresses only (outside
`development`), over `http` or `https`: CRLs are signed, so
distribution points are usually plain `http`; `crlRequireHTTPS` refuses
those, where your CAs serve `https`. A `ProximityReader` has the same
`refreshCRLs`.

The library schedules nothing and depends on no scheduler. Refresh when
the app starts, when it comes to the foreground once the last result's
`nextRefresh` has passed (not at every foreground: a fleet of devices
adds up), and in the background with WorkManager, and keep `crls` to pass back as `WalletConfiguration.crls`
at the next launch, so checks work before the first refresh and an
older list is still refused after a restart:

```kotlin
import dev.idfoundry.oid4vcwallet.CRLRefreshResult
import dev.idfoundry.oid4vcwallet.Wallet
import java.io.File
import java.time.Duration
import java.time.Instant

/** The lists kept last time, for `WalletConfiguration.crls`. */
fun savedCRLs(file: File): String = if (file.exists()) file.readText() else ""

/**
 * One refresh: keeps the lists for the next launch and returns how long
 * to wait before the next one. A failure is retried in 15 minutes.
 */
suspend fun refreshAndKeepCRLs(wallet: Wallet, file: File): Duration {
    val result: CRLRefreshResult = try {
        wallet.refreshCRLs()
    } catch (e: dev.idfoundry.oid4vcwallet.WalletException) {
        return Duration.ofMinutes(15)
    }
    val temp = File(file.parentFile, file.name + ".tmp")
    temp.writeText(result.crls)
    temp.renameTo(file)
    return Duration.between(Instant.now(), result.nextRefresh).coerceAtLeast(Duration.ofMinutes(1))
}
```

In the background, a `CoroutineWorker` (add `androidx.work:work-runtime-ktx`
to your app; the library doesn't depend on it) runs that and enqueues
the next run at the delay it returns. WorkManager runs it when the
system allows, often later, and needs a network connection:

```
class CRLRefreshWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val app = applicationContext as MyApp
        val delay = refreshAndKeepCRLs(app.wallet, app.crlFile)
        schedule(applicationContext, delay)
        return Result.success()
    }

    companion object {
        fun schedule(context: Context, delay: Duration) {
            val request = OneTimeWorkRequestBuilder<CRLRefreshWorker>()
                .setInitialDelay(delay)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork("crl-refresh", ExistingWorkPolicy.REPLACE, request)
        }
    }
}
```

At the foreground, in `ProcessLifecycleOwner`'s `onStart`, call
`refreshAndKeepCRLs` from the app's scope when the delay it last
returned has run out (keep the `Instant` it pointed to), and schedule
the worker with its result. A list that does pass its nextUpdate unrefreshed fails its
role's checks closed until a fresh one arrives.

### Settings to decide

Each of these is off or open by default. Decide each for your
ecosystem, and record why:

- `issuanceProfile`: `IssuanceProfile.HAIP` refuses issuers that don't
  follow HAIP 1.0 (`profileViolation`); it needs a `WalletProvider` and
  `clientID`. Set it where every issuer should be a HAIP one.
- Signed issuer metadata: `issuerMetadataRoots` asks for and verifies
  it; `requireSignedIssuerMetadata` refuses an issuer without it before
  the holder signs in or enters a code; `requireIssuerMetadataName`
  refuses metadata whose certificate doesn't name the issuer;
  `maxIssuerMetadataAgeSeconds` bounds its age; and
  `issuerMetadataRequireEKU` its signer's extended key usage. Set them
  together where your issuers sign their metadata.
- `requireIssuerName`: refuses an SD-JWT VC whose `iss` its signing
  certificate doesn't name. Set it where `issuerRoots` certify several
  issuers, so one can't issue in another's name.
- `allowForeignIss`: receives an SD-JWT VC whose `iss` isn't the issuer
  it came from. Leave it off unless an issuer names itself differently,
  and `issuerRoots` certify it alone.
- `statusIssuers`: the Status Issuers that may sign an issuer's status
  lists for it. Without it, only the issuer's own lists are accepted:
  add only delegations your ecosystem publishes.
- `statusMaxBytes` and `identifierListMaxBytes`: the largest status list
  (1 MiB) and identifier list (4 MiB) `checkStatus` reads. A larger
  list fails every check of the credentials on it: raise them only for
  issuers whose lists are larger.
- `statusCacheDir`: a directory of the app's own, under
  `context.cacheDir`, where `checkStatus` keeps the lists it verified
  across launches. Each launch then revalidates a kept list with its
  server (a `304 Not Modified`) instead of downloading it again, which
  matters for lists of millions of entries; a list the server doesn't
  confirm is never used.
- `mdocIssuerRoots` and `mdocIssuerRootsByDocType`: the IACAs mdocs, or
  each document type, must chain to, instead of `issuerRoots`, so an
  SD-JWT VC issuer's CA can't sign an mDL. `mdocIssuerRequireEKU`
  requires document signers' extended key usage (the mDL's is
  1.0.18013.5.1.2).
- `proximityDeviceAuth`: `MAC_PREFERRED` answers readers with deviceMac,
  which the reader can't show anyone else; it needs
  `holderKeyAgreement`. `SIGNATURE`, the default, signs.
- For a `ProximityReader`: `issuerRootsByDocType` confines each document
  type to its own IACAs, and `requireMDLSignerEKU` accepts only document
  signers with the mDL document signer extended key usage.

## Privacy

- Request batches of copies (`batchSize`) and refresh them as they're
  used up (`requestRefresh`), so presentations stay unlinkable; warn the
  holder when one wouldn't be (`linkableHere`).
- Log `WalletException.message`, never claims, credentials or QR codes.
- Set `FLAG_SECURE` on windows that show credentials, so the recents
  thumbnail and screenshots show no claims or portraits.
- Fetch an issuer's `Logo` once, when the holder accepts the credential,
  and keep it: loading it on the offer's preview tells whoever serves it
  that the offer was opened.

## The build

- Ship the release AAR, which carries the release build of the Go
  library. Refuse to run on the test build, which carries an in-process
  issuer and Verifier: check `OID4VC.isTestBuild` at launch.
- Check the AAR you ship: the release's `SHA256SUMS`, and its provenance
  with `gh attestation verify`.
- The AAR carries its own R8 rules (`consumer-rules.pro`), which keep the
  Go library's bindings. A minified build hasn't been tested as widely
  as a debug one: test yours.
