package dev.idfoundry.oid4vcwallet

import android.content.Context
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import java.time.Instant
import java.util.Locale
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Issuance as MobileIssuance
import dev.idfoundry.oid4vcwallet.gomobile.mobile.MdocPresentation as MobileMdocPresentation
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Presentation as MobilePresentation
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Wallet as MobileWallet

/** NewWallet's configuration. */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
public data class WalletConfiguration(
    /**
     * The wallet's registration with Authorization Servers: empty for a
     * wallet with no [WalletProvider], receiving credentials only from
     * pre-authorized codes redeemed with no client authentication.
     */
    @SerialName("client_id") val clientID: String = "",
    /**
     * Where the issuer's pages send the holder back to: a private-use URI
     * the app receives. Empty for a wallet that receives only
     * pre-authorized codes.
     */
    @SerialName("redirect_uri") val redirectURI: String = "",
    /** PEM certificates: the trust anchors for issuers' credentials, and for Verifiers' requests. */
    @SerialName("issuer_roots") val issuerRoots: String = "",
    /** PEM certificates: the trust anchors for Verifiers' requests. */
    @SerialName("verifier_roots") val verifierRoots: String = "",
    /**
     * PEM certificates: the registrars whose registrations of Verifiers
     * the wallet checks ([Presentation.Verifier.registration]). Empty:
     * registrations are ignored.
     */
    @SerialName("registrar_roots") val registrarRoots: String = "",
    /**
     * PEM certificates: the mdoc readers recognized when one signs an
     * `org-iso-mdoc` request ([MdocPresentation.Request.reader]). Empty:
     * every such request is shown by its origin.
     */
    @SerialName("mdoc_reader_roots") val mdocReaderRoots: String = "",
    /**
     * Recognizes only reader certificates with the ISO/IEC 18013-5
     * reader authentication extended key usage (1.0.18013.5.1.6), so a
     * certificate issued for another role under [mdocReaderRoots] isn't
     * taken for a reader's.
     */
    @SerialName("mdoc_reader_require_eku") val mdocReaderRequireEKU: Boolean = false,
    /**
     * Refuses an `org-iso-mdoc` request no recognized reader signed:
     * [Wallet.startMdocPresentation] throws `untrustedVerifier`, and
     * nothing is shown to the holder. Needs [mdocReaderRoots].
     */
    @SerialName("require_trusted_mdoc_reader") val requireTrustedMdocReader: Boolean = false,
    /**
     * Refuses an unsigned OpenID4VP request over the Digital Credentials
     * API: [Wallet.startDCAPIPresentation] throws `untrustedVerifier`,
     * before the holder sees it. Its only identity is the origin the
     * platform reports; HAIP requires a wallet to support unsigned
     * requests, so set it only where every Verifier must be one
     * [verifierRoots] accepts.
     */
    @SerialName("require_signed_dcapi_requests") val requireSignedDCAPIRequests: Boolean = false,
    /** Allows services on loopback addresses. */
    val development: Boolean = false,
    /**
     * PEM certificates the wallet's HTTPS requests trust besides the
     * system's: a development service's own CA (Go reads only Android's
     * system CA files, so a CA installed on the device doesn't reach it).
     * Only with [development].
     */
    @SerialName("development_roots") val developmentRoots: String = "",
    /**
     * The holder's preferred languages (BCP 47, most preferred first),
     * for issuers' display metadata. The device's languages are the
     * usual choice, and the default.
     */
    @EncodeDefault val locales: List<String> = defaultLocales(),
    /**
     * How many copies of each credential to request when an issuer
     * offers batches, each bound to its own key, so each presentation
     * can use one no Verifier has seen. 0 means the SDK's default (5);
     * it's capped at the issuer's batch size.
     */
    @SerialName("batch_size") val batchSize: Int = 0,
    /**
     * Asks Authorization Servers for a refresh token, so
     * [Wallet.refreshCredential] can later replace a credential's copies
     * without the holder. The server must allow the wallet the
     * `offline_access` scope, or the authorization fails.
     */
    @SerialName("request_refresh") val requestRefresh: Boolean = false,
    /** Which copy of a credential a presentation uses. */
    @SerialName("copy_policy") val copyPolicy: CopyPolicy = CopyPolicy.PER_PRESENTATION,
    /**
     * Pins hosts' certificates for the wallet's own HTTPS requests:
     * host → base64 SHA-256 digests of a certificate's
     * SubjectPublicKeyInfo, one of which a certificate in the verified
     * chain must have, or the request fails as `tlsPin` before anything
     * is sent. A host is a name, or `*.` and one, matching any name a
     * label below it; not an IP address. Pins add to certificate
     * verification, never replace it: pin a CA's key, so a leaf renewal
     * doesn't break the app, and keep a backup pin. They cover the
     * requests the SDK makes (issuers, Authorization Servers, Verifiers,
     * status lists), not the app's own, such as to its Wallet Provider:
     * pin that client yourself (OkHttp's CertificatePinner, or a network
     * security configuration).
     */
    @SerialName("tls_pins") val tlsPins: Map<String, List<String>> = emptyMap(),
    /** The profile issuance follows. */
    @SerialName("issuance_profile") val issuanceProfile: IssuanceProfile = IssuanceProfile.OPENID4VCI,
) {
    /** The profile issuance follows. */
    @Serializable
    public enum class IssuanceProfile {
        /**
         * The issuer's and its Authorization Server's metadata, as
         * OpenID4VCI 1.0 has a wallet do: a Wallet Attestation and a key
         * attestation only where they ask for them. The default.
         */
        @SerialName("openid4vci") OPENID4VCI,

        /**
         * Also refuses an issuer that doesn't follow HAIP 1.0
         * ([WalletException.Code.profileViolation]). Needs a
         * [WalletProvider] and a `clientID`.
         */
        @SerialName("haip") HAIP,
    }

    /**
     * Which copy of a credential a presentation uses (OpenID4VCI 1.0: "a
     * unique Credential per presentation or per Verifier").
     */
    @Serializable
    public enum class CopyPolicy {
        /**
         * Every presentation uses a copy no Verifier has seen: not even
         * one Verifier can link two presentations. The default.
         */
        @SerialName("per_presentation") PER_PRESENTATION,

        /**
         * A Verifier is shown the copy it has seen before, and only a new
         * Verifier an unused one: Verifiers can't link presentations to
         * each other, but one can recognise a returning holder.
         */
        @SerialName("per_verifier") PER_VERIFIER,
    }

    /** The scheme of [redirectURI]: the scheme the authorization's redirect comes back on. */
    val callbackScheme: String? get() = runCatching { java.net.URI(redirectURI).scheme }.getOrNull()

    /** The configuration's defaults. */
    public companion object {
        /** The device's languages, most preferred first. */
        public fun defaultLocales(): List<String> {
            val list = android.os.LocaleList.getDefault()
            return (0 until list.size()).map { list[it].toLanguageTag() }.ifEmpty { listOf(Locale.getDefault().toLanguageTag()) }
        }
    }
}

/**
 * An image the issuer names for display: an https URL or a data: image
 * (nothing else reaches the app), with alternative text.
 *
 * @property uri The image: an https URL or a `data:` URL.
 * @property altText Text describing the image, for accessibility.
 */
@Serializable
public data class Logo(val uri: String, @SerialName("alt_text") val altText: String? = null)

/**
 * How to show a credential, from the issuer's metadata (OpenID4VCI 1.0
 * §12.2.4) in the holder's language: each part only when the issuer
 * gives it. Colours are CSS colours, such as "#12107c".
 */
@Serializable
public data class CredentialDisplay(
    /** The issuer's name. */
    @SerialName("issuer_name") val issuerName: String? = null,
    /** The issuer's logo. */
    @SerialName("issuer_logo") val issuerLogo: Logo? = null,
    /** The credential's name. */
    val name: String? = null,
    /** A description of the credential. */
    val description: String? = null,
    /** The credential's logo. */
    val logo: Logo? = null,
    /** The card's background colour. */
    @SerialName("background_color") val backgroundColor: String? = null,
    /** The card's text colour. */
    @SerialName("text_color") val textColor: String? = null,
)

/**
 * A credential's revocation status in the issuer's status list, as last
 * checked ([Wallet.checkStatus]).
 */
@Serializable
public data class CredentialStatus(
    /**
     * The status as the issuer's list names it: `valid`, `invalid`, `suspended`, or "0x" and a
     * value of the list's own. [value] reads it.
     */
    @SerialName("value") val rawValue: String,
    /** When it was checked. */
    @SerialName("checked_at") @Serializable(InstantSerializer::class) val checkedAt: Instant,
) {
    /** A status in the issuer's list. */
    public sealed interface Value {
        /** Not revoked or suspended. */
        public data object Valid : Value
        /** Revoked for good (the list's `invalid`). */
        public data object Revoked : Value
        /** Suspended, for now. */
        public data object Suspended : Value

        /**
         * A status the issuer's list defines itself, as "0x" and its value.
         *
         * @property value The status, as "0x" and its value.
         */
        public data class Other(val value: String) : Value
    }

    /** [rawValue], read. */
    val value: Value
        get() = when (rawValue) {
            "valid" -> Value.Valid
            "invalid" -> Value.Revoked
            "suspended" -> Value.Suspended
            else -> Value.Other(rawValue)
        }
}

/** A credential the wallet holds, as the app shows it. */
@Serializable
public data class CredentialSummary(
    /** The credential's ID in the wallet. */
    val id: String,
    /** The issuer's identifier, an https URL. */
    @SerialName("credential_issuer") val credentialIssuer: String,
    /** The issuer's credential configuration it was issued under. */
    @SerialName("configuration_id") val configurationID: String,
    /** Its format: `dc+sd-jwt` or `mso_mdoc`. */
    val format: String,
    /** An SD-JWT VC's type. */
    val vct: String? = null,
    /** An mdoc's document type. */
    val doctype: String? = null,
    /** When the wallet received it. */
    @SerialName("received_at") @Serializable(InstantSerializer::class) val receivedAt: Instant,
    /**
     * Whether the key store still holds the credential's key: without it
     * (restored to another device, say) it can't be presented. Set in
     * [Wallet.credentials] and [Wallet.credential].
     */
    @SerialName("holder_key_present") val holderKeyPresent: Boolean? = null,
    /** How to show it, from the issuer's metadata when it was received. */
    val display: CredentialDisplay? = null,
    /** When it expires, if it says. */
    @SerialName("valid_until") @Serializable(InstantSerializer::class) val validUntil: Instant? = null,
    /** Its revocation status, as last checked; null before any check. */
    val status: CredentialStatus? = null,
    /**
     * How many copies the wallet holds, each bound to its own key, and
     * how many no Verifier has seen. Each presentation uses one of
     * those; once none is left, presentations can be linked.
     */
    val copies: Int = 0,
    /** How many copies no Verifier has seen. */
    @SerialName("copies_left") val copiesLeft: Int = 0,
    /**
     * Whether its issuance kept a refresh token
     * ([WalletConfiguration.requestRefresh]), so
     * [Wallet.refreshCredential] can replace its copies. The
     * Authorization Server may still refuse
     * ([WalletException.Code.reissueRequired]).
     */
    val refreshable: Boolean = false,
    /**
     * Whether a copy has been presented to more than one Verifier, so
     * those Verifiers could link the holder's presentations. Refreshing
     * gives it copies no Verifier has seen.
     */
    val linkable: Boolean = false,
    /**
     * Set only on a presentation's candidates ([Presentation.queries]):
     * whether the Verifier asking has been shown this credential before,
     * and whether presenting it now would hand it a copy another
     * Verifier has seen.
     */
    @SerialName("shown_to_verifier") val shownToVerifier: Boolean? = null,
    /**
     * Whether presenting it to the Verifier asking would hand it a copy
     * another Verifier has seen. Set only on a presentation's candidates.
     */
    @SerialName("linkable_here") val linkableHere: Boolean? = null,
) {
    /** Whether it has expired by [now]. */
    public fun isExpired(now: Instant = Instant.now()): Boolean = validUntil?.let { !it.isAfter(now) } ?: false
}

/**
 * A credential an issuer will issue later (OpenID4VCI 1.0 §9). It's
 * kept in the credential store until it's issued, denied or abandoned,
 * so it survives the app quitting.
 */
@Serializable
public data class DeferredCredential(
    /** The deferred credential's ID, for [Wallet.pollDeferred]. */
    val id: String,
    /** The issuer's identifier, an https URL. */
    @SerialName("credential_issuer") val credentialIssuer: String,
    /** The issuer's credential configuration requested. */
    @SerialName("configuration_id") val configurationID: String,
    /** How long the issuer asked the wallet to wait between polls. */
    @SerialName("interval_seconds") val intervalSeconds: Double,
    /** When the issuer deferred it. */
    @SerialName("deferred_at") @Serializable(InstantSerializer::class) val deferredAt: Instant,
    /**
     * When the access token it's polled with expires, if the issuer
     * said: after it, polls fail and it can only be abandoned.
     */
    @SerialName("access_token_expires_at") @Serializable(InstantSerializer::class) val accessTokenExpiresAt: Instant? = null,
)

/** A deferred credential's state, from [Wallet.pollDeferred]. */
public sealed interface DeferredStatus {
    /**
     * Not issued yet: poll again after [intervalSeconds].
     *
     * @property intervalSeconds How long to wait before polling again, in seconds.
     */
    public data class Pending(val intervalSeconds: Double) : DeferredStatus
    /**
     * Issued, and stored: [credential].
     *
     * @property credential The credential, now stored.
     */
    public data class Issued(val credential: CredentialSummary) : DeferredStatus
}

/** A credential with its claims, for display. */
public data class CredentialDetail(
    /** The credential. */
    val summary: CredentialSummary,
    /**
     * An SD-JWT VC's claims, or an mdoc's namespace → element → value;
     * byte strings (a portrait) are base64.
     */
    val claims: JsonElement,
)

/** One claim path element: a key, an array index, or every element. */
@Serializable(PathElementSerializer::class)
public sealed interface PathElement {
    /**
     * A claim name: [key].
     *
     * @property key The claim's name.
     */
    public data class Key(val key: String) : PathElement
    /**
     * An array element: [index].
     *
     * @property index The element's index.
     */
    public data class Index(val index: Int) : PathElement
    /** Every element of an array. */
    public data object All : PathElement
}

/**
 * A holder's wallet: OID4VCgo's walletflow over the app's key store,
 * credential store and Wallet Provider. Creating it makes no network
 * calls; [provider] is needed to receive credentials, not to present
 * them.
 */
public class Wallet(
    configuration: WalletConfiguration,
    keyStore: KeyStore,
    credentialStore: CredentialStore,
    provider: WalletProvider?,
) {
    private val handle: MobileWallet

    // Go holds these too; the wallet keeps them alive with it.
    private val adapters: List<Any>

    init {
        if (OID4VC.abiVersion != OID4VC.expectedABIVersion) {
            throw WalletException(
                WalletException.Code.internal, null,
                "the linked Go library has ABI ${OID4VC.abiVersion}, these sources ABI ${OID4VC.expectedABIVersion}: rebuild it",
            )
        }
        val keys = KeyStoreAdapter(keyStore)
        val credentials = CredentialStoreAdapter(credentialStore)
        val wp = provider?.let(::WalletProviderAdapter)
        val config = json.encodeToString(WalletConfiguration.serializer(), configuration)
        handle = OID4VC.wrap { Mobile.newWallet(config, keys, credentials, wp) }
        adapters = listOfNotNull(keys, credentials, wp)
    }

    /**
     * Deletes every key in [keyStore] that none of the wallet's
     * credentials is bound to — left by an issuance the app quit or
     * crashed in the middle of, or one dropped without [Issuance.close]
     * — and returns how many. Call it at launch, before any issuance or
     * refresh: one in progress holds keys of its own.
     */
    public suspend fun sweepOrphanedKeys(keyStore: AndroidKeystoreKeyStore): Int {
        val keep = decode<KeyIDsResult>(OID4VC.offMain { handle.holderKeyIDs() }).keyIDs.toSet()
        return OID4VC.offMain { keyStore.deleteKeys(keep) }
    }

    /** Every credential the wallet holds. */
    public suspend fun credentials(): List<CredentialSummary> {
        return decode<CredentialsResult>(OID4VC.offMain { handle.credentials() }).credentials
    }

    /** One credential with its claims. */
    public suspend fun credential(id: String): CredentialDetail {
        val text = OID4VC.offMain { handle.credential(id) }
        val summary = decode<CredentialSummary>(text)
        val claims = decode<JsonObject>(text)["claims"] ?: JsonNull
        return CredentialDetail(summary, claims)
    }

    /**
     * Fetches the issuer's status list for a credential, checks its
     * signature, and returns the credential with its revocation status
     * recorded. The list covers many credentials, so fetching it
     * doesn't tell the issuer which one is checked. A credential without
     * a status list is returned as it is.
     */
    public suspend fun checkStatus(id: String): CredentialSummary =
        decode(OID4VC.cancellable { op -> handle.checkStatus(op, id) })

    /** What [refreshCredential] obtained. */
    @Serializable
    public data class Refreshed(
        /**
         * The credential, its ID unchanged: with every copy unused, or as
         * it was when the issuer deferred the new one.
         */
        val credential: CredentialSummary,
        /** The deferred credential to poll, when the issuer deferred it: it settles as a new credential. */
        val deferred: DeferredCredential? = null,
    )

    /**
     * Replaces a `refreshable` credential's copies with a fresh batch,
     * each bound to a new attested key, without the holder (OpenID4VCI
     * 1.0 §13.5). Use it when `copiesLeft` runs low. Throws
     * [WalletException.Code.reissueRequired] when it can't be refreshed:
     * receive it again from a new offer.
     */
    public suspend fun refreshCredential(id: String): Refreshed =
        decode(OID4VC.cancellable { op -> handle.refreshCredential(op, id) })

    /**
     * Deletes a credential and its holder keys, and its refresh grant
     * once no other credential uses it, first revoking the refresh token
     * at the Authorization Server, best effort.
     */
    public suspend fun deleteCredential(id: String) {
        OID4VC.offMain { handle.deleteCredential(id) }
    }

    /**
     * The credentials issuers have deferred and not yet settled, oldest
     * first — including ones from before the app last quit. Makes no
     * network calls: poll each at its interval.
     */
    public suspend fun deferredCredentials(): List<DeferredCredential> {
        return decode<DeferredResult>(OID4VC.offMain { handle.deferred() }).deferred
    }

    /**
     * Asks the issuer once about a deferred credential. A refused one
     * throws [WalletException.Code.credentialDenied], and is then no
     * longer pending.
     */
    public suspend fun pollDeferred(id: String): DeferredStatus {
        val s = decode<PollResult>(OID4VC.cancellable { op -> handle.pollDeferred(op, id) })
        if (s.status == Mobile.DeferredIssued && s.credential != null) return DeferredStatus.Issued(s.credential)
        return DeferredStatus.Pending(s.intervalSeconds)
    }

    /**
     * Gives up on a deferred credential — its access token has expired,
     * say, or the holder no longer wants it — deleting it and its keys.
     */
    public suspend fun abandonDeferred(id: String) {
        OID4VC.offMain { handle.abandonDeferred(id) }
    }

    /** Resolves a Credential Offer (openid-credential-offer://…) and the issuer's metadata. */
    public suspend fun startIssuance(offer: String): Issuance =
        Issuance(OID4VC.cancellable { op -> handle.startIssuance(op, offer) })

    /**
     * Completes an authorization begun before the app was killed:
     * [redirect] is the issuer's redirect back to the redirect URI,
     * delivered to the app. Returns the issuance ready for
     * [Issuance.requestCredentials]. A redirect matching no
     * authorization in progress — not this wallet's, already completed,
     * or expired — throws [WalletException.Code.notFound].
     */
    public suspend fun resumeIssuance(redirect: String): Issuance =
        Issuance(OID4VC.cancellable { op -> handle.resumeIssuance(op, redirect) })

    /**
     * Fetches and verifies an OpenID4VP request (openid4vp://…), and
     * finds the credentials that can answer it.
     */
    public suspend fun startPresentation(request: String): Presentation =
        Presentation(OID4VC.cancellable { op -> handle.startPresentation(op, request) })

    /**
     * Parses an OpenID4VP request delivered through the Digital
     * Credentials API (OpenID4VP 1.0 Appendix A), as Credential Manager
     * hands it over: [protocol] (`openid4vp-v1-unsigned`, `-signed` or
     * `-multisigned`), its [requestData] (the request's `data` object, as
     * JSON) and the calling page's or app's [origin]. It's answered as a
     * presentation from [startPresentation], but [Presentation.respond]
     * and [Presentation.decline] send nothing: each returns, in
     * [Presentation.Presented.dcapiResponse], the response's data for the
     * platform to hand back.
     */
    public suspend fun startDCAPIPresentation(protocol: String, requestData: ByteArray, origin: String): Presentation =
        Presentation(OID4VC.cancellable { op -> handle.startDCAPIPresentation(op, protocol, requestData, origin) })

    /**
     * The held mdocs, each with whether the page at [origin] has been
     * shown it and whether presenting it there now would be linkable
     * (`shownToVerifier`, `linkableHere`): for a consent screen shown
     * before the platform releases the request itself.
     * [MdocPresentation.request] says the same once it has.
     */
    public suspend fun mdocCandidates(origin: String): List<CredentialSummary> {
        return decode<CredentialsResult>(OID4VC.offMain { handle.mdocCandidates(origin) }).credentials
    }

    /**
     * Parses an `org-iso-mdoc` request — an mdoc asked for over the
     * Digital Credentials API — and finds the held mdocs that can answer
     * it. [origin] is the requesting page's origin, as
     * [MdocPresentation.origin] serializes it.
     */
    public suspend fun startMdocPresentation(requestData: ByteArray, origin: String): MdocPresentation =
        MdocPresentation(OID4VC.cancellable { op -> handle.startMdocPresentation(op, requestData, origin) })

    /**
     * Starts an ISO/IEC 18013-5 in-person presentation over BLE: show
     * its [ProximityPresentation.qrCode]; it advertises until a reader
     * connects. It needs Bluetooth on and [ProximityPermissions.holder]
     * granted ([ProximityException] otherwise).
     */
    public fun startProximityPresentation(context: Context, timeouts: ProximityTimeouts = ProximityTimeouts()): ProximityPresentation {
        ProximityPermissions.require(context, ProximityPermissions.holder)
        val app = context.applicationContext
        return ProximityPresentation(OID4VC.wrap { handle.startProximityPresentation() }, { uuid ->
            GattServerTransport(app, uuid, GattCharacteristics.peripheralServer)
        }, timeouts)
    }

    internal fun startProximityPresentation(timeouts: ProximityTimeouts, transport: ProximityTransport): ProximityPresentation =
        ProximityPresentation(OID4VC.wrap { handle.startProximityPresentation() }, { transport }, timeouts)
}

/** What a Credential Offer offers. */
@Serializable
public data class Offer(
    /** The issuer's identifier, an https URL. */
    @SerialName("credential_issuer") val credentialIssuer: String,
    /** The issuer's name, in the holder's language. */
    @SerialName("issuer_name") val issuerName: String? = null,
    /** The issuer's logo. */
    @SerialName("issuer_logo") val issuerLogo: Logo? = null,
    /** The grant the offer names. */
    val grant: Grant,
    /** The PIN to ask the holder for, for a pre-authorized code offer. */
    @SerialName("tx_code") val txCode: TxCode? = null,
    /** The offered credentials. */
    val credentials: List<Credential>,
) {
    /** The PIN a pre-authorized code offer asks for, as the issuer describes it. */
    @Serializable
    public data class TxCode(
        /** `numeric` or `text`, if the issuer says. */
        @SerialName("input_mode") val inputMode: String? = null,
        /** How many characters it has, if the issuer says. */
        val length: Int? = null,
        /** The issuer's description, to show the holder: where to find the PIN, say. */
        val description: String? = null,
    )

    /** One offered credential. */
    @Serializable
    public data class Credential(
        /** The issuer's credential configuration. */
        @SerialName("configuration_id") val configurationID: String,
        /** Its format: `dc+sd-jwt` or `mso_mdoc`. */
        val format: String,
        /** An SD-JWT VC's type. */
        val vct: String? = null,
        /** An mdoc's document type. */
        val doctype: String? = null,
        /** The issuer's display metadata for it, in the holder's language. */
        val name: String? = null,
        /** The issuer's description of it. */
        val description: String? = null,
        /** Its logo. */
        val logo: Logo? = null,
        /** The card's background colour. */
        @SerialName("background_color") val backgroundColor: String? = null,
        /** The card's text colour. */
        @SerialName("text_color") val textColor: String? = null,
    )

    /** How the holder is authorized. */
    @Serializable
    public enum class Grant {
        /** The holder signs in at the issuer's pages, in a browser. */
        @SerialName("authorization_code") AUTHORIZATION_CODE,

        /** The issuer has already authenticated the holder, and may ask for a PIN ([Offer.txCode]). */
        @SerialName("pre-authorized_code") PRE_AUTHORIZED_CODE,
    }
}

/**
 * Receives one offer's credentials: show [offer]; then
 * [beginAuthorization], open the URL in an Auth Tab or Custom Tab and
 * [completeAuthorization], or [redeemPreAuthorizedCode]; then
 * [requestCredentials]; [close] when done. An issuance dropped without
 * [close] leaves its keys until [Wallet.sweepOrphanedKeys].
 */
public class Issuance internal constructor(private val session: MobileIssuance) {
    /** What's offered: show it before going on. */
    public val offer: Offer = decode(session.offer())

    /**
     * Begins the authorization code grant, returning the issuer's authorization URL to open in an
     * Auth Tab or Custom Tab. Calling it again begins again: after the holder closed the page,
     * say.
     */
    public suspend fun beginAuthorization(): String = OID4VC.cancellable { op -> session.beginAuthorization(op) }

    /**
     * Completes the authorization with the issuer's redirect back. The
     * redirect is used up whatever happens: if this fails — the token
     * request didn't get through, say — call [beginAuthorization] again,
     * rather than retrying this.
     */
    public suspend fun completeAuthorization(redirect: String) {
        OID4VC.cancellable { op -> session.completeAuthorization(op, redirect) }
    }

    /**
     * Redeems a pre-authorized code offer, with the PIN the holder typed when [Offer.txCode] asks
     * for one. A wrong PIN throws a retryable `protocol` error (`invalid_grant`): ask again.
     */
    public suspend fun redeemPreAuthorizedCode(pin: String = "") {
        OID4VC.cancellable { op -> session.redeemPreAuthorizedCode(op, pin) }
    }

    /** What [Issuance.requestCredentials] obtained. */
    @Serializable
    public data class Result(
        /** The credentials received and stored. */
        val credentials: List<CredentialSummary>,
        /**
         * Credentials the issuer will issue later: poll them with
         * [Wallet.pollDeferred], after [close] and relaunches too.
         */
        val deferred: List<DeferredCredential>,
        /**
         * Credentials the issuer refused for good, or that failed the
         * wallet's checks: they don't hold up the rest.
         */
        val failed: List<FailedCredential> = emptyList(),
    )

    /**
     * An offered credential that couldn't be obtained: its error's code
     * and, when the issuer gave one, its OAuth error code.
     */
    @Serializable
    public data class FailedCredential(
        /** The offered credential's configuration. */
        @SerialName("configuration_id") val configurationID: String,
        /** Why it failed, as the Go side names it: [code] reads it. */
        @SerialName("code") val rawCode: String,
        /** The issuer's OAuth error code, when it gave one. */
        @SerialName("detail") val protocolError: String? = null,
    ) {
        /** Why it failed. */
        val code: WalletException.Code get() = WalletException.Code(rawCode)
    }

    /** Requests, checks and stores every offered credential. */
    public suspend fun requestCredentials(): Result = decode(OID4VC.cancellable { op -> session.requestCredentials(op) })

    /** Ends the issuance, deleting its keys but those its deferred credentials still poll with. */
    public suspend fun close() {
        OID4VC.offMain { session.close() }
    }
}

/**
 * Answers one OpenID4VP request: show [verifier], [queries] and
 * [credentialSets], choose a selection (or start from
 * [defaultSelection]), [preview] it, then [respond] or [decline]. The
 * wallet presents exactly the selection, after checking it answers the
 * request ([WalletException.Code.invalidSelection] otherwise).
 */
public class Presentation internal constructor(private val handle: MobilePresentation) {
    /** Who is asking. */
    @Serializable
    public data class Verifier(
        /**
         * The Verifier's client ID; "" for an unsigned Digital Credentials API request, whose only
         * identity is its origin.
         */
        @SerialName("client_id") val clientID: String = "",
        /** A name to show for the Verifier. */
        val name: String = "",
        /**
         * Where the response is sent; "" for a Digital Credentials API request, answered through
         * the platform.
         */
        @SerialName("response_uri") val responseURI: String = "",
        /**
         * The Verifier's registration, from its request, checked against
         * [WalletConfiguration.registrarRoots].
         */
        val registration: Registration,
        /**
         * For a Digital Credentials API request ([Wallet.startDCAPIPresentation]),
         * the calling page's or app's origin: all that names the Verifier
         * of an unsigned request, which has no [clientID] or [name].
         */
        val origin: String? = null,
    )

    /**
     * A Verifier's registration with a registrar: who it is and what it
     * may request, as the registrar attests.
     */
    @Serializable
    public data class Registration(
        /** Whether the registration verified. */
        val status: Status,
        /** The rest are set when [status] is [Status.VERIFIED]. */
        val name: String? = null,
        /** Why it asks, as registered. */
        val purpose: String? = null,
        /** Its privacy policy's URL. */
        @SerialName("privacy_policy") val privacyPolicy: String? = null,
        /** The registrar that registered it. */
        val registrar: String? = null,
        /** The claims paths it's registered to request. */
        val claims: List<List<PathElement>> = emptyList(),
        /** When the registration expires. */
        @Serializable(InstantSerializer::class) val expires: Instant? = null,
    ) {
        /** Whether a registration verified. */
        @Serializable
        public enum class Status {
            /** A registrar the wallet trusts registered this Verifier. */
            @SerialName("verified") VERIFIED,

            /** The request carries a registration that didn't verify: it isn't relied on. */
            @SerialName("invalid") INVALID,

            /** No registration, or no registrar roots to check one. */
            @SerialName("none") NONE,
        }
    }

    /**
     * One of the request's credential queries, with the credentials
     * that can answer it: none when nothing held can.
     */
    @Serializable
    public data class Query(
        /** The query's ID: a key in a [Selection]. */
        @SerialName("query_id") val queryID: String,
        /** Whether it takes more than one credential; otherwise a selection gives it exactly one. */
        val multiple: Boolean = false,
        /** The held credentials that can answer it. */
        val credentials: List<CredentialSummary> = emptyList(),
        /**
         * For a Verifier with a verified registration: the claims paths
         * this query asks for beyond it, and whether it asks for every
         * claim. Nothing is refused for them: the holder decides.
         */
        val unregistered: List<List<PathElement>> = emptyList(),
        /** Whether it asks for every claim, beyond a verified registration. */
        @SerialName("unregistered_all") val unregisteredAll: Boolean = false,
    )

    /**
     * One of the request's sets of alternatives: each option is the
     * query IDs that together answer it, most preferred first. A
     * required set must be answered by one option.
     *
     * @property options Each option's query IDs, most preferred first.
     * @property required Whether one of the options must be answered.
     */
    @Serializable
    public data class CredentialSet(val options: List<List<String>>, val required: Boolean = true)

    /** What a selection would disclose from one credential. */
    @Serializable
    public data class Disclosure(
        /** The query it answers. */
        @SerialName("query_id") val queryID: String,
        /** The credential. */
        @SerialName("credential_id") val credentialID: String,
        /** The claims it would disclose, as paths. */
        val claims: List<List<PathElement>>,
    )

    /** What responding or declining sent. */
    @Serializable
    public data class Presented(
        /** The queries answered. */
        @SerialName("query_ids") val queryIDs: List<String> = emptyList(),
        /** Where to send the browser, when the Verifier asks. */
        @SerialName("redirect_uri") val redirectURI: String? = null,
        /**
         * For a Digital Credentials API request, the response's data — a
         * JSON object, `{"response": …}` — to hand back to the platform:
         * nothing was sent.
         */
        @SerialName("dcapi_response") val dcapiResponse: String? = null,
    )

    @Serializable
    private data class All(
        val queries: List<Query>,
        @SerialName("credential_sets") val credentialSets: List<CredentialSet> = emptyList(),
    )

    /** Who is asking. */
    public val verifier: Verifier = decode(handle.verifier())
    private val all: All = decode(handle.queries())

    /** The request's credential queries, in its order. */
    public val queries: List<Query> = all.queries

    /** The request's sets of alternatives; none means every query must be answered. */
    public val credentialSets: List<CredentialSet> = all.credentialSets

    /** Whether some credential can answer some query: if not, decline. */
    public val isAnswerable: Boolean get() = queries.any { it.credentials.isNotEmpty() }

    /**
     * The selection the wallet would make itself, for an app with no
     * policy of its own, or to start from: the first answerable option
     * of each credential set, and each query's first credential (all of
     * them when it takes several). Throws `noMatchingCredential` when
     * the request can't be answered.
     */
    public suspend fun defaultSelection(): Selection {
        return decode<SelectionResult>(OID4VC.offMain { handle.defaultSelection() }).selection
    }

    /** What responding with [selection] would disclose, without signing or sending anything. */
    public suspend fun preview(selection: Selection): List<Disclosure> {
        val text = selectionJSON(selection)
        return decode<DisclosuresResult>(OID4VC.offMain { handle.preview(text) }).disclosures
    }

    /**
     * Presents exactly [selection]: holder keys sign now, so a key store
     * requiring the holder prompts.
     */
    public suspend fun respond(selection: Selection): Presented {
        val text = selectionJSON(selection)
        return decode(OID4VC.cancellable { op -> handle.respond(op, text) })
    }

    /** Tells the Verifier the holder declined. */
    public suspend fun decline(): Presented = decode(OID4VC.cancellable { op -> handle.decline(op) })

    private fun selectionJSON(selection: Selection): String =
        json.encodeToString(MapSerializer(String.serializer(), ListSerializer(String.serializer())), selection)
}

/** What to present: for each query ID, the IDs of the credentials chosen to answer it. */
public typealias Selection = Map<String, List<String>>

/**
 * An `org-iso-mdoc` request (ISO/IEC TS 18013-7 Annex C): show
 * [request] for the holder's consent, then [respond] once; to decline,
 * cancel the platform's request — nothing is sent to the reader.
 */
public class MdocPresentation internal constructor(private val handle: MobileMdocPresentation) {
    /** What the page asks for. */
    @Serializable
    public data class Request(
        /** The requesting page's origin. */
        val origin: String,
        /**
         * The subject common name of the reader that signed the request,
         * when its certificate chains to
         * [WalletConfiguration.mdocReaderRoots]; "" when the holder can
         * only be shown [origin].
         */
        val reader: String = "",
        /** The requested documents, in the request's order. */
        val documents: List<Document>,
    )

    /** One requested document. */
    @Serializable
    public data class Document(
        /** Its document type. */
        val doctype: String,
        /** The elements requested. */
        val elements: List<Element>,
        /** The held mdocs of [doctype]; none when nothing can answer. */
        val credentials: List<CredentialSummary> = emptyList(),
    )

    /** One requested element. */
    @Serializable
    public data class Element(
        /** Its namespace. */
        val namespace: String,
        /** Its identifier in the namespace. */
        val identifier: String,
        /** Whether the reader says it will keep the value. */
        val retain: Boolean = false,
    )

    /** The answer to hand back to the platform. */
    @Serializable
    public data class Response(
        /** The CBOR EncryptedResponse, to hand back to the platform. */
        @Serializable(Base64Serializer::class) val response: ByteArray,
        /** Whether the copy presented had been seen by another Verifier. */
        val linkable: Boolean = false,
    )

    /** What's asked: show it for the holder's consent. */
    public val request: Request = decode(handle.request())

    /**
     * Presents the held mdoc [credentialID] for document number
     * [document], disclosing exactly [elements], each one it requested.
     * The holder key signs now, so a key store requiring the holder
     * prompts.
     */
    public suspend fun respond(document: Int, credentialID: String, elements: List<Element>): Response {
        val pairs = json.encodeToString(ListSerializer(ListSerializer(String.serializer())), elements.map { listOf(it.namespace, it.identifier) })
        return decode(OID4VC.cancellable { op -> handle.respond(op, document.toLong(), credentialID, pairs) })
    }

    /** Origins, as the platform reports them. */
    public companion object {
        /**
         * [url]'s web origin, as a browser serializes it and the session
         * transcript binds it: `scheme://host`, with the port only when it
         * isn't the scheme's default, and no path — the form
         * [Wallet.startMdocPresentation] takes.
         */
        public fun origin(url: String): String? {
            val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return null
            val scheme = uri.scheme?.lowercase() ?: return null
            val host = uri.host?.lowercase()
            if (host.isNullOrEmpty()) return null
            val defaultPort = mapOf("https" to 443, "http" to 80)[scheme]
            return if (uri.port < 0 || uri.port == defaultPort) "$scheme://$host" else "$scheme://$host:${uri.port}"
        }
    }
}

/** A credential store in memory, for tests and development. */
public class InMemoryCredentialStore : CredentialStore {
    private val stored = LinkedHashMap<String, ByteArray>()

    @Synchronized override fun put(id: String, record: ByteArray) {
        stored.remove(id)
        stored[id] = record
    }

    @Synchronized override fun record(id: String): ByteArray? = stored[id]

    @Synchronized override fun records(): List<ByteArray> = stored.values.toList()

    @Synchronized override fun delete(id: String) {
        stored.remove(id)
    }
}

// The Go side's JSON results' envelopes.

@Serializable
private data class KeyIDsResult(@SerialName("key_ids") val keyIDs: List<String>)

@Serializable
private data class CredentialsResult(val credentials: List<CredentialSummary>)

@Serializable
private data class DeferredResult(val deferred: List<DeferredCredential>)

@Serializable
private data class PollResult(
    val status: String,
    val credential: CredentialSummary? = null,
    @SerialName("interval_seconds") val intervalSeconds: Double = 0.0,
)

@Serializable
private data class SelectionResult(val selection: Map<String, List<String>>)

@Serializable
private data class DisclosuresResult(val disclosures: List<Presentation.Disclosure>)
