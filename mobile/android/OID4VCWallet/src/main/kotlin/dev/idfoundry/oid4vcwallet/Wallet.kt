package dev.idfoundry.oid4vcwallet

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
    /** The wallet's registration with Authorization Servers. */
    @SerialName("client_id") val clientID: String,
    @SerialName("redirect_uri") val redirectURI: String,
    /** PEM certificates: the trust anchors for issuers' credentials, and for Verifiers' requests. */
    @SerialName("issuer_roots") val issuerRoots: String = "",
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
    /** Allows services on loopback addresses. */
    val development: Boolean = false,
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
) {
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
    @SerialName("issuer_name") val issuerName: String? = null,
    @SerialName("issuer_logo") val issuerLogo: Logo? = null,
    val name: String? = null,
    val description: String? = null,
    val logo: Logo? = null,
    @SerialName("background_color") val backgroundColor: String? = null,
    @SerialName("text_color") val textColor: String? = null,
)

/**
 * A credential's revocation status in the issuer's status list, as last
 * checked ([Wallet.checkStatus]).
 */
@Serializable
public data class CredentialStatus(
    @SerialName("value") val rawValue: String,
    @SerialName("checked_at") @Serializable(InstantSerializer::class) val checkedAt: Instant,
) {
    public sealed interface Value {
        public data object Valid : Value
        public data object Revoked : Value
        public data object Suspended : Value

        /** A status the issuer's list defines itself, as "0x" and its value. */
        public data class Other(val value: String) : Value
    }

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
    val id: String,
    @SerialName("credential_issuer") val credentialIssuer: String,
    @SerialName("configuration_id") val configurationID: String,
    val format: String,
    val vct: String? = null,
    val doctype: String? = null,
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
    val id: String,
    @SerialName("credential_issuer") val credentialIssuer: String,
    @SerialName("configuration_id") val configurationID: String,
    /** How long the issuer asked the wallet to wait between polls. */
    @SerialName("interval_seconds") val intervalSeconds: Double,
    @SerialName("deferred_at") @Serializable(InstantSerializer::class) val deferredAt: Instant,
    /**
     * When the access token it's polled with expires, if the issuer
     * said: after it, polls fail and it can only be abandoned.
     */
    @SerialName("access_token_expires_at") @Serializable(InstantSerializer::class) val accessTokenExpiresAt: Instant? = null,
)

/** A deferred credential's state, from [Wallet.pollDeferred]. */
public sealed interface DeferredStatus {
    public data class Pending(val intervalSeconds: Double) : DeferredStatus
    public data class Issued(val credential: CredentialSummary) : DeferredStatus
}

/** A credential with its claims, for display. */
public data class CredentialDetail(
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
    public data class Key(val key: String) : PathElement
    public data class Index(val index: Int) : PathElement
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
}

/** What a Credential Offer offers. */
@Serializable
public data class Offer(
    @SerialName("credential_issuer") val credentialIssuer: String,
    @SerialName("issuer_name") val issuerName: String? = null,
    @SerialName("issuer_logo") val issuerLogo: Logo? = null,
    val grant: Grant,
    /** The PIN to ask the holder for, for a pre-authorized code offer. */
    @SerialName("tx_code") val txCode: TxCode? = null,
    val credentials: List<Credential>,
) {
    @Serializable
    public data class TxCode(
        @SerialName("input_mode") val inputMode: String? = null,
        val length: Int? = null,
        val description: String? = null,
    )

    @Serializable
    public data class Credential(
        @SerialName("configuration_id") val configurationID: String,
        val format: String,
        val vct: String? = null,
        val doctype: String? = null,
        /** The issuer's display metadata for it, in the holder's language. */
        val name: String? = null,
        val description: String? = null,
        val logo: Logo? = null,
        @SerialName("background_color") val backgroundColor: String? = null,
        @SerialName("text_color") val textColor: String? = null,
    )

    @Serializable
    public enum class Grant {
        @SerialName("authorization_code") AUTHORIZATION_CODE,
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
    public val offer: Offer = decode(session.offer())

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

    public suspend fun redeemPreAuthorizedCode(pin: String = "") {
        OID4VC.cancellable { op -> session.redeemPreAuthorizedCode(op, pin) }
    }

    @Serializable
    public data class Result(
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
        @SerialName("configuration_id") val configurationID: String,
        @SerialName("code") val rawCode: String,
        @SerialName("detail") val protocolError: String? = null,
    ) {
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
    @Serializable
    public data class Verifier(
        @SerialName("client_id") val clientID: String,
        val name: String,
        @SerialName("response_uri") val responseURI: String,
        /**
         * The Verifier's registration, from its request, checked against
         * [WalletConfiguration.registrarRoots].
         */
        val registration: Registration,
    )

    /**
     * A Verifier's registration with a registrar: who it is and what it
     * may request, as the registrar attests.
     */
    @Serializable
    public data class Registration(
        val status: Status,
        /** The rest are set when [status] is [Status.VERIFIED]. */
        val name: String? = null,
        val purpose: String? = null,
        @SerialName("privacy_policy") val privacyPolicy: String? = null,
        val registrar: String? = null,
        /** The claims paths it's registered to request. */
        val claims: List<List<PathElement>> = emptyList(),
        @Serializable(InstantSerializer::class) val expires: Instant? = null,
    ) {
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
        @SerialName("query_id") val queryID: String,
        /** Whether it takes more than one credential; otherwise a selection gives it exactly one. */
        val multiple: Boolean = false,
        val credentials: List<CredentialSummary> = emptyList(),
        /**
         * For a Verifier with a verified registration: the claims paths
         * this query asks for beyond it, and whether it asks for every
         * claim. Nothing is refused for them: the holder decides.
         */
        val unregistered: List<List<PathElement>> = emptyList(),
        @SerialName("unregistered_all") val unregisteredAll: Boolean = false,
    )

    /**
     * One of the request's sets of alternatives: each option is the
     * query IDs that together answer it, most preferred first. A
     * required set must be answered by one option.
     */
    @Serializable
    public data class CredentialSet(val options: List<List<String>>, val required: Boolean = true)

    @Serializable
    public data class Disclosure(
        @SerialName("query_id") val queryID: String,
        @SerialName("credential_id") val credentialID: String,
        val claims: List<List<PathElement>>,
    )

    @Serializable
    public data class Presented(
        @SerialName("query_ids") val queryIDs: List<String> = emptyList(),
        /** Where to send the browser, when the Verifier asks. */
        @SerialName("redirect_uri") val redirectURI: String? = null,
    )

    @Serializable
    private data class All(
        val queries: List<Query>,
        @SerialName("credential_sets") val credentialSets: List<CredentialSet> = emptyList(),
    )

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
        val documents: List<Document>,
    )

    @Serializable
    public data class Document(
        val doctype: String,
        val elements: List<Element>,
        /** The held mdocs of [doctype]; none when nothing can answer. */
        val credentials: List<CredentialSummary> = emptyList(),
    )

    @Serializable
    public data class Element(
        val namespace: String,
        val identifier: String,
        /** Whether the reader says it will keep the value. */
        val retain: Boolean = false,
    )

    @Serializable
    public data class Response(
        /** The CBOR EncryptedResponse, to hand back to the platform. */
        @Serializable(Base64Serializer::class) val response: ByteArray,
        /** Whether the copy presented had been seen by another Verifier. */
        val linkable: Boolean = false,
    )

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
