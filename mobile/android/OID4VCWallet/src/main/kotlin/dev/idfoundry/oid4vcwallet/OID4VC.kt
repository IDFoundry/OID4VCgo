package dev.idfoundry.oid4vcwallet

import dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Operation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * An error from OID4VCgo: a stable [code], the issuer's, Authorization
 * Server's or Verifier's own error code when it gave one
 * ([protocolError]), and a [message] for logs: it never carries personal
 * data, a remote party's own description, a URL's path or query, or
 * control characters. [description] is a sentence fit to show the
 * holder; [isRetryable] says whether trying the same step again may
 * succeed.
 */
public class WalletException internal constructor(
    public val code: Code,
    public val protocolError: String?,
    message: String,
) : Exception(message) {
    /** An error code, as the Go side names it. */
    @JvmInline
    public value class Code(public val rawValue: String) {
        override fun toString(): String = rawValue

        public companion object {
            public val invalidInput: Code = Code(Mobile.CodeInvalidInput)
            public val platform: Code = Code(Mobile.CodePlatform)
            public val network: Code = Code(Mobile.CodeNetwork)
            public val unavailable: Code = Code(Mobile.CodeUnavailable)
            public val cancelled: Code = Code(Mobile.CodeCancelled)
            public val notFound: Code = Code(Mobile.CodeNotFound)
            public val wrongStep: Code = Code(Mobile.CodeWrongStep)
            public val authorizationDenied: Code = Code(Mobile.CodeAuthorizationDenied)
            public val credentialDenied: Code = Code(Mobile.CodeCredentialDenied)
            public val noMatchingCredential: Code = Code(Mobile.CodeNoMatchingCredential)

            /**
             * A presentation's selection doesn't answer the request as it
             * asks: an unknown query or credential, one that doesn't answer
             * its query, more than one for a query that takes one, or a
             * required credential set left unanswered.
             */
            public val invalidSelection: Code = Code(Mobile.CodeInvalidSelection)

            /**
             * A credential can't be refreshed: no refresh token was kept, or
             * the Authorization Server no longer accepts it. Receive it again
             * from a new offer.
             */
            public val reissueRequired: Code = Code(Mobile.CodeReissueRequired)

            /**
             * Sending a presentation failed in a way that leaves it unknown
             * whether the Verifier received it: it's not sent again.
             */
            public val deliveryUnknown: Code = Code(Mobile.CodeDeliveryUnknown)

            /**
             * The Verifier's request is signed with a certificate that
             * doesn't chain to `verifierRoots`: it's refused unread.
             */
            public val untrustedVerifier: Code = Code(Mobile.CodeUntrustedVerifier)
            public val protocol: Code = Code(Mobile.CodeProtocol)
            public val internal: Code = Code(Mobile.CodeInternal)
        }
    }

    override val message: String get() = super.message ?: ""

    override fun toString(): String =
        protocolError?.let { "[${code.rawValue}:$it] $message" } ?: "[${code.rawValue}] $message"

    /**
     * Whether the same step may succeed if tried again: the network
     * failed or timed out, the service was unavailable, the issuer
     * refused the PIN (`invalid_grant`, up to its limit) or a stale
     * nonce (`invalid_nonce`: a retry fetches a fresh one), or asked to
     * be tried later.
     */
    public val isRetryable: Boolean
        get() = when (code) {
            Code.network, Code.unavailable -> true
            Code.protocol -> protocolError in setOf("invalid_grant", "invalid_nonce", "temporarily_unavailable", "slow_down")
            else -> false
        }

    /** A sentence fit to show the holder. */
    public val description: String
        get() = when {
            code == Code.network -> "The service couldn't be reached. Check your connection and try again."
            code == Code.unavailable -> "The service is unavailable just now. Try again later."
            code == Code.cancelled -> "Cancelled."
            code == Code.authorizationDenied -> "The issuer didn't authorize the request."
            code == Code.credentialDenied -> "The issuer declined to issue the credential."
            code == Code.noMatchingCredential -> "You have no credential that answers this request."
            code == Code.invalidSelection -> "Those credentials don't answer this request."
            code == Code.reissueRequired -> "This credential can't be refreshed. Receive it again from the issuer."
            code == Code.deliveryUnknown -> "Your response may not have reached the verifier. Check with them before sharing again."
            code == Code.untrustedVerifier -> "This verifier isn't one your wallet trusts, so its request wasn't opened."
            code == Code.protocol && protocolError == "invalid_grant" -> "That code or PIN wasn't accepted."
            code == Code.protocol -> "The service refused the request."
            code == Code.platform -> "The wallet couldn't use its keys or storage."
            code == Code.invalidInput -> "That link or code isn't valid."
            code == Code.notFound -> "That credential is no longer in the wallet."
            code == Code.wrongStep -> "That step isn't available now."
            else -> "Something went wrong."
        }

    internal companion object {
        /**
         * Parses an error crossing the boundary: its text is "[code]
         * message" or "[code:detail] message".
         */
        fun from(error: Throwable): WalletException {
            if (error is WalletException) return error
            val text = error.message ?: ""
            val close = text.indexOf(']')
            if (!text.startsWith("[") || close < 0) return WalletException(Code.internal, null, text)
            val tag = text.substring(1, close)
            val message = text.substring(close + 1).trim()
            val colon = tag.indexOf(':')
            return if (colon >= 0) {
                WalletException(Code(tag.substring(0, colon)), tag.substring(colon + 1), message)
            } else {
                WalletException(Code(tag), null, message)
            }
        }
    }
}

/** An OpenID4VP request link's parts. */
@Serializable
public data class RequestLink(
    @SerialName("client_id") val clientID: String,
    @SerialName("request_uri") val requestURI: String,
    @SerialName("request_uri_method") val requestURIMethod: String? = null,
)

/**
 * OID4VCgo's mobile API. Every call runs off the caller's thread: Go
 * calls block, and must never run on the main thread.
 */
public object OID4VC {
    /** The ABI version of the Go side this library was built against. */
    public val abiVersion: Int = Mobile.ABIVersion.toInt()

    /**
     * The ABI version these Kotlin sources were written for. A wallet
     * isn't made on a Go library of another — a stale build, or the Go
     * side changed without these sources — rather than misreading its
     * JSON. The Go tests keep it equal to the mobile package's.
     */
    public const val expectedABIVersion: Int = 12

    /**
     * Whether the linked Go library is the test build, carrying an
     * in-process test issuer and Verifier (`-tags mobiletest`): an app
     * should refuse to run on it.
     */
    public val isTestBuild: Boolean = Mobile.isTestBuild()

    public suspend fun parseRequestLink(link: String): RequestLink =
        decode(offMain { Mobile.parseRequestLink(link) })

    /**
     * Exercises [keyStore] as the wallet will — for each purpose: create
     * a key, sign with it, look it up, delete it — and returns the
     * purposes checked. A store asking for user presence on holder keys
     * prompts once.
     */
    public suspend fun checkKeyStore(keyStore: KeyStore): List<KeyPurpose> {
        val adapter = KeyStoreAdapter(keyStore)
        val report = decode<KeyStoreReport>(offMain { Mobile.checkKeyStore(adapter) })
        return report.checked.mapNotNull(KeyPurpose::fromRawValue)
    }

    /**
     * Runs [body] with an Operation, off the caller's thread; cancelling
     * the calling coroutine cancels the Operation, so the Go call returns
     * at once, and the coroutine ends with its CancellationException.
     */
    internal suspend fun <T> cancellable(body: (Operation) -> T): T {
        val op = Mobile.newOperation(0)
        return coroutineScope {
            val call = async(Dispatchers.IO) {
                try {
                    wrap { body(op) }
                } catch (e: WalletException) {
                    // Go's answer to the cancel below: the coroutine's own
                    // cancellation, not an error of the call's.
                    if (e.code == WalletException.Code.cancelled && !isActive) throw CancellationException(e.message)
                    throw e
                }
            }
            try {
                call.await()
            } catch (e: CancellationException) {
                op.cancel()
                throw e
            }
        }
    }

    /** Runs [body] off the caller's thread, turning its error into a WalletException. */
    internal suspend fun <T> offMain(body: () -> T): T = withContext(Dispatchers.IO) { wrap(body) }

    /** Runs a gomobile call, turning its error into a WalletException. */
    internal inline fun <T> wrap(body: () -> T): T =
        try {
            body()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw WalletException.from(e)
        }
}

/** CheckKeyStore's result. */
@Serializable
internal data class KeyStoreReport(val checked: List<String>)

internal val json = Json { ignoreUnknownKeys = true }

/** Decodes one of the Go side's JSON results. */
internal inline fun <reified T> decode(text: String): T =
    try {
        json.decodeFromString<T>(text)
    } catch (e: kotlinx.serialization.SerializationException) {
        // Only where: the decoder's own text can quote a value, a claim.
        throw WalletException(WalletException.Code.internal, null, "malformed result from the Go side")
    } catch (e: IllegalArgumentException) {
        throw WalletException(WalletException.Code.internal, null, "malformed result from the Go side")
    }
