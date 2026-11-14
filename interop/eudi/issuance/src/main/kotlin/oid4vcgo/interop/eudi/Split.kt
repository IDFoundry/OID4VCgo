package oid4vcgo.interop.eudi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.util.Base64

/** A Status List entry an issued SD-JWT VC references, and the instance that issued it. */
data class IssuedStatus(
    val instance: String?,
    val uri: String,
    val idx: Long,
)

/**
 * The two-instance profile's split: two instances of the issuer behind
 * interop/splitproxy, sharing one PostgreSQL database. [routes] is the
 * instance each path goes to; a request whose DPoP proof carries no
 * nonce goes to the other one, which answers with a DPoP nonce
 * challenge, so the retry carries a nonce the route's instance didn't
 * issue. What the cases see of it is checked after each.
 */
class Split(
    val routes: Map<String, String>,
) {
    /** The paths at which one instance accepted a DPoP nonce the other had issued. */
    val crossed = sortedSetOf<String>()

    /** Every SD-JWT VC's status entry, and who issued it. */
    val issued = mutableListOf<IssuedStatus>()

    /** The instance [path] goes to, if a route names it. */
    fun routeOf(path: String): String? = routes.entries.filter { path == it.key || path.startsWith(it.key.trimEnd('/') + "/") }.maxByOrNull { it.key.length }?.value

    /** Records the status entries of [credentials], SD-JWT VCs issued by [instance]. */
    fun recordIssued(
        instance: String?,
        credentials: List<String>,
    ) {
        for (c in credentials) {
            val payload = c.substringBefore('~').split('.').getOrNull(1) ?: continue
            val list =
                runCatching {
                    Json
                        .parseToJsonElement(String(Base64.getUrlDecoder().decode(payload)))
                        .jsonObject
                        .getValue("status")
                        .jsonObject
                        .getValue("status_list")
                        .jsonObject
                }.getOrNull() ?: continue
            issued += IssuedStatus(instance, list.getValue("uri").jsonPrimitive.content, list.getValue("idx").jsonPrimitive.long)
        }
    }
}

/** Is [e] a DPoP nonce challenge (RFC 9449 §8, §9)? */
private fun isNonceChallenge(e: Exchange) = e.status in 400..401 && e.dpopNonce && (e.error == "use_dpop_nonce" || e.wwwAuthenticate.orEmpty().contains("use_dpop_nonce"))

/**
 * Checks a case's exchanges against the split: each answered by the
 * instance it was meant for (the one it asked for, or its route's, or,
 * for a DPoP proof without a nonce, the other), the consent by its
 * route's; and records where a nonce challenge by one instance was
 * followed by a retry the other accepted.
 */
fun Run.checkSplit(split: Split) {
    val exchanges = wallet.recorder.exchanges.toList()
    val names = split.routes.values.toSet()
    val misrouted =
        exchanges.filter { e ->
            val route = split.routeOf(e.path)
            when {
                e.instance == null -> true
                e.forcedInstance != null -> e.instance != e.forcedInstance
                route == null -> false
                e.dpop && !e.dpopProofNonce -> e.instance == route || e.instance !in names
                else -> e.instance != route
            }
        }
    expect(misrouted.isEmpty(), "split: every request answered by the instance meant for it") {
        misrouted.joinToString { "${it.method} ${it.path} ${it.status} by ${it.instance} (forced ${it.forcedInstance})" }
    }
    val consent = wallet.recorder.consentInstances.toList()
    if (consent.isNotEmpty()) {
        val route = split.routeOf("/authorize")
        expect(consent.all { it == route }, "split: the consent page and its decision answered by $route") { consent.toString() }
    }
    exchanges.forEachIndexed { i, e ->
        if (!isNonceChallenge(e)) return@forEachIndexed
        val retry = exchanges.drop(i + 1).firstOrNull { it.path == e.path }
        if (retry != null && retry.status in 200..299 && retry.instance != null && retry.instance != e.instance) {
            split.crossed += e.path
        }
    }
    // What each routed endpoint answered, and from which instance: a
    // Credential Offer's reference left out.
    val served =
        exchanges
            .filter { split.routeOf(it.path) != null }
            .map { "${it.path.replace(Regex("^/credential-offer/.*"), "/credential-offer/…")} ${it.status} by ${it.instance}" }
            .distinct() + consent.distinct().map { "consent by $it" }
    ok("split: ${served.joinToString(", ")}")
}

/**
 * The split over the whole profile: a DPoP nonce one instance issued
 * accepted by the other at each endpoint that challenges, and the
 * Status List indices both instances reserved in the shared store,
 * none twice.
 */
fun Run.finishSplit(split: Split) {
    val want = listOf("/par", "/token", "/credential")
    expect(split.crossed.containsAll(want), "split: a DPoP nonce issued by one instance accepted by the other at ${want.joinToString()}") {
        "crossed at ${split.crossed}"
    }
    val byInstance = split.issued.groupBy({ it.instance }, { it.idx })
    val entries = split.issued.map { it.uri to it.idx }
    expect(
        byInstance.keys.filterNotNull().toSet() == split.routes.values.toSet() && entries.size == entries.toSet().size,
        "split: both instances reserved Status List indices in the shared store, none twice (${byInstance.entries.joinToString { "${it.key}: ${it.value.sorted()}" }})",
    ) { split.issued.toString() }
}
