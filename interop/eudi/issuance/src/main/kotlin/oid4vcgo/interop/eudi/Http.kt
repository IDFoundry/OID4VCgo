package oid4vcgo.interop.eudi

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.forms.FormDataContent
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Collections
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import java.net.http.HttpClient as JdkHttpClient

private const val CONTENT_TYPE = "Content-Type"

/** One HTTP exchange the wallet made, as the issuer saw it. */
data class Exchange(
    val method: String,
    val path: String,
    val requestContentType: String?,
    val dpop: Boolean,
    val clientAttestation: Boolean,
    val authorizationScheme: String?,
    val status: Int,
    val responseContentType: String?,
    val dpopNonce: Boolean,
    val wwwAuthenticate: String?,
    // A form request's parameters: the values of those in [FORM_VALUES], "" for the rest.
    val form: Map<String, String>,
)

// Parameters whose values a case checks; the rest (codes, verifiers, tokens) aren't recorded.
val FORM_VALUES = setOf("grant_type", "response_type", "code_challenge_method", "scope", "client_id", "redirect_uri", "authorization_details")

/** Every exchange of a case, in order. */
class Recorder {
    val exchanges: MutableList<Exchange> = Collections.synchronizedList(mutableListOf())

    fun clear() = exchanges.clear()

    fun to(path: String) = exchanges.filter { it.path == path }
}

/** An SSL context trusting only [anchors]: the wallet verifies the issuer's TLS certificate. */
fun sslContext(anchors: List<X509Certificate>): SSLContext {
    val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
    anchors.forEachIndexed { i, c -> ks.setCertificateEntry("anchor-$i", c) }
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(ks) }
    return SSLContext.getInstance("TLSv1.3").apply { init(null, tmf.trustManagers, null) }
}

/** The ktor client the library uses, recording every exchange into [recorder]. */
fun walletHttpClient(
    ssl: SSLContext,
    recorder: Recorder,
): HttpClient {
    val record =
        createClientPlugin("Recorder") {
            onResponse { response ->
                val request = response.call.request
                recorder.exchanges +=
                    Exchange(
                        method = request.method.value,
                        path = request.url.encodedPath,
                        requestContentType = request.content.contentType?.withoutParameters()?.toString(),
                        dpop = request.headers["DPoP"] != null,
                        clientAttestation = request.headers["OAuth-Client-Attestation"] != null && request.headers["OAuth-Client-Attestation-PoP"] != null,
                        authorizationScheme = request.headers["Authorization"]?.substringBefore(' '),
                        status = response.status.value,
                        responseContentType = response.headers[CONTENT_TYPE]?.substringBefore(';')?.trim(),
                        dpopNonce = response.headers["DPoP-Nonce"] != null,
                        wwwAuthenticate = response.headers["WWW-Authenticate"],
                        form =
                            (request.content as? FormDataContent)?.formData?.let { p ->
                                p.names().associateWith { if (it in FORM_VALUES) p[it].orEmpty() else "" }
                            } ?: emptyMap(),
                    )
            }
        }
    return HttpClient(Java) {
        engine {
            config {
                sslContext(ssl)
                followRedirects(JdkHttpClient.Redirect.NEVER)
            }
        }
        install(ContentNegotiation) { json(Json { ignoreUnknownKeys = true }) }
        install(record)
        expectSuccess = false
    }
}

/** The authorization response the consent page redirected to. */
data class AuthorizationResponse(
    val code: String?,
    val state: String?,
    val iss: String?,
    val error: String?,
)

/**
 * The End-User's part of the authorization code flow: the browser opens
 * [authorizationUrl], the issuer's consent page, and the user approves
 * (or denies) every scope it asks for, as a browser submitting the form
 * would. Returns the authorization response the issuer redirects to,
 * which must be [redirectUri] exactly, with the response as its query:
 * a private-use URI no HTTP client follows, so it's read from the
 * redirect's Location.
 */
fun consent(
    ssl: SSLContext,
    authorizationUrl: URI,
    redirectUri: String,
    subject: String,
    approve: Boolean,
): AuthorizationResponse {
    val browser = JdkHttpClient.newBuilder().sslContext(ssl).followRedirects(JdkHttpClient.Redirect.NEVER).build()
    val page = browser.send(HttpRequest.newBuilder(authorizationUrl).GET().build(), HttpResponse.BodyHandlers.ofString())
    check(page.statusCode() == 200) { "the consent page answered ${page.statusCode()}: ${page.body().take(300)}" }
    val form = page.body()
    val handle =
        checkNotNull(Regex("""name="handle" value="([^"]+)"""").find(form)?.groupValues?.get(1)) { "no interaction handle on the consent page" }
    val scopes = Regex("""name="scope" value="([^"]+)"""").findAll(form).map { it.groupValues[1] }.toList()
    val fields = listOf("handle" to handle, "subject" to subject, "decision" to if (approve) "approve" else "deny") + scopes.map { "scope" to it }
    val body = fields.joinToString("&") { (k, v) -> "$k=${URLEncoder.encode(v, Charsets.UTF_8)}" }
    val action = authorizationUrl.resolve("/authorize/decision")
    val decision =
        browser.send(
            HttpRequest
                .newBuilder(action)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(),
            HttpResponse.BodyHandlers.ofString(),
        )
    val location =
        checkNotNull(decision.headers().firstValue("Location").orElse(null)) {
            "the consent decision answered ${decision.statusCode()} without a redirect: ${decision.body().take(300)}"
        }
    check(location.startsWith("$redirectUri?")) { "the consent redirected to $location, not to $redirectUri" }
    val query =
        URI(location).rawQuery.orEmpty().split('&').filter { it.isNotEmpty() }.associate {
            val (k, v) = it.split('=', limit = 2) + ""
            URLDecoder.decode(k, Charsets.UTF_8) to URLDecoder.decode(v, Charsets.UTF_8)
        }
    return AuthorizationResponse(query["code"], query["state"], query["iss"], query["error"])
}

/** A plain-HTTP JSON POST to the issuer's offer-minting endpoint (loopback). */
fun mintOffer(
    offersUrl: String,
    request: String,
): String {
    val client = JdkHttpClient.newHttpClient()
    val response =
        client.send(
            HttpRequest
                .newBuilder(URI(offersUrl))
                .header(CONTENT_TYPE, "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(request))
                .build(),
            HttpResponse.BodyHandlers.ofString(),
        )
    check(response.statusCode() == 200) { "minting an offer answered ${response.statusCode()}: ${response.body()}" }
    return response.body()
}
