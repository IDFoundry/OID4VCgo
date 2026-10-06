package dev.idfoundry.oid4vcgo.demowallet.uitests

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URL
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.Base64
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/**
 * Drives the demo wallet end to end against mobile/cmd/testservices,
 * which run-ui-tests.sh starts, forwards into the device, and whose CA
 * it pushes to the app and passes here (the controlCA argument). The
 * Android counterpart of the iOS demo's DemoWalletUITests.
 */
@RunWith(AndroidJUnit4::class)
class DemoWalletUITests {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val device = UiDevice.getInstance(instrumentation)
    private val pin = "493536"

    @After
    fun stopDeferring() {
        control("defer?on=0", "POST")
    }

    /** Asks the test services' control endpoint, over TLS to their own CA. */
    private fun control(path: String, method: String = "GET"): JsonObject {
        val connection = URL("$CONTROL/$path").openConnection() as HttpsURLConnection
        connection.sslSocketFactory = controlTLS.socketFactory
        connection.requestMethod = method
        return connection.inputStream.use { Json.parseToJsonElement(it.readBytes().decodeToString()).jsonObject }
    }

    private val controlTLS: SSLContext by lazy {
        val pem = Base64.getDecoder().decode(InstrumentationRegistry.getArguments().getString("controlCA") ?: error("no controlCA argument: run run-ui-tests.sh"))
        val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            CertificateFactory.getInstance("X.509").generateCertificates(pem.inputStream()).forEachIndexed { i, c -> setCertificateEntry("ca$i", c) }
        }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(anchors) }
        SSLContext.getInstance("TLSv1.3").apply { init(null, trust.trustManagers, null) }
    }

    /**
     * Launches the app afresh — quitting it first — configured for the
     * test services, opening [offer] or [request] if given, from an
     * empty wallet if [reset]; with [trustVerifier] false, trusting
     * another CA for Verifiers (the issuer's).
     */
    private fun launch(offer: String? = null, request: String? = null, reset: Boolean = true, trustVerifier: Boolean = true) {
        var config = control("config")
        if (!trustVerifier) {
            val wallet = config["wallet"]!!.jsonObject
            config = JsonObject(config + ("wallet" to JsonObject(wallet + ("verifier_roots" to wallet["issuer_roots"]!!))))
        }
        device.executeShellCommand("am force-stop $APP")
        val intent = Intent(Intent.ACTION_MAIN).setClassName(APP, "$APP.MainActivity")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            .putExtra("config", config.toString()).putExtra("reset", reset)
        offer?.let { intent.putExtra("offer", it) }
        request?.let { intent.putExtra("request", it) }
        instrumentation.context.startActivity(intent)
        assertNotNull("the app didn't start", device.wait(Until.hasObject(By.pkg(APP).depth(0)), 20_000))
    }

    private fun res(tag: String): BySelector = By.res(tag)

    private fun find(selector: BySelector, timeout: Long = 20_000): UiObject2? = device.wait(Until.findObject(selector), timeout)

    private fun need(tag: String, timeout: Long = 20_000): UiObject2 = find(res(tag), timeout) ?: error("no \"$tag\" on screen")

    /** Waits for [tag]'s text, or any text under it, to contain [text]. */
    private fun waitFor(tag: String, text: String, timeout: Long = 20_000): Boolean =
        device.wait(Until.hasObject(res(tag).hasDescendant(By.textContains(text))), timeout) ||
            device.wait(Until.hasObject(res(tag).textContains(text)), 1_000)

    /** Scrolls down until [tag] is on screen: a long consent screen builds its last rows only then. */
    private fun reveal(tag: String): UiObject2 {
        find(res(tag), 5_000)?.let { return it }
        repeat(5) {
            device.findObject(By.scrollable(true))?.scroll(Direction.DOWN, 0.8f)
            find(res(tag), 2_000)?.let { return it }
        }
        error("no \"$tag\" on screen, even scrolled")
    }

    /** Taps [tag] once it's enabled. */
    private fun tapWhenEnabled(tag: String) {
        val target = reveal(tag)
        assertTrue("$tag stays disabled", target.wait(Until.enabled(true), 10_000))
        target.click()
    }

    /**
     * Answers the system's prompt with the screen lock, each time a
     * holder key signs: once for each credential shared.
     */
    private fun confirmWithScreenLock() {
        assertNotNull("no prompt for the holder", device.wait(Until.hasObject(By.text("Confirm it's you")), 20_000))
        do {
            device.executeShellCommand("input text 1111")
            device.executeShellCommand("input keyevent KEYCODE_ENTER")
            device.wait(Until.gone(By.text("Confirm it's you")), 5_000)
        } while (device.wait(Until.hasObject(By.text("Confirm it's you")), 3_000))
    }

    private fun offerWithPIN(): String = control("offer?pin=$pin", "POST")["offer"]!!.jsonPrimitive.content

    private fun typePIN(value: String) {
        need("pin").text = value
    }

    /** Receives a credential with the PIN, from an empty wallet unless [reset] is false. */
    private fun receiveWithPIN(reset: Boolean = true) {
        launch(offer = offerWithPIN(), reset = reset)
        typePIN(pin)
        need("receive").click()
        assertTrue("not received", waitFor("status", "Received 1", 60_000))
    }

    /** Opens [link] in a relaunched app, keeping what it holds, ready to share. */
    private fun presentOnce(link: String) {
        launch(request = link, reset = false)
        reveal("share").wait(Until.enabled(true), 10_000)
    }

    private fun share() {
        tapWhenEnabled("share")
        confirmWithScreenLock()
        assertTrue("not shared", waitFor("status", "Shared with", 30_000))
    }

    private fun request(query: String): Pair<String, String> {
        val r = control("request?$query", "POST")
        return r["id"]!!.jsonPrimitive.content to r["link"]!!.jsonPrimitive.content
    }

    private fun result(id: String): JsonObject = control("request/$id")

    /** The pre-authorized code grant, with the PIN typed in the app. */
    @Test
    fun receiveWithPINGrant() {
        receiveWithPIN()
    }

    /** A wrong PIN keeps the offer open, saying so; the right one then receives the credential. */
    @Test
    fun wrongPINThenRetry() {
        launch(offer = offerWithPIN())
        typePIN("000000")
        need("receive").click()
        assertTrue("a wrong PIN isn't reported on the offer", waitFor("offer-error", "PIN", 30_000))
        typePIN(pin)
        need("receive").click()
        assertTrue("not received", waitFor("status", "Received 1", 60_000))
    }

    /** A received credential's status: valid, then revoked once the issuer revokes it. */
    @Test
    fun checkStatusAndRevocation() {
        receiveWithPIN()
        need("credential").click()
        need("check-status").click()
        assertTrue("not valid", waitFor("credential-status", "Valid"))
        assertNotNull("no feedback that the check happened", find(res("check-done"), 10_000))
        control("revoke", "POST")
        need("check-status").click()
        assertTrue("not revoked", waitFor("credential-status", "Revoked"))
    }

    /**
     * Receives an SD-JWT VC, then presents it: the consent screen says
     * whose it is and what sharing discloses, the holder confirms with
     * the screen lock, and the Verifier gets the claim.
     */
    @Test
    fun present() {
        receiveWithPIN()
        // The home screen groups the credential under its holder.
        assertTrue("the credentials aren't grouped by holder", waitFor("holder", "Doe"))
        val (id, link) = request("format=")
        presentOnce(link)
        assertTrue("the candidate doesn't say whose it is", waitFor("candidate-holder", "Doe"))
        assertTrue("the disclosure isn't shown", waitFor("disclosed", "family_name"))
        share()
        val r = result(id)
        assertEquals("done", r["status"]?.jsonPrimitive?.content)
        assertEquals("Doe", r["claims"]?.jsonObject?.get("family_name")?.jsonPrimitive?.content)
        // The issuer issued three copies; presenting used one.
        assertTrue(waitFor("credential", "2 of 3 copies unused"))
    }

    /** A request taking several credentials (DCQL multiple): both are offered and chosen, and both reach the Verifier. */
    @Test
    fun presentSeveral() {
        receiveWithPIN()
        receiveWithPIN(reset = false)
        val (id, link) = request("format=dc%2Bsd-jwt&multiple=1")
        presentOnce(link)
        assertTrue("both credentials aren't offered", device.wait(Until.hasObject(res("candidate")), 10_000))
        assertEquals(2, device.findObjects(res("candidate")).size)
        assertEquals("the request takes several, so both start chosen", 2, device.findObjects(By.desc("Selected")).size)
        share()
        assertEquals(2, result(id)["credentials"]?.jsonPrimitive?.content?.toInt())
    }

    /** "Same copy for the same verifier": presenting twice to one verifier uses one copy, and says so the second time. */
    @Test
    fun copyPolicyPerVerifier() {
        receiveWithPIN()
        need("settings").click()
        (find(By.text("Same copy for the same verifier"), 10_000) ?: error("no copy policy setting")).click()
        for (round in 0 until 2) {
            presentOnce(request("format=dc%2Bsd-jwt").second)
            if (round == 0) {
                assertNull("a first presentation says the verifier has seen it", find(res("shown-before"), 2_000))
            } else {
                assertNotNull("the second doesn't say the verifier has seen it", find(res("shown-before"), 10_000))
            }
            share()
        }
        assertTrue(waitFor("credential", "2 of 3 copies unused"))
    }

    /** A request from a verifier the wallet doesn't trust is refused unopened: no consent screen, nothing shared. */
    @Test
    fun untrustedVerifierRefused() {
        val (id, link) = request("format=dc%2Bsd-jwt")
        launch(request = link, trustVerifier = false)
        need("untrusted-verifier")
        assertNotNull(find(res("nothing-shared"), 5_000))
        assertNull("the consent screen opened", find(res("share"), 2_000))
        assertNotEquals("done", result(id)["status"]?.jsonPrimitive?.content)
    }

    /** A registered verifier's registration shows, and a request beyond it is flagged. */
    @Test
    fun registeredVerifier() {
        receiveWithPIN()
        presentOnce(request("format=dc%2Bsd-jwt&registered=1").second)
        need("registered")
        assertNull("a request within the registration was flagged", find(res("over-asking"), 2_000))
        tapWhenEnabled("decline")
        assertTrue(waitFor("status", "Declined", 30_000))
        presentOnce(request("format=dc%2Bsd-jwt&registered=1&extra=given_name").second)
        assertTrue("a request beyond the registration isn't flagged", waitFor("over-asking", "given_name"))
        assertNotNull("the unregistered claim isn't marked", find(res("disclosed-unregistered"), 10_000))
    }

    /** Declines a request the wallet can't answer; the Verifier records it. */
    @Test
    fun decline() {
        val (id, link) = request("format=mso_mdoc")
        launch(request = link)
        assertFalse("sharing is offered with nothing to share", reveal("share").isEnabled)
        tapWhenEnabled("decline")
        assertTrue(waitFor("status", "Declined", 30_000))
        assertTrue("$id: ${result(id)}", result(id)["last_error"]?.jsonPrimitive?.content.orEmpty().contains("access_denied"))
    }

    /** The scanner offers a QR code from an image, and goes back. */
    @Test
    fun scanSheet() {
        launch()
        need("scan").click()
        // The camera permission, the first time.
        find(By.textContains("While using the app"), 3_000)?.click()
        need("scan-image")
        device.pressBack()
        need("scan")
    }

    /** Receives a credential the issuer defers: it waits, polled at the issuer's interval. */
    private fun receiveDeferred() {
        control("defer?on=1", "POST")
        launch(offer = offerWithPIN())
        typePIN(pin)
        need("receive").click()
        assertTrue("not deferred", waitFor("status", "1 deferred", 60_000))
        need("check-again")
    }

    @Test
    fun deferredApproved() {
        receiveDeferred()
        assertNull(find(res("credential"), 2_000))
        control("decide?approve=1", "POST")
        assertNotNull("the approved credential isn't listed", find(res("credential"), 30_000))
        assertNull("it's still listed as pending", find(res("check-again"), 2_000))
    }

    /** A pending credential survives the app quitting: relaunched, the app polls it, and receives it once approved. */
    @Test
    fun deferredSurvivesARelaunch() {
        receiveDeferred()
        launch(reset = false)
        need("check-again")
        control("decide?approve=1", "POST")
        assertNotNull("the approved credential isn't listed", find(res("credential"), 30_000))
    }

    @Test
    fun deferredDenied() {
        receiveDeferred()
        control("decide?approve=0", "POST")
        need("dismiss", 30_000)
        assertTrue(waitFor("pending-state", "Denied"))
        need("dismiss").click()
        assertNull(find(res("pending"), 3_000))
        assertNull(find(res("credential"), 1_000))
    }

    private companion object {
        const val APP = "dev.idfoundry.oid4vcgo.demowallet"
        const val CONTROL = "https://127.0.0.1:8600"
    }
}
