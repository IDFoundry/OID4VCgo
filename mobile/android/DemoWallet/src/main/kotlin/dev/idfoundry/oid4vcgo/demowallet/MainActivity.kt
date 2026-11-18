package dev.idfoundry.oid4vcgo.demowallet

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.viewModels
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent

/**
 * The demo wallet's one activity: the screens, links opened from other
 * apps, and the issuer's authorization pages.
 */
class MainActivity : ComponentActivity() {
    private val model: WalletModel by viewModels()

    /** The authorization in progress: completed by the redirect back, or by the holder closing the page. */
    private var authorization: PendingAuthorization? = null
    private var inCustomTab = false
    private lateinit var authTab: ActivityResultLauncher<Intent>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Credentials' claims and portraits stay out of the recents
        // thumbnail and screenshots.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        authTab = AuthTabIntent.registerActivityResultLauncher(this) { result ->
            authorization?.tabResult(result.resultUri?.takeIf { result.resultCode == AuthTabIntent.RESULT_OK }?.toString())
        }
        model.attach(this)
        // A link on the callback scheme while authorizing: in an Auth Tab
        // it's ignored (any app can send one, and the redirect comes as
        // the tab's result), in a Custom Tab it's the redirect.
        model.awaitingRedirect = { uri ->
            authorization?.let {
                it.link(uri.toString())
                true
            } ?: false
        }
        model.start(testExtras(intent))
        if (savedInstanceState == null) intent?.data?.let(model::openFromOutside)
        setContent { DemoApp(model, authorize = ::authorize, openBrowser = ::openBrowser) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        model.start(testExtras(intent))
        intent.data?.let(model::openFromOutside)
    }

    /**
     * [intent], for its test extras (config, reset, offer, request), in a
     * debuggable build only. This activity is exported, for its deep
     * links: in a release build any app could otherwise replace the
     * wallet's trust roots, wipe it, or open an offer or request without
     * the confirmation a link gets. A debuggable build also takes its
     * configuration from the demo-config.json the run scripts push to
     * its external files directory (DemoConfiguration.load): a release
     * build doesn't, as below Android 10 other apps can write there.
     */
    private fun testExtras(intent: Intent?): Intent? =
        intent.takeIf { applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0 }

    override fun onResume() {
        super.onResume()
        model.attach(this)
        model.reload()
        model.refreshNfcForeground()
        model.refreshNfcReader()
        // Back from a Custom Tab without the redirect: the holder closed
        // the issuer's page, which leaves the offer as it was. (The
        // redirect, when there is one, arrives through onNewIntent first.)
        if (inCustomTab) {
            inCustomTab = false
            val pending = authorization ?: return
            window.decorView.postDelayed({
                if (!pending.isCompleted) pending.cancel()
            }, 500)
        }
    }

    override fun onPause() {
        model.releaseNfcForeground()
        model.pauseNfcReader()
        super.onPause()
    }

    /**
     * Opens the issuer's authorization page and returns its redirect back
     * to the app: in an Auth Tab where the browser has them, ephemeral (no
     * cookies kept), as ASWebAuthenticationSession on iOS, whose
     * redirect comes back only as its result; else in a Custom Tab,
     * whose redirect reaches the app as a link (PendingAuthorization).
     */
    private suspend fun authorize(url: String): AuthorizationRedirect {
        val browser = CustomTabsClient.getPackageName(this, null)
        val inAuthTab = browser != null && CustomTabsClient.isAuthTabSupported(this, browser)
        val pending = PendingAuthorization(inAuthTab)
        authorization = pending
        try {
            if (inAuthTab) {
                AuthTabIntent.Builder().setEphemeralBrowsingEnabled(true).build()
                    .launch(authTab, Uri.parse(url), model.callbackScheme)
            } else {
                inCustomTab = true
                CustomTabsIntent.Builder().setEphemeralBrowsingEnabled(true).build().launchUrl(this, Uri.parse(url))
            }
            return pending.await()
        } finally {
            authorization = null
        }
    }

    private fun openBrowser(uri: Uri) {
        startActivity(Intent(Intent.ACTION_VIEW, uri))
    }
}
