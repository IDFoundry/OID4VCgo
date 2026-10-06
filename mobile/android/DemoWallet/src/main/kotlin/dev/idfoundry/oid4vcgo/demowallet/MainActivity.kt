package dev.idfoundry.oid4vcgo.demowallet

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.viewModels
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import kotlinx.coroutines.CompletableDeferred

/**
 * The demo wallet's one activity: the screens, links opened from other
 * apps, and the issuer's authorization pages.
 */
class MainActivity : ComponentActivity() {
    private val model: WalletModel by viewModels()

    /** The authorization in progress: completed by the redirect back, or by the holder closing the page. */
    private var authorization: CompletableDeferred<String>? = null
    private var inCustomTab = false
    private lateinit var authTab: ActivityResultLauncher<Intent>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        authTab = AuthTabIntent.registerActivityResultLauncher(this) { result ->
            val pending = authorization ?: return@registerActivityResultLauncher
            if (result.resultCode == AuthTabIntent.RESULT_OK && result.resultUri != null) {
                pending.complete(result.resultUri.toString())
            } else {
                pending.completeExceptionally(WalletModel.AuthorizationCancelled())
            }
        }
        model.attach(this)
        model.awaitingRedirect = { uri ->
            authorization?.let {
                it.complete(uri.toString())
                true
            } ?: false
        }
        model.start(intent)
        if (savedInstanceState == null) intent?.data?.let(model::openFromOutside)
        setContent { DemoApp(model, authorize = ::authorize, openBrowser = ::openBrowser) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        model.start(intent)
        intent.data?.let(model::openFromOutside)
    }

    override fun onResume() {
        super.onResume()
        model.attach(this)
        // Back from a Custom Tab without the redirect: the holder closed
        // the issuer's page, which leaves the offer as it was. (The
        // redirect, when there is one, arrives through onNewIntent first.)
        if (inCustomTab) {
            inCustomTab = false
            val pending = authorization ?: return
            window.decorView.postDelayed({
                if (!pending.isCompleted) pending.completeExceptionally(WalletModel.AuthorizationCancelled())
            }, 500)
        }
    }

    /**
     * Opens the issuer's authorization page and returns its redirect back
     * to the app: in an Auth Tab where the browser has them, ephemeral (no
     * cookies kept), as ASWebAuthenticationSession on iOS; else in a
     * Custom Tab, whose redirect reaches the app as a link.
     */
    private suspend fun authorize(url: String): String {
        val pending = CompletableDeferred<String>()
        authorization = pending
        try {
            val browser = CustomTabsClient.getPackageName(this, null)
            if (browser != null && CustomTabsClient.isAuthTabSupported(this, browser)) {
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
