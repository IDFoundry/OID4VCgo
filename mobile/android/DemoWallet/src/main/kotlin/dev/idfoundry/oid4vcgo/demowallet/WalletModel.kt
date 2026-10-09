package dev.idfoundry.oid4vcgo.demowallet

import android.app.Activity
import android.app.Application
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.idfoundry.oid4vcwallet.AndroidKeystoreKeyStore
import dev.idfoundry.oid4vcwallet.BiometricPromptAuthenticator
import dev.idfoundry.oid4vcwallet.CredentialDetail
import dev.idfoundry.oid4vcwallet.CredentialSummary
import dev.idfoundry.oid4vcwallet.DeferredCredential
import dev.idfoundry.oid4vcwallet.DeferredStatus
import dev.idfoundry.oid4vcwallet.FileCredentialStore
import dev.idfoundry.oid4vcwallet.Issuance
import dev.idfoundry.oid4vcwallet.MdocPresentation
import dev.idfoundry.oid4vcwallet.ProximityException
import dev.idfoundry.oid4vcwallet.ProximityPresentation
import dev.idfoundry.oid4vcwallet.ProximityReader
import dev.idfoundry.oid4vcwallet.ProximityReaderConfiguration
import dev.idfoundry.oid4vcwallet.ProximityReaderSession
import dev.idfoundry.oid4vcwallet.OID4VC
import dev.idfoundry.oid4vcwallet.Offer
import dev.idfoundry.oid4vcwallet.Presentation
import dev.idfoundry.oid4vcwallet.Selection
import dev.idfoundry.oid4vcwallet.Wallet
import dev.idfoundry.oid4vcwallet.WalletConfiguration
import dev.idfoundry.oid4vcwallet.WalletException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonElement
import java.lang.ref.WeakReference

/**
 * The demo wallet's state: the wallet, what it holds, and the issuance
 * or presentation in progress.
 */
class WalletModel(application: Application) : AndroidViewModel(application) {
    sealed interface Phase {
        data object Idle : Phase
        data object Offered : Phase
        data object Receiving : Phase
        data class Done(val text: String) : Phase
        data class Failed(val text: String) : Phase

        /** A presentation request from a verifier the wallet doesn't trust was refused unopened. */
        data object UntrustedVerifier : Phase
    }

    var credentials by mutableStateOf<List<CredentialSummary>>(emptyList())
        private set

    /** Each held credential's claims, by ID: to group the credentials by whose they are. */
    val claims = mutableStateMapOf<String, JsonElement>()
    var configured by mutableStateOf(false)
        private set

    /** Why the wallet can't run on this device, when it can't. */
    var unavailable by mutableStateOf<String?>(null)
        private set
    var offer by mutableStateOf<Offer?>(null)
        private set
    var phase by mutableStateOf<Phase>(Phase.Idle)
    var pin by mutableStateOf("")

    /** Something to tell the holder that isn't a receive's or presentation's outcome. */
    var notice by mutableStateOf<String?>(null)

    /** A link another app opened the wallet with, held until the holder chooses to open it. */
    var linkToConfirm by mutableStateOf<Uri?>(null)

    /** Which copy of a credential a presentation uses, as chosen in the app's settings. */
    var copyPolicy by mutableStateOf(WalletConfiguration.CopyPolicy.PER_PRESENTATION)
        private set

    private var wallet: Wallet? = null
    private var keys: AndroidKeystoreKeyStore? = null
    private var config: DemoConfiguration? = null
    private var issuance: Issuance? = null
    private val prefs = application.getSharedPreferences("demo", Context.MODE_PRIVATE)

    /** The activity holder keys ask the holder in. */
    private var activity = WeakReference<Activity>(null)

    fun attach(activity: Activity) {
        this.activity = WeakReference(activity)
    }

    /**
     * Configures the wallet from the launch intent, once, and resumes what
     * it holds. As a Credential Manager provider (GetCredentialActivity),
     * it only answers the request: the launch work — the orphaned-key
     * sweep above all, which would take the keys of an issuance the app
     * has in progress — is the app's.
     */
    fun start(intent: Intent?, provider: Boolean = false) {
        if (configured || unavailable != null) return
        val context = getApplication<Application>()
        val loaded = DemoConfiguration.load(context, intent) ?: return
        // Without a screen lock, holder keys would present with no one
        // there to agree: don't run.
        if (!context.getSystemService(KeyguardManager::class.java).isDeviceSecure) {
            unavailable = "Set a screen lock to use this wallet: presenting a credential needs your fingerprint or screen lock."
            return
        }
        val config = DevelopmentTLS.install(context, loaded)
        keys = AndroidKeystoreKeyStore(authenticator = BiometricPromptAuthenticator({ activity.get() }))
        this.config = config
        val reset = intent?.getBooleanExtra("reset", false) == true
        if (reset) prefs.edit().remove(COPY_POLICY).apply()
        copyPolicy = prefs.getString(COPY_POLICY, null)?.let { saved ->
            WalletConfiguration.CopyPolicy.entries.firstOrNull { it.name == saved }
        } ?: config.wallet.copyPolicy
        try {
            wallet = makeWallet()
            configured = true
        } catch (e: Exception) {
            phase = Phase.Failed(describe(e))
            return
        }
        if (OID4VC.isTestBuild) notice = "This build links the test Go library, with its in-process test issuer: never ship it."
        if (provider) return
        viewModelScope.launch {
            if (reset) deleteAll()
            // At launch, before any issuance: delete keys left by one the
            // app quit in the middle of.
            runCatching { wallet?.sweepOrphanedKeys(keys!!) }
            resumeDeferred()
            refresh()
            checkAllStatuses()
            refreshUsedUp()
            intent?.getStringExtra("offer")?.let { open(Uri.parse(it)) }
            intent?.getStringExtra("request")?.let { open(Uri.parse(it)) }
        }
    }

    private fun makeWallet(): Wallet {
        val config = config ?: throw IllegalStateException("not configured")
        return Wallet(
            config.wallet.copy(copyPolicy = copyPolicy), keys!!,
            FileCredentialStore.standard(getApplication()), config.providerURL?.let(::HTTPWalletProvider),
        )
    }

    /** Switches the copy policy, rebuilding the wallet over the same keys and credentials. */
    fun chooseCopyPolicy(policy: WalletConfiguration.CopyPolicy) {
        if (policy == copyPolicy || presentation != null) return
        copyPolicy = policy
        // At once, not apply()'s later write: the app may be stopped
        // right after (a UI test relaunching it did).
        prefs.edit().putString(COPY_POLICY, policy.name).commit()
        try {
            wallet = makeWallet()
        } catch (e: Exception) {
            phase = Phase.Failed(describe(e))
        }
    }

    /** Deletes every credential and pending deferred credential, with their keys (the `reset` extra, for UI tests). */
    private suspend fun deleteAll() {
        val wallet = wallet ?: return
        runCatching { wallet.credentials() }.getOrDefault(emptyList()).forEach { runCatching { wallet.deleteCredential(it.id) } }
        runCatching { wallet.deferredCredentials() }.getOrDefault(emptyList()).forEach { runCatching { wallet.abandonDeferred(it.id) } }
    }

    /** The redirect URI's scheme, which the authorization's redirect comes back on. */
    val callbackScheme: String get() = config?.wallet?.callbackScheme.orEmpty()

    /** Whether a receive or a presentation is in progress: a link that arrives then is refused. */
    private val busy: Boolean get() = phase == Phase.Offered || phase == Phase.Receiving || requestPhase != RequestPhase.IDLE

    /** Opens a link from another app: an issuer's redirect at once, an offer or a request once the holder confirms. */
    fun openFromOutside(uri: Uri) {
        when {
            uri.scheme.equals("mdoc", ignoreCase = true) ->
                if (readerAvailable) engagementToRead = uri.toString() else notice = "This wallet has no reader in its configuration."
            uri.scheme == OFFER_SCHEME || uri.scheme == REQUEST_SCHEME -> linkToConfirm = uri
            else -> open(uri)
        }
    }

    fun confirmLink() {
        val uri = linkToConfirm ?: return
        linkToConfirm = null
        open(uri)
    }

    /** Whether the authorization in progress is waiting for this redirect: then it isn't a relaunch's. */
    var awaitingRedirect: ((Uri) -> Boolean)? = null

    fun open(uri: Uri) {
        // The issuer's redirect, arriving after the app was killed while
        // the holder was at the issuer's pages, completes the issuance it
        // began.
        if (uri.scheme == callbackScheme && callbackScheme.isNotEmpty()) {
            if (awaitingRedirect?.invoke(uri) == true) return
            if (issuance == null) viewModelScope.launch { resume(uri.toString()) }
            return
        }
        if (uri.scheme != OFFER_SCHEME && uri.scheme != REQUEST_SCHEME) return
        if (busy) {
            notice = "Finish or cancel the current request before opening another."
            return
        }
        notice = null
        viewModelScope.launch {
            if (uri.scheme == OFFER_SCHEME) start(offer = uri.toString()) else startPresentation(uri.toString())
        }
    }

    // Presentation

    enum class RequestPhase { IDLE, SHOWN, SHARING }

    var presentation by mutableStateOf<Presentation?>(null)
        private set
    var disclosures by mutableStateOf<List<Presentation.Disclosure>>(emptyList())
        private set
    var requestPhase by mutableStateOf(RequestPhase.IDLE)
        private set

    /** The holder's choice: for each query, the credentials to answer it. */
    var selected by mutableStateOf<Selection>(emptyMap())
        private set

    /** The selection [disclosures] was computed for: Share sends only a selection the holder has seen previewed. */
    private var previewed by mutableStateOf<Selection?>(null)

    /** Why the selection couldn't be previewed, if it couldn't. */
    var previewError by mutableStateOf<String?>(null)
        private set

    /** Each candidate credential's claims, by ID: to say whose it is, and show the values sharing it discloses. */
    val candidateClaims = mutableStateMapOf<String, JsonElement>()

    /** Whether Share would send exactly what "Will share" shows. */
    val canShare: Boolean get() = selected.isNotEmpty() && previewed == selected && previewError == null && requestPhase == RequestPhase.SHOWN

    /**
     * Where a Digital Credentials API presentation's answer goes: the
     * response's data for the platform, or null when there's none to
     * give (the request couldn't be opened, or answering failed).
     */
    private var dcapiAnswer: ((String?) -> Unit)? = null

    /**
     * Opens an OpenID4VP request Credential Manager handed over, from
     * the page or app at [origin], for the consent screen; [answer] gets
     * the response's data once the holder shares or declines.
     * [preselect] is the credential the holder chose in the system's
     * chooser.
     */
    fun startDCAPI(protocol: String, data: ByteArray, origin: String, preselect: String?, answer: (String?) -> Unit) {
        dcapiAnswer = answer
        viewModelScope.launch {
            val wallet = wallet ?: return@launch answerDCAPI(null)
            open { wallet.startDCAPIPresentation(protocol, data, origin) }
            val p = presentation ?: return@launch answerDCAPI(null)
            // The holder already chose in the system's chooser: start from that.
            preselect?.let { id ->
                val query = p.queries.firstOrNull { q -> q.credentials.any { it.id == id } } ?: return@let
                selected = mapOf(query.queryID to listOf(id))
                updatePreview()
            }
        }
    }

    private fun answerDCAPI(data: String?) {
        dcapiAnswer?.invoke(data)
        dcapiAnswer = null
    }

    /** Fetches and verifies a presentation request, and preselects what the wallet would choose itself. */
    private suspend fun startPresentation(link: String) {
        val wallet = wallet ?: return
        open { wallet.startPresentation(link) }
    }

    /** Opens the presentation [start] begins, for the consent screen. */
    private suspend fun open(start: suspend () -> Presentation) {
        val wallet = wallet ?: return
        try {
            val p = start()
            candidateClaims.clear()
            for (c in p.queries.flatMap { it.credentials }) {
                if (c.id !in candidateClaims) runCatching { wallet.credential(c.id).claims }.getOrNull()?.let { candidateClaims[c.id] = it }
            }
            presentation = p
            selected = runCatching { p.defaultSelection() }.getOrDefault(emptyMap())
            requestPhase = RequestPhase.SHOWN
            updatePreview()
        } catch (e: WalletException) {
            phase = if (e.code == WalletException.Code.untrustedVerifier) Phase.UntrustedVerifier else Phase.Failed(describe(e))
        }
    }

    fun isSelected(id: String, queryID: String): Boolean = selected[queryID]?.contains(id) ?: false

    /**
     * Chooses credential [id] to answer [query], or unchooses it. A query
     * takes one credential unless it asks for several (DCQL `multiple`):
     * then choosing one unchooses its others.
     */
    fun toggle(id: String, query: Presentation.Query) {
        var chosen = selected[query.queryID].orEmpty()
        chosen = if (id in chosen) chosen - id else if (query.multiple) chosen + id else listOf(id)
        selected = if (chosen.isEmpty()) selected - query.queryID else selected + (query.queryID to chosen)
        viewModelScope.launch { updatePreview() }
    }

    private suspend fun updatePreview() {
        val selection = selected
        previewed = null
        previewError = null
        val p = presentation
        if (p == null || selection.isEmpty()) {
            disclosures = emptyList()
            return
        }
        try {
            val result = p.preview(selection)
            // A newer selection's preview supersedes this one.
            if (selection != selected) return
            disclosures = result
            previewed = selection
        } catch (e: WalletException) {
            if (selection != selected) return
            disclosures = emptyList()
            previewError = describe(e)
        }
    }

    /** Shares the selected credentials: holder keys sign now, so the holder is asked for their fingerprint or screen lock. */
    fun share(openBrowser: (Uri) -> Unit) = viewModelScope.launch {
        val p = presentation ?: return@launch
        val selection = previewed ?: return@launch
        if (!canShare) return@launch
        requestPhase = RequestPhase.SHARING
        try {
            val presented = p.respond(selection)
            phase = Phase.Done("Shared with ${verifierName(p)}")
            endPresentation()
            presented.dcapiResponse?.let { answerDCAPI(it) }
            // A copy of each shared credential is used up.
            refresh()
            refreshUsedUp()
            presented.redirectURI?.let(Uri::parse)?.takeIf { it.scheme == "https" }?.let(openBrowser)
        } catch (e: WalletException) {
            phase = Phase.Failed(describe(e))
            endPresentation()
            answerDCAPI(null)
            refresh()
        }
    }

    /** Who's asking, in words: the Verifier's name, or a DC API request's origin. */
    fun verifierName(p: Presentation): String = p.verifier.name.ifEmpty { p.verifier.origin?.let(Credentials::host) ?: "the verifier" }

    fun decline(openBrowser: (Uri) -> Unit) = viewModelScope.launch {
        val p = presentation ?: return@launch
        try {
            val presented = p.decline()
            phase = Phase.Done("Declined ${verifierName(p)}")
            endPresentation()
            presented.dcapiResponse?.let { answerDCAPI(it) }
            presented.redirectURI?.let(Uri::parse)?.takeIf { it.scheme == "https" }?.let(openBrowser)
        } catch (e: WalletException) {
            phase = Phase.Failed(describe(e))
            endPresentation()
            answerDCAPI(null)
        }
    }

    private fun endPresentation() {
        presentation = null
        disclosures = emptyList()
        selected = emptyMap()
        previewed = null
        previewError = null
        candidateClaims.clear()
        requestPhase = RequestPhase.IDLE
    }

    // Issuance

    private suspend fun start(offer: String) {
        val wallet = wallet ?: return
        closeIssuance()
        offerError = null
        try {
            val s = wallet.startIssuance(offer)
            issuance = s
            this.offer = s.offer
            pin = ""
            phase = Phase.Offered
        } catch (e: WalletException) {
            phase = Phase.Failed(describe(e))
        }
    }

    /** Why the last attempt to receive failed, when trying again may work: shown on the offer, which stays open. */
    var offerError by mutableStateOf<String?>(null)
        private set

    /** Whether the issuance has its access token: a retry then only requests the credentials. */
    private var authorized = false
    private var receiveJob: Job? = null

    /** The holder closed the issuer's page: the offer stays. */
    class AuthorizationCancelled : Exception("the holder closed the issuer's page")

    /** Starts receiving, as a job Cancel can stop; [authorize] opens the issuer's page and returns the redirect. */
    fun startReceive(authorize: suspend (String) -> String) {
        receiveJob = viewModelScope.launch { receive(authorize) }
    }

    /**
     * Receives the offered credentials. A failure that trying again may
     * fix (the network, a wrong PIN) keeps the offer open to try again;
     * any other ends it.
     */
    private suspend fun receive(authorize: suspend (String) -> String) {
        val issuance = issuance ?: return
        val offer = offer ?: return
        phase = Phase.Receiving
        offerError = null
        try {
            if (!authorized) {
                if (offer.grant == Offer.Grant.PRE_AUTHORIZED_CODE) {
                    issuance.redeemPreAuthorizedCode(pin)
                } else {
                    // After a failed completeAuthorization this starts the
                    // authorization over, as it must.
                    val url = issuance.beginAuthorization()
                    issuance.completeAuthorization(authorize(url))
                }
                authorized = true
            }
            requestCredentials(issuance)
        } catch (e: CancellationException) {
            if (phase == Phase.Receiving) phase = Phase.Offered
            throw e
        } catch (e: AuthorizationCancelled) {
            phase = Phase.Offered
        } catch (e: WalletException) {
            if (e.isRetryable) {
                phase = Phase.Offered
                offerError = describe(e)
                if (e.protocolError == "invalid_grant") pin = ""
                // Anything deferred before the failure is pending already.
                resumeDeferred()
            } else {
                phase = Phase.Failed(describe(e))
                // Don't leave the issuance's keys in Keystore: the holder
                // starts again from the offer.
                closeIssuance()
                resumeDeferred()
            }
        }
        refresh()
    }

    /** Completes, after a relaunch, an issuance whose authorization was in progress when the app was killed. */
    private suspend fun resume(redirect: String) {
        val wallet = wallet ?: return
        if (busy) return
        phase = Phase.Receiving
        try {
            val s = wallet.resumeIssuance(redirect)
            issuance = s
            offer = s.offer
            requestCredentials(s)
        } catch (e: WalletException) {
            if (e.code == WalletException.Code.notFound) {
                phase = Phase.Idle
                notice = "That sign-in has expired or was already used. Open the offer again."
            } else {
                phase = Phase.Failed(describe(e))
                closeIssuance()
            }
        }
        refresh()
    }

    private suspend fun requestCredentials(issuance: Issuance) {
        val result = issuance.requestCredentials()
        var summary = "Received ${result.credentials.size} credential(s)"
        if (result.deferred.isNotEmpty()) summary += ", ${result.deferred.size} deferred"
        if (result.failed.isNotEmpty()) {
            val reasons = result.failed.joinToString("; ") { f ->
                "${f.configurationID}: ${f.code}" + (f.protocolError?.let { " ($it)" } ?: "")
            }
            summary += "; ${result.failed.size} couldn't be issued — $reasons"
        }
        phase = Phase.Done(summary)
        // Deferred credentials are kept in the credential store, with what
        // polling them needs: they outlive the issuance, and the app
        // quitting.
        closeIssuance()
        result.deferred.forEach(::track)
    }

    // Deferred credentials

    /**
     * A credential the issuer will issue later, polled at the issuer's
     * interval until it's issued or denied. The wallet keeps it in the
     * credential store, so after a relaunch it's resumed.
     */
    data class PendingCredential(val id: String, val configurationID: String, val intervalSeconds: Double, val state: State) {
        sealed interface State {
            data object Waiting : State
            data object Checking : State
            data object Denied : State
            data class Failed(val message: String) : State
        }
    }

    val pending = mutableStateListOf<PendingCredential>()
    private val pollJobs = mutableMapOf<String, Job>()

    /** Picks up the deferred credentials the wallet holds — from before the app last quit — and polls them. */
    private suspend fun resumeDeferred() {
        val held = runCatching { wallet?.deferredCredentials() }.getOrNull() ?: return
        held.forEach(::track)
    }

    private fun track(d: DeferredCredential) {
        if (pending.any { it.id == d.id }) return
        pending += PendingCredential(d.id, d.configurationID, d.intervalSeconds, PendingCredential.State.Waiting)
        schedule(d.id)
    }

    /** Polls [id] once its interval has passed (at least a second). */
    private fun schedule(id: String) {
        val p = pending.firstOrNull { it.id == id } ?: return
        pollJobs[id]?.cancel()
        pollJobs[id] = viewModelScope.launch {
            delay((maxOf(p.intervalSeconds, 1.0) * 1000).toLong())
            poll(id)
        }
    }

    /** Asks the issuer about [id] now. */
    fun checkAgain(id: String) {
        pollJobs[id]?.cancel()
        viewModelScope.launch { poll(id) }
    }

    private suspend fun poll(id: String) {
        val wallet = wallet ?: return
        if (pending.none { it.id == id }) return
        update(id) { it.copy(state = PendingCredential.State.Checking) }
        try {
            when (val status = wallet.pollDeferred(id)) {
                is DeferredStatus.Pending -> {
                    update(id) { it.copy(state = PendingCredential.State.Waiting, intervalSeconds = status.intervalSeconds) }
                    schedule(id)
                }
                is DeferredStatus.Issued -> {
                    // This poll is that job: cancelling it would cancel the
                    // refresh below, and the new credential wouldn't show.
                    forget(id, cancel = false)
                    phase = Phase.Done("Received a deferred credential")
                    refresh()
                }
            }
        } catch (e: WalletException) {
            if (e.code == WalletException.Code.credentialDenied) {
                // The wallet has already forgotten it; the row stays until it's dismissed.
                update(id) { it.copy(state = PendingCredential.State.Denied) }
            } else {
                update(id) { it.copy(state = PendingCredential.State.Failed(describe(e))) }
                // A failure trying again may fix: keep polling, less often.
                if (e.isRetryable) {
                    update(id) { it.copy(intervalSeconds = minOf(maxOf(it.intervalSeconds, 1.0) * 2, 60.0)) }
                    schedule(id)
                }
            }
        }
    }

    /** Removes a denied credential's row. */
    fun dismiss(id: String) = forget(id)

    /** Gives up on a credential that can't be checked — its access token expired, say — deleting it and its keys. */
    fun abandon(id: String) = viewModelScope.launch {
        runCatching { wallet?.abandonDeferred(id) }
        forget(id)
    }

    private fun update(id: String, change: (PendingCredential) -> PendingCredential) {
        val i = pending.indexOfFirst { it.id == id }
        if (i >= 0) pending[i] = change(pending[i])
    }

    private fun forget(id: String, cancel: Boolean = true) {
        val job = pollJobs.remove(id)
        if (cancel) job?.cancel()
        pending.removeAll { it.id == id }
    }

    /** Stops receiving — the request in progress included — and ends the offer. */
    fun cancelOffer() = viewModelScope.launch {
        receiveJob?.cancel()
        receiveJob?.join()
        receiveJob = null
        closeIssuance()
        phase = Phase.Idle
        offerError = null
    }

    suspend fun detail(c: CredentialSummary): CredentialDetail? = runCatching { wallet?.credential(c.id) }.getOrNull()

    fun delete(c: CredentialSummary) = viewModelScope.launch {
        runCatching { wallet?.deleteCredential(c.id) }
        refresh()
    }

    /**
     * Lists the credentials again, as the activity resumes, and refreshes
     * any used up, as after presenting here: [GetCredentialActivity]
     * presents with its own model, using copies, while this one is in
     * the background. Not during an issuance or a presentation of this
     * model's own.
     */
    fun reload() {
        viewModelScope.launch {
            refresh()
            if (issuance == null && presentation == null) refreshUsedUp()
        }
    }

    suspend fun refresh() {
        val wallet = wallet ?: return
        try {
            credentials = wallet.credentials()
            loadClaims(emptySet())
            // In the background: the list needn't wait for Credential Manager.
            val held = credentials
            val all = claims.toMap()
            viewModelScope.launch { DigitalCredentials.sync(getApplication(), held, all) }
        } catch (e: WalletException) {
            phase = Phase.Failed("Couldn't list credentials: " + describe(e))
        }
    }

    /**
     * Loads the claims of credentials not loaded yet, and of [reload] (a
     * refresh can change them, such as an age claim), dropping those of
     * credentials no longer held.
     */
    private suspend fun loadClaims(reload: Set<String>) {
        val wallet = wallet ?: return
        claims.keys.retainAll { id -> credentials.any { it.id == id } && id !in reload }
        for (c in credentials) {
            if (c.id !in claims) runCatching { wallet.credential(c.id).claims }.getOrNull()?.let { claims[c.id] = it }
        }
    }

    /**
     * The held credentials grouped by whose they are — the holder's name
     * and date of birth from their claims — those of one holder oldest
     * first, and those naming no holder last.
     */
    val credentialsByHolder: List<Pair<Holder?, List<CredentialSummary>>>
        get() {
            val groups = LinkedHashMap<String, Pair<Holder?, MutableList<CredentialSummary>>>()
            for (c in credentials.sortedBy { it.receivedAt }) {
                val holder = Holder.of(claims[c.id])
                val key = holder?.let { "${it.name.orEmpty()}|${it.birthDate.orEmpty()}" }.orEmpty()
                val group = groups.getOrPut(key) { holder to mutableListOf() }
                group.second += c
                if (group.first?.portrait == null && holder?.portrait != null) groups[key] = holder to group.second
            }
            return groups.entries.sortedWith(compareBy<Map.Entry<String, *>>({ it.key.isEmpty() }, { it.key })).map { it.value }
        }

    /** Checks a credential's revocation status in its issuer's status list. Returns why it couldn't, if it couldn't. */
    suspend fun checkStatus(id: String): String? {
        val wallet = wallet ?: return "The wallet isn't configured."
        return try {
            val checked = wallet.checkStatus(id)
            credentials = credentials.map { if (it.id == id) checked else it }
            null
        } catch (e: WalletException) {
            describe(e)
        }
    }

    /** How refreshing a credential's copies ended. */
    sealed interface RefreshOutcome {
        data class Refreshed(val copies: Int) : RefreshOutcome
        data object Deferred : RefreshOutcome
        data object ReissueRequired : RefreshOutcome
        data class Failed(val reason: String) : RefreshOutcome
    }

    /** Replaces a credential's copies with a fresh batch, without the holder, using the refresh token its issuance kept. */
    suspend fun refreshCopies(id: String): RefreshOutcome {
        val wallet = wallet ?: return RefreshOutcome.Failed("The wallet isn't configured.")
        return try {
            val refreshed = wallet.refreshCredential(id)
            credentials = credentials.map { if (it.id == id) refreshed.credential else it }
            loadClaims(setOf(id))
            refreshed.deferred?.let {
                track(it)
                RefreshOutcome.Deferred
            } ?: RefreshOutcome.Refreshed(refreshed.credential.copies)
        } catch (e: WalletException) {
            if (e.code == WalletException.Code.reissueRequired) {
                refresh()
                RefreshOutcome.ReissueRequired
            } else {
                RefreshOutcome.Failed(describe(e))
            }
        }
    }

    /**
     * Refreshes, without the holder, each credential with a refresh token
     * and no unused copy left — after a presentation, and at launch — so
     * the next verifier gets a fresh copy rather than one another has
     * seen. Quietly: one that fails for now is tried again next time.
     */
    private suspend fun refreshUsedUp() {
        val wallet = wallet ?: return
        for (c in credentials.filter { it.refreshable && it.copiesLeft == 0 }) {
            try {
                val refreshed = wallet.refreshCredential(c.id)
                credentials = credentials.map { if (it.id == c.id) refreshed.credential else it }
                refreshed.deferred?.let(::track)
            } catch (e: WalletException) {
                if (e.code == WalletException.Code.reissueRequired) {
                    notice = "Every copy of a credential has been shared, and it can't be refreshed any more: receive it again from the issuer."
                    refresh()
                }
            }
        }
    }

    /**
     * Checks every credential's status, at launch: one status list per
     * issuer covers many credentials, so this tells no issuer which
     * credentials the holder has. Quietly.
     */
    private suspend fun checkAllStatuses() {
        val wallet = wallet ?: return
        for (c in credentials) {
            runCatching { wallet.checkStatus(c.id) }.getOrNull()?.let { checked ->
                credentials = credentials.map { if (it.id == c.id) checked else it }
            }
        }
    }

    private suspend fun closeIssuance() {
        runCatching { issuance?.close() }
        issuance = null
        offer = null
        authorized = false
    }

    // In person (ISO/IEC 18013-5 over BLE)

    /** The in-person presentation in progress, the holder's side. */
    var inPerson by mutableStateOf<ProximityPresentation?>(null)
        private set
    var inPersonState by mutableStateOf<ProximityPresentation.State?>(null)
        private set
    private var inPersonJob: Job? = null

    /**
     * Starts sharing in person: the QR code to show, and advertising. The
     * Bluetooth permissions are the screen's to have asked for.
     */
    fun shareInPerson() {
        val wallet = wallet ?: return
        if (busy || inPerson != null) return
        notice = null
        try {
            val p = wallet.startProximityPresentation(getApplication())
            inPerson = p
            // For driving two emulators: the QR code's text, an ephemeral
            // key and a service UUID, in debug builds.
            if (getApplication<Application>().applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0) {
                android.util.Log.d("DemoWallet", "in person: ${p.qrCode}")
            }
            inPersonJob = viewModelScope.launch {
                p.state.collect { s ->
                    inPersonState = s
                    if (s.isFinal) refresh()
                }
            }
        } catch (e: ProximityException) {
            notice = e.description
        } catch (e: WalletException) {
            notice = describe(e)
        }
    }

    /** Shares [elements] of [credentialID] with the reader, for document [document]. */
    fun respondInPerson(document: Int, credentialID: String, elements: List<MdocPresentation.Element>) {
        val p = inPerson ?: return
        viewModelScope.launch {
            try {
                p.respond(document, credentialID, elements)
            } catch (e: WalletException) {
                // A cancelled prompt leaves the request standing: try again or decline.
                notice = describe(e)
            } catch (e: ProximityException) {
                notice = e.description
            }
        }
    }

    fun declineInPerson() {
        val p = inPerson ?: return
        viewModelScope.launch { p.decline() }
    }

    /** Leaves the in-person screen, ending the session if it's still going. */
    fun closeInPerson() {
        inPerson?.cancel()
        inPersonJob?.cancel()
        inPerson = null
        inPersonState = null
    }

    // Reader mode

    /** Whether the demo reader is configured: the services gave it an identity. */
    val readerAvailable: Boolean get() = config?.reader != null

    /** A holder's engagement another app handed over (an mdoc: link), for reader mode to read. */
    var engagementToRead by mutableStateOf<String?>(null)

    var reading by mutableStateOf<ProximityReaderSession?>(null)
        private set
    var readingState by mutableStateOf<ProximityReaderSession.State?>(null)
        private set
    var readingPreset by mutableStateOf<ReaderPreset?>(null)
        private set
    private var readingJob: Job? = null

    private val reader: ProximityReader? by lazy {
        val r = config?.reader ?: return@lazy null
        runCatching {
            ProximityReader(
                ProximityReaderConfiguration(
                    issuerRoots = r.issuerRoots, readerKeyID = DemoReaderKeys.ID, readerChain = r.readerChain, maxClockSkewSeconds = 300,
                ),
                DemoReaderKeys(r),
            )
        }.onFailure { notice = describe(it) }.getOrNull()
    }

    /** Reads the holder's [qrCode], asking for [preset]. */
    fun read(qrCode: String, preset: ReaderPreset) {
        val reader = reader ?: return
        try {
            val session = reader.start(getApplication(), qrCode, preset.docType, preset.elements)
            reading = session
            readingPreset = preset
            readingJob = viewModelScope.launch { session.state.collect { readingState = it } }
        } catch (e: ProximityException) {
            notice = e.description
        } catch (e: WalletException) {
            notice = describe(e)
        }
    }

    fun closeReading() {
        engagementToRead = null
        reading?.cancel()
        readingJob?.cancel()
        reading = null
        readingState = null
        readingPreset = null
    }

    companion object {
        private const val COPY_POLICY = "demo-copy-policy"

        /** Credential Offer links' scheme, and presentation requests'. */
        const val OFFER_SCHEME = "openid-credential-offer"
        const val REQUEST_SCHEME = "openid4vp"

        /** An error as the holder sees it: the wallet's own sentence, and — for the demo — its code. */
        fun describe(e: Throwable): String {
            // An error's message is fit for logs: it never carries claims,
            // a URL's path or query, or a remote party's own text.
            android.util.Log.w("DemoWallet", e.toString())
            return describeOnly(e)
        }

        private fun describeOnly(e: Throwable): String =
            if (e is WalletException) "${e.description} (${e.code}${e.protocolError?.let { ": $it" } ?: ""})" else e.message ?: e.toString()
    }
}
