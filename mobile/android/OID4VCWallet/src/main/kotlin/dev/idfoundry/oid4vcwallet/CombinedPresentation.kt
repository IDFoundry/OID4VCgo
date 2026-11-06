package dev.idfoundry.oid4vcwallet

import android.app.Activity
import kotlinx.coroutines.flow.StateFlow

/** One app-level owner offering QR and NFC with a single consent flow. */
public class CombinedPresentation internal constructor(internal val owner: NfcPresentation) {
    /** QR text to display; empty when Bluetooth permission is missing. */
    public val qrCode: String get() = owner.presentation.qrCode
    /** The existing proximity consent and result states. */
    public val state: StateFlow<ProximityPresentation.State> get() = owner.presentation.state
    /** Null while waiting; records the winning engagement and retrieval transport. */
    public val selectedEngagement: StateFlow<SelectedEngagement?> get() = checkNotNull(owner.combined).state
    /** Answers the selected reader's request. */
    public suspend fun respond(document: Int, credentialID: String, elements: List<MdocPresentation.Element>): Boolean =
        owner.presentation.respond(document, credentialID, elements)
    /** Answers several of the selected reader's requested documents in one response ([ProximityPresentation.respond]). */
    public suspend fun respond(answers: List<MdocPresentation.Answer>): ProximityPresentation.Responded =
        owner.presentation.respond(answers)
    /** Declines the request. */
    public suspend fun decline(): Unit = owner.presentation.decline()
    /** Cancels both offers; use [close] to await cleanup. */
    public fun cancel(): Unit = owner.cancelCombined()
    /** Prefer the app's HCE service while its activity is resumed. May return false. */
    public fun preferForeground(activity: Activity, service: Class<out NfcEngagementService>): Boolean = owner.preferForeground(activity, service)
    /** Release the activity's foreground preference on pause. */
    public fun releaseForeground(activity: Activity): Boolean = owner.releaseForeground(activity)
    /** Withdraw both offers and await radio cleanup before starting a replacement. */
    public suspend fun close(): Unit = owner.close()
}
