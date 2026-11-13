package dev.idfoundry.oid4vcgo.demowallet

import android.app.Activity
import dev.idfoundry.oid4vcwallet.CombinedPresentation
import dev.idfoundry.oid4vcwallet.MdocPresentation
import dev.idfoundry.oid4vcwallet.NfcPresentation
import dev.idfoundry.oid4vcwallet.ProximityPresentation
import dev.idfoundry.oid4vcwallet.SelectedEngagement
import kotlinx.coroutines.flow.StateFlow

/** The holder's side of one in-person session: a QR code, an NFC tap, or both offered at once. */
sealed interface InPersonSession {
    /** The QR code to show; empty when the session offers none. */
    val qrCode: String
    val state: StateFlow<ProximityPresentation.State>
    /** Whether the session answers NFC taps, and so needs this app preferred for NFC. */
    val nfc: Boolean get() = false
    /** With QR and NFC both offered, the one the reader used; null until then. */
    val selected: StateFlow<SelectedEngagement?>? get() = null

    suspend fun respond(answers: List<MdocPresentation.Answer>)
    suspend fun decline()
    fun cancel()
    /** Prefers this app for NFC while [activity] is resumed; false if Android refused. */
    fun preferForeground(activity: Activity): Boolean = true
    fun releaseForeground(activity: Activity) {
        // Nothing to release: only NFC sessions prefer this app for NFC.
    }
    /** Withdraws the offers and waits for the radios to be released. */
    suspend fun close() = cancel()

    class Qr(private val p: ProximityPresentation) : InPersonSession {
        override val qrCode get() = p.qrCode
        override val state get() = p.state
        override suspend fun respond(answers: List<MdocPresentation.Answer>) { p.respond(answers) }
        override suspend fun decline() = p.decline()
        override fun cancel() = p.cancel()
        override suspend fun close() {
            p.cancel()
            p.awaitClosed()
        }
    }

    class Nfc(private val owner: NfcPresentation) : InPersonSession {
        override val qrCode get() = ""
        override val state get() = owner.presentation.state
        override val nfc get() = true
        override suspend fun respond(answers: List<MdocPresentation.Answer>) { owner.presentation.respond(answers) }
        override suspend fun decline() = owner.presentation.decline()
        override fun cancel() = owner.presentation.cancel()
        override fun preferForeground(activity: Activity) = owner.preferForeground(activity, DemoNfcService::class.java)
        override fun releaseForeground(activity: Activity) { owner.releaseForeground(activity) }
        override suspend fun close() = owner.close()
    }

    class Combined(private val c: CombinedPresentation) : InPersonSession {
        override val qrCode get() = c.qrCode
        override val state get() = c.state
        override val nfc get() = true
        override val selected get() = c.selectedEngagement
        override suspend fun respond(answers: List<MdocPresentation.Answer>) { c.respond(answers) }
        override suspend fun decline() = c.decline()
        override fun cancel() = c.cancel()
        override fun preferForeground(activity: Activity) = c.preferForeground(activity, DemoNfcService::class.java)
        override fun releaseForeground(activity: Activity) { c.releaseForeground(activity) }
        override suspend fun close() = c.close()
    }
}
