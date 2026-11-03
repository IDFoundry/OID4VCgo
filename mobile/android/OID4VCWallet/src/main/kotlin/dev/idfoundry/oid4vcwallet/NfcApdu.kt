package dev.idfoundry.oid4vcwallet

import java.io.IOException
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile
import dev.idfoundry.oid4vcwallet.gomobile.mobile.NFCExchange as MobileNfcExchange
import dev.idfoundry.oid4vcwallet.gomobile.mobile.NFCHolder as MobileNfcHolder

/** A response APDU carrying only [status]. Every byte the reader sends is parsed in Go. */
internal fun nfcResponse(status: Int): ByteArray = byteArrayOf((status ushr 8).toByte(), status.toByte())

/** What a command APDU selects, as Go's ClassifyNFCCommand reports it. */
internal object NfcCommandKind {
    const val OTHER = 0
    const val SELECT_NDEF = 1
    const val SELECT_DATA = 2
    const val SELECT_OTHER = 4
}

/** What the holder did with one command APDU. */
internal class NfcStep(
    val response: ByteArray?,
    val handoverRead: Boolean = false,
    val dataSelected: Boolean = false,
    /** A session message from the reader; [response] is null and the answer goes through [NfcHolderCore.respond]. */
    val message: ByteArray? = null,
    val delivered: Boolean = false,
)

internal class NfcDeactivation(val cancel: Boolean, val dataClosed: Boolean)

/**
 * The mdoc's NFC tag: Go's NFCHolder, which parses every command APDU and
 * builds every response. Host tests substitute a scripted one.
 */
internal interface NfcHolderCore {
    fun classify(command: ByteArray): Int
    fun process(command: ByteArray): NfcStep
    fun respond(message: ByteArray): NfcStep
    fun refuseMessage(): ByteArray
    fun deactivate(handoverCommitted: Boolean, qrSelected: Boolean): NfcDeactivation
    fun close()
}

internal class GoNfcHolder(private val holder: MobileNfcHolder) : NfcHolderCore {
    override fun classify(command: ByteArray): Int = Mobile.classifyNFCCommand(command).toInt()
    override fun process(command: ByteArray): NfcStep = step(holder.process(command))
    override fun respond(message: ByteArray): NfcStep = step(holder.respond(message))
    override fun refuseMessage(): ByteArray = holder.refuseMessage()
    override fun deactivate(handoverCommitted: Boolean, qrSelected: Boolean): NfcDeactivation =
        holder.deactivate(handoverCommitted, qrSelected).let { NfcDeactivation(it.cancel, it.dataClosed) }
    override fun close() = holder.close()

    private fun step(s: dev.idfoundry.oid4vcwallet.gomobile.mobile.NFCStep) = NfcStep(
        response = if (s.hasMessage) null else s.response,
        handoverRead = s.handoverRead,
        dataSelected = s.dataSelected,
        message = if (s.hasMessage) s.message ?: byteArrayOf() else null,
        delivered = s.delivered,
    )
}

/** A reader's sequence of command APDUs, each depending on the last response: Go's NFCExchange. */
internal interface NfcCommandSequence {
    fun done(): Boolean
    /** How long to wait before sending [command] (TNEP's waiting time). */
    fun waitMillis(): Long
    fun command(): ByteArray
    fun next(response: ByteArray)
    fun result(): ByteArray
    fun close()
}

internal class GoNfcExchange(private val x: MobileNfcExchange) : NfcCommandSequence {
    override fun done(): Boolean = x.done()
    override fun waitMillis(): Long = x.waitMillis()
    override fun command(): ByteArray = x.command()
    override fun next(response: ByteArray) = x.next(response)
    override fun result(): ByteArray = x.result()
    override fun close() = x.close()
    fun negotiated(): Boolean = x.negotiated()
}

/**
 * Runs a reader's sequence over [exchange]: sends each command after the
 * wait the sequence asks for, here, where cancellation interrupts it.
 */
internal fun NfcCommandSequence.drive(exchange: (ByteArray) -> ByteArray): ByteArray {
    try {
        while (!done()) {
            val wait = waitMillis()
            if (wait > 0) Thread.sleep(wait)
            next(exchange(command()))
        }
        return try { result() } catch (e: Exception) { throw IOException(e.message, e) }
    } finally {
        close()
    }
}

/** The NFC data reader's APDUs, built and parsed by Go; host tests substitute their own. */
internal interface NfcDataCodec {
    fun selectCommand(): ByteArray
    fun checkSelected(response: ByteArray)
    fun transact(maxTransceive: Int, parameters: NfcDataParametersJSON, message: ByteArray): NfcCommandSequence
}

internal object GoNfcDataCodec : NfcDataCodec {
    override fun selectCommand(): ByteArray = Mobile.nfcSelectDataApplication()
    override fun checkSelected(response: ByteArray) {
        try { Mobile.checkNFCDataApplicationSelected(response) } catch (e: Exception) { throw IOException(e.message, e) }
    }
    override fun transact(maxTransceive: Int, parameters: NfcDataParametersJSON, message: ByteArray): NfcCommandSequence =
        GoNfcExchange(Mobile.newNFCTransact(maxTransceive.toLong(), parameters.maxCommand.toLong(), parameters.maxResponse.toLong(), message))
}
