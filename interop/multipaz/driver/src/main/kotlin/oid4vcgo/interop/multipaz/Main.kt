package oid4vcgo.interop.multipaz

import kotlinx.coroutines.runBlocking
import org.multipaz.crypto.X509Cert
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.trustmanagement.TrustManager
import org.multipaz.trustmanagement.TrustMetadata
import java.io.File
import kotlin.system.exitProcess

/**
 * Runs every case between Multipaz and OID4VCgo's peer and prints one
 * line each, "ok" or "FAIL"; exits 1 if any failed.
 *
 * Usage: driver -peer BINARY -dir DIR
 */
fun main(args: Array<String>) {
    val flags = args.toList().chunked(2).associate { it[0] to it.getOrNull(1) }
    val peerBinary = flags["-peer"] ?: usage()
    val dir = File(flags["-dir"] ?: usage())
    val failed = runBlocking {
        val pki = Pki.create()
        File(dir, "mpz-iaca.pem").writeText(pki.iaca.toPem())
        File(dir, "mpz-reader-ca.pem").writeText(pki.readerRoot.toPem())
        Peer(peerBinary, dir, File(dir, "peer.log")).use { peer ->
            val goIACA = X509Cert.fromPem(File(dir, "go-iaca.pem").readText())
            val goReaderCA = X509Cert.fromPem(File(dir, "go-reader-ca.pem").readText())
            val issuerTrust = TrustManager(EphemeralStorage()).apply {
                addX509Cert(goIACA, TrustMetadata(displayName = "OID4VCgo IACA"))
            }
            Cases(peer, pki, Holder.create(pki, goReaderCA), issuerTrust).run()
        }
    }
    println(if (failed == 0) "RESULT: every case passed, and every control refused" else "RESULT: $failed failed")
    exitProcess(if (failed == 0) 0 else 1)
}

private fun usage(): Nothing {
    System.err.println("usage: driver -peer BINARY -dir DIR")
    exitProcess(2)
}
