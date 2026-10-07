package dev.idfoundry.oid4vcgo.demowallet

import dev.idfoundry.oid4vcwallet.KeyPurpose
import dev.idfoundry.oid4vcwallet.KeyStore
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/**
 * The demo reader's key — a software P-256 key from the configuration
 * (DemoConfiguration.Reader), its public half its certificate's — as
 * the KeyStore a ProximityReader signs with. Demo only: a real reader
 * keeps its key in Android Keystore.
 */
class DemoReaderKeys(reader: DemoConfiguration.Reader) : KeyStore {
    private val key: PrivateKey
    private val public: ECPublicKey

    init {
        val der = Base64.getMimeDecoder().decode(
            reader.readerKey.lines().filterNot { it.startsWith("-----") }.joinToString(""),
        )
        key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der))
        val leaf = CertificateFactory.getInstance("X.509").generateCertificate(reader.readerChain.byteInputStream()) as X509Certificate
        public = leaf.publicKey as ECPublicKey
    }

    override fun createKey(purpose: KeyPurpose): String = throw UnsupportedOperationException("the demo reader has one key")

    override fun publicKey(id: String): ByteArray? {
        if (id != ID) return null
        fun fixed(n: BigInteger): ByteArray = n.toByteArray().let { b -> if (b.size > 32) b.copyOfRange(b.size - 32, b.size) else ByteArray(32 - b.size) + b }
        return byteArrayOf(0x04) + fixed(public.w.affineX) + fixed(public.w.affineY)
    }

    override fun sign(id: String, digest: ByteArray): ByteArray {
        require(id == ID) { "no key $id" }
        return Signature.getInstance("NONEwithECDSA").run {
            initSign(key)
            update(digest)
            sign()
        }
    }

    override fun deleteKey(id: String) {}

    companion object {
        const val ID: String = "demo-reader"
    }
}
