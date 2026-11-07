package dev.idfoundry.oid4vcwallet

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore as JavaKeyStore
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * The key authenticating the status lists a `statusCacheDir` keeps
 * (`status_cache_key` in ABI.md): 32 random bytes, made on first use and
 * kept in the directory wrapped by an Android Keystore key, so that a
 * list anyone else wrote to the directory is dropped rather than used.
 * A 304 from a list's server confirms the `ETag` a kept list names, not
 * the list kept with it. Whoever can write the directory can only
 * replace or remove the wrapped key, which makes a new key: the lists
 * kept under the old one are then downloaded again.
 */
internal object StatusCacheKey {
    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS = "dev.idfoundry.oid4vcwallet.statuscachekey"
    private const val FILE = ".status-cache-key"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_BYTES = 12
    private const val TAG_BYTES = 16
    const val KEY_BYTES = 32

    /** The directory a null `statusCacheDir` keeps lists in, in the app's cache directory. */
    const val DEFAULT_DIR = "oid4vcwallet-status-lists"

    /** Where the key for a directory comes from: the Keystore-wrapped file, unless a test replaced it. */
    @Volatile
    var source: (File) -> ByteArray = ::wrappedKey

    /**
     * Where a null `statusCacheDir` keeps lists, unless a test replaced
     * it: [DEFAULT_DIR] in `java.io.tmpdir`, which Android sets to the
     * app's `context.cacheDir` as each of its processes starts. It's a
     * process-wide property any code in the app can change, though, and
     * a process that can't use the app's storage (an isolated one, a
     * service running under another uid) has it naming a directory not
     * its own, or nothing; so it's used only when [appCacheDir] finds
     * it's this app's own cache directory, and is null otherwise.
     */
    @Volatile
    var defaultDir: () -> File? = {
        appCacheDir(System.getProperty("java.io.tmpdir"), ::ownerUid, android.os.Process.myUid())?.let { File(it, DEFAULT_DIR) }
    }

    /**
     * An app's own cache directory's canonical path, in its
     * credential-encrypted or device-encrypted storage, on internal or
     * adopted storage: `/data/data/<package>/cache` or
     * `/data/user/<user>/<package>/cache`, say.
     */
    private val appCachePath = Regex("""(/data/data|/data/user(_de)?/\d+|/mnt/expand/[^/]+/user(_de)?/\d+)/[^/]+/cache""")

    /**
     * [tmpdir], made canonical, when it's an app's cache directory owned
     * by [uid], this process's ([ownerOf] says whose a directory is):
     * null otherwise, or when it can't be told.
     */
    fun appCacheDir(tmpdir: String?, ownerOf: (File) -> Int?, uid: Int): File? {
        if (tmpdir.isNullOrEmpty()) return null
        val dir = runCatching { File(tmpdir).canonicalFile }.getOrNull() ?: return null
        if (!appCachePath.matches(dir.path)) return null
        return dir.takeIf { runCatching { ownerOf(it) }.getOrNull() == uid }
    }

    /** Whose [dir] is: its owner's uid, or null when it can't be told. */
    private fun ownerUid(dir: File): Int? = runCatching { android.system.Os.stat(dir.path).st_uid }.getOrNull()

    /**
     * [encoded], a configuration's JSON, keeping lists in
     * [statusCacheDir] with the `status_cache_key` that authenticates
     * them. Empty keeps them in memory only. Null keeps them in
     * [defaultDir], or in memory only when there's none or its key
     * can't be had (nor the directory made): the default never stops a
     * wallet being made.
     */
    fun configuration(encoded: String, statusCacheDir: String?): String {
        if (statusCacheDir?.isEmpty() == true) return encoded
        val dir = statusCacheDir?.let(::File) ?: defaultDir() ?: return encoded
        val key = if (statusCacheDir != null) source(dir) else runCatching { source(dir) }.getOrNull() ?: return encoded
        val config = json.parseToJsonElement(encoded).jsonObject
        return JsonObject(
            config + mapOf(
                "status_cache_dir" to JsonPrimitive(dir.path),
                "status_cache_key" to JsonPrimitive(Base64.getEncoder().encodeToString(key)),
            ),
        ).toString()
    }

    /** The key kept in [dir], made and kept there, wrapped, when there's none it can unwrap. */
    @Synchronized
    private fun wrappedKey(dir: File): ByteArray {
        val file = File(dir, FILE)
        val keystoreKey = keystoreKey()
        runCatching { unwrap(keystoreKey, file.readBytes()) }.getOrNull()?.let { return it }
        val key = ByteArray(KEY_BYTES).also { SecureRandom().nextBytes(it) }
        val wrap = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, keystoreKey) }
        val wrapped = wrap.iv + wrap.doFinal(key)
        if (!dir.isDirectory && !dir.mkdirs()) throw StoreException("can't create the status cache directory")
        val tmp = File.createTempFile(".key-", ".tmp", dir)
        try {
            tmp.writeBytes(wrapped)
            if (!tmp.renameTo(file)) throw StoreException("can't keep the status cache key")
        } finally {
            // Gone once renamed; a leftover is retried when the process ends.
            if (tmp.exists() && !tmp.delete()) tmp.deleteOnExit()
        }
        return key
    }

    private fun unwrap(keystoreKey: SecretKey, wrapped: ByteArray): ByteArray? {
        if (wrapped.size != IV_BYTES + KEY_BYTES + TAG_BYTES) return null
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, keystoreKey, GCMParameterSpec(TAG_BYTES * 8, wrapped, 0, IV_BYTES))
        }
        return cipher.doFinal(wrapped, IV_BYTES, wrapped.size - IV_BYTES)
    }

    /** The Keystore key wrapping each directory's key, made on first use. */
    private fun keystoreKey(): SecretKey {
        val ks = JavaKeyStore.getInstance(PROVIDER).apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).run {
            init(spec)
            generateKey()
        }
    }
}
