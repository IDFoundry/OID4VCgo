package dev.idfoundry.oid4vcwallet

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore as JavaKeyStore
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.concurrent.withLock

/**
 * A credential store of files: one per credential record, in a
 * directory of the app's (`noBackupFilesDir/credentials`, by default,
 * which no backup or device transfer copies). Each record is encrypted
 * (AES-256-GCM, its ID as associated data) under an Android Keystore key
 * that, by default, works only while the device is unlocked — iOS's
 * complete file protection. A credential is useless without its holder
 * key, which is in this device's Keystore and can't be restored
 * elsewhere; so is a record without the store's key.
 */
public class FileCredentialStore(
    /** The directory the records are kept in. */
    public val directory: File,
    /** How the records are encrypted. */
    public val options: Options = Options(),
) : CredentialStore {
    /** When records can be read and written. */
    public enum class Protection {
        /** Only while the device is unlocked. The default. */
        WHEN_UNLOCKED,

        /**
         * Whenever the device has been unlocked once since it started:
         * file-based encryption's credential-encrypted storage alone, as
         * iOS's "until first user authentication". For an app that must
         * read credentials while locked.
         */
        AFTER_FIRST_UNLOCK,
    }

    /**
     * How a [FileCredentialStore] encrypts its records: by default under a key that works only
     * while the device is unlocked.
     */
    public data class Options(
        /** When records can be read and written. */
        val protection: Protection = Protection.WHEN_UNLOCKED,
        /**
         * The Keystore alias of the key the records are encrypted under.
         * Deleting it makes every record unreadable. The key is made with
         * [protection] on first use, and keeps it: a store with another
         * protection needs another alias.
         */
        val keyAlias: String = "org.idfoundry.oid4vcgo.store.credentials",
    )

    private val lock = ReentrantLock()

    init {
        if (!directory.isDirectory && !directory.mkdirs()) throw StoreException("can't create the store's directory")
    }

    /** Records are files: they survive the app quitting. */
    override val isDurable: Boolean get() = true

    override fun put(id: String, record: ByteArray) {
        val target = file(id)
        val sealed = seal(id, record)
        lock.withLock {
            // Written whole, then moved over the old one: a reader never
            // sees half a record.
            val temp = File(directory, ".$id.tmp")
            try {
                temp.writeBytes(sealed)
                Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
            } catch (e: IOException) {
                Files.deleteIfExists(temp.toPath())
                throw StoreException("can't write credential record $id")
            }
        }
    }

    override fun record(id: String): ByteArray? {
        val f = file(id)
        val sealed = lock.withLock { if (f.isFile) f.readBytes() else null } ?: return null
        return open(id, sealed)
    }

    override fun records(): List<ByteArray> {
        val files = lock.withLock {
            directory.listFiles { f -> f.isFile && f.name.endsWith(SUFFIX) && !f.name.startsWith(".") }.orEmpty()
                .sortedBy { it.name }
                .map { it.name.removeSuffix(SUFFIX) to it.readBytes() }
        }
        return files.map { (id, sealed) -> open(id, sealed) }
    }

    override fun delete(id: String) {
        val f = file(id)
        try {
            lock.withLock { Files.deleteIfExists(f.toPath()) }
        } catch (e: IOException) {
            throw StoreException("can't delete credential record $id")
        }
    }

    private fun file(id: String): File {
        if (id.isEmpty() || !id.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '_' }) {
            throw StoreException("malformed credential ID")
        }
        return File(directory, id + SUFFIX)
    }

    /** version (1) || 12-byte IV || ciphertext and tag, the record's ID bound as associated data. */
    private fun seal(id: String, record: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(id.toByteArray())
        return byteArrayOf(VERSION) + cipher.iv + cipher.doFinal(record)
    }

    private fun open(id: String, sealed: ByteArray): ByteArray {
        if (sealed.size < 1 + IV_BYTES + TAG_BYTES || sealed[0] != VERSION) throw StoreException("credential record $id is malformed")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BYTES * 8, sealed, 1, IV_BYTES))
        cipher.updateAAD(id.toByteArray())
        return try {
            cipher.doFinal(sealed, 1 + IV_BYTES, sealed.size - 1 - IV_BYTES)
        } catch (e: javax.crypto.AEADBadTagException) {
            throw StoreException("credential record $id doesn't decrypt")
        }
    }

    /** The store's key, made on first use. */
    private fun key(): SecretKey = lock.withLock {
        val keystore = JavaKeyStore.getInstance(PROVIDER).apply { load(null) }
        (keystore.getKey(options.keyAlias, null) as? SecretKey) ?: run {
            val spec = KeyGenParameterSpec.Builder(options.keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                // API 28's: below it, WHEN_UNLOCKED holds only until the
                // first unlock since boot, as AFTER_FIRST_UNLOCK does.
                .apply { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setUnlockedDeviceRequired(options.protection == Protection.WHEN_UNLOCKED) }
                .build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).run {
                init(spec)
                generateKey()
            }
        }
    }

    public companion object {
        private const val PROVIDER = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val SUFFIX = ".rec"
        private const val VERSION: Byte = 1
        private const val IV_BYTES = 12
        private const val TAG_BYTES = 16

        /** A store in `noBackupFilesDir/credentials`, which no backup or device transfer copies. */
        public fun standard(context: Context, options: Options = Options()): FileCredentialStore =
            FileCredentialStore(File(context.noBackupFilesDir, "credentials"), options)
    }
}
