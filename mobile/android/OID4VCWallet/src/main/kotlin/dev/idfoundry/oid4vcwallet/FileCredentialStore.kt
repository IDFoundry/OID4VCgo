package dev.idfoundry.oid4vcwallet

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore as JavaKeyStore
import java.util.concurrent.ConcurrentHashMap
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
 *
 * A [directory] of your own should be one no backup copies too
 * (`noBackupFilesDir`, or excluded in the app's backup rules): a
 * restored record can't be read without the key, which isn't restored.
 * [records] skips a record that doesn't decrypt, logging its ID, rather
 * than make every other credential unreadable; [record] reports it.
 *
 * Every write takes an exclusive lock on a lock file in the directory —
 * a [java.nio.channels.FileChannel] lock, which excludes other
 * processes, inside a lock per directory, which excludes this one's
 * other threads and stores — so [compareAndSwap] is atomic across every
 * process and store using the directory. Reads take none: each record
 * is written whole and moved into place, so a reader never sees part of
 * one.
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
        val keyAlias: String = FileCredentialStore.DEFAULT_KEY_ALIAS,
    )

    /** This process's lock on the directory, shared by every store on it. */
    private val directoryLock: ReentrantLock

    init {
        if (!directory.isDirectory && !directory.mkdirs()) throw StoreException("can't create the store's directory")
        directoryLock = directoryLocks.computeIfAbsent(directory.canonicalPath) { ReentrantLock() }
    }

    /** Records are files: they survive the app quitting. */
    override val isDurable: Boolean get() = true

    override fun put(id: String, record: ByteArray) {
        val target = file(id)
        val sealed = seal(id, record)
        withStoreLock { write(id, target, sealed) }
    }

    override fun record(id: String): ByteArray? {
        val sealed = read(file(id)) ?: return null
        return open(id, sealed)
    }

    override fun records(): List<ByteArray> {
        val files = directory.listFiles { f -> f.isFile && f.name.endsWith(SUFFIX) && !f.name.startsWith(".") }.orEmpty()
            .sortedBy { it.name }
            .mapNotNull { f -> read(f)?.let { f.name.removeSuffix(SUFFIX) to it } } // one deleted meanwhile isn't listed
        return files.mapNotNull { (id, sealed) ->
            try {
                open(id, sealed)
            } catch (e: StoreException) {
                Log.w(TAG, "skipping credential record $id: ${e.message}")
                null
            }
        }
    }

    override fun delete(id: String) {
        val f = file(id)
        withStoreLock { remove(id, f) }
    }

    override fun compareAndSwap(id: String, expected: ByteArray?, record: ByteArray?): ByteArray? {
        val target = file(id)
        // Sealed, and the key made if need be, before the lock: making
        // the key takes it too.
        val sealed = record?.let { seal(id, it) } ?: run { key(); null }
        return withStoreLock {
            val current = read(target)?.let { open(id, it) }
            if (current.contentEquals(expected)) {
                if (sealed == null) remove(id, target) else write(id, target, sealed)
            }
            current
        }
    }

    /**
     * Runs [body] holding the store's exclusive lock: this process's lock
     * on the directory, then a [java.nio.channels.FileChannel] lock on its
     * lock file, which other processes take too. (A FileChannel lock is
     * held per process, so it can't exclude this one's other threads.)
     */
    private fun <T> withStoreLock(body: () -> T): T = directoryLock.withLock {
        val file = try {
            RandomAccessFile(File(directory, LOCK_FILE), "rw")
        } catch (e: IOException) {
            throw StoreException("can't open the credential store's lock file")
        }
        file.use {
            val held = try {
                it.channel.lock()
            } catch (e: IOException) {
                throw StoreException("can't lock the credential store")
            }
            try {
                body()
            } finally {
                held.release()
            }
        }
    }

    /** Writes [sealed] whole to a new file, then moves it over [target]: a reader never sees half a record. */
    private fun write(id: String, target: File, sealed: ByteArray) {
        var temp: File? = null
        try {
            temp = File.createTempFile(".$id.", ".tmp", directory)
            // Synced before the move, so a crash can't leave a renamed
            // but empty record.
            FileOutputStream(temp).use { out ->
                out.write(sealed)
                out.fd.sync()
            }
            Files.move(temp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: IOException) {
            temp?.let { Files.deleteIfExists(it.toPath()) }
            throw StoreException("can't write credential record $id")
        }
    }

    private fun remove(id: String, f: File) {
        try {
            Files.deleteIfExists(f.toPath())
        } catch (e: IOException) {
            throw StoreException("can't delete credential record $id")
        }
    }

    /** [f]'s contents, or null when there's no such file. */
    private fun read(f: File): ByteArray? = try {
        f.readBytes()
    } catch (e: FileNotFoundException) {
        null
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

    /** The store's key, made on first use — by one process: made under the store's lock. */
    private fun key(): SecretKey = existingKey() ?: withStoreLock { existingKey() ?: newKey() }

    private fun existingKey(): SecretKey? =
        JavaKeyStore.getInstance(PROVIDER).apply { load(null) }.getKey(options.keyAlias, null) as? SecretKey

    private fun newKey(): SecretKey {
        if (directory.listFiles { f -> f.name.endsWith(SUFFIX) }.orEmpty().isNotEmpty()) {
            // Restored files, or a deleted key: they're unreadable now.
            Log.w(TAG, "the store's key is missing: making a new one, so its existing records can't be read")
        }
        val spec = KeyGenParameterSpec.Builder(options.keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            // API 28's: below it, WHEN_UNLOCKED holds only until the
            // first unlock since boot, as AFTER_FIRST_UNLOCK does.
            .apply { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setUnlockedDeviceRequired(options.protection == Protection.WHEN_UNLOCKED) }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER).run {
            init(spec)
            generateKey()
        }
    }

    /** Stores in the app's standard places. */
    public companion object {
        /** The default store key's alias, which no key store's sweep may reach. */
        internal const val DEFAULT_KEY_ALIAS = "org.idfoundry.oid4vcgo.store.credentials"
        private const val TAG = "OID4VCWallet"
        private const val PROVIDER = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val SUFFIX = ".rec"

        /** The file every write locks: hidden, so never a record. */
        private const val LOCK_FILE = ".lock"
        private const val VERSION: Byte = 1
        private const val IV_BYTES = 12
        private const val TAG_BYTES = 16

        /** Each directory's lock in this process, by canonical path: every store on it shares one. */
        private val directoryLocks = ConcurrentHashMap<String, ReentrantLock>()

        /** A store in `noBackupFilesDir/credentials`, which no backup or device transfer copies. */
        public fun standard(context: Context, options: Options = Options()): FileCredentialStore =
            FileCredentialStore(File(context.noBackupFilesDir, "credentials"), options)
    }
}
