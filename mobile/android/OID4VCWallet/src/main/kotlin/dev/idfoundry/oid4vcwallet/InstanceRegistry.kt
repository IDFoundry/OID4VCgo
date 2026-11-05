package dev.idfoundry.oid4vcwallet

import android.content.Context
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.ConcurrentHashMap

/**
 * The wallet's registration with a Wallet Provider: its registration
 * key and the instance ID the provider gave for it (WALLET_PROVIDER.md,
 * `POST /v1/instances`). One per installation.
 *
 * @property keyThumbprint The registration key's JWK SHA-256 thumbprint
 *   (RFC 7638), base64url: [HttpWalletProvider] checks the key store
 *   still holds that key under [keyID].
 * @property keyID The registration key's ID in [HttpWalletProvider]'s
 *   registration key store, which signs every request after registration.
 * @property instanceID The provider's instance ID.
 */
@Serializable
public data class RegisteredInstance(
    @SerialName("key_thumbprint") val keyThumbprint: String,
    @SerialName("key_id") val keyID: String,
    @SerialName("instance_id") val instanceID: String,
)

/**
 * Where [HttpWalletProvider] keeps the wallet's registration, so the
 * installation registers once, across launches. An instance ID isn't a
 * secret — every request naming it is signed with the registration key —
 * but losing it loses the instance: the wallet then registers again,
 * with a new registration key, and the instance keys the lost instance
 * recorded can't be attested again. [FileInstanceRegistry] keeps it in
 * a file; [InMemoryInstanceRegistry] is for tests.
 *
 * Called on Go's thread, never the main one; an exception it throws
 * fails the attestation as [WalletException.Code.platform].
 */
public interface InstanceRegistry {
    /** The registration kept, or null for none. */
    public fun instance(): RegisteredInstance?

    /** Keeps [instance], replacing the one kept. */
    public fun put(instance: RegisteredInstance)

    /**
     * Forgets [instance] if it's the one kept; forgetting one that isn't
     * isn't an error, and leaves the one kept.
     */
    public fun remove(instance: RegisteredInstance)
}

/** An [InstanceRegistry] in memory, lost when the app quits: for tests. */
public class InMemoryInstanceRegistry : InstanceRegistry {
    private var kept: RegisteredInstance? = null

    @Synchronized
    override fun instance(): RegisteredInstance? = kept

    @Synchronized
    override fun put(instance: RegisteredInstance) {
        kept = instance
    }

    @Synchronized
    override fun remove(instance: RegisteredInstance) {
        if (kept == instance) kept = null
    }
}

/**
 * An [InstanceRegistry] in a JSON file ([file]), written whole and moved
 * into place, so a reader never sees part of it. Writes in this process
 * are serialised per file; keep one wallet process writing it. Put it
 * where no backup copies it ([standard]: `noBackupFilesDir`): a restored
 * instance ID is useless without its registration key, which stays in
 * this device's Keystore.
 */
public class FileInstanceRegistry(
    /** The file the registration is kept in; its directory is made if missing. */
    public val file: File,
) : InstanceRegistry {
    private val lock: Any = locks.computeIfAbsent(file.absoluteFile.normalize().path) { Any() }

    override fun instance(): RegisteredInstance? = synchronized(lock) { read() }

    override fun put(instance: RegisteredInstance): Unit = synchronized(lock) { write(instance) }

    override fun remove(instance: RegisteredInstance): Unit = synchronized(lock) {
        if (read() == instance && !file.delete() && file.exists()) throw StoreException("can't delete the instance registry ${file.name}")
    }

    private fun read(): RegisteredInstance? {
        if (!file.exists()) return null
        val text = file.readText()
        return try {
            json.decodeFromString(Contents.serializer(), text).instance
        } catch (e: kotlinx.serialization.SerializationException) {
            throw StoreException(malformed())
        } catch (e: IllegalArgumentException) {
            throw StoreException(malformed())
        }
    }

    private fun malformed(): String = "the instance registry ${file.name} is malformed"

    private fun write(instance: RegisteredInstance) {
        val dir = file.absoluteFile.parentFile ?: throw IOException("the instance registry has no directory")
        if (!dir.isDirectory && !dir.mkdirs()) throw StoreException("can't create the instance registry's directory")
        val temp = File.createTempFile(".instance", ".tmp", dir)
        try {
            temp.writeText(json.encodeToString(Contents.serializer(), Contents(instance)))
            Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } finally {
            Files.deleteIfExists(temp.toPath())
        }
    }

    @Serializable
    private class Contents(
        @SerialName("instance") val instance: RegisteredInstance,
    )

    /** Registries in the app's standard place. */
    public companion object {
        private val locks = ConcurrentHashMap<String, Any>()

        /** A registry in `noBackupFilesDir/walletprovider/instance.json`, which no backup or device transfer copies. */
        public fun standard(context: Context): FileInstanceRegistry =
            FileInstanceRegistry(File(File(context.noBackupFilesDir, "walletprovider"), "instance.json"))
    }
}
