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
 * A wallet instance registered with a Wallet Provider: the instance key
 * and the instance ID the provider gave for it (WALLET_PROVIDER.md,
 * `POST /v1/instances`).
 *
 * @property keyThumbprint The instance key's JWK SHA-256 thumbprint
 *   (RFC 7638), base64url: what [HttpWalletProvider] finds it by.
 * @property keyID The instance key's ID in the wallet's [KeyStore], which
 *   signs the instance's requests.
 * @property instanceID The provider's instance ID.
 */
@Serializable
public data class RegisteredInstance(
    @SerialName("key_thumbprint") val keyThumbprint: String,
    @SerialName("key_id") val keyID: String,
    @SerialName("instance_id") val instanceID: String,
)

/**
 * Where [HttpWalletProvider] keeps the instances it registered, so each
 * instance key registers once, across launches. An instance ID isn't a
 * secret — every request naming it is signed with the instance key —
 * but losing it loses the instance: the provider registers each key
 * once (`instance_key_registered`). [FileInstanceRegistry] keeps them in
 * a file; [InMemoryInstanceRegistry] is for tests.
 *
 * Called on Go's thread, never the main one; an exception it throws
 * fails the attestation as [WalletException.Code.platform].
 */
public interface InstanceRegistry {
    /** Every registered instance, the most recently [put] last. */
    public fun instances(): List<RegisteredInstance>

    /**
     * Records [instance], replacing any with its key thumbprint, as the
     * most recent.
     */
    public fun put(instance: RegisteredInstance)

    /** Forgets the instance with [keyThumbprint]; forgetting one that isn't there isn't an error. */
    public fun remove(keyThumbprint: String)
}

/** An [InstanceRegistry] in memory, lost when the app quits: for tests. */
public class InMemoryInstanceRegistry : InstanceRegistry {
    private val entries = LinkedHashMap<String, RegisteredInstance>()

    @Synchronized
    override fun instances(): List<RegisteredInstance> = entries.values.toList()

    @Synchronized
    override fun put(instance: RegisteredInstance) {
        entries.remove(instance.keyThumbprint)
        entries[instance.keyThumbprint] = instance
    }

    @Synchronized
    override fun remove(keyThumbprint: String) {
        entries.remove(keyThumbprint)
    }
}

/**
 * An [InstanceRegistry] in a JSON file ([file]), written whole and moved
 * into place, so a reader never sees part of it. It keeps the most recent
 * [MAX_INSTANCES]. Writes in this process are serialised per file; keep
 * one wallet process writing it. Put it where no backup copies it
 * ([standard]: `noBackupFilesDir`): a restored instance ID is useless
 * without its instance key, which stays in this device's Keystore.
 */
public class FileInstanceRegistry(
    /** The file the instances are kept in; its directory is made if missing. */
    public val file: File,
) : InstanceRegistry {
    private val lock: Any = locks.computeIfAbsent(file.absoluteFile.normalize().path) { Any() }

    override fun instances(): List<RegisteredInstance> = synchronized(lock) { read() }

    override fun put(instance: RegisteredInstance): Unit = synchronized(lock) {
        val list = read().filter { it.keyThumbprint != instance.keyThumbprint } + instance
        write(list.takeLast(MAX_INSTANCES))
    }

    override fun remove(keyThumbprint: String): Unit = synchronized(lock) {
        val list = read()
        if (list.any { it.keyThumbprint == keyThumbprint }) write(list.filter { it.keyThumbprint != keyThumbprint })
    }

    private fun read(): List<RegisteredInstance> {
        if (!file.exists()) return emptyList()
        val text = file.readText()
        return try {
            json.decodeFromString(Contents.serializer(), text).instances
        } catch (e: kotlinx.serialization.SerializationException) {
            throw StoreException("the instance registry ${file.name} is malformed")
        } catch (e: IllegalArgumentException) {
            throw StoreException("the instance registry ${file.name} is malformed")
        }
    }

    private fun write(list: List<RegisteredInstance>) {
        val dir = file.absoluteFile.parentFile ?: throw IOException("the instance registry has no directory")
        if (!dir.isDirectory && !dir.mkdirs()) throw StoreException("can't create the instance registry's directory")
        val temp = File.createTempFile(".instances", ".tmp", dir)
        try {
            temp.writeText(json.encodeToString(Contents.serializer(), Contents(list)))
            Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } finally {
            Files.deleteIfExists(temp.toPath())
        }
    }

    @Serializable
    private class Contents(
        @SerialName("instances") val instances: List<RegisteredInstance>,
    )

    /** Registries in the app's standard place. */
    public companion object {
        /** The most instances a [FileInstanceRegistry] keeps: the oldest go first. */
        public const val MAX_INSTANCES: Int = 64

        private val locks = ConcurrentHashMap<String, Any>()

        /** A registry in `noBackupFilesDir/walletprovider/instances.json`, which no backup or device transfer copies. */
        public fun standard(context: Context): FileInstanceRegistry =
            FileInstanceRegistry(File(File(context.noBackupFilesDir, "walletprovider"), "instances.json"))
    }
}
