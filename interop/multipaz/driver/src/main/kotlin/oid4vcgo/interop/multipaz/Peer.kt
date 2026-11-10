package oid4vcgo.interop.multipaz

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File

/**
 * OID4VCgo's side (../scripts/peer), as a child process: one JSON
 * object per line each way.
 */
class Peer(binary: String, dir: File, log: File, verifier: String, setupIssuer: String, issuer: String) : AutoCloseable {
    private val process = ProcessBuilder(
        binary, "-dir", dir.path, "-verifier", verifier, "-setup-issuer", setupIssuer, "-issuer", issuer,
    )
        .redirectError(ProcessBuilder.Redirect.appendTo(log))
        .start()
    private val input = process.outputStream.bufferedWriter()
    private val output = process.inputStream.bufferedReader()

    init {
        val ready = output.readLine() ?: error("the peer exited before it was ready; see ${log.path}")
        check(Json.parseToJsonElement(ready).jsonObject["ready"]?.jsonPrimitive?.content == "true") { "the peer said $ready" }
    }

    /** Sends [op] with [args], and returns the answer: [Reply.error] says why it failed. */
    fun call(op: String, vararg args: Pair<String, Any?>): Reply {
        val request = buildJsonObject {
            put("op", JsonPrimitive(op))
            for ((name, value) in args) {
                when (value) {
                    null -> continue
                    is Boolean -> put(name, JsonPrimitive(value))
                    else -> put(name, JsonPrimitive(value.toString()))
                }
            }
        }
        input.write(request.toString())
        input.newLine()
        input.flush()
        val line = output.readLine() ?: error("the peer exited")
        return Reply(Json.parseToJsonElement(line).jsonObject)
    }

    override fun close() {
        input.close()
        process.waitFor()
    }
}

/** The peer's answer to one request. */
class Reply(val json: JsonObject) {
    fun string(name: String): String? = json[name]?.jsonPrimitive?.content
    val error: String? get() = string("error")
    val claims: Map<String, String>
        get() = json["claims"]?.jsonObject?.mapValues { it.value.jsonPrimitive.content } ?: emptyMap()
    override fun toString() = json.toString()
}
