package dev.idfoundry.oid4vcwallet

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
import java.time.Instant
import java.time.OffsetDateTime
import java.util.Base64

/** An RFC 3339 time, as the Go side writes them. */
internal object InstantSerializer : KSerializer<Instant> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Instant", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Instant =
        try {
            OffsetDateTime.parse(decoder.decodeString()).toInstant()
        } catch (e: java.time.format.DateTimeParseException) {
            throw SerializationException("not an RFC 3339 time")
        }

    override fun serialize(encoder: Encoder, value: Instant): Unit = encoder.encodeString(value.toString())
}

/** A byte string, as the Go side writes them: standard base64. */
internal object Base64Serializer : KSerializer<ByteArray> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("Base64", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): ByteArray =
        try {
            Base64.getDecoder().decode(decoder.decodeString())
        } catch (e: IllegalArgumentException) {
            throw SerializationException("not base64")
        }

    override fun serialize(encoder: Encoder, value: ByteArray): Unit = encoder.encodeString(Base64.getEncoder().encodeToString(value))
}

/** A claim path element: a key, an array index, or null for every element. */
internal object PathElementSerializer : KSerializer<PathElement> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("PathElement", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): PathElement {
        val element = (decoder as JsonDecoder).decodeJsonElement()
        if (element is JsonNull) return PathElement.All
        val primitive = element as? JsonPrimitive ?: throw SerializationException("not a path element")
        if (primitive.isString) return PathElement.Key(primitive.content)
        return PathElement.Index(primitive.intOrNull ?: throw SerializationException("not a path element"))
    }

    override fun serialize(encoder: Encoder, value: PathElement) {
        when (value) {
            is PathElement.Key -> encoder.encodeString(value.key)
            is PathElement.Index -> encoder.encodeInt(value.index)
            PathElement.All -> encoder.encodeNull()
        }
    }
}
