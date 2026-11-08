package oid4vcgo.interop.eudi

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * The driver's configuration, as interop/eudi/scripts/setup-issuer
 * writes it (driver.json): what a Wallet Provider would give a wallet,
 * and what the issuer issues.
 */
class DriverConfig(
    val credentialIssuer: String,
    val offersUrl: String,
    val tlsTrust: List<X509Certificate>,
    val clientId: String,
    val redirectUri: String,
    val subject: String,
    val attesterIssuer: String,
    val attesterKey: ECKey,
    val attesterX5c: List<Base64>,
    val otherAttesterKey: ECKey,
    val otherAttesterX5c: List<Base64>,
    val keyAttestationKey: ECKey,
    val otherKeyAttestationKey: ECKey,
    val sdJwtConfigurationId: String,
    val mdocConfigurationId: String,
    val vct: String,
    val docType: String,
    val namespace: String,
    val claims: Map<String, String>,
    val issuerCa: List<X509Certificate>,
    val iaca: List<X509Certificate>,
    val otherCa: List<X509Certificate>,
) {
    companion object {
        fun load(path: String): DriverConfig {
            val o = Json.parseToJsonElement(File(path).readText()).jsonObject
            fun s(name: String) = o.getValue(name).jsonPrimitive.content
            fun key(name: String) = ECKey.parse(o.getValue(name).jsonObject.toString())
            fun x5c(name: String) = o.getValue(name).jsonArray.map { Base64(it.jsonPrimitive.content) }
            return DriverConfig(
                credentialIssuer = s("credential_issuer"),
                offersUrl = s("offers_url"),
                tlsTrust = certificates(s("tls_trust_pem")),
                clientId = s("client_id"),
                redirectUri = s("redirect_uri"),
                subject = s("subject"),
                attesterIssuer = s("attester_issuer"),
                attesterKey = key("attester_key"),
                attesterX5c = x5c("attester_x5c"),
                otherAttesterKey = key("other_attester_key"),
                otherAttesterX5c = x5c("other_attester_x5c"),
                keyAttestationKey = key("key_attestation_key"),
                otherKeyAttestationKey = key("other_key_attestation_key"),
                sdJwtConfigurationId = s("sdjwt_configuration_id"),
                mdocConfigurationId = s("mdoc_configuration_id"),
                vct = s("vct"),
                docType = s("doctype"),
                namespace = s("namespace"),
                claims = (o.getValue("claims") as JsonObject).mapValues { it.value.jsonPrimitive.content },
                issuerCa = certificates(s("issuer_ca_pem")),
                iaca = certificates(s("iaca_pem")),
                otherCa = certificates(s("other_ca_pem")),
            )
        }

        fun certificates(pem: String): List<X509Certificate> =
            CertificateFactory
                .getInstance("X.509")
                .generateCertificates(ByteArrayInputStream(pem.toByteArray()))
                .map { it as X509Certificate }
    }
}
