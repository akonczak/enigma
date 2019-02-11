package com.bluehex.enigma

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.StringBufferInputStream
import java.io.StringReader
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import kotlin.text.RegexOption.IGNORE_CASE


class PEMUtil {

    companion object {
        const val CERT_BEGIN: String = "-----BEGIN CERTIFICATE-----"
        const val CERT_END: String = "-----END CERTIFICATE-----"

        const val KEY_BEGIN: String = "-----BEGIN PRIVATE KEY-----"
        const val KEY_END: String = "-----END PRIVATE KEY-----"


        private val CERTIFICATE_PATTERN = """$CERT_BEGIN(?:\s|\r|\n)?([a-z0-9+/=\r\n]+)$CERT_END""".toRegex(IGNORE_CASE)

        private val KEY_PATTERN = """$KEY_BEGIN(?:\s|\r|\n)?([a-z0-9+/=\r\n]+)$KEY_END""".toRegex(IGNORE_CASE)


        fun key(input: InputStream): Any {

            return ""
        }

        fun certificate(input: String):List<Certificate>{
            val factory = CertificateFactory.getInstance("X.509")
            CERTIFICATE_PATTERN.findAll(input).map {
                Base64Util.decode(it.groups[1]!!.value)
            }

            return splitCerts(input).map { factory.generateCertificate( it.byteInputStream()) }.toList()
        }

        fun isCert(content: String): Boolean = CERTIFICATE_PATTERN.containsMatchIn(content)

        fun isKey(content: String): Boolean = KEY_PATTERN.containsMatchIn(content)

        fun splitCerts(multipleCertificates: String): List<String> {
            return CERTIFICATE_PATTERN.findAll(multipleCertificates).map {
                it.value
            }.toList()
        }

    }

}
