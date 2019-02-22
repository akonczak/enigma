package com.bluehex.enigma

import java.io.InputStream
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.interfaces.RSAPrivateKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import kotlin.text.RegexOption.IGNORE_CASE


/**
 * PEM format
 *
 * 1. start tag
 * 2. content of the key encoded in base 64
 * 3. end tag
 *
 */
class PEMUtil {

    companion object {
        const val CERT_BEGIN: String = "-----BEGIN CERTIFICATE-----"
        const val CERT_END: String = "-----END CERTIFICATE-----"

        const val KEY_BEGIN: String = "-----BEGIN PRIVATE KEY-----"
        const val KEY_END: String = "-----END PRIVATE KEY-----"

        private val keyFactory = KeyFactory.getInstance("RSA")

        private val CERTIFICATE_PATTERN = """$CERT_BEGIN(?:\s|\r|\n)?([a-z0-9+/=\r\n]+)$CERT_END""".toRegex(IGNORE_CASE)

        private val KEY_PATTERN = """$KEY_BEGIN(?:\s|\r|\n)?([a-z0-9+/=\r\n]+)$KEY_END""".toRegex(IGNORE_CASE)

        @Throws(InvalidKeySpecException::class)
        fun readPrivateKey(input: InputStream): PrivateKey {
            KEY_PATTERN.find(readStream(input))?.let { result ->
                result.groups[1]?.let {
                    val decode = Base64Util.decodeAsBytes(it.value.replace(Regex("\\n"), ""))
                    val keySpec = PKCS8EncodedKeySpec(decode)
                    return keyFactory.generatePrivate(keySpec) as RSAPrivateKey
                }
            }
            throw InvalidKeySpecException("Invalid PEM format for private key")
        }

        @Throws(CertificateException::class)
        fun readPublicKey(input: InputStream): List<Certificate> {
            val factory = CertificateFactory.getInstance("X.509")
            return splitCerts(readStream(input)).map { factory.generateCertificate(it.byteInputStream()) }.toList()
        }

        @Throws(CertificateException::class)
        fun readSinglePublicKey(input: InputStream): Certificate {
            val factory = CertificateFactory.getInstance("X.509")
            return factory.generateCertificate(input)
        }

        fun isCert(content: String): Boolean = CERTIFICATE_PATTERN.containsMatchIn(content)

        fun isKey(content: String): Boolean = KEY_PATTERN.containsMatchIn(content)

        fun splitCerts(multipleCertificates: String): List<String> {
            return CERTIFICATE_PATTERN.findAll(multipleCertificates).map {
                it.value
            }.toList()
        }

        fun readStream(stream: InputStream): String {
            return InputStreamReader(stream).readText()
        }

    }

}
