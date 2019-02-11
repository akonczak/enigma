package com.bluehex.enigma

import com.bluehex.enigma.PEMUtil.Companion.CERT_BEGIN
import com.bluehex.enigma.PEMUtil.Companion.CERT_END
import com.bluehex.enigma.PEMUtil.Companion.KEY_BEGIN
import com.bluehex.enigma.PEMUtil.Companion.KEY_END
import org.hamcrest.CoreMatchers.`is`
import org.junit.Assert.assertThat
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.security.cert.X509Certificate
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal class PEMUtilTest {

    private fun cert(base64: String): String = "$CERT_BEGIN$base64$CERT_END"

    private fun key(base64: String): String = "$KEY_BEGIN$base64$KEY_END"

    @Test
    fun shouldSplitCertContent() {
        val multiCertificateContent = "${cert("a")}${cert("b")}"
        val certs = PEMUtil.splitCerts(multiCertificateContent)
        assertThat(certs.size, `is`(2))
        assertThat(certs[0], `is`("${cert("a")}"))
        assertThat(certs[1], `is`("${cert("b")}"))
    }

    @Test
    fun shouldDetectCert() {
        assertTrue { PEMUtil.isCert("${cert("a")}${cert("b")}") }
        assertTrue { PEMUtil.isCert("${cert("a")}") }
        assertFalse { PEMUtil.isCert("$CERT_BEGIN") }
        assertFalse { PEMUtil.isCert("") }
    }

    @Test
    fun shouldDetectKey() {
        assertTrue { PEMUtil.isKey("${key("a")}${key("b")}") }
        assertTrue { PEMUtil.isKey("${key("a")}") }
        assertFalse { PEMUtil.isKey("$KEY_BEGIN") }
        assertFalse { PEMUtil.isKey("") }
    }


    @Test
    fun shouldReadCertificateFromFile() {
        val certificate = PEMUtil.certificate(fileContent("certificate.pem"))
        val first:X509Certificate = certificate.first() as X509Certificate
        assertThat(first.serialNumber, `is`(BigInteger("17819279867143787359")))
    }

    private fun fileContent(name: String): String {
        return javaClass.classLoader.getResource(name).readText()
    }

}


