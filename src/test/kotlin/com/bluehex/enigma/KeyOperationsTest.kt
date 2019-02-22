package com.bluehex.enigma

import com.bluehex.enigma.FileUtil.Companion.fileContentAsStream
import org.junit.jupiter.api.Test

internal class OperationsTest {

    val publicKey = PEMUtil.readPublicKey(fileContentAsStream("certificate.pem"))
    val publicKeyOperations = PublicKeyOperations(publicKey.first().publicKey)

    val privateKey = PEMUtil.readPrivateKey(fileContentAsStream("key.pem"))
    val privateKeyOperations = PrivateKeyOperations(privateKey)

    @Test
    fun shouldEncryptAndDecrypt() {
        val encryptedMsg1 = publicKeyOperations.encrypt("test")
        val encryptedMsg2 = publicKeyOperations.encrypt("test1")
        println(Base64Util.encodeAsString(encryptedMsg1))
        println(Base64Util.encodeAsString(encryptedMsg2))

        val decryptMsg1 = privateKeyOperations.decrypt(encryptedMsg1)
        val decryptMsg2 = privateKeyOperations.decrypt(encryptedMsg2)
        println(String(decryptMsg1))
        println(String(decryptMsg2))

    }

}
