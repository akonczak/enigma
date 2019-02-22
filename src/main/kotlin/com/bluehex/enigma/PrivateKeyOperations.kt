package com.bluehex.enigma

import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.Signature
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

class PrivateKeyOperations(val key: PrivateKey) {

    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding")


    init {
        cipher.init(Cipher.DECRYPT_MODE, key)
    }

    @Synchronized
    @Throws(NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class, IllegalBlockSizeException::class, BadPaddingException::class)
    fun decrypt(encryptedText: ByteArray): ByteArray {
        return cipher.doFinal(encryptedText)
    }

    @Synchronized
    @Throws(NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class, IllegalBlockSizeException::class, BadPaddingException::class)
    fun decrypt(encryptedText: String): ByteArray {
        return cipher.doFinal(encryptedText.toByteArray())
    }

    @Throws(NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class, IllegalBlockSizeException::class, BadPaddingException::class)
    fun sign(plainText: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA1WithRSA")
        sig.initSign(key)
        sig.update(plainText)
        return Base64Util.encode(sig.sign())
    }

}
