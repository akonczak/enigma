package com.bluehex.enigma

import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.Signature
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException

class PublicKeyOperations(val key: PublicKey) {

    val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding")

    init {
        cipher.init(Cipher.ENCRYPT_MODE, key)
    }

    @Synchronized
    @Throws(NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class, IllegalBlockSizeException::class, BadPaddingException::class)
    fun encrypt(plainText: ByteArray): ByteArray {
        return cipher.doFinal(plainText)
    }

    @Synchronized
    @Throws(NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class, IllegalBlockSizeException::class, BadPaddingException::class)
    fun encrypt(plainText: String): ByteArray {
        return cipher.doFinal(plainText.toByteArray())
    }

    @Throws(NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class, IllegalBlockSizeException::class, BadPaddingException::class)
    fun verify(bytes: ByteArray): Boolean {
        val sig = Signature.getInstance("SHA1WithRSA")
        sig.initVerify(key)
        return sig.verify(bytes)
    }

}
