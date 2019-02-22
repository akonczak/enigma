package com.bluehex.enigma

import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException


class Enigma {

    companion object {
        @Throws(NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class, IllegalBlockSizeException::class, BadPaddingException::class)
        fun encrypt(key: PublicKey, plaintext: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            return cipher.doFinal(plaintext)
        }

        @Throws(NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class, IllegalBlockSizeException::class, BadPaddingException::class)
        fun decrypt(key: PrivateKey, ciphertext: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding")
            cipher.init(Cipher.DECRYPT_MODE, key)
            return cipher.doFinal(ciphertext)
        }

        @Throws(NoSuchAlgorithmException::class, NoSuchPaddingException::class, InvalidKeyException::class, IllegalBlockSizeException::class, BadPaddingException::class)
        fun sign(key: PrivateKey, ciphertext: ByteArray): ByteArray {
            val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding")
            cipher.init(Cipher.DECRYPT_MODE, key)
            return cipher.doFinal(ciphertext)
        }
    }

}
