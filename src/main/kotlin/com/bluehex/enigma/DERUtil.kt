package com.bluehex.enigma

import java.io.BufferedInputStream
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.InvalidKeySpecException
import java.security.NoSuchAlgorithmException
import java.io.IOException
import java.io.InputStream
import java.security.PrivateKey
import java.security.spec.X509EncodedKeySpec
import java.security.PublicKey



class DERUtil{
    companion object {

        @Throws(IOException::class, NoSuchAlgorithmException::class, InvalidKeySpecException::class)
        fun readPublicKey(stream: InputStream): PublicKey {
            val publicSpec = X509EncodedKeySpec(readStream(stream))
            val keyFactory = KeyFactory.getInstance("RSA")
            return keyFactory.generatePublic(publicSpec)
        }

        @Throws(IOException::class, NoSuchAlgorithmException::class, InvalidKeySpecException::class)
        fun readPrivateKey(stream: InputStream): PrivateKey {
            val keySpec = PKCS8EncodedKeySpec(readStream(stream))
            val keyFactory = KeyFactory.getInstance("RSA")
            return keyFactory.generatePrivate(keySpec)
        }

        fun readStream(stream: InputStream):ByteArray{
            return BufferedInputStream(stream).readAllBytes()
        }
    }
}
