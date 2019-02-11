package com.bluehex.enigma

import java.util.*


class Base64Util {

    companion object {


        fun decode(encodedString: String): String {
            return String(Base64.getDecoder().decode(encodedString))
        }

        fun encode(plainString: String): String {
            return Base64.getEncoder().encodeToString(plainString.toByteArray())
        }

    }

}
