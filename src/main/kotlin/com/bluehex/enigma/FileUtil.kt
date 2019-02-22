package com.bluehex.enigma

import java.io.InputStream

class FileUtil{
    companion object {
        fun fileContent(name: String): String {
            return javaClass.classLoader.getResource(name).readText()
        }

        fun fileContentAsStream(name: String): InputStream {
            return javaClass.classLoader.getResourceAsStream(name)
        }
    }
}
