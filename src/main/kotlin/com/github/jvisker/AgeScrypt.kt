package com.github.jvisker

import org.bouncycastle.crypto.generators.SCrypt
private const val R = 8
private const val P = 1
private const val LENGTH = 32

object AgeScrypt {
    fun scryptExpand(passphraseBytes: ByteArray, saltBytes: ByteArray, N: Int): ByteArray {
        return  SCrypt.generate(passphraseBytes, saltBytes, N, R, P, LENGTH)
    }
}
