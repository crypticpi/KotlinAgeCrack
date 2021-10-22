package com.github.jvisker

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private val zeroNonce = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

object AgeEncryption{
    @Throws(java.lang.Exception::class)
    fun decrypt(cipherText: ByteArray, key: ByteArray): ByteArray {

        val keySecret = SecretKeySpec(key, 0, key.size, "AES")

        // Get Cipher Instance
        val cipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding")

        // Create IvParamterSpec
        val ivParameterSpec: AlgorithmParameterSpec = IvParameterSpec(zeroNonce)

        // Create SecretKeySpec
        val keySpec = SecretKeySpec(keySecret.encoded, "ChaCha20")

        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec)

        // Perform Decryption
        return cipher.doFinal(cipherText)
    }

    //todo: untested and unused for now. But maybe useful if expanding the features
    fun encrypt(data: ByteArray, key: SecretKey): ByteArray {

        // Get Cipher Instance
        val cipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding")

        // Create IvParamterSpec
        val ivParameterSpec: AlgorithmParameterSpec = IvParameterSpec(zeroNonce)

        // Create SecretKeySpec
        val keySpec = SecretKeySpec(key.encoded, "ChaCha20")

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec)

        // Perform Encryption
        return cipher.doFinal(data)
    }

    fun hkdf(saltBytes: ByteArray, labelBytes: ByteArray, fileKeyBytes: ByteArray, length: Int): ByteArray {
        val digest = SHA256Digest()
        val data = ByteArray(length)
        HKDFBytesGenerator(digest)
            .apply { init(HKDFParameters(fileKeyBytes, saltBytes, labelBytes)) }
            .generateBytes(data, 0, length)
        return data
    }

    fun hmac(key: ByteArray, message: ByteArray): ByteArray {
        val macKey: SecretKey = SecretKeySpec(key, "HmacSHA256")
        val mac: Mac = Mac.getInstance("HmacSHA256")
        mac.init(macKey)
        return mac.doFinal(message)
    }

    fun verifyHmac(key: ByteArray, message: ByteArray, tag: ByteArray): Boolean {
        return hmac(key, message).contentEquals(tag)
    }
}
