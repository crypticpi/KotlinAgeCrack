package com.github.jvisker

import java.util.*
import javax.crypto.AEADBadTagException
import kotlin.math.pow

private val PREFIX_BYTES = "age-encryption.org/v1/scrypt".toByteArray()
private val LABEL_BYTES = "header".toByteArray()

class AgePasswordFile(
     encryptedFileKeyBase64: String,
     saltBase64: String,
     hmacBase64: String,
     workFactor: Int, // log2(N)
     headerString: String //leading up to and including the ---
) {
    private val encryptedFileKeyBytes: ByteArray = Base64.getDecoder().decode(encryptedFileKeyBase64)
    private val macBytes = Base64.getDecoder().decode(hmacBase64)
    private val n = 2.0.pow(workFactor).toInt()
    private val saltBytes = Base64.getDecoder().decode(saltBase64)
    private val totalSalt = PREFIX_BYTES + saltBytes
    private val headerBytes = headerString.toByteArray()

    fun checkPassphrase(passphrase: String): Boolean {
        return try {
            val passphraseBytes = passphrase.toByteArray()
            val key = AgeScrypt.scryptExpand(passphraseBytes, totalSalt, n)
            val decryptedFileKeyBytes = AgeEncryption.decrypt(encryptedFileKeyBytes, key)
            //TODO: The HMAC *might* not be needed. In most cases it seems that bad pass phrases cause an error to be thrown
            AgeEncryption.verifyHmac(
                key = AgeEncryption.hkdf(byteArrayOf(), LABEL_BYTES, decryptedFileKeyBytes, 32),
                message = headerBytes,
                tag = macBytes
            )
        } catch (e: AEADBadTagException) {
            false
        }
    }
}
