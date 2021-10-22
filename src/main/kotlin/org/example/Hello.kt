package org.example

import kotlinx.coroutines.*
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.crypto.params.HKDFParameters
import java.io.File
import java.security.spec.AlgorithmParameterSpec
import java.util.*
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow
import kotlin.system.exitProcess

val zeroNonce = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

suspend fun main() {
    //to verify a password do this
// 0. Get encrypted file key (line after ->)
// 1. Get encoded mac (starting with ---)
// 2. Expand password using scrypt to get key
// 3. Decrypt file key with key (scrypt_decrypt_file_key)
// 4. Check that hmac(hkdf(filekey, headerlabel).verify(header_contents, macBytes) is correct

    val encryptedFileKeyBytes = Base64.getDecoder().decode("DKW9oexyVCiMxKMpRhIHTJLBwHWV4ueMRCRCRTuzLYE")
    val macBytes = Base64.getDecoder().decode("MsIumr0AzCfdOPpt7gPMTvoXI0P9Gc1lHWzjwyOdPy0")
    val work = 1
    val N = 2.0.pow(work).toInt()
    val prefixBytes = "age-encryption.org/v1/scrypt".toByteArray()
    val saltBytes = Base64.getDecoder().decode("2Jk+g2K3eaEszktpRBVpjA")
    val totalSalt = prefixBytes + saltBytes
    val label = "header".toByteArray()
    val headerBytes = """age-encryption.org/v1
-> scrypt 2Jk+g2K3eaEszktpRBVpjA 1
DKW9oexyVCiMxKMpRhIHTJLBwHWV4ueMRCRCRTuzLYE
---""".toByteArray()


    var count = 0
val chunksize = 100000
    File("/Users/jvisker/Downloads/rockyou.txt").readLines().chunked(chunksize) {
        count++
        println(count*chunksize)

        println (count.toLong()*chunksize.toLong()/32_000_000*100)
        runBlocking {
            val responses = it.map {

                coroutineScope {
                    async(Dispatchers.IO) {
                        try {

                            val passphraseBytes = it.toByteArray()
                            val key = scryptExpand(passphraseBytes, totalSalt, N)
                            val decryptedFileKeyBytes = decrypt(encryptedFileKeyBytes, key) //This is good
                            val results = verifyHmac(hkdf(byteArrayOf(), label, decryptedFileKeyBytes, 32), headerBytes, macBytes)
                            if (results){
                                println("the answer" + it)
                                exitProcess(0)
                            }
                             results
                        } catch (e: AEADBadTagException) {
//                    e.printStackTrace()
                            false
                        }
                    }
                }
            }.awaitAll()


        }

    }


}

val r = 8
val p = 1
val length = 32
fun scryptExpand(passphraseBytes: ByteArray, saltBytes: ByteArray, N: Int): ByteArray {

    val b = SCrypt.generate(passphraseBytes, saltBytes, N, r, p, length)

    return b
}


@Throws(java.lang.Exception::class)
fun decrypt(cipherText: ByteArray, key2: ByteArray): ByteArray {

    val keySecret = SecretKeySpec(key2, 0, key2.size, "AES")
    val nonceBytes = zeroNonce

    // Get Cipher Instance
    val cipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding")

    // Create IvParamterSpec
    val ivParameterSpec: AlgorithmParameterSpec = IvParameterSpec(nonceBytes)

    // Create SecretKeySpec
    val keySpec = SecretKeySpec(keySecret.encoded, "ChaCha20")

    // Initialize Cipher for DECRYPT_MODE
    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParameterSpec)

    // Perform Decryption
    val k = cipher.doFinal(cipherText)

    return k
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

//fun encrypt(data: ByteArray, key: SecretKey): ByteArray {
//
//    val nonceBytes = zeroNonce
//
//    // Get Cipher Instance
//    val cipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding")
//
//    // Create IvParamterSpec
//    val ivParameterSpec: AlgorithmParameterSpec = IvParameterSpec(nonceBytes)
//
//    // Create SecretKeySpec
//    val keySpec = SecretKeySpec(key.encoded, "ChaCha20")
//
//    // Initialize Cipher for ENCRYPT_MODE
//    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec)
//
//    // Perform Encryption
//    return cipher.doFinal(data)
//}
