//package org.example
//
//import java.util.*
//import javax.crypto.KeyGenerator
//import javax.crypto.SecretKey
//
//
//fun main(args: Array<String>) {
//    val key: SecretKey = ChaCha20Poly1305KeyGenerator.generateKey()
//
//    val testMessage = "hallo!"
////    val encryptedBytes = encrypt(testMessage.toByteArray(), key)
//    val decryptedMessage = String(decrypt(encryptedBytes, key.encoded))
//    println("testMessage: $testMessage")
//    println(key.algorithm + " SecretKey: " + Base64.getEncoder().encodeToString(key.encoded))
//    println("encryptedBytes: " + Base64.getEncoder().encodeToString(encryptedBytes))
//    println("decryptedMessage: $decryptedMessage")
//}
//
//object ChaCha20Poly1305KeyGenerator {
//    fun generateKey(): SecretKey {
//        val keyGenerator = KeyGenerator.getInstance("ChaCha20")
//        //Keysize MUST be 256 bit - as of Java11 only 256Bit is supported
//        keyGenerator.init(256)
//        return keyGenerator.generateKey()
//    }
//
//    @JvmStatic
//    fun main(args: Array<String>) {
//        val key = generateKey()
//        println(key.algorithm + " SecretKey: " + Base64.getEncoder().encodeToString(key.encoded))
//    }
//}
////
////
////
