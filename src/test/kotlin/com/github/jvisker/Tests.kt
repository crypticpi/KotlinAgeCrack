package com.github.jvisker

import junit.framework.Assert.assertFalse
import junit.framework.Assert.assertTrue
import org.apache.commons.codec.binary.Hex
import org.junit.Test
import java.util.*

class Tests {

    @Test
    fun scrypt() {
        val expected = Hex.decodeHex("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2")
        val actual = AgeScrypt.scryptExpand(
            passphraseBytes = "pleaseletmein".toByteArray(),
            saltBytes = "SodiumChloride".toByteArray(),
            N = 16384
        )
        assertTrue(expected.contentEquals(actual))
    }

    @Test
    fun hkdfTest() {
        val keying_material = Hex.decodeHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = Hex.decodeHex("000102030405060708090a0b0c")
        val info = Hex.decodeHex("f0f1f2f3f4f5f6f7f8f9")
        val L = 42
        val actual = AgeEncryption.hkdf(
            saltBytes = salt,
            labelBytes = info,
            fileKeyBytes = keying_material,
            length = L
        )
        val expected =
            Hex.decodeHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        assertTrue(expected.contentEquals(actual))
    }

    @Test
    fun hmacVerify() {
        val expected = Hex.decodeHex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        val actual = AgeEncryption.hmac(
            key = "Jefe".toByteArray(),
            message = "what do ya want for nothing?".toByteArray()
        )
        assertTrue(expected.contentEquals(actual))

        val key = "This is a key".toByteArray()
        val message = "This is data to be verified.".toByteArray()
        val mac = AgeEncryption.hmac(
            key = key,
            message = message
        )

        assertTrue(AgeEncryption.verifyHmac(key, message, mac))
        val badMac = ByteArray(32).apply { fill(1) }
        assertFalse(AgeEncryption.verifyHmac(key, message, badMac))
    }

    @Test
    fun bytes(){
        val expected = Hex.decodeHex("6167652d656e6372797074696f6e2e6f72672f76310a2d3e2073637279707420334259576a776559534733783548644b63356b2f62512031380a4e70436a726372597078636952754746736471746f746575525038497433504232426561745163746a2b630a2d2d2d")
        val actual = """age-encryption.org/v1
-> scrypt 3BYWjweYSG3x5HdKc5k/bQ 18
NpCjrcrYpxciRuGFsdqtoteuRP8It3PB2BeatQctj+c
---""".toByteArray()
        assertTrue(expected.contentEquals(actual))

    }
}
