package com.github.jvisker

import kotlinx.coroutines.*
import me.tongfei.progressbar.ProgressBar
import java.io.File
import kotlin.system.exitProcess


suspend fun main() {
// At a high level passwords are validated by
// 0. Get encrypted file key (line after ->)
// 1. Get encoded mac (starting with ---)
// 2. Expand password using scrypt to get an scrypt key
// 3. Decrypt file key with the scrypt key
// 4. Use the file key to valiate the hmac signature

    val exampleAgeFile = AgePasswordFile(
        encryptedFileKeyBase64 = "DKW9oexyVCiMxKMpRhIHTJLBwHWV4ueMRCRCRTuzLYE", // line after ->
        saltBase64 = "2Jk+g2K3eaEszktpRBVpjA",
        hmacBase64 = "MsIumr0AzCfdOPpt7gPMTvoXI0P9Gc1lHWzjwyOdPy0", //on line with --- but after
        workFactor = 1,
        headerString = """age-encryption.org/v1
-> scrypt 2Jk+g2K3eaEszktpRBVpjA 1
DKW9oexyVCiMxKMpRhIHTJLBwHWV4ueMRCRCRTuzLYE
---"""
    )

    var currentIndex = 0L
    val parallelism = 10000
    val passwordList =
        File("/Users/jvisker/Downloads/rockyou.txt").readLines() //todo: could run out of memory if the list was too bit

    ProgressBar("Running", passwordList.size.toLong()).use { pb ->
        passwordList.chunked(parallelism) {
            runBlocking {
                val crackedPasswordPair = it.map { passphrase ->
                    coroutineScope {
                        async(Dispatchers.IO) {
                            passphrase to exampleAgeFile.checkPassphrase(passphrase)
                        }
                    }
                }.awaitAll().find { it.second }
                if (crackedPasswordPair != null) {
                    pb.close()
                    println("The passphrase is: ${crackedPasswordPair.first}")
                    exitProcess(0)
                }
            }
            currentIndex += it.size
            pb.stepTo(currentIndex)
            it.lastOrNull()?.let { pw -> pb.setExtraMessage(pw) }
        }
    }
}
