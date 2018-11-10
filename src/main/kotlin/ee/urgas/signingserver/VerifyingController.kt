package ee.urgas.signingserver

import mu.KotlinLogging
import org.springframework.web.bind.annotation.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private val log = KotlinLogging.logger {}

@RestController
class VerifyingController {

    companion object {
        private const val ALLOWED_DELAY = 5
    }

    private final val signatureAlgorithm = "HmacSHA256"
    private final val keyBytes = "key".toByteArray(Charsets.UTF_8)
    private final val keySpec = SecretKeySpec(keyBytes, signatureAlgorithm)
    private final val mac = Mac.getInstance(signatureAlgorithm)

    init {
        mac.init(keySpec)
    }


    @PostMapping("/")
    fun verify(@RequestBody message: SignedMessage): Response {

        log.info { message }

        // include all message attributes
        val toBeSigned = message.message + message.timestamp

        val signatureBytes = mac.doFinal(toBeSigned.toByteArray(Charsets.UTF_8))
        val signatureString = bytesToHex(signatureBytes)

        // check signature
        if (message.signature != signatureString) {
            log.info { "Expected sig: $signatureString, actual sig: ${message.signature}" }
            return Response("Invalid signature")
        }

        // check timestamp
        val currentTime = System.currentTimeMillis() / 1000
        val timeDelta = currentTime - message.timestamp
        log.info { "Current time: $currentTime, time difference: $timeDelta" }
        if (timeDelta > ALLOWED_DELAY) {
            log.info { "Request timed out, message timestamp: ${message.timestamp}, current time: $currentTime" }
            return Response("Timeout")
        }
        if (timeDelta < 0) {
            log.info { "Request sent in the future, message timestamp: ${message.timestamp}, current time: $currentTime" }
            return Response("Request sent in the future")
        }

        val response = Response("OK: ${message.message}")
        log.info { response }
        return response
    }


    fun bytesToHex(byteArray: ByteArray) =
            byteArray.joinToString("") { String.format("%02x", (it.toInt() and 0xff)) }


}

data class SignedMessage(val message: String, val timestamp: Long, val signature: String)

data class Response(val status: String)
