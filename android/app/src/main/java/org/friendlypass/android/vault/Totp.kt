package org.friendlypass.android.vault

import org.friendlypass.android.vault.model.TotpCode
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Minimal RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) so the skeleton can show a live code before the Rust
 * engine lands. The real implementation moves to `friendlypass::totp` in a later wave.
 */
object Totp {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun code(secretBase32: String, unixSecs: Long, periodSecs: Int = 30, digits: Int = 6): TotpCode {
        require(periodSecs > 0) { "period must be positive" }
        require(digits in 1..9) { "digits out of range" }
        val counter = unixSecs / periodSecs
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(base32Decode(secretBase32), "HmacSHA1"))
        val hash = mac.doFinal(counter.toBigEndianBytes())
        val offset = hash[hash.size - 1].toInt() and 0x0f
        val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
            ((hash[offset + 1].toInt() and 0xff) shl 16) or
            ((hash[offset + 2].toInt() and 0xff) shl 8) or
            (hash[offset + 3].toInt() and 0xff)
        val modulus = POWERS_OF_TEN[digits]
        val value = binary % modulus
        val code = value.toString().padStart(digits, '0')
        val remaining = (periodSecs - (unixSecs % periodSecs).toInt()).let { if (it == 0) periodSecs else it }
        return TotpCode(code = code, periodSecs = periodSecs, remainingSecs = remaining)
    }

    private val POWERS_OF_TEN = intArrayOf(1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000)

    private fun Long.toBigEndianBytes(): ByteArray = ByteArray(8) { i ->
        ((this ushr (56 - 8 * i)) and 0xff).toByte()
    }

    /** Decodes RFC 4648 base32 (case-insensitive, padding optional). */
    fun base32Decode(encoded: String): ByteArray {
        val cleaned = encoded.filterNot { it == '=' || it.isWhitespace() || it == '-' }.uppercase()
        val out = ByteArray(cleaned.length * 5 / 8)
        var buffer = 0
        var bits = 0
        var index = 0
        for (c in cleaned) {
            val value = ALPHABET.indexOf(c)
            require(value >= 0) { "invalid base32 character" }
            buffer = (buffer shl 5) or value
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out[index++] = ((buffer ushr bits) and 0xff).toByte()
            }
        }
        return out
    }
}
