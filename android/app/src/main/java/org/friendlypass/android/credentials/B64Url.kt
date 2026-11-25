package org.friendlypass.android.credentials

import java.util.Base64

/** Base64url without padding, the only encoding WebAuthn/Android credential payloads use. */
internal object B64Url {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()

    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)

    /** Decodes padded or unpadded base64url; returns null for malformed input instead of throwing. */
    fun decodeOrNull(value: String): ByteArray? = try {
        decoder.decode(value)
    } catch (_: IllegalArgumentException) {
        null
    }

    fun decode(value: String): ByteArray =
        decodeOrNull(value) ?: throw IllegalArgumentException("Not valid base64url")
}
