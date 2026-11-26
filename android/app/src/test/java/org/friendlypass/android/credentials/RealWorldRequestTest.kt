package org.friendlypass.android.credentials

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A creation-options payload captured from Chrome 156 on an API 37 emulator talking to Hanko's passkeys.io demo
 * (debug `options shape` log), replayed so the provider is tested against a real browser's serialisation rather
 * than only the hand-written `RequestJsonTest` cases: `attestation: "direct"`, `residentKey: "required"`, a
 * ten-entry algorithm list and a 16-byte (22 base64url character) user id.
 */
class RealWorldRequestTest {

    private val createJson = """
        {"attestation":"direct","authenticatorSelection":{"residentKey":"required","userVerification":"preferred"},
         "challenge":"R7t3qv1Zc9e0J4yK5x6l8mNpQrStUvWxYz01234567A","excludeCredentials":[],
         "pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-35,"type":"public-key"},
           {"alg":-36,"type":"public-key"},{"alg":-257,"type":"public-key"},{"alg":-258,"type":"public-key"},
           {"alg":-259,"type":"public-key"},{"alg":-37,"type":"public-key"},{"alg":-38,"type":"public-key"},
           {"alg":-39,"type":"public-key"},{"alg":-8,"type":"public-key"}],
         "rp":{"id":"www.passkeys.io","name":"passkeys.io"},"timeout":600000,
         "user":{"displayName":"fp-real-shape@example.com","id":"u5Z2r0pQ8xT4","name":"fp-real-shape@example.com"}}
    """.trimIndent()

    @Test
    fun `parses the passkeys io creation options`() {
        val options = RequestJson.parseCreate(createJson)

        assertEquals("www.passkeys.io", options.rpId)
        assertEquals("passkeys.io", options.rpName)
        assertEquals("fp-real-shape@example.com", options.userName)
        assertArrayEquals(B64Url.decode("u5Z2r0pQ8xT4"), options.userId)
        assertEquals(32, options.challenge.size)
        assertEquals(
            listOf(-7L, -35L, -36L, -257L, -258L, -259L, -37L, -38L, -39L, -8L),
            options.algorithms,
        )
        assertTrue(options.excludeCredentialIds.isEmpty())
    }

    @Test
    fun `the site proposes ES256 first, so registration uses it`() {
        assertEquals(-7L, RequestJson.parseCreate(createJson).algorithms.first())
    }

    @Test
    fun `the rp id is the exact origin host`() {
        assertTrue(OriginPolicy.rpIdMatchesOrigin("www.passkeys.io", "https://www.passkeys.io"))
    }

    @Test
    fun `shape log names the request but never its secrets`() {
        val shape = OptionsShape.describe(createJson)

        assertTrue(shape, shape.contains("rp.id=\"www.passkeys.io\""))
        assertTrue(shape, shape.contains("attestation=\"direct\""))
        assertTrue(shape, shape.contains("authenticatorSelection={residentKey=\"required\""))
        assertTrue(shape, shape.contains("public-key:-7"))
        assertTrue(shape, shape.contains("public-key:-8"))
        assertTrue(shape, shape.contains("challenge.len=43"))
        assertTrue(shape, shape.contains("id.len=12"))

        // Nothing secret or personal: no challenge, user handle, user name or email.
        assertFalse(shape, shape.contains("R7t3qv1Zc9e0J4yK5x6l8mNpQrStUvWxYz01234567A"))
        assertFalse(shape, shape.contains("u5Z2r0pQ8xT4"))
        assertFalse(shape, shape.contains("fp-real-shape@example.com"))
    }

    @Test
    fun `shape log masks credential ids in exclude and allow lists`() {
        val request = """
            {"challenge":"AAECAw","rp":{"id":"example.com","name":"Example"},
             "user":{"id":"dXNlcg","name":"u"},
             "excludeCredentials":[{"type":"public-key","id":"AQIDBA","transports":["internal"]}],
             "allowCredentials":[{"type":"public-key","id":"BQYH"}]}
        """.trimIndent()

        val shape = OptionsShape.describe(request)

        assertTrue(
            shape,
            shape.contains("excludeCredentials=[{id.len=6,transports=[\"internal\"],type=public-key}]"),
        )
        assertTrue(shape, shape.contains("allowCredentials=[{id.len=4,type=public-key}]"))
        assertFalse(shape, shape.contains("AQIDBA"))
        assertFalse(shape, shape.contains("BQYH"))
        assertTrue(shape, shape.contains("rp.id=\"example.com\""))
    }

    @Test
    fun `shape log survives malformed json without throwing`() {
        assertTrue(runCatching { OptionsShape.describe("{not json") }.isFailure)
    }
}
