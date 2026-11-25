package org.friendlypass.android.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialJsonTest {

    @Test
    fun `assertion response has the WebAuthn fields and unpadded base64url`() {
        val credentialId = byteArrayOf(1, 2, 3)
        val clientData = """{"type":"webauthn.get"}""".toByteArray()
        val authData = byteArrayOf(4, 5)
        val signature = byteArrayOf(6, 7, 8)
        val userHandle = "user".toByteArray()

        val json = CredentialJson.assertion(credentialId, clientData, authData, signature, userHandle)
        val root = Json.parse(json).asJsonObject()!!
        val response = root.objectField("response")!!

        assertEquals("AQID", root.stringField("id"))
        assertEquals("AQID", root.stringField("rawId"))
        assertEquals("public-key", root.stringField("type"))
        assertEquals("platform", root.stringField("authenticatorAttachment"))
        assertEquals(emptyMap<String, Any?>(), root.objectField("clientExtensionResults"))
        assertEquals(B64Url.encode(clientData), response.stringField("clientDataJSON"))
        assertEquals("BAU", response.stringField("authenticatorData"))
        assertEquals("BgcI", response.stringField("signature"))
        assertEquals("dXNlcg", response.stringField("userHandle"))
        assertFalse(json.contains("="))
        assertFalse(json.contains("+"))
        assertFalse(json.contains("/"))
    }

    @Test
    fun `assertion response omits clientDataJSON for a privileged caller`() {
        val root = Json.parse(
            CredentialJson.assertion(byteArrayOf(1), null, byteArrayOf(2), byteArrayOf(3), ByteArray(0)),
        ).asJsonObject()!!

        assertEquals("", root.objectField("response")!!.stringField("clientDataJSON"))
        assertEquals("", root.objectField("response")!!.stringField("userHandle"))
    }

    @Test
    fun `registration response carries attestation, spki and transports`() {
        val json = CredentialJson.registration(
            credentialId = byteArrayOf(1, 2),
            clientDataJson = "{}".toByteArray(),
            attestationObject = byteArrayOf(3, 4),
            authenticatorData = byteArrayOf(5, 6),
            publicKeySpkiDer = byteArrayOf(7, 8, 9),
            publicKeyAlgorithm = -7,
        )
        val root = Json.parse(json).asJsonObject()!!
        val response = root.objectField("response")!!

        assertEquals("AQI", root.stringField("id"))
        assertEquals("public-key", root.stringField("type"))
        assertEquals("platform", root.stringField("authenticatorAttachment"))
        assertEquals("e30", response.stringField("clientDataJSON"))
        assertEquals("AwQ", response.stringField("attestationObject"))
        assertEquals("BQY", response.stringField("authenticatorData"))
        assertEquals("BwgJ", response.stringField("publicKey"))
        assertEquals(-7L, response.longField("publicKeyAlgorithm"))
        assertEquals(listOf("internal", "hybrid"), response.arrayField("transports"))
    }

    @Test
    fun `client data JSON encodes the challenge and origin`() {
        val root = Json.parse(
            CredentialJson.clientDataJson(
                type = CredentialJson.TYPE_GET,
                challenge = byteArrayOf(1, 2, 3),
                origin = "android:apk-key-hash:abc",
                androidPackageName = "org.friendlypass.credtest",
            ),
        ).asJsonObject()!!

        assertEquals("webauthn.get", root.stringField("type"))
        assertEquals("AQID", root.stringField("challenge"))
        assertEquals("android:apk-key-hash:abc", root.stringField("origin"))
        assertEquals(false, root["crossOrigin"])
        assertEquals("org.friendlypass.credtest", root.stringField("androidPackageName"))
    }
}
