package org.friendlypass.android.credentials

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RequestJsonTest {

    private val getJson = """
        {
          "challenge": "AAECAw",
          "rpId": "credtest.friendlypass.test",
          "allowCredentials": [
            {"type": "public-key", "id": "AQID"},
            {"type": "public-key", "id": "BAUG"}
          ],
          "userVerification": "required",
          "timeout": 60000
        }
    """.trimIndent()

    @Test
    fun `parses a get request challenge, rpId and allow list`() {
        val options = RequestJson.parseGet(getJson)

        assertArrayEquals(byteArrayOf(0, 1, 2, 3), options.challenge)
        assertEquals("credtest.friendlypass.test", options.rpId)
        assertEquals(2, options.allowCredentialIds.size)
        assertArrayEquals(byteArrayOf(1, 2, 3), options.allowCredentialIds[0])
        assertArrayEquals(byteArrayOf(4, 5, 6), options.allowCredentialIds[1])
        assertEquals("required", options.userVerification)
    }

    @Test
    fun `get request without rpId or credentials still parses`() {
        val options = RequestJson.parseGet("""{"challenge":"AAECAw"}""")

        assertEquals(null, options.rpId)
        assertTrue(options.allowCredentialIds.isEmpty())
    }

    @Test
    fun `get request without a challenge is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            RequestJson.parseGet("""{"rpId":"example.com"}""")
        }
        assertThrows(IllegalArgumentException::class.java) {
            RequestJson.parseGet("""{"challenge":"!!!"}""")
        }
    }

    @Test
    fun `parses creation options including rp, user and algorithms`() {
        val options = RequestJson.parseCreate(
            """
            {
              "challenge": "AAECAw",
              "rp": {"id": "credtest.friendlypass.test", "name": "friendlypass credtest"},
              "user": {"id": "dXNlcg", "name": "david", "displayName": "David"},
              "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257}
              ],
              "excludeCredentials": [{"type": "public-key", "id": "AQID"}],
              "authenticatorSelection": {"residentKey": "required"},
              "attestation": "none"
            }
            """.trimIndent(),
        )

        assertEquals("credtest.friendlypass.test", options.rpId)
        assertEquals("friendlypass credtest", options.rpName)
        assertArrayEquals("user".toByteArray(), options.userId)
        assertEquals("david", options.userName)
        assertEquals("David", options.userDisplayName)
        assertEquals(listOf(-7L, -257L), options.algorithms)
        assertEquals(1, options.excludeCredentialIds.size)
        assertArrayEquals(byteArrayOf(1, 2, 3), options.excludeCredentialIds[0])
    }

    @Test
    fun `creation defaults to ES256 when no supported algorithm is listed`() {
        val options = RequestJson.parseCreate(
            """{"challenge":"AAECAw","rp":{"id":"example.com"},"user":{"id":"dXNlcg","name":"d"}}""",
        )
        assertEquals(listOf(-7L), options.algorithms)
        assertEquals("d", options.userDisplayName)
    }

    @Test
    fun `creation without rp id is rejected`() {
        assertThrows(IllegalArgumentException::class.java) {
            RequestJson.parseCreate("""{"challenge":"AAECAw","user":{"id":"dXNlcg"}}""")
        }
    }

    @Test
    fun `exclude credentials detects an existing credential id`() {
        val existing = listOf(byteArrayOf(1, 2, 3), byteArrayOf(9))
        assertTrue(RequestJson.hasExcludedCredential(existing, listOf(byteArrayOf(4), byteArrayOf(9))))
        assertFalse(RequestJson.hasExcludedCredential(existing, listOf(byteArrayOf(4))))
        assertFalse(RequestJson.hasExcludedCredential(existing, emptyList()))
    }
}
