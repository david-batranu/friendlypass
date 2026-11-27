package org.friendlypass.android.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordGeneratorTest {

    @Test
    fun `generate respects length and selected character classes`() {
        val pw = PasswordGenerator.generate(
            PasswordGenerator.Options(length = 24, uppercase = true, lowercase = true, digits = true, symbols = true),
        )
        assertEquals(24, pw.length)
        assertTrue(pw.any { it.isUpperCase() })
        assertTrue(pw.any { it.isLowerCase() })
        assertTrue(pw.any { it.isDigit() })
        assertTrue(pw.any { !it.isLetterOrDigit() })
    }

    @Test
    fun `evaluateStrength classifies empty weak and strong passwords`() {
        assertEquals("Empty", PasswordGenerator.evaluateStrength("").label)
        assertEquals("Weak", PasswordGenerator.evaluateStrength("abc").label)
        val strong = PasswordGenerator.evaluateStrength("K9#mP2!xQ7@vL4&nR8\$w")
        assertTrue(strong.entropyBits >= 90)
        assertEquals("Excellent", strong.label)
    }
}
