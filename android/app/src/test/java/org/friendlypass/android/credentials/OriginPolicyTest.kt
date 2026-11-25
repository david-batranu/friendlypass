package org.friendlypass.android.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class OriginPolicyTest {

    @Test
    fun `apk key hash origin is base64url of the certificate digest`() {
        val digest = MessageDigest.getInstance("SHA-256").digest("certificate".toByteArray())
        val origin = OriginPolicy.apkKeyHashOrigin(digest)

        assertTrue(origin.startsWith("android:apk-key-hash:"))
        assertEquals(B64Url.encode(digest), origin.removePrefix("android:apk-key-hash:"))
        assertFalse(origin.substringAfter(':').contains('='))
    }

    @Test
    fun `host parsing ignores scheme, port, userinfo and path`() {
        assertEquals("example.com", OriginPolicy.hostOf("https://example.com/a/b?c=d"))
        assertEquals("example.com", OriginPolicy.hostOf("https://user:pass@example.com:8443/x"))
        assertEquals(null, OriginPolicy.hostOf("android:apk-key-hash:abc"))
    }

    @Test
    fun `rpId must equal or be a parent of the origin host`() {
        assertTrue(OriginPolicy.rpIdMatchesOrigin("example.com", "https://example.com"))
        assertTrue(OriginPolicy.rpIdMatchesOrigin("example.com", "https://login.example.com"))
        assertFalse(OriginPolicy.rpIdMatchesOrigin("login.example.com", "https://example.com"))
        assertFalse(OriginPolicy.rpIdMatchesOrigin("example.com", "https://notexample.com"))
        assertFalse(OriginPolicy.rpIdMatchesOrigin("example.com", "https://example.com.evil.net"))
    }

    @Test
    fun `privileged browser origin allows a matching rpId`() {
        assertTrue(
            OriginPolicy.isPasskeyRpAllowed(
                rpId = "pypi.org",
                origin = "https://pypi.org",
                privileged = true,
                callingPackage = "com.android.chrome",
                isDebugBuild = false,
                entryHasAndroidApp = false,
            ),
        )
        assertFalse(
            OriginPolicy.isPasskeyRpAllowed(
                rpId = "evil.example",
                origin = "https://pypi.org",
                privileged = true,
                callingPackage = "com.android.chrome",
                isDebugBuild = false,
                entryHasAndroidApp = false,
            ),
        )
    }

    @Test
    fun `unprivileged apps need a stored Android app entry`() {
        assertFalse(
            OriginPolicy.isPasskeyRpAllowed(
                rpId = "com.example.app",
                origin = "android:apk-key-hash:abc",
                privileged = false,
                callingPackage = "com.example.app",
                isDebugBuild = false,
                entryHasAndroidApp = false,
            ),
        )
        assertTrue(
            OriginPolicy.isPasskeyRpAllowed(
                rpId = "com.example.app",
                origin = "android:apk-key-hash:abc",
                privileged = false,
                callingPackage = "com.example.app",
                isDebugBuild = false,
                entryHasAndroidApp = true,
            ),
        )
    }

    @Test
    fun `debug credential test app is the only package exception`() {
        assertTrue(OriginPolicy.isDebugCredtest(OriginPolicy.CREDTEST_PACKAGE, isDebugBuild = true))
        assertFalse(OriginPolicy.isDebugCredtest(OriginPolicy.CREDTEST_PACKAGE, isDebugBuild = false))
        assertFalse(OriginPolicy.isDebugCredtest("org.friendlypass.android", isDebugBuild = true))
        assertTrue(
            OriginPolicy.isPasskeyRpAllowed(
                rpId = "credtest.friendlypass.test",
                origin = "android:apk-key-hash:abc",
                privileged = false,
                callingPackage = OriginPolicy.CREDTEST_PACKAGE,
                isDebugBuild = true,
                entryHasAndroidApp = false,
            ),
        )
    }
}
