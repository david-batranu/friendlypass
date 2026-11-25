package org.friendlypass.android.credentials

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialListingTest {

    private val github = entry(
        uuid = "github",
        title = "GitHub",
        username = "david",
        url = "https://github.com",
    )
    private val exampleApp = entry(
        uuid = "example",
        title = "Example App",
        username = "demo@example.app",
        url = "androidapp://com.example.app",
        androidApps = listOf("com.example.app"),
    )
    private val pypi = entry(
        uuid = "pypi",
        title = "PyPI",
        username = "david",
        url = "https://pypi.org",
    )

    @Test
    fun `locked vault produces no entries and asks for authentication`() {
        val vault = TestVaultRepository(listOf(github), unlocked = false)
        val listing = CredentialListingBuilder(vault).build(
            ListingRequest(
                passwordRequested = true,
                publicKeyRequested = true,
                rpId = "pypi.org",
                origin = "https://github.com",
                callingPackage = "org.friendlypass.credtest",
                isDebugBuild = true,
            ),
        )

        assertTrue(listing.locked)
        assertTrue(listing.passwordEntries.isEmpty())
        assertTrue(listing.passkeyEntries.isEmpty())
    }

    @Test
    fun `unlocked vault matches passwords by web origin`() {
        val vault = TestVaultRepository(listOf(github, exampleApp))
        val listing = CredentialListingBuilder(vault).build(
            ListingRequest(
                passwordRequested = true,
                publicKeyRequested = false,
                origin = "https://github.com",
                callingPackage = "com.android.chrome",
                isDebugBuild = false,
                privileged = true,
            ),
        )

        assertFalse(listing.locked)
        assertEquals(listOf("github"), listing.passwordEntries.map { it.uuid })
        assertEquals("GitHub", listing.passwordEntries.single().displayName)
    }

    @Test
    fun `unlocked vault matches passwords by calling package`() {
        val vault = TestVaultRepository(listOf(github, exampleApp))
        val listing = CredentialListingBuilder(vault).build(
            ListingRequest(
                passwordRequested = true,
                publicKeyRequested = false,
                origin = "android:apk-key-hash:abc",
                callingPackage = "com.example.app",
                isDebugBuild = false,
            ),
        )

        assertEquals(listOf("example"), listing.passwordEntries.map { it.uuid })
    }

    @Test
    fun `allowed user ids filter password entries`() {
        val vault = TestVaultRepository(listOf(github, exampleApp))
        val listing = CredentialListingBuilder(vault).build(
            ListingRequest(
                passwordRequested = true,
                publicKeyRequested = false,
                origin = "https://github.com",
                allowedUserIds = setOf("nobody"),
                callingPackage = "com.android.chrome",
                isDebugBuild = false,
                privileged = true,
            ),
        )

        assertTrue(listing.passwordEntries.isEmpty())
    }

    @Test
    fun `debug credential test app sees entries without a web origin`() {
        val vault = TestVaultRepository(listOf(github, pypi))
        val listing = CredentialListingBuilder(vault).build(
            ListingRequest(
                passwordRequested = true,
                publicKeyRequested = false,
                origin = "android:apk-key-hash:abc",
                callingPackage = OriginPolicy.CREDTEST_PACKAGE,
                isDebugBuild = true,
            ),
        )

        assertEquals(setOf("github", "pypi"), listing.passwordEntries.map { it.uuid }.toSet())
    }

    @Test
    fun `release builds never get the credential test fallback`() {
        val vault = TestVaultRepository(listOf(github, pypi))
        val listing = CredentialListingBuilder(vault).build(
            ListingRequest(
                passwordRequested = true,
                publicKeyRequested = false,
                origin = "android:apk-key-hash:abc",
                callingPackage = OriginPolicy.CREDTEST_PACKAGE,
                isDebugBuild = false,
            ),
        )

        assertTrue(listing.passwordEntries.isEmpty())
    }

    @Test
    fun `passkeys are listed for an allowed debug rp`() {
        val vault = TestVaultRepository(
            entries = listOf(pypi),
            passkeys = listOf(passkey("pypi", "credtest.friendlypass.test", byteArrayOf(1, 2, 3))),
        )
        val listing = CredentialListingBuilder(vault).build(
            ListingRequest(
                passwordRequested = false,
                publicKeyRequested = true,
                rpId = "credtest.friendlypass.test",
                origin = "android:apk-key-hash:abc",
                callingPackage = OriginPolicy.CREDTEST_PACKAGE,
                isDebugBuild = true,
            ),
        )

        assertEquals(listOf("pypi"), listing.passkeyEntries.map { it.uuid })
        assertEquals("PyPI", listing.passkeyEntries.single().displayName)
    }

    @Test
    fun `passkeys respect the allow credential list`() {
        val vault = TestVaultRepository(
            entries = listOf(pypi),
            passkeys = listOf(passkey("pypi", "pypi.org", byteArrayOf(1, 2, 3))),
        )
        val builder = CredentialListingBuilder(vault)
        val request = ListingRequest(
            passwordRequested = false,
            publicKeyRequested = true,
            rpId = "pypi.org",
            origin = "https://pypi.org",
            callingPackage = "com.android.chrome",
            isDebugBuild = false,
            privileged = true,
        )

        assertEquals(1, builder.build(request).passkeyEntries.size)
        assertEquals(
            0,
            builder.build(request.copy(allowCredentialIds = listOf(byteArrayOf(9, 9)))).passkeyEntries.size,
        )
        assertEquals(
            1,
            builder.build(request.copy(allowCredentialIds = listOf(byteArrayOf(1, 2, 3)))).passkeyEntries.size,
        )
    }

    @Test
    fun `unprivileged apps cannot list passkeys for a web rp`() {
        val vault = TestVaultRepository(
            entries = listOf(pypi),
            passkeys = listOf(passkey("pypi", "pypi.org", byteArrayOf(1, 2, 3))),
        )
        val listing = CredentialListingBuilder(vault).build(
            ListingRequest(
                passwordRequested = false,
                publicKeyRequested = true,
                rpId = "pypi.org",
                origin = "android:apk-key-hash:abc",
                callingPackage = "com.example.mail",
                isDebugBuild = false,
            ),
        )

        assertTrue(listing.passkeyEntries.isEmpty())
    }

    @Test
    fun `unprivileged apps may use a passkey whose rp is a stored Android app`() {
        val vault = TestVaultRepository(
            entries = listOf(exampleApp),
            passkeys = listOf(passkey("example", "com.example.app", byteArrayOf(4, 5))),
        )
        val listing = CredentialListingBuilder(vault).build(
            ListingRequest(
                passwordRequested = false,
                publicKeyRequested = true,
                rpId = "com.example.app",
                origin = "android:apk-key-hash:abc",
                callingPackage = "com.example.app",
                isDebugBuild = false,
            ),
        )

        assertEquals(listOf("example"), listing.passkeyEntries.map { it.uuid })
    }
}
