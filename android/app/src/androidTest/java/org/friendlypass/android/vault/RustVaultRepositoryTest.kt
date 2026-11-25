package org.friendlypass.android.vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.friendlypass.android.storage.DatabaseStore
import org.friendlypass.android.storage.Snapshot
import org.friendlypass.android.storage.WriteResult
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.EntrySummary
import org.friendlypass.android.vault.model.NewLogin
import org.friendlypass.android.vault.model.PasskeyCreateRequest
import org.friendlypass.android.vault.model.VaultException
import org.friendlypass.android.vault.model.VaultState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.friendlypass_mobile.NewLogin as RustNewLogin
import uniffi.friendlypass_mobile.openVault
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Instrumented tests for the real UniFFI vault. The `.so` cannot be loaded by JVM unit tests, so these run on the
 * emulator; the fake store keeps them independent of the SAF picker.
 */
@RunWith(AndroidJUnit4::class)
class RustVaultRepositoryTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val ref = DatabaseRef("content://org.friendlypass.test/sample4.kdbx", "sample4.kdbx")

    private fun asset(name: String): ByteArray =
        instrumentation.context.assets.open(name).use { it.readBytes() }

    private fun repository(store: DatabaseStore) = RustVaultRepository(store, instrumentation.targetContext)

    private suspend fun unlock(repo: RustVaultRepository, password: String, keyfile: ByteArray? = null) {
        repo.selectDatabase(ref)
        repo.unlock(password.toCharArray(), keyfile)
    }

    @Test
    fun unlockWithWrongPasswordFailsAndStaysLocked(): Unit = runBlocking {
        val repo = repository(MemoryStore(ref, asset("sample4.kdbx")))

        val error = runCatching { unlock(repo, "not-the-password") }.exceptionOrNull()

        assertTrue(error is VaultException.InvalidCredentials)
        assertTrue(repo.state.value is VaultState.Locked)
        assertThrows(VaultException.Locked::class.java) { repo.groups() }
    }

    @Test
    fun unlockWithPasswordAndKeyfileBrowsesAndSearches(): Unit = runBlocking {
        val repo = repository(MemoryStore(ref, asset("sample4_keyfile.kdbx")))
        val password = "testpassword".toCharArray()
        val keyfile = asset("sample4.keyx")

        repo.selectDatabase(ref)
        repo.unlock(password, keyfile)

        assertTrue("password must be wiped", password.all { it == '\u0000' })
        assertTrue("key file must be wiped", keyfile.all { it == 0.toByte() })
        val state = repo.state.value as VaultState.Unlocked
        assertEquals(ref, state.db)

        val groups = repo.groups()
        assertTrue(groups.isNotEmpty())
        assertEquals(repo.rootGroupUuid(), groups.first { it.parentUuid == null }.uuid)

        val entry = repo.search("keyfile entry").single()
        assertEquals("kfuser", repo.entry(entry.uuid).summary.username)
        assertTrue(repo.search("nothing-matches-this").isEmpty())
    }

    @Test
    fun browseAndSearchTheSampleDatabase(): Unit = runBlocking {
        val repo = repository(MemoryStore(ref, asset("sample4.kdbx")))
        unlock(repo, "testpassword")

        val titles = repo.groups().flatMap { repo.entriesInGroup(it.uuid) }.map(EntrySummary::title)
        assertTrue(titles.contains("Sample Entry"))
        assertTrue(titles.contains("Web Login"))

        val detail = repo.entry(repo.search("WEB LOGIN").single().uuid)
        assertEquals("webuser", detail.summary.username)
        assertEquals("https://web.example.org", detail.summary.url)
        assertEquals("web note", detail.notes)

        val sample = repo.entry(repo.search("user@example.com").single().uuid)
        assertEquals("some notes", sample.notes)
        assertTrue(sample.password.isNotBlank())
        assertFalse(sample.summary.hasPasskey)
    }

    @Test
    fun totpUsesTheRequestedInstant(): Unit = runBlocking {
        val totpRef = DatabaseRef("content://org.friendlypass.test/totp.kdbx", "totp.kdbx")
        val repo = repository(MemoryStore(totpRef, asset("totp.kdbx")))
        repo.selectDatabase(totpRef)
        repo.unlock("testpassword".toCharArray(), null)

        val entry = repo.search("TOTP Entry").single()
        assertTrue(entry.hasTotp)
        val code = requireNotNull(repo.totp(entry.uuid, 59L))
        assertEquals("287082", code.code)
        assertEquals(30, code.periodSecs)
        assertEquals(1, code.remainingSecs)
    }

    @Test
    fun matchWebPrefersTheExactHost(): Unit = runBlocking {
        val repo = repository(MemoryStore(ref, asset("sample4.kdbx")))
        unlock(repo, "testpassword")

        assertEquals(listOf("Web Login"), repo.matchWeb("https://web.example.org/login").map { it.title })
        assertEquals(listOf("Sample Entry"), repo.matchWeb("https://example.com").map { it.title })
        assertTrue(repo.matchWeb("https://unrelated.invalid").isEmpty())
    }

    @Test
    fun addLoginPersistsThroughTheStore(): Unit = runBlocking {
        val store = MemoryStore(ref, asset("sample4.kdbx"))
        val repo = repository(store)
        unlock(repo, "testpassword")

        val uuid = repo.addLogin(
            NewLogin(
                title = "Instrumented Login",
                username = "instrumented",
                password = "instrumented-secret",
                url = "https://instrumented.example",
                androidApp = "com.instrumented.app",
            ),
        )

        assertEquals(1, store.writes)
        val detail = repo.entry(uuid)
        assertEquals("Instrumented Login", detail.summary.title)
        assertEquals(listOf("com.instrumented.app"), detail.androidApps)

        // A second save reuses the snapshot the first write returned; no spurious conflict.
        val secondUuid = repo.addLogin(
            NewLogin("Second Instrumented", "second", "second-secret", null, null),
        )
        assertEquals(2, store.writes)

        // Reopen from bytes the store now holds: both entries really were persisted.
        repo.lock()
        assertTrue(repo.state.value is VaultState.Locked)
        repo.unlock("testpassword".toCharArray(), null)
        val reopened = repo.search("instrumented login").single()
        assertEquals(uuid, reopened.uuid)
        assertEquals("instrumented-secret", repo.entry(uuid).password)
        assertEquals(uuid, repo.search("Instrumented Login").single().uuid)
        assertEquals(secondUuid, repo.search("Second Instrumented").single().uuid)
        assertEquals(listOf("Instrumented Login"), repo.matchApp("com.instrumented.app").map { it.title })
    }

    @Test
    fun conflictReappliesPendingAdditionsAndKeepsBothWritersEntries(): Unit = runBlocking {
        val original = asset("sample4.kdbx")
        val externalBytes = externalDatabaseWith(original, "External Writer")
        val store = MemoryStore(ref, original).apply {
            conflicts = 1
            this.externalBytes = externalBytes
        }
        val repo = repository(store)
        unlock(repo, "testpassword")

        val uuid = repo.addLogin(
            NewLogin("Local Writer", "local", "local-secret", "https://local.example", null),
        )

        assertEquals(2, store.writes)
        assertEquals(1, repo.search("Local Writer").size)
        assertEquals(1, repo.search("External Writer").size)

        // The merged result is what the store holds now.
        repo.lock()
        repo.unlock("testpassword".toCharArray(), null)
        assertNotNull(repo.search("Local Writer").singleOrNull())
        assertNotNull(repo.search("External Writer").singleOrNull())
        assertEquals(uuid, repo.search("Local Writer").single().uuid)
        assertEquals("local-secret", repo.entry(uuid).password)
    }

    @Test
    fun passkeyRegistrationPersistsAndAssertsWithJavaSecurity(): Unit = runBlocking {
        val store = MemoryStore(ref, asset("sample4.kdbx"))
        val repo = repository(store)
        unlock(repo, "testpassword")

        val registration = repo.registerPasskey(
            PasskeyCreateRequest(
                rpId = "passkey.example",
                rpName = "Passkey Example",
                userName = "alice@example.com",
                userDisplayName = "Alice",
                userHandle = "alice-handle".toByteArray(),
                algorithms = listOf(-7),
                excludeCredentialIds = emptyList(),
            ),
        )

        assertEquals("passkey.example", repo.entry(registration.entryUuid).summary.title)
        assertTrue(repo.entry(registration.entryUuid).summary.hasPasskey)
        assertEquals(1, store.writes)
        val found = repo.passkeysForRp("passkey.example", emptyList())
        assertEquals(1, found.size)
        assertEquals(registration.entryUuid, found.single().entryUuid)

        val clientDataHash = ByteArray(32) { (it * 7).toByte() }
        val assertion = repo.assertPasskey(registration.entryUuid, "passkey.example", clientDataHash)
        assertTrue(assertion.credentialId.contentEquals(registration.credentialId))
        assertTrue(assertion.userHandle.contentEquals("alice-handle".toByteArray()))

        val key = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(registration.publicKeySpkiDer))
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(key)
        verifier.update(assertion.authenticatorData)
        verifier.update(clientDataHash)
        assertTrue("ES256 signature verifies", verifier.verify(assertion.signature))

        // Survives a lock/unlock through the store bytes.
        repo.lock()
        repo.unlock("testpassword".toCharArray(), null)
        assertEquals(1, repo.passkeysForRp("passkey.example", emptyList()).size)
        val reopenedAssertion = repo.assertPasskey(registration.entryUuid, "passkey.example", clientDataHash)
        assertTrue(assertion.credentialId.contentEquals(reopenedAssertion.credentialId))
        assertTrue(assertion.authenticatorData.contentEquals(reopenedAssertion.authenticatorData))
    }

    private fun externalDatabaseWith(bytes: ByteArray, title: String): ByteArray {
        val opened = openVault(bytes, "testpassword", null)
        return try {
            opened.addLogin(
                RustNewLogin(
                    title = title,
                    username = "other",
                    password = "other-secret",
                    url = "https://external.example",
                    androidApp = null,
                ),
            )
            opened.save()
        } finally {
            opened.destroy()
        }
    }

    /** In-memory SAF stand-in; [conflicts] simulates a second writer replacing the document once. */
    private class MemoryStore(
        private val ref: DatabaseRef,
        initial: ByteArray,
    ) : DatabaseStore {
        private var bytes: ByteArray = initial.copyOf()
        private var lastModified: Long = 1L
        private var size: Long = initial.size.toLong()

        var conflicts: Int = 0
        var externalBytes: ByteArray? = null
        var writes: Int = 0
            private set

        override fun recent(): List<DatabaseRef> = listOf(ref)

        override fun remember(db: DatabaseRef) = Unit

        override fun forget(db: DatabaseRef) = Unit

        override suspend fun read(db: DatabaseRef): Snapshot =
            Snapshot(bytes = bytes.copyOf(), lastModified = lastModified, size = size)

        override suspend fun write(db: DatabaseRef, bytes: ByteArray, expected: Snapshot): WriteResult {
            writes += 1
            if (expected.lastModified != lastModified || expected.size != size) {
                return WriteResult.Conflict
            }
            if (conflicts > 0) {
                conflicts -= 1
                externalBytes?.let {
                    this.bytes = it.copyOf()
                    size = it.size.toLong()
                    lastModified += 10
                }
                return WriteResult.Conflict
            }
            this.bytes = bytes.copyOf()
            size = bytes.size.toLong()
            lastModified += 1
            return WriteResult.Written(Snapshot(this.bytes.copyOf(), lastModified, size))
        }
    }
}
