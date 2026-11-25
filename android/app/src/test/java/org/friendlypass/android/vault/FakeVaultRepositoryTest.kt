package org.friendlypass.android.vault

import kotlinx.coroutines.test.runTest
import org.friendlypass.android.storage.DatabaseStore
import org.friendlypass.android.storage.Snapshot
import org.friendlypass.android.storage.WriteResult
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.EntrySummary
import org.friendlypass.android.vault.model.NewLogin
import org.friendlypass.android.vault.model.VaultException
import org.friendlypass.android.vault.model.VaultState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class FakeVaultRepositoryTest {

    private fun lockedRepository(): FakeVaultRepository = FakeVaultRepository().apply {
        selectDatabase(FakeVaultRepository.DEMO_DATABASE)
    }

    private suspend fun unlockedRepository(): FakeVaultRepository = lockedRepository().apply {
        unlock("test".toCharArray(), null)
    }

    private fun FakeVaultRepository.allEntries(): List<EntrySummary> =
        groups().flatMap { entriesInGroup(it.uuid) }

    @Test
    fun `select database locks and records it`() {
        val repo = FakeVaultRepository()
        assertEquals(VaultState.NoDatabase, repo.state.value)

        repo.selectDatabase(FakeVaultRepository.DEMO_DATABASE)

        val state = repo.state.value as VaultState.Locked
        assertEquals(FakeVaultRepository.DEMO_DATABASE, state.db)
    }

    @Test
    fun `demo password unlocks and wipes the inputs`() = runTest {
        val repo = lockedRepository()
        val password = "test".toCharArray()
        val keyfile = byteArrayOf(1, 2, 3)

        repo.unlock(password, keyfile)

        val state = repo.state.value as VaultState.Unlocked
        assertEquals(FakeVaultRepository.DEMO_DATABASE, state.db)
        assertTrue(state.databaseName.isNotBlank())
        assertTrue("password must be wiped", password.all { it == '\u0000' })
        assertTrue("key file must be wiped", keyfile.all { it == 0.toByte() })
    }

    @Test
    fun `wrong password throws invalid credentials and stays locked`() = runTest {
        val repo = lockedRepository()

        val error = runCatching { repo.unlock("not-test".toCharArray(), null) }.exceptionOrNull()

        assertTrue(error is VaultException.InvalidCredentials)
        assertTrue(repo.state.value is VaultState.Locked)
    }

    @Test
    fun `reads throw locked before unlocking`() {
        val repo = lockedRepository()
        assertThrows(VaultException.Locked::class.java) { repo.groups() }
        assertThrows(VaultException.Locked::class.java) { repo.entry("whatever") }
        assertThrows(VaultException.Locked::class.java) { repo.search("github") }
    }

    @Test
    fun `lock returns to locked and refuses reads`() = runTest {
        val repo = unlockedRepository()

        repo.lock()

        assertTrue(repo.state.value is VaultState.Locked)
        assertThrows(VaultException.Locked::class.java) { repo.groups() }
    }

    @Test
    fun `seeded data has groups, a github login, an android app, one totp and one passkey`() = runTest {
        val repo = unlockedRepository()

        val groups = repo.groups()
        assertTrue(groups.size >= 4)
        assertEquals(repo.rootGroupUuid(), groups.first { it.parentUuid == null }.uuid)

        val entries = repo.allEntries()
        assertTrue(entries.isNotEmpty())
        assertEquals(1, entries.count { it.hasTotp })
        assertEquals(1, entries.count { it.hasPasskey })
        assertTrue(entries.any { it.url == "https://github.com" })
        assertTrue(entries.any { it.url == "androidapp://com.example.app" })

        val github = entries.first { it.title == "GitHub" }
        val detail = repo.entry(github.uuid)
        assertEquals("david", detail.summary.username)
        assertTrue(detail.urls.contains("https://gist.github.com"))
        assertEquals("Root/Work", detail.summary.groupPath)

        val android = entries.first { it.title == "Example App" }
        assertTrue(repo.entry(android.uuid).androidApps.contains("com.example.app"))
    }

    @Test
    fun `entries in group only returns direct children`() = runTest {
        val repo = unlockedRepository()
        val root = repo.rootGroupUuid()

        assertTrue(repo.entriesInGroup(root).isEmpty())

        val work = repo.groups().first { it.name == "Work" }
        val titles = repo.entriesInGroup(work.uuid).map { it.title }
        assertEquals(listOf("GitHub", "Jira", "PyPI"), titles)
    }

    @Test
    fun `search is case insensitive across title username url notes and tags`() = runTest {
        val repo = unlockedRepository()

        assertEquals(listOf("GitHub"), repo.search("GITHUB").map { it.title })
        assertEquals(listOf("Fastmail"), repo.search("david@example.com").map { it.title })
        assertEquals(listOf("Bank"), repo.search("bank.example.org").map { it.title })
        assertTrue(repo.search("home network").map { it.title }.contains("Home Assistant"))
        assertTrue(repo.search("finance").map { it.title }.contains("Bank"))
        assertTrue(repo.search("   ").isEmpty())
    }

    @Test
    fun `totp returns a six digit code with countdown`() = runTest {
        val repo = unlockedRepository()
        val fastmail = repo.allEntries().first { it.title == "Fastmail" }

        val code = requireNotNull(repo.totp(fastmail.uuid, 59L))

        assertEquals(6, code.code.length)
        assertTrue(code.code.all { it.isDigit() })
        assertEquals(30, code.periodSecs)
        assertEquals(1, code.remainingSecs) // 59 s is the last second of the window
        assertEquals(null, repo.totp(repo.allEntries().first { it.title == "GitHub" }.uuid, 59L))
    }

    @Test
    fun `totp matches the RFC 6238 SHA-1 vector`() {
        // Secret "12345678901234567890" from RFC 6238, base32 encoded.
        val secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

        assertEquals("287082", Totp.code(secret, 59L, digits = 6).code)
        assertEquals("94287082", Totp.code(secret, 59L, digits = 8).code)
        assertEquals("081804", Totp.code(secret, 1_111_111_109L, digits = 6).code)
    }

    @Test
    fun `match web returns exact host first and ignores other hosts`() = runTest {
        val repo = unlockedRepository()

        assertEquals(listOf("GitHub"), repo.matchWeb("https://gist.github.com/an/example").map { it.title })
        assertEquals("GitHub", repo.matchWeb("https://github.com/login")[0].title)
        assertTrue(repo.matchWeb("https://example.net").isEmpty())
    }

    @Test
    fun `match app uses the android package name`() = runTest {
        val repo = unlockedRepository()

        assertEquals(listOf("Example App"), repo.matchApp("com.example.app").map { it.title })
        assertEquals(listOf("Example App"), repo.matchApp("com.example.app").map { it.title })
        assertTrue(repo.matchApp("com.other.app").isEmpty())
    }

    @Test
    fun `passkeys are looked up by relying party`() = runTest {
        val repo = unlockedRepository()

        val passkeys = repo.passkeysForRp("pypi.org", emptyList())

        assertEquals(1, passkeys.size)
        assertEquals("PyPI", repo.entry(passkeys[0].entryUuid).summary.title)
        assertTrue(repo.passkeysForRp("other.example", emptyList()).isEmpty())
        assertTrue(repo.passkeysForRp("pypi.org", listOf(byteArrayOf(9, 9))).isEmpty())
    }

    @Test
    fun `passkey operations that need the rust vault fail cleanly`() = runTest {
        val repo = unlockedRepository()
        val error = runCatching {
            repo.registerPasskey(
                org.friendlypass.android.vault.model.PasskeyCreateRequest(
                    rpId = "example.org",
                    rpName = "Example",
                    userName = "david",
                    userDisplayName = "David",
                    userHandle = byteArrayOf(1),
                    algorithms = listOf(-7),
                    excludeCredentialIds = emptyList(),
                ),
            )
        }.exceptionOrNull()

        assertTrue(error is VaultException.Failure)
    }

    @Test
    fun `add login retries after conflicts and returns the new uuid`() = runTest {
        val store = RecordingStore(conflicts = 2)
        val repo = FakeVaultRepository(store).apply {
            selectDatabase(FakeVaultRepository.DEMO_DATABASE)
            unlock("test".toCharArray(), null)
        }

        val uuid = repo.addLogin(NewLogin("New site", "david", "secret", "https://new.example", null))

        assertEquals(3, store.writes)
        assertEquals("New site", repo.entry(uuid).summary.title)
        assertTrue(repo.search("new site").any { it.uuid == uuid })
    }

    @Test
    fun `add login gives up after three conflicts`() = runTest {
        val store = RecordingStore(conflicts = 3)
        val repo = FakeVaultRepository(store).apply {
            selectDatabase(FakeVaultRepository.DEMO_DATABASE)
            unlock("test".toCharArray(), null)
        }

        val error = runCatching {
            repo.addLogin(NewLogin("New site", "david", "secret", "https://new.example", null))
        }.exceptionOrNull()

        assertTrue(error is VaultException.Conflict)
        assertEquals(3, store.writes)
    }

    @Test
    fun `add login stores the android package as AndroidApp field`() = runTest {
        val repo = unlockedRepository()

        val uuid = repo.addLogin(NewLogin("Mobile", "david", "secret", null, "com.mobile.app"))

        val detail = repo.entry(uuid)
        assertTrue(detail.urls.contains("androidapp://com.mobile.app"))
        assertTrue(detail.customFields.any { it.name == "AndroidApp" && it.value == "com.mobile.app" })
        assertFalse(detail.summary.hasPasskey)
    }

    private class RecordingStore(private val conflicts: Int) : DatabaseStore {
        var writes = 0

        override fun recent(): List<DatabaseRef> = emptyList()

        override fun remember(db: DatabaseRef) = Unit

        override fun forget(db: DatabaseRef) = Unit

        override suspend fun read(db: DatabaseRef): Snapshot =
            Snapshot(bytes = byteArrayOf(0x00, 0x01), lastModified = 1L, size = 2L)

        override suspend fun write(db: DatabaseRef, bytes: ByteArray, expected: Snapshot): WriteResult {
            writes++
            return if (writes <= conflicts) {
                WriteResult.Conflict
            } else {
                WriteResult.Written(Snapshot(bytes, 2L, bytes.size.toLong()))
            }
        }
    }
}
