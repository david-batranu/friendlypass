package org.friendlypass.android.credentials

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.friendlypass.android.vault.VaultRepository
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.EntryDetail
import org.friendlypass.android.vault.model.EntrySummary
import org.friendlypass.android.vault.model.GroupNode
import org.friendlypass.android.vault.model.NewLogin
import org.friendlypass.android.vault.model.PasskeyAssertion
import org.friendlypass.android.vault.model.PasskeyCreateRequest
import org.friendlypass.android.vault.model.PasskeyInfo
import org.friendlypass.android.vault.model.PasskeyRegistration
import org.friendlypass.android.vault.model.TotpCode
import org.friendlypass.android.vault.model.VaultException
import org.friendlypass.android.vault.model.VaultState

/**
 * Test-only [VaultRepository] returning canned passkey values (the production fake throws for passkeys until the
 * Rust vault lands).
 */
class TestVaultRepository(
    private val entries: List<EntryDetail> = emptyList(),
    private val passkeys: List<PasskeyInfo> = emptyList(),
    unlocked: Boolean = true,
    private val registerResult: PasskeyRegistration? = null,
    private val assertResult: PasskeyAssertion? = null,
) : VaultRepository {

    private val db = DatabaseRef("content://test/demo.kdbx", "demo.kdbx")
    private val _state = MutableStateFlow<VaultState>(
        if (unlocked) VaultState.Unlocked(db, "friendlypass demo") else VaultState.Locked(db),
    )
    override val state: StateFlow<VaultState> = _state.asStateFlow()

    var lastPasskeyRequest: PasskeyCreateRequest? = null
        private set
    var lastAssertedUuid: String? = null
        private set
    var lastAssertedHash: ByteArray? = null
        private set
    var lastLogin: NewLogin? = null
        private set

    override fun lock() {
        _state.value = VaultState.Locked(db)
    }

    override fun selectDatabase(db: DatabaseRef) {
        _state.value = VaultState.Locked(db)
    }

    override suspend fun unlock(password: CharArray?, keyfile: ByteArray?) {
        _state.value = VaultState.Unlocked(db, "friendlypass demo")
    }

    override fun groups(): List<GroupNode> = listOf(GroupNode("root", "Root", null, entries.size))

    override fun rootGroupUuid(): String = "root"

    override fun entriesInGroup(groupUuid: String): List<EntrySummary> = entries.map { it.summary }

    override fun search(query: String): List<EntrySummary> =
        entries.map { it.summary }.filter { it.title.contains(query, ignoreCase = true) }

    override fun entry(uuid: String): EntryDetail =
        entries.firstOrNull { it.summary.uuid == uuid } ?: throw VaultException.Failure("missing")

    override fun totp(uuid: String, nowSecs: Long): TotpCode? = null

    override fun matchWeb(url: String): List<EntrySummary> {
        val host = OriginPolicy.hostOf(url) ?: return emptyList()
        return entries.map { it.summary }.filter { summary ->
            OriginPolicy.hostOf(summary.url) == host
        }
    }

    override fun matchApp(packageName: String): List<EntrySummary> = entries
        .filter { detail -> detail.androidApps.any { it == packageName } }
        .map { it.summary }

    override suspend fun addLogin(login: NewLogin): String {
        lastLogin = login
        return "new-entry"
    }

    override fun passkeysForRp(rpId: String, allowCredentialIds: List<ByteArray>): List<PasskeyInfo> = passkeys
        .filter { it.rpId == rpId }
        .filter { allowCredentialIds.isEmpty() || allowCredentialIds.any { allow -> allow.contentEquals(it.credentialId) } }

    override suspend fun registerPasskey(req: PasskeyCreateRequest): PasskeyRegistration {
        lastPasskeyRequest = req
        return registerResult ?: throw VaultException.Failure("no canned registration")
    }

    override fun assertPasskey(entryUuid: String, rpId: String, clientDataHash: ByteArray): PasskeyAssertion {
        lastAssertedUuid = entryUuid
        lastAssertedHash = clientDataHash.copyOf()
        return assertResult ?: throw VaultException.Failure("no canned assertion")
    }
}

fun entry(
    uuid: String,
    title: String,
    username: String = "user",
    password: String = "secret",
    url: String = "",
    androidApps: List<String> = emptyList(),
): EntryDetail = EntryDetail(
    summary = EntrySummary(uuid, title, username, url, "Root", hasTotp = false, hasPasskey = false),
    password = password,
    notes = "",
    urls = listOfNotNull(url.takeIf { it.isNotBlank() }),
    androidApps = androidApps,
    customFields = emptyList(),
    tags = emptyList(),
)

fun passkey(entryUuid: String, rpId: String, credentialId: ByteArray, username: String = "user"): PasskeyInfo =
    PasskeyInfo(entryUuid, credentialId, rpId, username, username.toByteArray())
