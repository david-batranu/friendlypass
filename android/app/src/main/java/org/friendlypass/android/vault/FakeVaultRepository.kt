package org.friendlypass.android.vault

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.friendlypass.android.storage.DatabaseStore
import org.friendlypass.android.storage.WriteResult
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.EntryDetail
import org.friendlypass.android.vault.model.EntryField
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
 * In-memory vault with realistic sample data. It is the app's vault until the UniFFI-backed
 * `RustVaultRepository` lands, and it is what the JVM and instrumented tests run against.
 *
 * Password for every demo database: **"test"**.
 *
 * [store] is optional and only used by tests that exercise the conflict-safe save loop; the app never passes a
 * real store to the fake because writing fake bytes over a user's KDBX file would corrupt it.
 */
class FakeVaultRepository(
    private val store: DatabaseStore? = null,
) : VaultRepository {

    private val stateLock = Any()
    private val _state = MutableStateFlow<VaultState>(VaultState.NoDatabase)
    override val state: StateFlow<VaultState> = _state.asStateFlow()

    private var database: FakeDatabase? = null

    override fun selectDatabase(db: DatabaseRef) {
        synchronized(stateLock) {
            if (database?.ref != db) {
                database = FakeDatabase.seed(db)
            }
            _state.value = VaultState.Locked(db)
        }
    }

    override suspend fun unlock(password: CharArray?, keyfile: ByteArray?) {
        try {
            val ref = synchronized(stateLock) {
                when (val s = _state.value) {
                    is VaultState.Locked -> s.db
                    is VaultState.Unlocked -> s.db
                    VaultState.NoDatabase -> throw VaultException.Locked()
                }
            }
            // The fake vault only knows one password; a key file of any non-zero length is accepted as a
            // second factor so the key-file picker can be exercised end to end.
            val supplied = password?.concatToString() ?: ""
            val keyfileOk = keyfile == null || keyfile.isNotEmpty()
            if (supplied != DEMO_PASSWORD || !keyfileOk) {
                throw VaultException.InvalidCredentials()
            }
            synchronized(stateLock) {
                _state.value = VaultState.Unlocked(ref, database?.name ?: ref.displayName)
            }
        } finally {
            password?.fill('\u0000')
            keyfile?.fill(0)
        }
    }

    override fun lock() {
        synchronized(stateLock) {
            _state.value = when (val s = _state.value) {
                is VaultState.Locked -> s
                is VaultState.Unlocked -> VaultState.Locked(s.db)
                VaultState.NoDatabase -> VaultState.NoDatabase
            }
        }
    }

    override fun groups(): List<GroupNode> = requireUnlocked().groups.values.toList()

    override fun rootGroupUuid(): String = requireUnlocked().rootUuid

    override fun entriesInGroup(groupUuid: String): List<EntrySummary> {
        val db = requireUnlocked()
        return db.entries.values
            .filter { it.summary.groupPath == db.pathOf(groupUuid) }
            .map { it.summary }
            .sortedBy { it.title.lowercase() }
    }

    override fun search(query: String): List<EntrySummary> {
        val db = requireUnlocked()
        val needle = query.trim().lowercase()
        if (needle.isEmpty()) return emptyList()
        return db.entries.values
            .filter { detail ->
                detail.summary.title.lowercase().contains(needle) ||
                    detail.summary.username.lowercase().contains(needle) ||
                    detail.urls.any { it.lowercase().contains(needle) } ||
                    detail.notes.lowercase().contains(needle) ||
                    detail.tags.any { it.lowercase().contains(needle) }
            }
            .sortedBy { it.summary.title.lowercase() }
            .map { it.summary }
    }

    override fun entry(uuid: String): EntryDetail =
        requireUnlocked().entries[uuid] ?: throw VaultException.Failure("Entry not found")

    override fun totp(uuid: String, nowSecs: Long): TotpCode? {
        val db = requireUnlocked()
        val secret = db.totpSecrets[uuid] ?: return null
        return Totp.code(secret, nowSecs)
    }

    override fun matchWeb(url: String): List<EntrySummary> {
        val db = requireUnlocked()
        val target = Matching.Target(webUrl = url)
        return db.entries.values
            .mapNotNull { detail ->
                val score = detail.urls.mapNotNull { Matching.webScore(it, target) }.minOrNull()
                score?.let { it to detail.summary }
            }
            .sortedBy { it.first }
            .map { it.second }
    }

    override fun matchApp(packageName: String): List<EntrySummary> {
        val db = requireUnlocked()
        val target = Matching.Target(androidPackage = packageName)
        return db.entries.values
            .mapNotNull { detail ->
                Matching.androidScore(detail.urls, detail.androidApps, target)?.let { it to detail.summary }
            }
            .sortedBy { it.first }
            .map { it.second }
    }

    override suspend fun addLogin(login: NewLogin): String {
        val db = requireUnlocked()
        val uuid = newUuid()
        val urls = buildList {
            login.url?.takeIf { it.isNotBlank() }?.let(::add)
            login.androidApp?.takeIf { it.isNotBlank() }?.let { add("androidapp://$it") }
        }
        val detail = EntryDetail(
            summary = EntrySummary(
                uuid = uuid,
                title = login.title,
                username = login.username,
                url = urls.firstOrNull().orEmpty(),
                groupPath = db.pathOf(db.rootUuid),
                hasTotp = false,
                hasPasskey = false,
            ),
            password = login.password,
            notes = "",
            urls = urls,
            androidApps = listOfNotNull(login.androidApp),
            customFields = listOfNotNull(
                login.androidApp?.let { EntryField("AndroidApp", it, protected = false) },
            ),
            tags = emptyList(),
        )
        synchronized(stateLock) {
            db.entries[uuid] = detail
        }
        persist()
        return uuid
    }

    override fun passkeysForRp(rpId: String, allowCredentialIds: List<ByteArray>): List<PasskeyInfo> {
        val db = requireUnlocked()
        return db.entries.values
            .filter { it.summary.hasPasskey }
            .filter { detail ->
                val rp = detail.customFields.firstOrNull { it.name == PASSKEY_RP_FIELD }?.value
                rp == rpId
            }
            .filter { detail ->
                allowCredentialIds.isEmpty() || allowCredentialIds.any { it.contentEquals(credentialIdFor(detail)) }
            }
            .map { detail ->
                PasskeyInfo(
                    entryUuid = detail.summary.uuid,
                    credentialId = credentialIdFor(detail),
                    rpId = rpId,
                    username = detail.summary.username,
                    userHandle = detail.summary.username.toByteArray(),
                )
            }
    }

    override suspend fun registerPasskey(req: PasskeyCreateRequest): PasskeyRegistration =
        throw VaultException.Failure("Passkey registration needs the Rust vault")

    override fun assertPasskey(entryUuid: String, rpId: String, clientDataHash: ByteArray): PasskeyAssertion =
        throw VaultException.Failure("Passkey assertions need the Rust vault")

    private fun credentialIdFor(detail: EntryDetail): ByteArray =
        detail.customFields.firstOrNull { it.name == PASSKEY_CREDENTIAL_FIELD }?.value?.toByteArray()
            ?: detail.summary.uuid.toByteArray()

    private fun requireUnlocked(): FakeDatabase {
        if (_state.value !is VaultState.Unlocked) throw VaultException.Locked()
        return database ?: throw VaultException.Locked()
    }

    /**
     * Conflict-safe save loop used by [addLogin]; the production fake is constructed without a store, so this is
     * only reachable from tests. Mirrors the retry algorithm in the contract (read fresh, write, max 3 tries).
     */
    private suspend fun persist() {
        val store = store ?: return
        val db = requireUnlocked()
        val bytes = serialize(db)
        var attempt = 0
        while (true) {
            val snapshot = try {
                store.read(db.ref)
            } catch (_: VaultException) {
                // Demo database with no backing document: keep the change in memory.
                return
            }
            when (store.write(db.ref, bytes, snapshot)) {
                is WriteResult.Written -> return
                WriteResult.Conflict -> {
                    if (++attempt >= MAX_SAVE_ATTEMPTS) throw VaultException.Conflict()
                }
            }
        }
    }

    /** Not a KDBX file: the fake deliberately never writes to real user documents. */
    private fun serialize(db: FakeDatabase): ByteArray = buildString {
        append("FRIENDLYPASS-FAKE-1\n")
        db.entries.values.forEach { detail ->
            append(detail.summary.uuid).append('\t')
                .append(detail.summary.title).append('\t')
                .append(detail.summary.username).append('\t')
                .append(detail.urls.joinToString(",")).append('\n')
        }
    }.toByteArray()

    private fun newUuid(): String = java.util.UUID.randomUUID().toString().replace("-", "").lowercase()

    class FakeDatabase private constructor(
        val ref: DatabaseRef,
        val name: String,
        val rootUuid: String,
        val groups: LinkedHashMap<String, GroupNode>,
        val entries: LinkedHashMap<String, EntryDetail>,
        val totpSecrets: MutableMap<String, String>,
    ) {
        fun pathOf(groupUuid: String): String {
            val names = ArrayDeque<String>()
            var current: GroupNode? = groups[groupUuid]
            while (current != null) {
                names.addFirst(current.name)
                current = current.parentUuid?.let { groups[it] }
            }
            return names.joinToString("/")
        }

        companion object {
            const val ROOT = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
            private const val EMAIL = "b1c2d3e4f5a60718293a4b5c6d7e8f91"
            private const val WORK = "c1d2e3f4a5b60718293a4b5c6d7e8f92"
            private const val APPS = "d1e2f3a4b5c60718293a4b5c6d7e8f93"
            private const val FINANCE = "e1f2a3b4c5d60718293a4b5c6d7e8f94"

            fun seed(ref: DatabaseRef): FakeDatabase {
                val groups = linkedMapOf(
                    ROOT to GroupNode(ROOT, "Root", null, 0),
                    EMAIL to GroupNode(EMAIL, "Email", ROOT, 2),
                    WORK to GroupNode(WORK, "Work", ROOT, 3),
                    APPS to GroupNode(APPS, "Apps", ROOT, 2),
                    FINANCE to GroupNode(FINANCE, "Finance", ROOT, 1),
                )
                val entries = linkedMapOf<String, EntryDetail>()
                val totp = mutableMapOf<String, String>()

                fun path(group: String) = run {
                    val names = ArrayDeque<String>()
                    var current: GroupNode? = groups[group]
                    while (current != null) {
                        names.addFirst(current.name)
                        current = current.parentUuid?.let { groups[it] }
                    }
                    names.joinToString("/")
                }

                fun add(
                    uuid: String,
                    group: String,
                    title: String,
                    username: String,
                    password: String,
                    urls: List<String>,
                    notes: String = "",
                    tags: List<String> = emptyList(),
                    androidApps: List<String> = emptyList(),
                    customFields: List<EntryField> = emptyList(),
                    totpSecret: String? = null,
                    passkeyRp: String? = null,
                ) {
                    val detail = EntryDetail(
                        summary = EntrySummary(
                            uuid = uuid,
                            title = title,
                            username = username,
                            url = urls.firstOrNull().orEmpty(),
                            groupPath = path(group),
                            hasTotp = totpSecret != null,
                            hasPasskey = passkeyRp != null,
                        ),
                        password = password,
                        notes = notes,
                        urls = urls,
                        androidApps = androidApps,
                        customFields = buildList {
                            addAll(customFields)
                            passkeyRp?.let {
                                add(EntryField(PASSKEY_RP_FIELD, it, protected = false))
                                add(EntryField(PASSKEY_CREDENTIAL_FIELD, "cred-$uuid", protected = true))
                            }
                        },
                        tags = tags,
                    )
                    entries[uuid] = detail
                    totpSecret?.let { totp[uuid] = it }
                }

                add(
                    uuid = "f1a2b3c4d5e60718293a4b5c6d7e8f01",
                    group = EMAIL,
                    title = "Fastmail",
                    username = "david@example.com",
                    password = "fastmail-demo-password",
                    urls = listOf("https://app.fastmail.com"),
                    notes = "Personal mailbox. TOTP code is generated from the entry's otp field.",
                    tags = listOf("email", "personal"),
                    totpSecret = "JBSWY3DPEHPK3PXP",
                )
                add(
                    uuid = "f1a2b3c4d5e60718293a4b5c6d7e8f02",
                    group = EMAIL,
                    title = "Gmail",
                    username = "david@gmail.example",
                    password = "gmail-demo-password",
                    urls = listOf("https://mail.google.com", "https://accounts.google.com"),
                    tags = listOf("email"),
                )
                add(
                    uuid = "f1a2b3c4d5e60718293a4b5c6d7e8f03",
                    group = WORK,
                    title = "GitHub",
                    username = "david",
                    password = "github-demo-password",
                    urls = listOf("https://github.com", "https://gist.github.com"),
                    notes = "Work account. 2FA is enabled.",
                    tags = listOf("work", "git"),
                    customFields = listOf(EntryField("Team", "Platform", protected = false)),
                )
                add(
                    uuid = "f1a2b3c4d5e60718293a4b5c6d7e8f04",
                    group = WORK,
                    title = "Jira",
                    username = "david@friendlypass.example",
                    password = "jira-demo-password",
                    urls = listOf("https://friendlypass.atlassian.net"),
                    tags = listOf("work"),
                )
                add(
                    uuid = "f1a2b3c4d5e60718293a4b5c6d7e8f05",
                    group = WORK,
                    title = "PyPI",
                    username = "david",
                    password = "pypi-demo-password",
                    urls = listOf("https://pypi.org"),
                    notes = "Sign in with the passkey associated with this entry.",
                    tags = listOf("work", "packaging"),
                    passkeyRp = "pypi.org",
                )
                add(
                    uuid = "f1a2b3c4d5e60718293a4b5c6d7e8f06",
                    group = APPS,
                    title = "Example App",
                    username = "demo@example.app",
                    password = "android-demo-password",
                    urls = listOf("androidapp://com.example.app"),
                    notes = "Android app entry, matched by package name in autofill.",
                    tags = listOf("android"),
                    androidApps = listOf("com.example.app"),
                )
                add(
                    uuid = "f1a2b3c4d5e60718293a4b5c6d7e8f07",
                    group = APPS,
                    title = "Home Assistant",
                    username = "admin",
                    password = "home-assistant-demo",
                    urls = listOf("https://home.example.lan"),
                    notes = "Only reachable on the home network.",
                    tags = listOf("smarthome"),
                )
                add(
                    uuid = "f1a2b3c4d5e60718293a4b5c6d7e8f08",
                    group = FINANCE,
                    title = "Bank",
                    username = "david",
                    password = "bank-demo-password",
                    urls = listOf("https://bank.example.org"),
                    tags = listOf("finance"),
                )
                return FakeDatabase(
                    ref = ref,
                    name = "friendlypass demo",
                    rootUuid = ROOT,
                    groups = groups,
                    entries = entries,
                    totpSecrets = totp,
                )
            }
        }
    }

    companion object {
        const val DEMO_PASSWORD = "test"
        const val PASSKEY_RP_FIELD = "KPEX_PASSKEY_RELYING_PARTY"
        const val PASSKEY_CREDENTIAL_FIELD = "KPEX_PASSKEY_CREDENTIAL_ID"
        private const val MAX_SAVE_ATTEMPTS = 3

        /** The database the skeleton is wired to until the Rust engine lands. */
        val DEMO_DATABASE = DatabaseRef("demo://friendlypass/sample4.kdbx", "sample4.kdbx")
    }
}
