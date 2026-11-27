package org.friendlypass.android.vault

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.friendlypass.android.storage.DatabaseStore
import org.friendlypass.android.storage.Snapshot
import org.friendlypass.android.storage.WriteResult
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.EntryDetail
import org.friendlypass.android.vault.model.EntryField
import org.friendlypass.android.vault.model.EntryInput
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
import uniffi.friendlypass_mobile.EntryDetail as RustEntryDetail
import uniffi.friendlypass_mobile.EntryField as RustEntryField
import uniffi.friendlypass_mobile.EntryInput as RustEntryInput
import uniffi.friendlypass_mobile.EntrySummary as RustEntrySummary
import uniffi.friendlypass_mobile.GroupNode as RustGroupNode
import uniffi.friendlypass_mobile.MergeResult as RustMergeResult
import uniffi.friendlypass_mobile.NewLogin as RustNewLogin
import uniffi.friendlypass_mobile.PasskeyAssertion as RustPasskeyAssertion
import uniffi.friendlypass_mobile.PasskeyCreateRequest as RustPasskeyCreateRequest
import uniffi.friendlypass_mobile.PasskeyInfo as RustPasskeyInfo
import uniffi.friendlypass_mobile.PasskeyRegistration as RustPasskeyRegistration
import uniffi.friendlypass_mobile.TotpCode as RustTotpCode
import uniffi.friendlypass_mobile.Vault as RustVault
import uniffi.friendlypass_mobile.VaultException as RustVaultException
import uniffi.friendlypass_mobile.openVault

/**
 * [VaultRepository] backed by the UniFFI `friendlypass_mobile` cdylib.
 *
 * All Rust calls run on [Dispatchers.IO]. Concurrent edits across synced devices (desktop + Android) are
 * handled the same way as the desktop app:
 * - [syncIfChanged] performs a cheap metadata check and reloads the database in place when another client
 *   saved a newer copy and there are no unsaved local edits.
 * - [addLogin] and [registerPasskey] merge remote changes via `Vault.mergeFromBytes` (UUID + timestamp +
 *   tombstones + conflict history + attachments + `meta.custom_data` + root-UUID check) whenever the
 *   backing document changed before writing, preserving exact entry UUIDs and passkey keypairs.
 *
 * The password and key file are only held while unlocked, as arrays that are zeroed by [lock]. They never appear
 * in log messages, exception messages or the state flow.
 *
 * The debug `DEMO_DATABASE` URI (`demo://…`) has no backing SAF document; for it this class delegates to
 * [FakeVaultRepository] so the documented `DEMO_DATABASE` extra keeps working without writing fake bytes over a
 * user file.
 */
class RustVaultRepository(
    private val store: DatabaseStore,
    @Suppress("UNUSED_PARAMETER") context: Context,
) : VaultRepository {

    private val monitor = Any()
    private val persistMutex = Mutex()
    private val mutableState = MutableStateFlow<VaultState>(VaultState.NoDatabase)
    private val stateFlow: StateFlow<VaultState> = mutableState.asStateFlow()
    override val state: StateFlow<VaultState> get() = stateFlow

    private val mutableRevision = MutableStateFlow(0L)
    override val revision: StateFlow<Long> = mutableRevision.asStateFlow()

    private val mutableSyncEvents = MutableSharedFlow<String>(extraBufferCapacity = 4)
    override val syncEvents: SharedFlow<String> = mutableSyncEvents.asSharedFlow()

    /** Non-null only while the debug demo database is selected. */
    @Volatile
    private var demo: FakeVaultRepository? = null

    private var vault: RustVault? = null
    private var snapshot: Snapshot? = null
    private var sessionPassword: CharArray? = null
    private var sessionKeyfile: ByteArray? = null
    private var hasUnsavedChanges: Boolean = false

    override fun selectDatabase(db: DatabaseRef) {
        if (db.uri.startsWith(DEMO_URI_PREFIX)) {
            val fake = FakeVaultRepository().apply { selectDatabase(db) }
            synchronized(monitor) {
                dropRustVaultLocked()
                demo = fake
            }
            mutableState.value = fake.state.value
            return
        }
        synchronized(monitor) {
            demo = null
            dropRustVaultLocked()
            mutableState.value = VaultState.Locked(db)
        }
    }

    override suspend fun unlock(password: CharArray?, keyfile: ByteArray?) {
        demo?.let { fake ->
            try {
                fake.unlock(password, keyfile)
            } finally {
                mutableState.value = fake.state.value
                mutableRevision.value += 1
            }
            return
        }

        val db = synchronized(monitor) {
            when (val current = mutableState.value) {
                is VaultState.Locked -> current.db
                is VaultState.Unlocked -> current.db
                VaultState.NoDatabase -> throw VaultException.Locked()
            }
        }

        val passwordCopy = password?.copyOf()
        val keyfileCopy = keyfile?.copyOf()
        val fresh: Snapshot
        val opened: RustVault
        try {
            fresh = withContext(Dispatchers.IO) { store.read(db) }
            opened = withContext(Dispatchers.IO) {
                openVault(
                    fresh.bytes,
                    passwordCopy?.concatToString(),
                    keyfileCopy,
                )
            }
        } catch (error: RustVaultException) {
            passwordCopy?.fill('\u0000')
            keyfileCopy?.fill(0)
            throw error.toContract()
        } catch (error: Exception) {
            passwordCopy?.fill('\u0000')
            keyfileCopy?.fill(0)
            throw error.toContract()
        } finally {
            password?.fill('\u0000')
            keyfile?.fill(0)
        }

        val name = try {
            opened.databaseName()
        } catch (error: RustVaultException) {
            opened.destroy()
            passwordCopy?.fill('\u0000')
            keyfileCopy?.fill(0)
            throw error.toContract()
        }

        synchronized(monitor) {
            dropRustVaultLocked()
            vault = opened
            snapshot = fresh
            sessionPassword = passwordCopy
            sessionKeyfile = keyfileCopy
            hasUnsavedChanges = false
            mutableState.value = VaultState.Unlocked(db, name)
            mutableRevision.value += 1
        }
    }

    override fun lock() {
        demo?.let { fake ->
            fake.lock()
            mutableState.value = fake.state.value
            return
        }
        synchronized(monitor) {
            dropRustVaultLocked()
            mutableState.value = when (val current = mutableState.value) {
                is VaultState.Locked -> current
                is VaultState.Unlocked -> VaultState.Locked(current.db)
                VaultState.NoDatabase -> VaultState.NoDatabase
            }
        }
    }

    override fun clearDatabase() {
        synchronized(monitor) {
            demo = null
            dropRustVaultLocked()
            mutableState.value = VaultState.NoDatabase
        }
    }

    override suspend fun syncIfChanged(): Boolean {
        if (demo != null) return false
        return persistMutex.withLock {
            val (db, currentSnapshot, dirty) = synchronized(monitor) {
                val unlocked = mutableState.value as? VaultState.Unlocked ?: return@withLock false
                val snap = snapshot ?: return@withLock false
                Triple(unlocked.db, snap, hasUnsavedChanges)
            }
            // Do not discard unsaved local edits; they will be merged on the next save.
            if (dirty) return@withLock false

            val changed = runCatching { store.hasChanged(db, currentSnapshot) }.getOrDefault(false)
            if (!changed) return@withLock false

            val fresh = runCatching { withContext(Dispatchers.IO) { store.read(db) } }.getOrNull()
                ?: return@withLock false
            if (fresh.bytes.contentEquals(currentSnapshot.bytes)) {
                synchronized(monitor) {
                    if (snapshot === currentSnapshot) {
                        snapshot = fresh
                    }
                }
                return@withLock false
            }

            val password = synchronized(monitor) { sessionPassword?.concatToString() }
            val keyfile = synchronized(monitor) { sessionKeyfile?.copyOf() }
            val (reopened, latestFresh) = try {
                openWithRetry(db, fresh, password, keyfile)
            } catch (_: Exception) {
                return@withLock false
            } finally {
                keyfile?.fill(0)
            }

            val name = try {
                withContext(Dispatchers.IO) { reopened.databaseName() }
            } catch (_: Exception) {
                reopened.destroy()
                return@withLock false
            }

            synchronized(monitor) {
                val current = mutableState.value
                if (current !is VaultState.Unlocked || current.db != db || hasUnsavedChanges) {
                    reopened.destroy()
                    return@withLock false
                }
                dropVaultOnlyLocked()
                vault = reopened
                snapshot = latestFresh
                mutableState.value = VaultState.Unlocked(db, name)
                mutableRevision.value += 1
            }
            mutableSyncEvents.tryEmit("Reloaded external changes")
            true
        }
    }

    override fun groups(): List<GroupNode> =
        demo?.groups() ?: rustCall { requireVault().groups() }.map(RustGroupNode::toModel)

    override fun rootGroupUuid(): String =
        demo?.rootGroupUuid() ?: rustCall { requireVault().rootGroupUuid() }

    override fun entriesInGroup(groupUuid: String): List<EntrySummary> =
        demo?.entriesInGroup(groupUuid)
            ?: rustCall { requireVault().entriesInGroup(groupUuid) }.map(RustEntrySummary::toModel)

    override fun allEntries(): List<EntrySummary> =
        demo?.allEntries()
            ?: rustCall { requireVault().allEntries() }.map(RustEntrySummary::toModel)

    override fun search(query: String): List<EntrySummary> =
        demo?.search(query)
            ?: rustCall { requireVault().search(query) }.map(RustEntrySummary::toModel)

    override fun entry(uuid: String): EntryDetail =
        demo?.entry(uuid) ?: rustCall { requireVault().entry(uuid) }.toModel()

    override fun totp(uuid: String, nowSecs: Long): TotpCode? =
        demo?.totp(uuid, nowSecs)
            ?: rustCall { requireVault().totp(uuid, nowSecs.toULong()) }?.toModel()

    override fun matchWeb(url: String): List<EntrySummary> =
        demo?.matchWeb(url)
            ?: rustCall { requireVault().matchWeb(url) }.map(RustEntrySummary::toModel)

    override fun matchApp(packageName: String): List<EntrySummary> =
        demo?.matchApp(packageName)
            ?: rustCall { requireVault().matchApp(packageName) }.map(RustEntrySummary::toModel)

    override suspend fun addLogin(login: NewLogin): String {
        demo?.let { fake ->
            return fake.addLogin(login).also { mutableRevision.value += 1 }
        }

        return persistMutex.withLock {
            val uuid = withContext(Dispatchers.IO) {
                rustCall { requireVault().addLogin(login.toRust()) }
            }
            synchronized(monitor) { hasUnsavedChanges = true }
            try {
                persistWithMerge()
            } finally {
                mutableRevision.value += 1
            }
            uuid
        }
    }

    override suspend fun createEntry(input: EntryInput): String {
        demo?.let { fake ->
            return fake.createEntry(input).also { mutableRevision.value += 1 }
        }
        return persistMutex.withLock {
            val uuid = withContext(Dispatchers.IO) {
                rustCall { requireVault().createEntry(input.toRust()) }
            }
            synchronized(monitor) { hasUnsavedChanges = true }
            try {
                persistWithMerge()
            } finally {
                mutableRevision.value += 1
            }
            uuid
        }
    }

    override suspend fun updateEntry(uuid: String, input: EntryInput) {
        demo?.let { fake ->
            fake.updateEntry(uuid, input)
            mutableRevision.value += 1
            return
        }
        persistMutex.withLock {
            withContext(Dispatchers.IO) {
                rustCall { requireVault().updateEntry(uuid, input.toRust()) }
            }
            synchronized(monitor) { hasUnsavedChanges = true }
            try {
                persistWithMerge()
            } finally {
                mutableRevision.value += 1
            }
        }
    }

    override suspend fun deleteEntry(uuid: String) {
        demo?.let { fake ->
            fake.deleteEntry(uuid)
            mutableRevision.value += 1
            return
        }
        persistMutex.withLock {
            withContext(Dispatchers.IO) {
                rustCall { requireVault().deleteEntry(uuid) }
            }
            synchronized(monitor) { hasUnsavedChanges = true }
            try {
                persistWithMerge()
            } finally {
                mutableRevision.value += 1
            }
        }
    }

    override suspend fun createGroup(parentUuid: String, name: String): String {
        demo?.let { fake ->
            return fake.createGroup(parentUuid, name).also { mutableRevision.value += 1 }
        }
        return persistMutex.withLock {
            val uuid = withContext(Dispatchers.IO) {
                rustCall { requireVault().createGroup(parentUuid, name) }
            }
            synchronized(monitor) { hasUnsavedChanges = true }
            try {
                persistWithMerge()
            } finally {
                mutableRevision.value += 1
            }
            uuid
        }
    }

    override suspend fun renameGroup(groupUuid: String, name: String) {
        demo?.let { fake ->
            fake.renameGroup(groupUuid, name)
            mutableRevision.value += 1
            return
        }
        persistMutex.withLock {
            withContext(Dispatchers.IO) {
                rustCall { requireVault().renameGroup(groupUuid, name) }
            }
            synchronized(monitor) { hasUnsavedChanges = true }
            try {
                persistWithMerge()
            } finally {
                mutableRevision.value += 1
            }
        }
    }

    override suspend fun deleteGroup(groupUuid: String) {
        demo?.let { fake ->
            fake.deleteGroup(groupUuid)
            mutableRevision.value += 1
            return
        }
        persistMutex.withLock {
            withContext(Dispatchers.IO) {
                rustCall { requireVault().deleteGroup(groupUuid) }
            }
            synchronized(monitor) { hasUnsavedChanges = true }
            try {
                persistWithMerge()
            } finally {
                mutableRevision.value += 1
            }
        }
    }

    override fun passkeysForRp(rpId: String, allowCredentialIds: List<ByteArray>): List<PasskeyInfo> =
        demo?.passkeysForRp(rpId, allowCredentialIds)
            ?: rustCall {
                requireVault().passkeysForRp(rpId, allowCredentialIds)
            }.map(RustPasskeyInfo::toModel)

    override suspend fun registerPasskey(req: PasskeyCreateRequest): PasskeyRegistration {
        demo?.let { return it.registerPasskey(req) }

        return persistMutex.withLock {
            val registration = withContext(Dispatchers.IO) {
                rustCall { requireVault().registerPasskey(req.toRust()) }.toModel()
            }
            synchronized(monitor) { hasUnsavedChanges = true }
            try {
                persistWithMerge()
            } finally {
                mutableRevision.value += 1
            }
            registration
        }
    }

    override fun assertPasskey(
        entryUuid: String,
        rpId: String,
        clientDataHash: ByteArray,
    ): PasskeyAssertion =
        demo?.assertPasskey(entryUuid, rpId, clientDataHash)
            ?: rustCall {
                requireVault().assertPasskey(entryUuid, rpId, clientDataHash)
            }.toModel()

    // ------------------------------------------------------------------ save

    /**
     * Write the current vault; on [WriteResult.Conflict] re-read the document, merge external changes into
     * the in-memory vault via `Vault.mergeFromBytes`, re-serialize, and try again. Three writes at most.
     */
    private suspend fun persistWithMerge() {
        val db = synchronized(monitor) {
            when (val current = mutableState.value) {
                is VaultState.Unlocked -> current.db
                else -> throw VaultException.Locked()
            }
        }
        var expected = synchronized(monitor) { snapshot } ?: throw VaultException.Locked()
        var bytes = withContext(Dispatchers.IO) { rustCall { requireVault().save() } }

        var attempt = 1
        while (true) {
            val result = withContext(Dispatchers.IO) { store.write(db, bytes, expected) }
            when (result) {
                is WriteResult.Written -> {
                    synchronized(monitor) {
                        snapshot = result.snapshot
                        hasUnsavedChanges = false
                    }
                    return
                }

                WriteResult.Conflict -> {
                    if (attempt >= MAX_SAVE_ATTEMPTS) throw VaultException.Conflict()
                    attempt += 1

                    val fresh = withContext(Dispatchers.IO) { store.read(db) }
                    if (!fresh.bytes.contentEquals(expected.bytes)) {
                        val (merged, latestFresh) = mergeWithRetry(db, fresh)
                        bytes = withContext(Dispatchers.IO) { rustCall { requireVault().save() } }
                        val name = withContext(Dispatchers.IO) {
                            runCatching { requireVault().databaseName() }.getOrNull()
                        }
                        synchronized(monitor) {
                            snapshot = latestFresh
                            if (name != null && mutableState.value is VaultState.Unlocked) {
                                mutableState.value = VaultState.Unlocked(db, name)
                            }
                        }
                        expected = latestFresh
                        mutableSyncEvents.tryEmit("Merged external changes (${merged.description})")
                    } else {
                        synchronized(monitor) { snapshot = fresh }
                        expected = fresh
                    }
                }
            }
        }
    }

    /** Retries briefly in case a cloud sync provider is mid-write when we read the remote copy. */
    private suspend fun mergeWithRetry(
        db: DatabaseRef,
        initialFresh: Snapshot,
    ): Pair<RustMergeResult, Snapshot> {
        var fresh = initialFresh
        var lastError: RustVaultException? = null
        for (retryIndex in 0..OPEN_RETRY_DELAYS_MS.size) {
            if (retryIndex > 0) {
                delay(OPEN_RETRY_DELAYS_MS[retryIndex - 1])
                fresh = withContext(Dispatchers.IO) { store.read(db) }
            }
            try {
                val merged = withContext(Dispatchers.IO) {
                    requireVault().mergeFromBytes(fresh.bytes)
                }
                return merged to fresh
            } catch (error: RustVaultException) {
                // Wrong credentials or an unrelated database will not resolve by retrying.
                if (error is RustVaultException.InvalidCredentials ||
                    (error is RustVaultException.Corrupt && error.msg.contains("different database"))
                ) {
                    throw error.toContract()
                }
                lastError = error
            }
        }
        throw lastError?.toContract() ?: VaultException.Conflict()
    }

    /** Retries briefly in case a cloud sync provider is mid-write when we auto-reload. */
    private suspend fun openWithRetry(
        db: DatabaseRef,
        initialFresh: Snapshot,
        password: String?,
        keyfile: ByteArray?,
    ): Pair<RustVault, Snapshot> {
        var fresh = initialFresh
        var lastError: Exception? = null
        for (retryIndex in 0..OPEN_RETRY_DELAYS_MS.size) {
            if (retryIndex > 0) {
                delay(OPEN_RETRY_DELAYS_MS[retryIndex - 1])
                fresh = withContext(Dispatchers.IO) { store.read(db) }
            }
            try {
                val opened = withContext(Dispatchers.IO) {
                    openVault(fresh.bytes, password, keyfile)
                }
                return opened to fresh
            } catch (error: RustVaultException) {
                if (error is RustVaultException.InvalidCredentials) throw error
                lastError = error
            } catch (error: Exception) {
                lastError = error
            }
        }
        throw lastError ?: VaultException.Failure("Could not reopen database")
    }

    // --------------------------------------------------------------- helpers

    private fun requireVault(): RustVault =
        synchronized(monitor) { vault } ?: throw VaultException.Locked()

    /** Drops the vault and every credential copy; caller holds [monitor]. */
    private fun dropRustVaultLocked() {
        dropVaultOnlyLocked()
        sessionPassword?.fill('\u0000')
        sessionKeyfile?.fill(0)
        sessionPassword = null
        sessionKeyfile = null
        snapshot = null
        hasUnsavedChanges = false
    }

    private fun dropVaultOnlyLocked() {
        val current = vault ?: return
        vault = null
        runCatching { current.destroy() }
    }

    private inline fun <T> rustCall(block: () -> T): T =
        try {
            block()
        } catch (error: RustVaultException) {
            throw error.toContract()
        }

    private companion object {
        const val MAX_SAVE_ATTEMPTS = 3
        const val DEMO_URI_PREFIX = "demo://"
        val OPEN_RETRY_DELAYS_MS = longArrayOf(100L, 250L, 500L)
    }
}

// --------------------------------------------------------------- conversions

private fun RustVaultException.toContract(): VaultException = when (this) {
    is RustVaultException.InvalidCredentials -> VaultException.InvalidCredentials()
    is RustVaultException.Corrupt -> VaultException.Failure(msg.ifBlank { "Corrupt database" })
    is RustVaultException.Unsupported -> VaultException.Failure(msg.ifBlank { "Unsupported database" })
    is RustVaultException.NotFound -> VaultException.Failure("Entry not found")
    is RustVaultException.Io -> VaultException.Failure(msg.ifBlank { "I/O error" })
}

private fun Exception.toContract(): VaultException = when (this) {
    is VaultException -> this
    else -> VaultException.Failure(message?.takeIf { it.isNotBlank() } ?: "Vault operation failed")
}

private fun RustEntrySummary.toModel(): EntrySummary = EntrySummary(
    uuid = uuid,
    title = title,
    username = username,
    url = url,
    groupPath = groupPath,
    hasTotp = hasTotp,
    hasPasskey = hasPasskey,
)

private fun RustEntryField.toModel(): EntryField = EntryField(
    name = name,
    value = value,
    protected = protected,
)

private fun RustEntryDetail.toModel(): EntryDetail = EntryDetail(
    summary = summary.toModel(),
    password = password,
    notes = notes,
    urls = urls.toList(),
    androidApps = androidApps.toList(),
    customFields = customFields.map(RustEntryField::toModel),
    tags = tags.toList(),
    groupUuid = groupUuid,
    otpUri = otpUri,
)

private fun EntryField.toRust(): RustEntryField = RustEntryField(
    name = name,
    value = value,
    protected = protected,
)

private fun EntryInput.toRust(): RustEntryInput = RustEntryInput(
    groupUuid = groupUuid,
    title = title,
    username = username,
    password = password,
    url = url,
    notes = notes,
    totp = totp,
    androidApps = androidApps,
    customFields = customFields.map(EntryField::toRust),
    tags = tags,
)

private fun RustGroupNode.toModel(): GroupNode = GroupNode(
    uuid = uuid,
    name = name,
    parentUuid = parentUuid,
    entryCount = entryCount.toInt(),
)

private fun RustTotpCode.toModel(): TotpCode = TotpCode(
    code = code,
    periodSecs = periodSecs.toInt(),
    remainingSecs = remainingSecs.toInt(),
)

private fun RustPasskeyInfo.toModel(): PasskeyInfo = PasskeyInfo(
    entryUuid = entryUuid,
    credentialId = credentialId,
    rpId = rpId,
    username = username,
    userHandle = userHandle,
)

private fun RustPasskeyRegistration.toModel(): PasskeyRegistration = PasskeyRegistration(
    entryUuid = entryUuid,
    credentialId = credentialId,
    authenticatorData = authenticatorData,
    attestationObject = attestationObject,
    publicKeySpkiDer = publicKeySpkiDer,
    algorithm = algorithm,
)

private fun RustPasskeyAssertion.toModel(): PasskeyAssertion = PasskeyAssertion(
    credentialId = credentialId,
    authenticatorData = authenticatorData,
    signature = signature,
    userHandle = userHandle,
)

private fun NewLogin.toRust(): RustNewLogin = RustNewLogin(
    title = title,
    username = username,
    password = password,
    url = url,
    androidApp = androidApp,
)

private fun PasskeyCreateRequest.toRust(): RustPasskeyCreateRequest = RustPasskeyCreateRequest(
    rpId = rpId,
    rpName = rpName,
    userName = userName,
    userDisplayName = userDisplayName,
    userHandle = userHandle,
    algorithms = algorithms,
    excludeCredentialIds = excludeCredentialIds,
)
