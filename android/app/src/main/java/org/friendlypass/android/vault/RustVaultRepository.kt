package org.friendlypass.android.vault

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.friendlypass.android.storage.DatabaseStore
import org.friendlypass.android.storage.Snapshot
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
import uniffi.friendlypass_mobile.EntryDetail as RustEntryDetail
import uniffi.friendlypass_mobile.EntryField as RustEntryField
import uniffi.friendlypass_mobile.EntrySummary as RustEntrySummary
import uniffi.friendlypass_mobile.GroupNode as RustGroupNode
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
 * All Rust calls run on [Dispatchers.IO]. The encrypted bytes handed to the Rust vault carry the same credentials
 * the vault was opened with, so a conflict can re-read the document, open it again, re-apply this session's
 * not-yet-persisted additions and save once more (contract save algorithm, at most three writes).
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
    private val mutableState = MutableStateFlow<VaultState>(VaultState.NoDatabase)
    private val stateFlow: StateFlow<VaultState> = mutableState.asStateFlow()
    override val state: StateFlow<VaultState> get() = stateFlow

    /** Non-null only while the debug demo database is selected. */
    @Volatile
    private var demo: FakeVaultRepository? = null

    private var vault: RustVault? = null
    private var snapshot: Snapshot? = null
    private var sessionPassword: CharArray? = null
    private var sessionKeyfile: ByteArray? = null
    private val pending = mutableListOf<PendingAddition>()

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
            mutableState.value = VaultState.Unlocked(db, name)
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

    override fun groups(): List<GroupNode> =
        demo?.groups() ?: rustCall { requireVault().groups() }.map(RustGroupNode::toModel)

    override fun rootGroupUuid(): String =
        demo?.rootGroupUuid() ?: rustCall { requireVault().rootGroupUuid() }

    override fun entriesInGroup(groupUuid: String): List<EntrySummary> =
        demo?.entriesInGroup(groupUuid)
            ?: rustCall { requireVault().entriesInGroup(groupUuid) }.map(RustEntrySummary::toModel)

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
        demo?.let { return it.addLogin(login) }

        val initial = withContext(Dispatchers.IO) {
            rustCall { requireVault().addLogin(login.toRust()) }
        }
        synchronized(monitor) { pending += PendingAddition.Login(login) }
        val reapplied = persistPending()
        return reapplied?.loginUuids?.lastOrNull() ?: initial
    }

    override fun passkeysForRp(rpId: String, allowCredentialIds: List<ByteArray>): List<PasskeyInfo> =
        demo?.passkeysForRp(rpId, allowCredentialIds)
            ?: rustCall {
                requireVault().passkeysForRp(rpId, allowCredentialIds)
            }.map(RustPasskeyInfo::toModel)

    override suspend fun registerPasskey(req: PasskeyCreateRequest): PasskeyRegistration {
        demo?.let { return it.registerPasskey(req) }

        val initial = withContext(Dispatchers.IO) {
            rustCall { requireVault().registerPasskey(req.toRust()) }.toModel()
        }
        synchronized(monitor) { pending += PendingAddition.Passkey(req) }
        val reapplied = persistPending()
        return reapplied?.registrations?.lastOrNull() ?: initial
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
     * Write the current vault; on [WriteResult.Conflict] re-read the document, reopen it with the remembered
     * credentials, re-apply every pending addition and try again. Three writes at most.
     *
     * @return results from the last re-application, or `null` when the first write succeeded.
     */
    private suspend fun persistPending(): Applied? {
        val db = synchronized(monitor) {
            when (val current = mutableState.value) {
                is VaultState.Unlocked -> current.db
                else -> throw VaultException.Locked()
            }
        }
        var expected = synchronized(monitor) { snapshot } ?: throw VaultException.Locked()
        var bytes = withContext(Dispatchers.IO) { rustCall { requireVault().save() } }
        var applied: Applied? = null

        var attempt = 1
        while (true) {
            val result = withContext(Dispatchers.IO) { store.write(db, bytes, expected) }
            when (result) {
                is WriteResult.Written -> {
                    synchronized(monitor) {
                        snapshot = result.snapshot
                        pending.clear()
                    }
                    return applied
                }

                WriteResult.Conflict -> {
                    if (attempt >= MAX_SAVE_ATTEMPTS) throw VaultException.Conflict()
                    attempt += 1

                    val fresh = withContext(Dispatchers.IO) { store.read(db) }
                    val password = synchronized(monitor) { sessionPassword?.concatToString() }
                    val keyfile = synchronized(monitor) { sessionKeyfile?.copyOf() }
                    val reopened = try {
                        withContext(Dispatchers.IO) {
                            openVault(fresh.bytes, password, keyfile)
                        }
                    } finally {
                        keyfile?.fill(0)
                    }
                    val additions = synchronized(monitor) { pending.toList() }
                    val results = try {
                        withContext(Dispatchers.IO) { applyPending(reopened, additions) }
                    } catch (error: Exception) {
                        reopened.destroy()
                        throw error.toContract()
                    }
                    bytes = try {
                        withContext(Dispatchers.IO) { reopened.save() }
                    } catch (error: Exception) {
                        reopened.destroy()
                        throw error.toContract()
                    }

                    synchronized(monitor) {
                        dropVaultOnlyLocked()
                        vault = reopened
                        snapshot = fresh
                    }
                    expected = fresh
                    applied = results
                }
            }
        }
    }

    private fun applyPending(target: RustVault, additions: List<PendingAddition>): Applied {
        val loginUuids = mutableListOf<String>()
        val registrations = mutableListOf<PasskeyRegistration>()
        for (addition in additions) {
            when (addition) {
                is PendingAddition.Login ->
                    loginUuids += rustCall { target.addLogin(addition.login.toRust()) }

                is PendingAddition.Passkey ->
                    registrations += rustCall {
                        target.registerPasskey(addition.request.toRust())
                    }.toModel()
            }
        }
        return Applied(loginUuids, registrations)
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
        pending.clear()
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

    private sealed interface PendingAddition {
        data class Login(val login: NewLogin) : PendingAddition

        data class Passkey(val request: PasskeyCreateRequest) : PendingAddition
    }

    private data class Applied(
        val loginUuids: List<String>,
        val registrations: List<PasskeyRegistration>,
    )

    private companion object {
        const val MAX_SAVE_ATTEMPTS = 3
        const val DEMO_URI_PREFIX = "demo://"
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
