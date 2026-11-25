package org.friendlypass.android.vault

import kotlinx.coroutines.flow.StateFlow
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
import org.friendlypass.android.vault.model.VaultState

/**
 * Everything the UI needs from a database. Implemented by [FakeVaultRepository] until the UniFFI-backed
 * `RustVaultRepository` lands; callers must not care which one is active.
 *
 * All read methods throw [org.friendlypass.android.vault.model.VaultException.Locked] while the vault is not
 * unlocked. Auto-lock (idle timeout, screen off) lives in the app layer and simply calls [lock].
 */
interface VaultRepository {
    val state: StateFlow<VaultState>

    /** Selects [db] and moves to `Locked(db)`; remembers it as the current database. */
    fun selectDatabase(db: DatabaseRef)

    /** Throws [org.friendlypass.android.vault.model.VaultException] on failure and wipes both inputs. */
    suspend fun unlock(password: CharArray?, keyfile: ByteArray?)

    /** Drops the open vault; the state becomes `Locked` (or stays `NoDatabase`). */
    fun lock()

    fun groups(): List<GroupNode>

    fun rootGroupUuid(): String

    fun entriesInGroup(groupUuid: String): List<EntrySummary>

    fun search(query: String): List<EntrySummary>

    fun entry(uuid: String): EntryDetail

    fun totp(uuid: String, nowSecs: Long = System.currentTimeMillis() / 1000): TotpCode?

    /** Sorted best match first. */
    fun matchWeb(url: String): List<EntrySummary>

    fun matchApp(packageName: String): List<EntrySummary>

    /** Adds the login and saves through the [org.friendlypass.android.storage.DatabaseStore]. */
    suspend fun addLogin(login: NewLogin): String

    fun passkeysForRp(rpId: String, allowCredentialIds: List<ByteArray>): List<PasskeyInfo>

    suspend fun registerPasskey(req: PasskeyCreateRequest): PasskeyRegistration

    fun assertPasskey(entryUuid: String, rpId: String, clientDataHash: ByteArray): PasskeyAssertion
}
