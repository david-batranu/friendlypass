package org.friendlypass.android.vault.model

/** Stable, persistable reference to a database document (SAF URI + label). */
data class DatabaseRef(val uri: String, val displayName: String)

/**
 * Mirror of the Rust `VaultError` / Kotlin-side errors surfaced by [org.friendlypass.android.vault.VaultRepository].
 * Messages never contain credentials or entry contents.
 */
sealed class VaultException(msg: String) : Exception(msg) {
    class InvalidCredentials : VaultException("Wrong password or key file")
    class Locked : VaultException("Database is locked")
    class Conflict : VaultException("Database changed elsewhere and could not be merged")
    class Failure(msg: String) : VaultException(msg)
}

/** What the repository currently holds. */
sealed interface VaultState {
    data object NoDatabase : VaultState
    data class Locked(val db: DatabaseRef) : VaultState
    data class Unlocked(val db: DatabaseRef, val databaseName: String) : VaultState
}

/**
 * Mirror of the UniFFI `EntrySummary` record. `uuid` is dashless lowercase hex.
 */
data class EntrySummary(
    val uuid: String,
    val title: String,
    val username: String,
    val url: String,
    val groupPath: String,
    val hasTotp: Boolean,
    val hasPasskey: Boolean,
)

/** Mirror of the UniFFI `EntryField` record. */
data class EntryField(
    val name: String,
    val value: String,
    val protected: Boolean,
)

/** Mirror of the UniFFI `EntryDetail` record. */
data class EntryDetail(
    val summary: EntrySummary,
    val password: String,
    val notes: String,
    /** Main URL first. */
    val urls: List<String>,
    val androidApps: List<String>,
    val customFields: List<EntryField>,
    val tags: List<String>,
    val groupUuid: String = "",
    val otpUri: String? = null,
)

/** Mirror of the UniFFI `EntryInput` record for creating or editing an entry. */
data class EntryInput(
    val groupUuid: String,
    val title: String,
    val username: String,
    val password: String,
    val url: String,
    val notes: String,
    val totp: String? = null,
    val androidApps: List<String> = emptyList(),
    val customFields: List<EntryField> = emptyList(),
    val tags: List<String> = emptyList(),
)

/** Mirror of the UniFFI `GroupNode` record. The recycle bin is never included. */
data class GroupNode(
    val uuid: String,
    val name: String,
    val parentUuid: String?,
    val entryCount: Int,
)

/** Mirror of the UniFFI `TotpCode` record. */
data class TotpCode(
    val code: String,
    val periodSecs: Int,
    val remainingSecs: Int,
)

/** Mirror of the UniFFI `NewLogin` record. */
data class NewLogin(
    val title: String,
    val username: String,
    val password: String,
    val url: String?,
    val androidApp: String?,
)

/** Mirror of the UniFFI `PasskeyInfo` record. */
data class PasskeyInfo(
    val entryUuid: String,
    val credentialId: ByteArray,
    val rpId: String,
    val username: String,
    val userHandle: ByteArray,
)

/** Mirror of the UniFFI `PasskeyCreateRequest` record. */
data class PasskeyCreateRequest(
    val rpId: String,
    val rpName: String,
    val userName: String,
    val userDisplayName: String,
    val userHandle: ByteArray,
    val algorithms: List<Long>,
    val excludeCredentialIds: List<ByteArray>,
)

/** Mirror of the UniFFI `PasskeyRegistration` record. */
data class PasskeyRegistration(
    val entryUuid: String,
    val credentialId: ByteArray,
    val authenticatorData: ByteArray,
    val attestationObject: ByteArray,
    val publicKeySpkiDer: ByteArray,
    val algorithm: Long,
)

/** Mirror of the UniFFI `PasskeyAssertion` record. */
data class PasskeyAssertion(
    val credentialId: ByteArray,
    val authenticatorData: ByteArray,
    val signature: ByteArray,
    val userHandle: ByteArray,
)
