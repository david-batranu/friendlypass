package org.friendlypass.android.storage

import org.friendlypass.android.vault.model.DatabaseRef

/** Bytes read from a database document plus the provider metadata they were read at. */
data class Snapshot(
    val bytes: ByteArray,
    val lastModified: Long?,
    val size: Long?,
)

sealed interface WriteResult {
    data class Written(val snapshot: Snapshot) : WriteResult

    /** The document changed since [Snapshot] was read; the caller must re-read and retry. */
    data object Conflict : WriteResult
}

/** Storage-facing view of a database document plus the persisted "recent databases" list. */
interface DatabaseStore {
    fun recent(): List<DatabaseRef>

    fun remember(db: DatabaseRef)

    fun forget(db: DatabaseRef)

    /** Reads through the provider, falling back to the app-private cache when the provider fails. */
    suspend fun read(db: DatabaseRef): Snapshot

    /** Returns [WriteResult.Conflict] when the remote metadata no longer matches [expected]. */
    suspend fun write(db: DatabaseRef, bytes: ByteArray, expected: Snapshot): WriteResult
}

/** Provider metadata used to detect external changes. `null` fields mean the provider does not publish them. */
data class DocumentMetadata(val lastModified: Long?, val size: Long?)

/**
 * The narrow slice of SAF the store needs. Keeping it behind an interface lets the conflict logic be unit
 * tested on the JVM without Robolectric.
 */
interface DocumentGateway {
    /** `null` when the provider returns no document row (or cannot be queried). */
    fun metadata(uri: String): DocumentMetadata?

    fun displayName(uri: String): String?

    fun read(uri: String): ByteArray

    /** Truncating write (`openOutputStream(uri, "wt")`). */
    fun write(uri: String, bytes: ByteArray)

    fun readCache(key: String): ByteArray?

    fun writeCache(key: String, bytes: ByteArray)

    fun deleteCache(key: String)
}

/** Persisted recent-database list (URI + display name only). */
interface RecentStore {
    fun load(): List<DatabaseRef>

    fun save(entries: List<DatabaseRef>)
}
