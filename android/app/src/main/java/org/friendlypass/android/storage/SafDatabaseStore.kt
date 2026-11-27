package org.friendlypass.android.storage

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.friendlypass.android.BuildConfig
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.VaultException
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.MessageDigest
import java.util.Base64

/**
 * SAF-backed [DatabaseStore].
 *
 * Read: provider first; the bytes are cached under `filesDir/cache-<sha256(uri)>.kdbx`, and a provider failure
 * returns that cached copy with `lastModified = null` so a later write cannot silently overwrite a file that
 * changed while we were offline.
 *
 * Write: the metadata is re-queried first and compared with [expected]; any difference (including "expected
 * unknown" vs "provider now reports metadata") is a [WriteResult.Conflict]. Only a matching snapshot is written
 * through [SafWrite] (which picks the first truncating mode the provider accepts), then re-queried and cached.
 */
class SafDatabaseStore(
    private val gateway: DocumentGateway,
    private val recentStore: RecentStore,
) : DatabaseStore {

    override fun recent(): List<DatabaseRef> = recentStore.load()

    override fun remember(db: DatabaseRef) {
        val entries = recentStore.load().filterNot { it.uri == db.uri }
        recentStore.save((listOf(db) + entries).take(MAX_RECENT))
    }

    override fun forget(db: DatabaseRef) {
        recentStore.save(recentStore.load().filterNot { it.uri == db.uri })
        gateway.deleteCache(cacheKey(db.uri))
    }

    override suspend fun read(db: DatabaseRef): Snapshot = withContext(Dispatchers.IO) {
        val key = cacheKey(db.uri)
        val bytes = try {
            gateway.read(db.uri).also { gateway.writeCache(key, it) }
        } catch (e: Exception) {
            val cached = gateway.readCache(key) ?: throw VaultException.Failure(
                "Could not read ${db.displayName}: ${e.message ?: "provider unavailable"}",
            )
            // Offline: the cached copy is usable, but it cannot vouch for the provider's current metadata.
            return@withContext Snapshot(bytes = cached, lastModified = null, size = null)
        }
        val metadata = runCatching { gateway.metadata(db.uri) }.getOrNull()
        Snapshot(bytes = bytes, lastModified = metadata?.lastModified, size = metadata?.size)
    }

    override suspend fun hasChanged(db: DatabaseRef, expected: Snapshot): Boolean =
        withContext(Dispatchers.IO) {
            val current = runCatching { gateway.metadata(db.uri) }.getOrNull() ?: return@withContext false
            if (current.lastModified == null && current.size == null) return@withContext true
            current.lastModified != expected.lastModified || current.size != expected.size
        }

    override suspend fun write(db: DatabaseRef, bytes: ByteArray, expected: Snapshot): WriteResult =
        withContext(Dispatchers.IO) {
            val current = runCatching { gateway.metadata(db.uri) }.getOrNull()
            if (!unchanged(db, current, expected)) return@withContext WriteResult.Conflict
            try {
                SafWrite.write(gateway, db.uri, bytes)
            } catch (e: Exception) {
                throw VaultException.Failure(
                    "Could not save ${db.displayName}: ${e.message ?: "provider unavailable"}",
                )
            }
            val after = runCatching { gateway.metadata(db.uri) }.getOrNull()
            gateway.writeCache(cacheKey(db.uri), bytes)
            WriteResult.Written(
                Snapshot(
                    bytes = bytes,
                    lastModified = after?.lastModified ?: current?.lastModified,
                    size = after?.size ?: bytes.size.toLong(),
                ),
            )
        }

    private fun unchanged(db: DatabaseRef, current: DocumentMetadata?, expected: Snapshot): Boolean {
        // No document row at all: we cannot prove the file is unchanged, so never truncate it.
        if (current == null) return false
        // Provider publishes neither timestamp nor size: verify content bytes directly so concurrent
        // edits from another client are never silently overwritten.
        if (current.lastModified == null && current.size == null) {
            val remoteBytes = runCatching { gateway.read(db.uri) }.getOrNull() ?: return false
            return remoteBytes.contentEquals(expected.bytes)
        }
        return current.lastModified == expected.lastModified && current.size == expected.size
    }

    companion object {
        private const val MAX_RECENT = 10

        fun cacheKey(uri: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(uri.toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it) }
        }
    }
}

/** Android implementation of [DocumentGateway] over `ContentResolver` and the app's private files directory. */
class AndroidDocumentGateway(private val context: Context) : DocumentGateway {

    /**
     * Debug builds also accept `file://` refs so instrumented tests can copy a real KDBX fixture into
     * app-private storage and exercise the Rust vault without a SAF picker. Release builds never do.
     */
    private fun debugFile(uri: String): File? {
        if (!BuildConfig.DEBUG) return null
        val parsed = Uri.parse(uri)
        if (parsed.scheme != "file") return null
        val path = parsed.path ?: return null
        return File(path)
    }

    override fun metadata(uri: String): DocumentMetadata? {
        debugFile(uri)?.let { file ->
            return if (file.isFile) DocumentMetadata(file.lastModified(), file.length()) else null
        }
        val parsed = Uri.parse(uri)
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_LAST_MODIFIED,
            DocumentsContract.Document.COLUMN_SIZE,
        )
        context.contentResolver.query(parsed, projection, null, null, null)?.use { cursor ->
            if (!cursor.moveToFirst()) return null
            val lastModifiedIndex = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            val sizeIndex = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
            val lastModified = if (lastModifiedIndex >= 0 && !cursor.isNull(lastModifiedIndex)) {
                cursor.getLong(lastModifiedIndex)
            } else {
                null
            }
            val size = if (sizeIndex >= 0 && !cursor.isNull(sizeIndex)) cursor.getLong(sizeIndex) else null
            return DocumentMetadata(lastModified, size)
        }
        return null
    }

    override fun displayName(uri: String): String? {
        debugFile(uri)?.let { return it.name }
        val parsed = Uri.parse(uri)
        context.contentResolver.query(parsed, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
            if (!it.moveToFirst()) return null
            val index = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index < 0 || it.isNull(index)) return null
            return it.getString(index)
        }
        return null
    }

    override fun read(uri: String): ByteArray {
        debugFile(uri)?.let { file -> return file.readBytes() }
        val parsed = Uri.parse(uri)
        return context.contentResolver.openInputStream(parsed)?.use { it.readBytes() }
            ?: throw java.io.IOException("provider returned no stream")
    }

    override fun openWrite(uri: String, mode: String): java.io.OutputStream? {
        debugFile(uri)?.let { file ->
            file.parentFile?.mkdirs()
            // file:// is debug-test-only and always truncates, mirroring the "rwt"/"wt" modes.
            return java.io.FileOutputStream(file, false)
        }
        val parsed = Uri.parse(uri)
        return context.contentResolver.openOutputStream(parsed, mode)
    }

    override fun readCache(key: String): ByteArray? {
        val file = cacheFile(key)
        return if (file.isFile) file.readBytes() else null
    }

    override fun writeCache(key: String, bytes: ByteArray) {
        cacheFile(key).writeBytes(bytes)
    }

    override fun deleteCache(key: String) {
        cacheFile(key).delete()
    }

    private fun cacheFile(key: String): File = File(context.filesDir, "cache-$key.kdbx")
}

/**
 * Writes a whole document through the first SAF mode the provider accepts.
 *
 * Providers disagree about truncating modes, and the difference breaks saving on a real device: Google Drive's
 * document provider rejects `"wt"` with `FileNotFoundException: Unsupported mode: wt` (Google recommends `"rwt"`
 * instead), while some local/third-party providers only implement `"wt"`. Plain `"w"` is never used: it may
 * not truncate on Android 10+, which would leave stale bytes after a shorter KDBX and corrupt the database.
 *
 * A failure to *open* a mode falls through to the next one; a failure while writing is propagated, because
 * retrying a partially written document would duplicate bytes.
 */
internal object SafWrite {

    val MODES: List<String> = listOf("rwt", "wt")

    fun write(gateway: DocumentGateway, uri: String, bytes: ByteArray) {
        var last: Exception? = null
        for (mode in MODES) {
            val stream = try {
                gateway.openWrite(uri, mode) ?: continue
            } catch (e: FileNotFoundException) {
                last = e
                continue
            } catch (e: UnsupportedOperationException) {
                last = e
                continue
            } catch (e: IllegalArgumentException) {
                last = e
                continue
            }
            stream.use {
                it.write(bytes)
                it.flush()
            }
            return
        }
        throw IOException("provider does not support writing (tried ${MODES.joinToString()})", last)
    }
}

/** Recent list in `SharedPreferences`: URI plus display name, nothing else. */
class PrefsRecentStore(context: Context) : RecentStore {

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    override fun load(): List<DatabaseRef> {
        val raw = prefs.getString(KEY_RECENT, null) ?: return emptyList()
        return raw.lineSequence()
            .filter { it.isNotBlank() }
            .mapNotNull { line ->
                val separator = line.indexOf('\t')
                if (separator <= 0) return@mapNotNull null
                val uri = line.substring(0, separator)
                val name = runCatching {
                    String(Base64.getDecoder().decode(line.substring(separator + 1)), Charsets.UTF_8)
                }.getOrNull() ?: return@mapNotNull null
                DatabaseRef(uri, name)
            }
            .toList()
    }

    override fun save(entries: List<DatabaseRef>) {
        val encoded = entries.joinToString("\n") { db ->
            val name = Base64.getEncoder().encodeToString(db.displayName.toByteArray(Charsets.UTF_8))
            "${db.uri}\t$name"
        }
        prefs.edit().putString(KEY_RECENT, encoded).apply()
    }

    companion object {
        private const val PREFS_NAME = "friendlypass.recent"
        private const val KEY_RECENT = "databases"
    }
}

/** Small helpers used when the picker returns a document. */
object SafDocuments {
    /** Persists read+write access across restarts; returns false if the provider does not grant it. */
    fun persistPermission(context: Context, uri: Uri): Boolean = runCatching {
        context.contentResolver.takePersistableUriPermission(
            uri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
        )
        true
    }.getOrDefault(false)

    /** Display name via `OpenableColumns`, falling back to the last path segment. */
    fun displayName(context: Context, uri: Uri): String {
        runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
                if (it.moveToFirst()) {
                    val index = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (index >= 0 && !it.isNull(index)) return it.getString(index)
                }
            }
        }
        return uri.lastPathSegment ?: "database.kdbx"
    }
}
