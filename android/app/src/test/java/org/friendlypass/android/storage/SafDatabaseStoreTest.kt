package org.friendlypass.android.storage

import kotlinx.coroutines.test.runTest
import org.friendlypass.android.vault.model.DatabaseRef
import org.friendlypass.android.vault.model.VaultException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.FileNotFoundException
import java.io.IOException
import java.io.OutputStream

class SafDatabaseStoreTest {

    private val db = DatabaseRef("content://test/doc.kdbx", "doc.kdbx")
    private val gateway = FakeGateway()
    private val recentStore = InMemoryRecentStore()
    private val store = SafDatabaseStore(gateway, recentStore)

    @Test
    fun `read returns provider bytes and metadata and caches them`() = runTest {
        gateway.documentBytes = byteArrayOf(1, 2, 3, 4)
        gateway.documentMetadata = DocumentMetadata(lastModified = 100L, size = 4L)

        val snapshot = store.read(db)

        assertArrayEquals(byteArrayOf(1, 2, 3, 4), snapshot.bytes)
        assertEquals(100L, snapshot.lastModified)
        assertEquals(4L, snapshot.size)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), gateway.cache[SafDatabaseStore.cacheKey(db.uri)])
    }

    @Test
    fun `read falls back to the cached copy with null metadata when the provider fails`() = runTest {
        gateway.documentBytes = byteArrayOf(7, 8, 9)
        gateway.documentMetadata = DocumentMetadata(lastModified = 10L, size = 3L)
        store.read(db) // populates the cache
        gateway.failReads = true
        gateway.documentMetadata = DocumentMetadata(lastModified = 11L, size = 3L)

        val snapshot = store.read(db)

        assertArrayEquals(byteArrayOf(7, 8, 9), snapshot.bytes)
        assertNull("offline reads must not claim a timestamp", snapshot.lastModified)
        assertNull(snapshot.size)
    }

    @Test
    fun `read without cache or provider throws a failure`() = runTest {
        gateway.failReads = true

        val error = runCatching { store.read(db) }.exceptionOrNull()

        assertTrue(error is VaultException.Failure)
    }

    @Test
    fun `write succeeds when metadata is unchanged and updates the cache`() = runTest {
        gateway.documentMetadata = DocumentMetadata(lastModified = 100L, size = 4L)
        val expected = Snapshot(byteArrayOf(1, 2, 3, 4), lastModified = 100L, size = 4L)

        val result = store.write(db, byteArrayOf(9, 9, 9, 9, 9), expected)

        assertTrue(result is WriteResult.Written)
        assertArrayEquals(byteArrayOf(9, 9, 9, 9, 9), gateway.documentBytes)
        val written = result as WriteResult.Written
        assertEquals(gateway.documentMetadata?.lastModified, written.snapshot.lastModified)
        assertEquals(5L, written.snapshot.size)
        assertArrayEquals(byteArrayOf(9, 9, 9, 9, 9), gateway.cache[SafDatabaseStore.cacheKey(db.uri)])
    }

    @Test
    fun `write returns conflict when lastModified changed`() = runTest {
        gateway.documentMetadata = DocumentMetadata(lastModified = 101L, size = 4L)
        val expected = Snapshot(byteArrayOf(1, 2, 3, 4), lastModified = 100L, size = 4L)

        val result = store.write(db, byteArrayOf(9), expected)

        assertEquals(WriteResult.Conflict, result)
        assertNull("conflicting writes must not touch the document", gateway.writeBytes)
    }

    @Test
    fun `write returns conflict when size changed`() = runTest {
        gateway.documentMetadata = DocumentMetadata(lastModified = 100L, size = 5L)
        val expected = Snapshot(byteArrayOf(1, 2, 3, 4), lastModified = 100L, size = 4L)

        assertEquals(WriteResult.Conflict, store.write(db, byteArrayOf(9), expected))
        assertNull(gateway.writeBytes)
    }

    @Test
    fun `write returns conflict when the provider reports metadata after an offline read`() = runTest {
        gateway.documentBytes = byteArrayOf(1, 2, 3, 4)
        gateway.documentMetadata = DocumentMetadata(lastModified = 10L, size = 4L)
        val cached = store.read(db)
        gateway.failReads = true
        val offline = store.read(db) // cached copy, no metadata
        assertNull(offline.lastModified)

        // Provider is back and reports metadata that we cannot match against the offline snapshot.
        gateway.failReads = false
        val result = store.write(db, byteArrayOf(5, 6, 7, 8), offline)

        assertEquals(WriteResult.Conflict, result)
        assertNull(gateway.writeBytes)
        // The earlier online snapshot would have been accepted.
        assertEquals(true, store.write(db, byteArrayOf(5, 6, 7, 8), cached) is WriteResult.Written)
    }

    @Test
    fun `write returns conflict when the provider has no metadata row`() = runTest {
        gateway.documentMetadata = null
        val expected = Snapshot(byteArrayOf(1), lastModified = 1L, size = 1L)

        assertEquals(WriteResult.Conflict, store.write(db, byteArrayOf(2), expected))
        assertNull(gateway.writeBytes)
    }

    @Test
    fun `write rethrows provider failures as failure`() = runTest {
        gateway.documentMetadata = DocumentMetadata(lastModified = 1L, size = 1L)
        gateway.failWrites = true
        val expected = Snapshot(byteArrayOf(1), lastModified = 1L, size = 1L)

        val error = runCatching { store.write(db, byteArrayOf(2), expected) }.exceptionOrNull()

        assertTrue(error is VaultException.Failure)
    }

    @Test
    fun `write asks for rwt first so Google Drive accepts the document`() = runTest {
        gateway.documentMetadata = DocumentMetadata(lastModified = 1L, size = 1L)
        val expected = Snapshot(byteArrayOf(1), lastModified = 1L, size = 1L)

        val result = store.write(db, byteArrayOf(2, 3), expected)

        assertTrue(result is WriteResult.Written)
        assertEquals("rwt", gateway.writeMode)
    }

    @Test
    fun `write falls back to wt when a provider rejects rwt`() = runTest {
        gateway.documentMetadata = DocumentMetadata(lastModified = 1L, size = 1L)
        gateway.unsupportedModes = setOf("rwt")
        val expected = Snapshot(byteArrayOf(1), lastModified = 1L, size = 1L)

        val result = store.write(db, byteArrayOf(2, 3), expected)

        assertTrue(result is WriteResult.Written)
        assertEquals("wt", gateway.writeMode)
        assertArrayEquals(byteArrayOf(2, 3), gateway.documentBytes)
    }

    @Test
    fun `write never falls back to the non-truncating w mode`() = runTest {
        gateway.documentMetadata = DocumentMetadata(lastModified = 1L, size = 1L)
        gateway.unsupportedModes = setOf("rwt", "wt")
        val expected = Snapshot(byteArrayOf(1), lastModified = 1L, size = 1L)

        val error = runCatching { store.write(db, byteArrayOf(2, 3), expected) }.exceptionOrNull()

        assertTrue(error is VaultException.Failure)
        assertNull(gateway.writeBytes)
        assertNull(gateway.writeMode)
    }

    @Test
    fun `write fails without touching the document when every mode is rejected`() = runTest {
        gateway.documentMetadata = DocumentMetadata(lastModified = 1L, size = 1L)
        gateway.unsupportedModes = setOf("rwt", "wt")
        val expected = Snapshot(byteArrayOf(1), lastModified = 1L, size = 1L)

        val error = runCatching { store.write(db, byteArrayOf(2), expected) }.exceptionOrNull()

        assertTrue(error is VaultException.Failure)
        assertNull(gateway.writeBytes)
    }

    @Test
    fun `recent list keeps newest first without duplicates`() {
        val first = DatabaseRef("content://test/a.kdbx", "a.kdbx")
        val second = DatabaseRef("content://test/b.kdbx", "b.kdbx")

        store.remember(first)
        store.remember(second)
        store.remember(first)

        assertEquals(listOf(first, second), store.recent())
    }

    @Test
    fun `forget removes the entry and its cache`() {
        store.remember(db)
        gateway.cache[SafDatabaseStore.cacheKey(db.uri)] = byteArrayOf(1)

        store.forget(db)

        assertTrue(store.recent().isEmpty())
        assertFalse(gateway.cache.containsKey(SafDatabaseStore.cacheKey(db.uri)))
    }

    @Test
    fun `cache key is the sha256 of the uri`() {
        val key = SafDatabaseStore.cacheKey(db.uri)

        assertEquals(64, key.length)
        assertEquals(key, SafDatabaseStore.cacheKey(db.uri))
        assertTrue(key.all { it in "0123456789abcdef" })
    }

    private class InMemoryRecentStore : RecentStore {
        private var entries: List<DatabaseRef> = emptyList()

        override fun load(): List<DatabaseRef> = entries

        override fun save(entries: List<DatabaseRef>) {
            this.entries = entries
        }
    }

    private class FakeGateway : DocumentGateway {
        var documentBytes: ByteArray = ByteArray(0)
        var documentMetadata: DocumentMetadata? = DocumentMetadata(lastModified = 1L, size = 1L)
        var failReads = false
        var failWrites = false
        var unsupportedModes: Set<String> = emptySet()
        var writeMode: String? = null
        var writeBytes: ByteArray? = null
        val cache = mutableMapOf<String, ByteArray>()

        override fun metadata(uri: String): DocumentMetadata? = documentMetadata

        override fun displayName(uri: String): String = "doc.kdbx"

        override fun read(uri: String): ByteArray {
            if (failReads) throw IOException("provider offline")
            return documentBytes
        }

        override fun openWrite(uri: String, mode: String): OutputStream {
            if (failWrites) throw IOException("provider read-only")
            if (mode in unsupportedModes) throw FileNotFoundException("Unsupported mode: $mode")
            writeMode = mode
            return object : ByteArrayOutputStream() {
                override fun close() {
                    super.close()
                    val bytes = toByteArray()
                    writeBytes = bytes
                    documentBytes = bytes
                    documentMetadata = DocumentMetadata(
                        lastModified = (documentMetadata?.lastModified ?: 0L) + 1,
                        size = bytes.size.toLong(),
                    )
                }
            }
        }

        override fun readCache(key: String): ByteArray? = cache[key]

        override fun writeCache(key: String, bytes: ByteArray) {
            cache[key] = bytes
        }

        override fun deleteCache(key: String) {
            cache.remove(key)
        }
    }
}
