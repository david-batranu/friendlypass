package org.friendlypass.android.debug

import android.content.Context
import android.net.Uri
import org.friendlypass.android.vault.model.DatabaseRef
import java.io.File

/**
 * Debug-build helper for instrumented tests: copies a real KDBX fixture into app-private storage and returns a
 * `file://` [DatabaseRef] that [org.friendlypass.android.storage.AndroidDocumentGateway] reads and writes in debug
 * builds only. Never part of a release APK.
 *
 * Tests pass bytes read from the androidTest assets (`InstrumentationRegistry.getInstrumentation().context.assets`),
 * which the app under test cannot see directly.
 *
 * Password of the bundled `sample4.kdbx`: **testpassword** (documented in the repository README).
 */
object DebugVaultFile {

    const val DIRECTORY = "debug-vault"
    const val PASSWORD = "testpassword"

    /** Copies [bytes] into app storage under [name] and returns the database reference for it. */
    fun install(context: Context, bytes: ByteArray, name: String): DatabaseRef {
        val file = file(context, name)
        file.parentFile?.mkdirs()
        file.writeBytes(bytes)
        return ref(file)
    }

    /** The (readable) file behind [ref] or a named fixture. */
    fun file(context: Context, name: String): File = File(File(context.filesDir, DIRECTORY), name)

    /** Reads the current bytes of the installed fixture, or null when it does not exist. */
    fun read(context: Context, name: String): ByteArray? =
        file(context, name).takeIf { it.isFile }?.readBytes()

    fun delete(context: Context, name: String) {
        file(context, name).delete()
    }

    fun ref(file: File): DatabaseRef = DatabaseRef(Uri.fromFile(file).toString(), file.name)
}
