package org.friendlypass.android.credentials

import android.util.Log
import org.friendlypass.android.BuildConfig

/**
 * Diagnostics for the credential provider.
 *
 * A failure in this package used to be reported to the caller as a generic "could not register the passkey" with
 * no trace in logcat, which made a real-device report impossible to diagnose. Every step that can throw is now
 * logged with its name and the exception class/message.
 *
 * Nothing secret is ever logged: no challenges, user handles, credential ids, passwords or key material. The
 * option *shape* (which fields the browser sent, algorithms, lengths, presence flags) is safe and is what a
 * request-shape regression needs, so it is logged at debug level only.
 */
internal object CredentialLog {

    const val TAG = "friendlypass.credentials"

    /** Records that [step] failed; safe to call with any throwable (only class + message are logged). */
    fun failure(step: String, error: Throwable) {
        Log.w(
            TAG,
            "passkey step '$step' failed: ${error.javaClass.name}: ${sanitize(error.message)}",
            error,
        )
    }

    /** Records a non-fatal diagnostic (for example a request whose shape could not be described). */
    fun warning(step: String, detail: String) {
        Log.w(TAG, "passkey step '$step': ${sanitize(detail)}")
    }

    /** Debug-build only: the non-secret shape of an incoming options JSON. */
    fun optionsShape(kind: String, requestJson: String) {
        if (!BuildConfig.DEBUG) return
        val shape = runCatching { OptionsShape.describe(requestJson) }
            .getOrElse { "unparseable (${it.javaClass.simpleName})" }
        Log.d(TAG, "$kind options: $shape")
    }

    /**
     * Exception messages from providers can embed document names and paths; the vault's own messages are short
     * and secret-free. Trim absurdly long provider messages and collapse newlines so one line stays readable.
     */
    private fun sanitize(message: String?): String {
        val text = message.orEmpty().replace('\n', ' ').replace('\r', ' ').trim()
        return when {
            text.isEmpty() -> "<no message>"
            text.length > 400 -> text.take(400) + "…"
            else -> text
        }
    }
}

/**
 * Describes a WebAuthn options JSON without any secret values: field names, algorithm ids, counts and byte
 * lengths. Used only for debug logging; it never returns challenges, user handles, credential ids or user names.
 */
internal object OptionsShape {

    fun describe(requestJson: String): String {
        val root = Json.parse(requestJson).asJsonObject()
            ?: throw IllegalArgumentException("not an object")
        val parts = mutableListOf<String>()

        // Top-level key order is exactly what the browser serialised; a new/renamed field shows up here.
        parts += "keys=[${root.keys.joinToString(",")}]"

        (root.stringField("rpId"))?.let { parts += "rpId=\"$it\"" }
        root.objectField("rp")?.let { rp ->
            rp.stringField("id")?.let { parts += "rp.id=\"$it\"" }
            rp.stringField("name")?.let { parts += "rp.name.len=${it.length}" }
        }
        root.stringField("attestation")?.let { parts += "attestation=\"$it\"" }
        root.objectField("authenticatorSelection")?.let { selection ->
            val fields = selection.entries.joinToString(",") { (key, value) ->
                when (value) {
                    is Boolean -> "$key=$value"
                    is String -> "$key=\"$value\""
                    else -> "$key=${value?.javaClass?.simpleName ?: "null"}"
                }
            }
            parts += "authenticatorSelection={$fields}"
        }
        root.arrayField("pubKeyCredParams")?.let { params ->
            val algorithms = params.mapNotNull { item ->
                val entry = item.asJsonObject() ?: return@mapNotNull null
                val type = entry.stringField("type") ?: "?"
                val alg = entry.longField("alg") ?: return@mapNotNull null
                "$type:$alg"
            }
            parts += "pubKeyCredParams=[${algorithms.joinToString(",")}]"
        }
        root.longField("timeout")?.let { parts += "timeout=$it" }
        (root.stringField("challenge"))?.let { parts += "challenge.len=${it.length}" }
        root.objectField("user")?.let { user ->
            val fields = user.keys.sorted().joinToString(",") { key ->
                val value = user[key]
                when (key) {
                    "id" -> "id.len=${(value as? String)?.length ?: -1}"
                    else -> "$key=${(value as? String)?.length ?: -1}"
                }
            }
            parts += "user={$fields}"
        }
        describeCredentials(root, "excludeCredentials", parts)
        describeCredentials(root, "allowCredentials", parts)
        root.objectField("extensions")?.let { extensions ->
            parts += "extensions=[${extensions.keys.joinToString(",")}]"
        }
        return parts.joinToString(" ")
    }

    private fun describeCredentials(
        root: Map<String, Any?>,
        name: String,
        parts: MutableList<String>,
    ) {
        val list = root.arrayField(name) ?: return
        val described = list.map { item ->
            val entry = item.asJsonObject() ?: return@map null
            val idLength = entry.stringField("id")?.length ?: -1
            val type = entry.stringField("type") ?: "?"
            val transports = entry.arrayField("transports")
                ?.joinToString(",") { "\"${it as? String ?: "?"}\"" }
            if (transports == null) {
                "{id.len=$idLength,type=$type}"
            } else {
                "{id.len=$idLength,transports=[$transports],type=$type}"
            }
        }
        parts += "$name=[${described.joinToString(",")}]"
    }
}
