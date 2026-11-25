package org.friendlypass.android.credentials

/**
 * The subset of a WebAuthn `PublicKeyCredentialRequestOptions` (as serialised by
 * `GetPublicKeyCredentialOption.requestJson`) that the provider needs.
 */
internal data class PublicKeyGetOptions(
    val challenge: ByteArray,
    val rpId: String?,
    val allowCredentialIds: List<ByteArray>,
    val userVerification: String?,
)

/**
 * The subset of a WebAuthn `PublicKeyCredentialCreationOptions` (as serialised by
 * `CreatePublicKeyCredentialRequest.requestJson`) that the provider needs.
 */
internal data class PublicKeyCreateOptions(
    val challenge: ByteArray,
    val rpId: String,
    val rpName: String,
    val userId: ByteArray,
    val userName: String,
    val userDisplayName: String,
    val algorithms: List<Long>,
    val excludeCredentialIds: List<ByteArray>,
)

/**
 * Parses the JSON payloads Credential Manager hands to providers. Pure Kotlin so the mapping is covered by JVM
 * tests; malformed input throws [IllegalArgumentException] and is turned into a credential exception by the
 * caller (never logged with its contents).
 */
internal object RequestJson {

    fun parseGet(requestJson: String): PublicKeyGetOptions {
        val root = Json.parse(requestJson).asJsonObject()
            ?: throw IllegalArgumentException("Request JSON is not an object")
        val challenge = root.stringField("challenge")
            ?.let { B64Url.decodeOrNull(it) }
            ?: throw IllegalArgumentException("Missing challenge")
        val allow = root.arrayField("allowCredentials")
            ?.mapNotNull { item ->
                val entry = item.asJsonObject() ?: return@mapNotNull null
                entry.stringField("id")?.let { B64Url.decodeOrNull(it) }
            }
            .orEmpty()
        return PublicKeyGetOptions(
            challenge = challenge,
            rpId = root.stringField("rpId"),
            allowCredentialIds = allow,
            userVerification = root.stringField("userVerification"),
        )
    }

    fun parseCreate(requestJson: String): PublicKeyCreateOptions {
        val root = Json.parse(requestJson).asJsonObject()
            ?: throw IllegalArgumentException("Request JSON is not an object")
        val challenge = root.stringField("challenge")
            ?.let { B64Url.decodeOrNull(it) }
            ?: throw IllegalArgumentException("Missing challenge")
        val rp = root.objectField("rp") ?: throw IllegalArgumentException("Missing rp")
        val rpId = rp.stringField("id")?.takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException("Missing rp.id")
        val user = root.objectField("user") ?: throw IllegalArgumentException("Missing user")
        val userId = user.stringField("id")?.let { B64Url.decodeOrNull(it) } ?: ByteArray(0)
        val algorithms = root.arrayField("pubKeyCredParams")
            ?.mapNotNull { item ->
                val param = item.asJsonObject() ?: return@mapNotNull null
                if (param.stringField("type") != "public-key") return@mapNotNull null
                param.longField("alg")
            }
            ?.takeIf { it.isNotEmpty() }
            ?: listOf(ES256)
        val excluded = root.arrayField("excludeCredentials")
            ?.mapNotNull { item ->
                val entry = item.asJsonObject() ?: return@mapNotNull null
                entry.stringField("id")?.let { B64Url.decodeOrNull(it) }
            }
            .orEmpty()
        return PublicKeyCreateOptions(
            challenge = challenge,
            rpId = rpId,
            rpName = rp.stringField("name").orEmpty(),
            userId = userId,
            userName = user.stringField("name").orEmpty(),
            userDisplayName = user.stringField("displayName") ?: user.stringField("name").orEmpty(),
            algorithms = algorithms,
            excludeCredentialIds = excluded,
        )
    }

    const val ES256: Long = -7

    /** True when any of [excludeCredentialIds] already exists for the relying party. */
    fun hasExcludedCredential(
        existing: List<ByteArray>,
        excludeCredentialIds: List<ByteArray>,
    ): Boolean = excludeCredentialIds.any { excluded -> existing.any { it.contentEquals(excluded) } }
}
