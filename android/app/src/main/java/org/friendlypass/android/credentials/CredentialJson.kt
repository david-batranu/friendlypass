package org.friendlypass.android.credentials

/**
 * Builds the `authenticationResponseJson` / `registrationResponseJson` payloads Credential Manager expects.
 *
 * When a privileged caller supplied its own `clientDataHash`, the provider cannot reconstruct the browser's
 * clientDataJSON. In that case `clientDataJSON` is emitted as the empty string: the caller already owns the JSON
 * it hashed, and only the assertion signature (over `authenticatorData || clientDataHash`) is authoritative.
 */
internal object CredentialJson {

    fun assertion(
        credentialId: ByteArray,
        clientDataJson: ByteArray?,
        authenticatorData: ByteArray,
        signature: ByteArray,
        userHandle: ByteArray,
    ): String = Json.write(
        Json.obj(
            "id" to B64Url.encode(credentialId),
            "rawId" to B64Url.encode(credentialId),
            "type" to "public-key",
            "response" to Json.obj(
                "clientDataJSON" to (clientDataJson?.let(B64Url::encode) ?: ""),
                "authenticatorData" to B64Url.encode(authenticatorData),
                "signature" to B64Url.encode(signature),
                "userHandle" to B64Url.encode(userHandle),
            ),
            "authenticatorAttachment" to "platform",
            "clientExtensionResults" to Json.obj(),
        ),
    )

    fun registration(
        credentialId: ByteArray,
        clientDataJson: ByteArray?,
        attestationObject: ByteArray,
        authenticatorData: ByteArray,
        publicKeySpkiDer: ByteArray,
        publicKeyAlgorithm: Long,
    ): String = Json.write(
        Json.obj(
            "id" to B64Url.encode(credentialId),
            "rawId" to B64Url.encode(credentialId),
            "type" to "public-key",
            "response" to Json.obj(
                "clientDataJSON" to (clientDataJson?.let(B64Url::encode) ?: ""),
                "attestationObject" to B64Url.encode(attestationObject),
                "authenticatorData" to B64Url.encode(authenticatorData),
                "transports" to Json.arr("internal", "hybrid"),
                "publicKey" to B64Url.encode(publicKeySpkiDer),
                "publicKeyAlgorithm" to publicKeyAlgorithm,
            ),
            "authenticatorAttachment" to "platform",
            "clientExtensionResults" to Json.obj(),
        ),
    )

    /** WebAuthn client data for builds we create ourselves (non-privileged callers). */
    fun clientDataJson(
        type: String,
        challenge: ByteArray,
        origin: String,
        androidPackageName: String?,
    ): String = Json.write(
        Json.obj(
            "type" to type,
            "challenge" to B64Url.encode(challenge),
            "origin" to origin,
            "crossOrigin" to false,
            "androidPackageName" to androidPackageName,
        ),
    )

    const val TYPE_GET = "webauthn.get"
    const val TYPE_CREATE = "webauthn.create"
}
