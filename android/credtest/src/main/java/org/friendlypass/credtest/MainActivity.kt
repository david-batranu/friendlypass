package org.friendlypass.credtest

import android.app.Activity
import android.os.Bundle
import android.security.keystore.KeyProperties
import android.text.method.ScrollingMovementMethod
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPasswordOption
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Debug-only driver for the friendlypass Credential Manager provider. Every button prints the JSON result (this is
 * a test app, never part of the product APK) and the passkey sign-in verifies the ES256 assertion against the
 * public key captured during registration.
 */
class MainActivity : Activity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val random = SecureRandom()
    private val prefs by lazy { getSharedPreferences("credtest", MODE_PRIVATE) }
    private val credentialManager by lazy { CredentialManager.create(this) }

    private lateinit var status: TextView
    private lateinit var result: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildUi())
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun buildUi(): ScrollView {
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }
        status = TextView(this).apply {
            textSize = 16f
            text = "Ready"
        }
        result = TextView(this).apply {
            textSize = 12f
            typeface = android.graphics.Typeface.MONOSPACE
            movementMethod = ScrollingMovementMethod()
            setTextIsSelectable(true)
            setPadding(0, 32, 0, 0)
        }

        column.addView(status)
        column.addView(button("Get password") { getPassword() })
        column.addView(button("Save password") { savePassword() })
        column.addView(button("Create passkey") { createPasskey() })
        column.addView(button("Create real passkey") { createRealPasskey() })
        column.addView(button("Sign in with passkey") { signInWithPasskey() })
        column.addView(
            TextView(this).apply {
                textSize = 12f
                setPadding(0, 32, 0, 0)
                text = "rpId: ${activeRpId()}\nRegister a passkey first, then sign in."
            },
        )
        column.addView(result)

        return ScrollView(this).apply {
            addView(
                column,
                ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
            )
        }
    }

    private fun button(label: String, action: () -> Unit): Button = Button(this).apply {
        text = label
        setOnClickListener { action() }
    }

    private fun run(title: String, block: suspend () -> String) {
        status.text = "$title…"
        result.text = ""
        scope.launch {
            try {
                val text = block()
                status.text = "$title: ok"
                result.text = text
            } catch (e: Exception) {
                status.text = "$title: failed"
                result.text = "${e.javaClass.simpleName}: ${e.message.orEmpty()}"
            }
        }
    }

    private fun getPassword() = run("Get password") {
        val request = GetCredentialRequest.Builder()
            .addCredentialOption(GetPasswordOption())
            .build()
        val credential = credentialManager.getCredential(this, request).credential
        when (credential) {
            is PasswordCredential -> "type=password\nid=${credential.id}\npassword=${credential.password}"
            else -> "unexpected credential type: ${credential.type}"
        }
    }

    private fun savePassword() = run("Save password") {
        val request = CreatePasswordRequest(
            id = "credtest-user",
            password = "credtest-password-${System.currentTimeMillis()}",
        )
        val response = credentialManager.createCredential(this, request)
        if (response is CreatePasswordResponse) "password saved" else "unexpected response: $response"
    }

    private fun createPasskey() = run("Create passkey") {
        val challenge = ByteArray(32).also(random::nextBytes)
        val userHandle = "credtest-user".toByteArray()
        val requestJson = JSONObject()
            .put("challenge", b64(challenge))
            .put(
                "rp",
                JSONObject().put("id", RP_ID).put("name", "friendlypass credtest"),
            )
            .put(
                "user",
                JSONObject()
                    .put("id", b64(userHandle))
                    .put("name", "credtest")
                    .put("displayName", "Credtest user"),
            )
            .put(
                "pubKeyCredParams",
                org.json.JSONArray()
                    .put(JSONObject().put("type", "public-key").put("alg", -7))
                    .put(JSONObject().put("type", "public-key").put("alg", -257)),
            )
            .put("excludeCredentials", org.json.JSONArray())
            .put(
                "authenticatorSelection",
                JSONObject().put("residentKey", "required").put("userVerification", "required"),
            )
            .put("attestation", "none")
            .toString()

        create(requestJson, RP_ID)
    }

    /**
     * Replays the creation options Chrome sent to passkeys.io (captured on an emulator): `attestation: "direct"`,
     * `residentKey: "required"`, `userVerification: "preferred"`, ten algorithms and a 16-byte user id. Keep this
     * shape in sync with `RealWorldRequestTest`.
     */
    private fun createRealPasskey() = run("Create real passkey") {
        val challenge = ByteArray(32).also(random::nextBytes)
        val userHandle = ByteArray(16).also(random::nextBytes)
        val algorithms = longArrayOf(-7, -35, -36, -257, -258, -259, -37, -38, -39, -8)
        val params = org.json.JSONArray()
        for (algorithm in algorithms) {
            params.put(JSONObject().put("type", "public-key").put("alg", algorithm))
        }
        val requestJson = JSONObject()
            .put("attestation", "direct")
            .put(
                "authenticatorSelection",
                JSONObject().put("residentKey", "required").put("userVerification", "preferred"),
            )
            .put("challenge", b64(challenge))
            .put("excludeCredentials", org.json.JSONArray())
            .put("pubKeyCredParams", params)
            .put("rp", JSONObject().put("id", REAL_RP_ID).put("name", "passkeys.io"))
            .put("timeout", 600000)
            .put(
                "user",
                JSONObject()
                    .put("displayName", REAL_USER)
                    .put("id", b64(userHandle))
                    .put("name", REAL_USER),
            )
            .toString()

        create(requestJson, REAL_RP_ID)
    }

    private suspend fun create(requestJson: String, rpId: String): String {
        val response = credentialManager.createCredential(
            this,
            CreatePublicKeyCredentialRequest(requestJson),
        )
        if (response !is CreatePublicKeyCredentialResponse) {
            return "unexpected response: $response"
        }
        val json = JSONObject(response.registrationResponseJson)
        val inner = json.getJSONObject("response")
        prefs.edit()
            .putString(KEY_CREDENTIAL_ID, json.getString("id"))
            .putString(KEY_PUBLIC_KEY, inner.getString("publicKey"))
            .putLong(KEY_ALGORITHM, inner.optLong("publicKeyAlgorithm", -7))
            .putString(KEY_RP_ID, rpId)
            .apply()
        return response.registrationResponseJson
    }

    private fun signInWithPasskey() = run("Sign in with passkey") {
        val credentialId = prefs.getString(KEY_CREDENTIAL_ID, null)
        val rpId = activeRpId()
        val challenge = ByteArray(32).also(random::nextBytes)
        val allowCredentials = org.json.JSONArray()
        if (credentialId != null) {
            allowCredentials.put(JSONObject().put("type", "public-key").put("id", credentialId))
        }
        val requestJson = JSONObject()
            .put("challenge", b64(challenge))
            .put("rpId", rpId)
            .put("allowCredentials", allowCredentials)
            .put("userVerification", "required")
            .toString()

        val response = credentialManager.getCredential(
            this,
            GetCredentialRequest.Builder()
                .addCredentialOption(GetPublicKeyCredentialOption(requestJson))
                .build(),
        )
        val credential = response.credential
        if (credential !is PublicKeyCredential) {
            return@run "unexpected credential type: ${credential.type}"
        }
        val json = credential.authenticationResponseJson
        if (prefs.getString(KEY_PUBLIC_KEY, null) == null) {
            "$json\n\n(no stored public key — run \"Create passkey\" to verify a signature)"
        } else {
            "$json\n\n${verify(json)}"
        }
    }

    /** Verifies the assertion signature against the SPKI captured at registration. */
    private fun verify(authenticationResponseJson: String): String {
        val json = JSONObject(authenticationResponseJson)
        val inner = json.getJSONObject("response")
        val authenticatorData = decode(inner.getString("authenticatorData"))
        val clientDataJson = inner.optString("clientDataJSON", "")
        val signature = decode(inner.getString("signature"))
        val spki = decode(prefs.getString(KEY_PUBLIC_KEY, null) ?: return "no stored public key")
        val algorithm = prefs.getLong(KEY_ALGORITHM, -7)
        val signed = if (clientDataJson.isBlank()) {
            return "clientDataJSON is empty (privileged caller path); cannot verify here"
        } else {
            authenticatorData + MessageDigest.getInstance("SHA-256").digest(decode(clientDataJson))
        }
        val (keyAlgorithm, signatureAlgorithm) = when (algorithm) {
            -257L -> KeyProperties.KEY_ALGORITHM_RSA to "SHA256withRSA"
            else -> KeyProperties.KEY_ALGORITHM_EC to "SHA256withECDSA"
        }
        val publicKey = KeyFactory.getInstance(keyAlgorithm).generatePublic(X509EncodedKeySpec(spki))
        val verifier = Signature.getInstance(signatureAlgorithm).apply {
            initVerify(publicKey)
            update(signed)
        }
        return if (verifier.verify(signature)) {
            "signature: VALID ($signatureAlgorithm)"
        } else {
            "signature: INVALID ($signatureAlgorithm)"
        }
    }

    private fun b64(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun activeRpId(): String = prefs.getString(KEY_RP_ID, RP_ID) ?: RP_ID

    private fun decode(value: String): ByteArray = Base64.getUrlDecoder().decode(value)

    companion object {
        private const val RP_ID = "credtest.friendlypass.test"
        private const val REAL_RP_ID = "www.passkeys.io"
        private const val REAL_USER = "fp-real-shape@example.com"
        private const val KEY_CREDENTIAL_ID = "credential_id"
        private const val KEY_PUBLIC_KEY = "public_key"
        private const val KEY_ALGORITHM = "algorithm"
        private const val KEY_RP_ID = "rp_id"
    }
}
