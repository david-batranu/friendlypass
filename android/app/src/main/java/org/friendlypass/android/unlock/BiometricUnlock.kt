package org.friendlypass.android.unlock

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import org.friendlypass.android.vault.model.DatabaseRef
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Biometric unlock per the contract: the password and optional key file are encrypted per database with an
 * AndroidKeyStore AES-256-GCM key that requires user authentication and is invalidated when biometrics are
 * re-enrolled. When the key is invalidated (or decryption fails) the stored blob is cleared and the caller falls
 * back to the password.
 *
 * Nothing is ever logged; ciphertext lives in a private SharedPreferences file and the key never leaves the
 * keystore.
 */
class BiometricUnlock(context: Context) {

    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    /** Biometric hardware present and enrolled. */
    fun canAuthenticate(): Boolean =
        BiometricManager.from(appContext)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    fun isEnabled(db: DatabaseRef): Boolean = prefs.contains(blobKey(db))

    fun isAvailableFor(db: DatabaseRef): Boolean = canAuthenticate() && isEnabled(db)

    /**
     * Encrypts [password]/[keyfile] after a biometric confirmation. The prompt is required because the key is
     * auth-bound for both directions; it also proves the user is present when enabling.
     */
    fun enable(
        activity: FragmentActivity,
        db: DatabaseRef,
        password: CharArray?,
        keyfile: ByteArray?,
        onEnabled: () -> Unit,
        onError: (String) -> Unit,
    ) {
        val hash = hashOf(db)
        val plaintext = encodeCredentials(password, keyfile)
        try {
            deleteKey(hash)
            val cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.ENCRYPT_MODE, createKey(hash))
            }
            authenticate(
                activity = activity,
                cipher = cipher,
                title = "Enable biometric unlock",
                subtitle = db.displayName,
                onSuccess = { authenticated ->
                    try {
                        val ciphertext = authenticated.doFinal(plaintext)
                        val blob = Base64.getEncoder().encodeToString(authenticated.iv) + ":" +
                            Base64.getEncoder().encodeToString(ciphertext)
                        prefs.edit().putString(blobKey(db), blob).apply()
                        onEnabled()
                    } catch (e: Exception) {
                        deleteKey(hash)
                        onError("Could not store the biometric key")
                    } finally {
                        plaintext.fill(0)
                    }
                },
                onError = { message ->
                    plaintext.fill(0)
                    deleteKey(hash)
                    onError(message)
                },
            )
        } catch (e: Exception) {
            plaintext.fill(0)
            deleteKey(hash)
            onError("Biometric unlock is not available on this device")
        }
    }

    /** Prompts for biometrics and returns the decrypted credentials. */
    fun authenticate(
        activity: FragmentActivity,
        db: DatabaseRef,
        onCredentials: (CharArray?, ByteArray?) -> Unit,
        onError: (String) -> Unit,
    ) {
        val hash = hashOf(db)
        val blob = prefs.getString(blobKey(db), null)
        if (blob == null) {
            onError("Biometric unlock is not enabled")
            return
        }
        val parts = blob.split(':')
        if (parts.size != 2) {
            disable(db)
            onError("Biometric unlock must be set up again")
            return
        }
        val iv: ByteArray
        val ciphertext: ByteArray
        try {
            iv = Base64.getDecoder().decode(parts[0])
            ciphertext = Base64.getDecoder().decode(parts[1])
        } catch (e: IllegalArgumentException) {
            disable(db)
            onError("Biometric unlock must be set up again")
            return
        }
        val cipher = try {
            Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, secretKey(hash), GCMParameterSpec(128, iv))
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            // New enrolment (or the key was otherwise invalidated): forget the blob, use the password.
            disable(db)
            onError("Biometric unlock was reset because your biometrics changed. Enter your password.")
            return
        } catch (e: Exception) {
            disable(db)
            onError("Biometric unlock is no longer available. Enter your password.")
            return
        }
        authenticate(
            activity = activity,
            cipher = cipher,
            title = "Unlock database",
            subtitle = db.displayName,
            onSuccess = { authenticated ->
                try {
                    val plaintext = authenticated.doFinal(ciphertext)
                    val credentials = decodeCredentials(plaintext)
                    plaintext.fill(0)
                    onCredentials(credentials.first, credentials.second)
                } catch (e: Exception) {
                    disable(db)
                    onError("Biometric unlock is no longer available. Enter your password.")
                }
            },
            onError = onError,
        )
    }

    fun disable(db: DatabaseRef) {
        prefs.edit().remove(blobKey(db)).apply()
        deleteKey(hashOf(db))
    }

    fun hasStoredKey(db: DatabaseRef): Boolean = prefs.contains(blobKey(db))

    private fun authenticate(
        activity: FragmentActivity,
        cipher: Cipher,
        title: String,
        subtitle: String,
        onSuccess: (Cipher) -> Unit,
        onError: (String) -> Unit,
    ) {
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val authenticated = result.cryptoObject?.cipher
                    if (authenticated == null) {
                        onError("Biometric authentication returned no cipher")
                    } else {
                        onSuccess(authenticated)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(errString.toString())
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText(activity.getString(android.R.string.cancel))
            .setConfirmationRequired(false)
            .build()
        try {
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        } catch (e: Exception) {
            onError("Biometric prompt is not available")
        }
    }

    private fun createKey(hash: String): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS_PREFIX + hash,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(builder.build())
        return generator.generateKey()
    }

    private fun secretKey(hash: String): SecretKey =
        (keyStore.getKey(KEY_ALIAS_PREFIX + hash, null) as? SecretKey)
            ?: throw IllegalStateException("biometric key missing")

    private fun deleteKey(hash: String) {
        runCatching { keyStore.deleteEntry(KEY_ALIAS_PREFIX + hash) }
    }

    private fun blobKey(db: DatabaseRef): String = hashOf(db) + ".blob"

    private fun hashOf(db: DatabaseRef): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(db.uri.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun encodeCredentials(password: CharArray?, keyfile: ByteArray?): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            val passwordBytes = password?.let { charsToBytes(it) }
            data.writeInt(passwordBytes?.size ?: -1)
            passwordBytes?.let { data.write(it); it.fill(0) }
            data.writeInt(keyfile?.size ?: -1)
            keyfile?.let { data.write(it) }
        }
        return out.toByteArray()
    }

    private fun decodeCredentials(plaintext: ByteArray): Pair<CharArray?, ByteArray?> {
        DataInputStream(ByteArrayInputStream(plaintext)).use { data ->
            val passwordLength = data.readInt()
            val password = if (passwordLength >= 0) {
                val bytes = ByteArray(passwordLength)
                data.readFully(bytes)
                bytesToChars(bytes).also { bytes.fill(0) }
            } else {
                null
            }
            val keyfileLength = data.readInt()
            val keyfile = if (keyfileLength >= 0) {
                ByteArray(keyfileLength).also { data.readFully(it) }
            } else {
                null
            }
            return password to keyfile
        }
    }

    private fun charsToBytes(chars: CharArray): ByteArray {
        val buffer = Charsets.UTF_8.newEncoder().encode(CharBuffer.wrap(chars))
        return ByteArray(buffer.remaining()).also { buffer.get(it) }
    }

    private fun bytesToChars(bytes: ByteArray): CharArray {
        val buffer = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes))
        return CharArray(buffer.remaining()).also { buffer.get(it) }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val PREFS_NAME = "friendlypass.biometric"
        private const val KEY_ALIAS_PREFIX = "friendlypass.bio."
    }
}
