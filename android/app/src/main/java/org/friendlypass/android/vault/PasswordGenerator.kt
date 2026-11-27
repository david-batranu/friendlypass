package org.friendlypass.android.vault

import java.security.SecureRandom
import kotlin.math.log2

/**
 * Password generator backed by Rust's CSPRNG (`friendlypass_mobile.generatePassword`), with a pure-JVM
 * [SecureRandom] fallback so JVM unit tests work without loading the `.so`.
 */
object PasswordGenerator {
    private const val UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    private const val LOWER = "abcdefghijkmnopqrstuvwxyz"
    private const val DIGITS = "23456789"
    private const val SYMBOLS = "!@#\$%^&*()-_=+[]{};:,.?"

    private val fallbackRandom = SecureRandom()

    data class Options(
        val length: Int = 20,
        val uppercase: Boolean = true,
        val lowercase: Boolean = true,
        val digits: Boolean = true,
        val symbols: Boolean = true,
    )

    data class Strength(
        val label: String,
        val progress: Float,
        val entropyBits: Int,
    )

    fun generate(options: Options = Options()): String {
        val rustResult = runCatching {
            uniffi.friendlypass_mobile.generatePassword(
                options.length.toUInt(),
                options.uppercase,
                options.lowercase,
                options.digits,
                options.symbols,
            )
        }.getOrNull()
        if (rustResult != null) return rustResult
        return generateFallback(options)
    }

    fun evaluateStrength(password: String): Strength {
        if (password.isEmpty()) return Strength("Empty", 0f, 0)
        var charset = 0
        if (password.any { it.isLowerCase() }) charset += 26
        if (password.any { it.isUpperCase() }) charset += 26
        if (password.any { it.isDigit() }) charset += 10
        if (password.any { !it.isLetterOrDigit() }) charset += 32
        if (charset == 0) charset = 26
        val bits = (password.length * log2(charset.toDouble())).toInt()
        return when {
            bits < 40 -> Strength("Weak", 0.25f, bits)
            bits < 64 -> Strength("Fair", 0.50f, bits)
            bits < 90 -> Strength("Strong", 0.78f, bits)
            else -> Strength("Excellent", 1.0f, bits)
        }
    }

    private fun generateFallback(options: Options): String {
        val classes = buildList {
            if (options.uppercase) add(UPPER)
            if (options.lowercase) add(LOWER)
            if (options.digits) add(DIGITS)
            if (options.symbols) add(SYMBOLS)
        }
        require(classes.isNotEmpty()) { "Select at least one character set" }
        val len = options.length.coerceIn(classes.size.coerceAtLeast(4), 128)
        val pool = classes.joinToString("")
        val chars = CharArray(len)
        for (i in classes.indices) {
            val c = classes[i]
            chars[i] = c[fallbackRandom.nextInt(c.length)]
        }
        for (i in classes.size until len) {
            chars[i] = pool[fallbackRandom.nextInt(pool.length)]
        }
        for (i in len - 1 downTo 1) {
            val j = fallbackRandom.nextInt(i + 1)
            val tmp = chars[i]
            chars[i] = chars[j]
            chars[j] = tmp
        }
        return String(chars)
    }
}
