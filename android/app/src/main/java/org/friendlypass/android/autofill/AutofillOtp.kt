package org.friendlypass.android.autofill

import kotlinx.coroutines.delay
import org.friendlypass.android.vault.VaultRepository
import org.friendlypass.android.vault.model.TotpCode

/**
 * One-time-code fill values. Kept Android-free so the digit splitting is unit tested on the JVM.
 *
 * A normal OTP input (one group of one field) gets the whole code. A segmented code (one group of N
 * fields, e.g. six single-digit boxes) gets one digit per field.
 */
object AutofillOtp {

    /** Minimum validity left before the code is shown; otherwise the next step is awaited. */
    const val MIN_REMAINING_SECS = 3

    /** One value per OTP field, in the order the fields were reported. */
    fun values(code: String, groupSizes: List<Int>): List<String> {
        if (groupSizes.isEmpty()) return listOf(code)
        return groupSizes.flatMap { size ->
            if (size <= 1) {
                listOf(code)
            } else {
                val digits = code.take(size)
                (0 until size).map { i -> digits.getOrElse(i) { ' ' }.toString().trim() }
            }
        }
    }

    /**
     * The code at tap time. When less than [minRemainingSecs] are left, waits for the next step so the user
     * never gets a code that expires while it is being filled.
     */
    suspend fun freshCode(
        vault: VaultRepository,
        entryUuid: String,
        minRemainingSecs: Int = MIN_REMAINING_SECS,
    ): TotpCode? {
        var code = vault.totp(entryUuid) ?: return null
        if (code.remainingSecs < minRemainingSecs) {
            delay((code.remainingSecs + 1) * 1_000L)
            code = vault.totp(entryUuid) ?: return null
        }
        return code
    }
}
