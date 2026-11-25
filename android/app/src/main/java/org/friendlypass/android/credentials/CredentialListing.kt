package org.friendlypass.android.credentials

import org.friendlypass.android.vault.VaultRepository
import org.friendlypass.android.vault.model.EntrySummary
import org.friendlypass.android.vault.model.VaultException
import org.friendlypass.android.vault.model.VaultState

/** One password candidate to show in the system sheet. */
internal data class PasswordEntrySpec(
    val uuid: String,
    val username: String,
    val displayName: String,
)

/** One passkey candidate to show in the system sheet. */
internal data class PasskeyEntrySpec(
    val uuid: String,
    val username: String,
    val displayName: String,
    val credentialId: ByteArray,
)

/** What the sheet should show for one credential option. */
internal data class CredentialListing(
    val locked: Boolean = false,
    val passwordEntries: List<PasswordEntrySpec> = emptyList(),
    val passkeyEntries: List<PasskeyEntrySpec> = emptyList(),
)

/** Everything the listing depends on, so it can be built without Android classes in JVM tests. */
internal data class ListingRequest(
    val passwordRequested: Boolean,
    val publicKeyRequested: Boolean,
    val rpId: String? = null,
    val allowCredentialIds: List<ByteArray> = emptyList(),
    val allowedUserIds: Set<String> = emptySet(),
    val origin: String? = null,
    val callingPackage: String,
    val isDebugBuild: Boolean,
    val privileged: Boolean = false,
)

/**
 * Turns vault contents into credential entries. Pure with respect to Android: it only touches the
 * [VaultRepository] interface, so it is exercised directly by the JVM tests.
 */
internal class CredentialListingBuilder(private val vault: VaultRepository) {

    fun build(request: ListingRequest): CredentialListing {
        val state = vault.state.value
        if (state !is VaultState.Unlocked) {
            return CredentialListing(locked = state is VaultState.Locked)
        }

        val passwordEntries = if (request.passwordRequested) passwordEntries(request) else emptyList()
        val passkeyEntries = if (request.publicKeyRequested && request.rpId != null) {
            passkeyEntries(request, request.rpId)
        } else {
            emptyList()
        }
        return CredentialListing(
            locked = false,
            passwordEntries = passwordEntries,
            passkeyEntries = passkeyEntries,
        )
    }

    private fun passwordEntries(request: ListingRequest): List<PasswordEntrySpec> {
        val matches = LinkedHashMap<String, EntrySummary>()
        val origin = request.origin
        if (OriginPolicy.isWebOrigin(origin)) {
            runCatching { vault.matchWeb(origin!!) }.getOrElse { emptyList() }
                .forEach { matches[it.uuid] = it }
        }
        runCatching { vault.matchApp(request.callingPackage) }.getOrElse { emptyList() }
            .forEach { matches[it.uuid] = it }

        // Debug-only convenience for :credtest, which has no web origin and no seeded entry for its package.
        if (matches.isEmpty() && request.isDebugBuild &&
            request.callingPackage == OriginPolicy.CREDTEST_PACKAGE
        ) {
            runCatching { allEntries() }.getOrElse { emptyList() }
                .forEach { matches[it.uuid] = it }
        }

        return matches.values
            .filter { request.allowedUserIds.isEmpty() || it.username in request.allowedUserIds }
            .map { PasswordEntrySpec(uuid = it.uuid, username = it.username, displayName = it.title) }
    }

    private fun passkeyEntries(request: ListingRequest, rpId: String): List<PasskeyEntrySpec> {
        val entryHasAndroidApp = runCatching { vault.matchApp(rpId).isNotEmpty() }.getOrDefault(false)
        if (!OriginPolicy.isPasskeyRpAllowed(
                rpId = rpId,
                origin = request.origin,
                privileged = request.privileged,
                callingPackage = request.callingPackage,
                isDebugBuild = request.isDebugBuild,
                entryHasAndroidApp = entryHasAndroidApp,
            )
        ) {
            return emptyList()
        }

        val passkeys = runCatching {
            vault.passkeysForRp(rpId, request.allowCredentialIds)
        }.getOrElse { error ->
            if (error is VaultException.Locked) throw error
            emptyList()
        }
        return passkeys.map { passkey ->
            val title = runCatching { vault.entry(passkey.entryUuid).summary.title }
                .getOrElse { passkey.username.ifBlank { rpId } }
            PasskeyEntrySpec(
                uuid = passkey.entryUuid,
                username = passkey.username.ifBlank { title },
                displayName = title,
                credentialId = passkey.credentialId,
            )
        }
    }

    private fun allEntries(): List<EntrySummary> =
        vault.groups().flatMap { vault.entriesInGroup(it.uuid) }
}
