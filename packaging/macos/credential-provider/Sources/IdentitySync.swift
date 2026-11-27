import AuthenticationServices
import Foundation

/// Syncs non-secret credential identities (passkeys, passwords, and on
/// macOS 15+ TOTP one-time codes) into `ASCredentialIdentityStore.shared`.
enum IdentitySync {
    static func replaceAll(with result: IPCClient.IdentitiesResult) async -> Bool {
        let state = await ASCredentialIdentityStore.shared.state()
        guard state.isEnabled else {
            return false
        }

        var entries: [any ASCredentialIdentity] = []

        for pk in result.passkeys {
            guard let credId = Data(base64Encoded: pk.credentialIdB64), !credId.isEmpty else {
                continue
            }
            let handle = Data(base64Encoded: pk.userHandleB64) ?? Data()
            let identity = ASPasskeyCredentialIdentity(
                relyingPartyIdentifier: pk.rpId,
                userName: pk.username,
                credentialID: credId,
                userHandle: handle,
                recordIdentifier: pk.uuid
            )
            entries.append(identity)
        }

        for pw in result.passwords {
            let sid = ASCredentialServiceIdentifier(
                identifier: pw.service,
                type: pw.isUrl ? .URL : .domain
            )
            let identity = ASPasswordCredentialIdentity(
                serviceIdentifier: sid,
                user: pw.username,
                recordIdentifier: pw.uuid
            )
            entries.append(identity)
        }

        if #available(macOS 15.0, *) {
            for totp in result.totps {
                let sid = ASCredentialServiceIdentifier(
                    identifier: totp.service,
                    type: totp.isUrl ? .URL : .domain
                )
                let identity = ASOneTimeCodeCredentialIdentity(
                    serviceIdentifier: sid,
                    label: totp.label,
                    recordIdentifier: totp.uuid
                )
                entries.append(identity)
            }
        }

        do {
            try await ASCredentialIdentityStore.shared.replaceCredentialIdentities(entries)
            return true
        } catch {
            return false
        }
    }
}
