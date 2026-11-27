import Darwin
import Foundation

/// Wire client for talking to `friendlypass-gui` over the shared App Group
/// Unix domain socket (`cp.sock`), using 4-byte little-endian length-prefixed
/// UTF-8 JSON frames. Never logs secrets or decrypted credential material.
final class IPCClient: Sendable {
    static let maxFrameBytes = 1024 * 1024

    enum ClientError: Error {
        case socketUnavailable
        case appNotRunning
        case vaultLocked
        case credentialNotFound
        case credentialExcluded
        case serverError(code: String, message: String)
        case protocolError
    }

    struct StatusResult: Sendable {
        let unlocked: Bool
        let dbName: String?
    }

    struct PasskeyIdentityDTO: Decodable, Sendable {
        let uuid: String
        let rpId: String
        let username: String
        let credentialIdB64: String
        let userHandleB64: String

        enum CodingKeys: String, CodingKey {
            case uuid
            case rpId = "rp_id"
            case username
            case credentialIdB64 = "credential_id_b64"
            case userHandleB64 = "user_handle_b64"
        }
    }

    struct PasswordIdentityDTO: Decodable, Sendable {
        let uuid: String
        let service: String
        let isUrl: Bool
        let username: String

        enum CodingKeys: String, CodingKey {
            case uuid, service, username
            case isUrl = "is_url"
        }
    }

    struct TotpIdentityDTO: Decodable, Sendable {
        let uuid: String
        let service: String
        let isUrl: Bool
        let label: String

        enum CodingKeys: String, CodingKey {
            case uuid, service, label
            case isUrl = "is_url"
        }
    }

    struct IdentitiesResult: Sendable {
        let passkeys: [PasskeyIdentityDTO]
        let passwords: [PasswordIdentityDTO]
        let totps: [TotpIdentityDTO]
    }

    struct CredentialItemDTO: Decodable, Sendable {
        let kind: String
        let uuid: String
        let title: String
        let username: String
        let subtitle: String
        let rpId: String?
        let credentialIdB64: String?
        let matched: Bool

        enum CodingKeys: String, CodingKey {
            case kind, uuid, title, username, subtitle, matched
            case rpId = "rp_id"
            case credentialIdB64 = "credential_id_b64"
        }
    }

    struct PasswordResult: Sendable {
        let username: String
        let password: String
    }

    struct TotpResult: Sendable {
        let code: String
        let validForSecs: UInt64
    }

    struct PasskeyAssertionResult: Sendable {
        let relyingParty: String
        let credentialID: Data
        let userHandle: Data
        let authenticatorData: Data
        let signature: Data
    }

    struct PasskeyRegistrationResult: Sendable {
        let uuid: String
        let relyingParty: String
        let credentialID: Data
        let attestationObject: Data
    }

    private struct RawResponse: Decodable {
        let ok: Bool
        let error: String?
        let message: String?
        let payload: RawPayload?
    }

    private struct RawPayload: Decodable {
        let kind: String
        // status
        let unlocked: Bool?
        let dbName: String?
        // identities
        let passkeys: [PasskeyIdentityDTO]?
        let passwords: [PasswordIdentityDTO]?
        let totps: [TotpIdentityDTO]?
        // credentials
        let items: [CredentialItemDTO]?
        // password
        let username: String?
        let password: String?
        // totp
        let code: String?
        let validForSecs: UInt64?
        // passkey assertion / registration
        let uuid: String?
        let relyingParty: String?
        let credentialIdB64: String?
        let userHandleB64: String?
        let authenticatorDataB64: String?
        let signatureB64: String?
        let attestationObjectB64: String?

        enum CodingKeys: String, CodingKey {
            case kind, unlocked, passkeys, passwords, totps, items, username, password, code, uuid
            case dbName = "db_name"
            case validForSecs = "valid_for_secs"
            case relyingParty = "relying_party"
            case credentialIdB64 = "credential_id_b64"
            case userHandleB64 = "user_handle_b64"
            case authenticatorDataB64 = "authenticator_data_b64"
            case signatureB64 = "signature_b64"
            case attestationObjectB64 = "attestation_object_b64"
        }
    }

    func socketPath() -> String? {
        if let override = ProcessInfo.processInfo.environment["FP_CREDENTIAL_PROVIDER_SOCKET"],
           !override.isEmpty {
            return override
        }
        guard let groupId = Bundle.main.object(forInfoDictionaryKey: "FPAppGroupIdentifier") as? String,
              !groupId.isEmpty else {
            return nil
        }
        if let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: groupId
        ) {
            return container.appendingPathComponent("cp.sock").path
        }
        return nil
    }

    func status(requestUnlock: Bool = false) throws -> StatusResult {
        let body: [String: Any] = [
            "op": "status",
            "request_unlock": requestUnlock,
        ]
        let payload = try send(body)
        return StatusResult(unlocked: payload.unlocked ?? false, dbName: payload.dbName)
    }

    func listIdentities() throws -> IdentitiesResult {
        let payload = try send(["op": "list_identities"])
        return IdentitiesResult(
            passkeys: payload.passkeys ?? [],
            passwords: payload.passwords ?? [],
            totps: payload.totps ?? []
        )
    }

    func listCredentials(
        kind: String,
        serviceIdentifiers: [String],
        rpId: String? = nil,
        allowedCredentialIDs: [Data]? = nil,
        query: String? = nil
    ) throws -> [CredentialItemDTO] {
        var body: [String: Any] = [
            "op": "list_credentials",
            "kind": kind,
            "service_identifiers": serviceIdentifiers,
        ]
        if let rpId, !rpId.isEmpty {
            body["rp_id"] = rpId
        }
        if let allowedCredentialIDs {
            body["allowed_credential_ids_b64"] = allowedCredentialIDs.map { $0.base64EncodedString() }
        }
        if let query, !query.isEmpty {
            body["query"] = query
        }
        let payload = try send(body)
        return payload.items ?? []
    }

    func getPassword(uuid: String) throws -> PasswordResult {
        let payload = try send(["op": "get_password", "uuid": uuid])
        guard let username = payload.username, let password = payload.password else {
            throw ClientError.protocolError
        }
        return PasswordResult(username: username, password: password)
    }

    func getTotp(uuid: String) throws -> TotpResult {
        let payload = try send(["op": "get_totp", "uuid": uuid])
        guard let code = payload.code else {
            throw ClientError.protocolError
        }
        return TotpResult(code: code, validForSecs: payload.validForSecs ?? 0)
    }

    func assertPasskey(
        uuid: String?,
        rpId: String,
        credentialID: Data?,
        clientDataHash: Data
    ) throws -> PasskeyAssertionResult {
        var body: [String: Any] = [
            "op": "assert_passkey",
            "rp_id": rpId,
            "client_data_hash_b64": clientDataHash.base64EncodedString(),
        ]
        if let uuid, !uuid.isEmpty {
            body["uuid"] = uuid
        }
        if let credentialID, !credentialID.isEmpty {
            body["credential_id_b64"] = credentialID.base64EncodedString()
        }
        let payload = try send(body)
        guard let rp = payload.relyingParty,
              let credB64 = payload.credentialIdB64,
              let credId = Data(base64Encoded: credB64),
              let handleB64 = payload.userHandleB64,
              let handle = Data(base64Encoded: handleB64),
              let authB64 = payload.authenticatorDataB64,
              let authData = Data(base64Encoded: authB64),
              let sigB64 = payload.signatureB64,
              let signature = Data(base64Encoded: sigB64) else {
            throw ClientError.protocolError
        }
        return PasskeyAssertionResult(
            relyingParty: rp,
            credentialID: credId,
            userHandle: handle,
            authenticatorData: authData,
            signature: signature
        )
    }

    func registerPasskey(
        rpId: String,
        username: String,
        userHandle: Data,
        clientDataHash: Data,
        algorithms: [Int64],
        excludedCredentialIDs: [Data]
    ) throws -> PasskeyRegistrationResult {
        let body: [String: Any] = [
            "op": "register_passkey",
            "rp_id": rpId,
            "username": username,
            "user_handle_b64": userHandle.base64EncodedString(),
            "client_data_hash_b64": clientDataHash.base64EncodedString(),
            "algorithms": algorithms,
            "excluded_credential_ids_b64": excludedCredentialIDs.map { $0.base64EncodedString() },
        ]
        let payload = try send(body, timeoutSecs: 20)
        guard let uuid = payload.uuid,
              let rp = payload.relyingParty,
              let credB64 = payload.credentialIdB64,
              let credId = Data(base64Encoded: credB64),
              let attB64 = payload.attestationObjectB64,
              let attObj = Data(base64Encoded: attB64) else {
            throw ClientError.protocolError
        }
        return PasskeyRegistrationResult(
            uuid: uuid,
            relyingParty: rp,
            credentialID: credId,
            attestationObject: attObj
        )
    }

    // MARK: - Low-level Unix domain socket framing

    private func send(_ object: [String: Any], timeoutSecs: Int = 5) throws -> RawPayload {
        guard let path = socketPath() else {
            throw ClientError.socketUnavailable
        }
        let reqData = try JSONSerialization.data(withJSONObject: object, options: [])
        guard reqData.count <= Self.maxFrameBytes else {
            throw ClientError.protocolError
        }

        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw ClientError.appNotRunning
        }
        defer { Darwin.close(fd) }

        var nosigpipe: Int32 = 1
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, socklen_t(MemoryLayout<Int32>.size))

        var tv = timeval(tv_sec: timeoutSecs, tv_usec: 0)
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path) - 1
        guard pathBytes.count <= maxLen else {
            throw ClientError.socketUnavailable
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: UInt8.self, capacity: maxLen + 1) { dst in
                for i in 0..<pathBytes.count {
                    dst[i] = pathBytes[i]
                }
                dst[pathBytes.count] = 0
            }
        }
        let addrLen = socklen_t(MemoryLayout<sa_family_t>.size + pathBytes.count + 2)
        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                Darwin.connect(fd, sockPtr, addrLen)
            }
        }
        guard connectResult == 0 else {
            throw ClientError.appNotRunning
        }

        var lenLE = UInt32(reqData.count).littleEndian
        let header = withUnsafeBytes(of: &lenLE) { Data($0) }
        try writeAll(fd: fd, data: header)
        try writeAll(fd: fd, data: reqData)

        let respHeader = try readExact(fd: fd, count: 4)
        let respLen = respHeader.withUnsafeBytes { raw -> UInt32 in
            UInt32(littleEndian: raw.load(as: UInt32.self))
        }
        guard respLen > 0, Int(respLen) <= Self.maxFrameBytes else {
            throw ClientError.protocolError
        }
        let respData = try readExact(fd: fd, count: Int(respLen))
        let decoded = try JSONDecoder().decode(RawResponse.self, from: respData)
        if !decoded.ok {
            let code = decoded.error ?? "unknown"
            let message = decoded.message ?? "Operation failed"
            switch code {
            case "vault_locked":
                throw ClientError.vaultLocked
            case "credential_not_found":
                throw ClientError.credentialNotFound
            case "credential_excluded":
                throw ClientError.credentialExcluded
            default:
                throw ClientError.serverError(code: code, message: message)
            }
        }
        guard let payload = decoded.payload else {
            throw ClientError.protocolError
        }
        return payload
    }

    private func writeAll(fd: Int32, data: Data) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < data.count {
                let n = Darwin.write(fd, base.advanced(by: offset), data.count - offset)
                if n <= 0 {
                    throw ClientError.appNotRunning
                }
                offset += n
            }
        }
    }

    private func readExact(fd: Int32, count: Int) throws -> Data {
        var buffer = Data(count: count)
        try buffer.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < count {
                let n = Darwin.read(fd, base.advanced(by: offset), count - offset)
                if n <= 0 {
                    throw ClientError.protocolError
                }
                offset += n
            }
        }
        return buffer
    }
}
