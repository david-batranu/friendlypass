import AppKit
@preconcurrency import AuthenticationServices
import Foundation

/// macOS AutoFill Credential Provider Extension (`com.apple.authentication-services-credential-provider-ui`).
///
/// Supports Passkeys (registration & assertion), Passwords, and One-Time Codes
/// (TOTP on macOS 15+) by delegating vault access and cryptographic operations
/// to the running `friendlypass` desktop app over the peer-verified App Group
/// Unix socket.
@objc(FriendlyPassCredentialProviderViewController)
final class CredentialProviderViewController: ASCredentialProviderViewController,
    NSTableViewDataSource,
    NSTableViewDelegate,
    NSSearchFieldDelegate
{
    private enum Mode {
        case idle
        case picker(
            kind: String,
            serviceIdentifiers: [String],
            passkeyParams: ASPasskeyCredentialRequestParameters?
        )
        case provideRequest(any ASCredentialRequest)
        case registerPasskey(ASPasskeyCredentialRequest)
        case configuration
    }

    private let client = IPCClient()
    private var mode: Mode = .idle
    private var items: [IPCClient.CredentialItemDTO] = []
    private var pollTimer: Timer?

    // UI elements
    private let titleLabel = NSTextField(labelWithString: "friendlypass")
    private let subtitleLabel = NSTextField(wrappingLabelWithString: "")
    private let statusLabel = NSTextField(wrappingLabelWithString: "")
    private let searchField = NSSearchField()
    private let scrollView = NSScrollView()
    private let tableView = NSTableView()
    private let openAppButton = NSButton(title: "Open friendlypass", target: nil, action: nil)
    private let retryButton = NSButton(title: "Retry", target: nil, action: nil)
    private let primaryButton = NSButton(title: "Use Selected", target: nil, action: nil)
    private let cancelButton = NSButton(title: "Cancel", target: nil, action: nil)

    deinit {
        pollTimer?.invalidate()
    }

    // MARK: - View Construction

    override func loadView() {
        let root = NSView(frame: NSRect(x: 0, y: 0, width: 460, height: 340))
        root.translatesAutoresizingMaskIntoConstraints = false
        self.view = root

        titleLabel.font = NSFont.systemFont(ofSize: 16, weight: .semibold)
        subtitleLabel.font = NSFont.systemFont(ofSize: 12)
        subtitleLabel.textColor = .secondaryLabelColor
        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.isHidden = true

        searchField.placeholderString = "Search friendlypass…"
        searchField.delegate = self
        searchField.isHidden = true

        let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("cred"))
        col.title = "Credentials"
        col.resizingMask = .autoresizingMask
        tableView.addTableColumn(col)
        tableView.headerView = nil
        tableView.rowHeight = 44
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.dataSource = self
        tableView.delegate = self
        tableView.target = self
        tableView.doubleAction = #selector(primaryAction(_:))

        scrollView.documentView = tableView
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .bezelBorder
        scrollView.isHidden = true

        openAppButton.bezelStyle = .rounded
        openAppButton.target = self
        openAppButton.action = #selector(openHostApp(_:))
        openAppButton.isHidden = true

        retryButton.bezelStyle = .rounded
        retryButton.target = self
        retryButton.action = #selector(retryAction(_:))
        retryButton.isHidden = true

        cancelButton.bezelStyle = .rounded
        cancelButton.keyEquivalent = "\u{1b}"
        cancelButton.target = self
        cancelButton.action = #selector(cancelAction(_:))

        primaryButton.bezelStyle = .rounded
        primaryButton.keyEquivalent = "\r"
        primaryButton.target = self
        primaryButton.action = #selector(primaryAction(_:))

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let buttonRow = NSStackView(views: [openAppButton, retryButton, spacer, cancelButton, primaryButton])
        buttonRow.orientation = .horizontal
        buttonRow.spacing = 8

        let stack = NSStackView(views: [
            titleLabel,
            subtitleLabel,
            statusLabel,
            searchField,
            scrollView,
            buttonRow,
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(stack)

        NSLayoutConstraint.activate([
            root.widthAnchor.constraint(greaterThanOrEqualToConstant: 440),
            root.heightAnchor.constraint(greaterThanOrEqualToConstant: 260),
            stack.topAnchor.constraint(equalTo: root.topAnchor, constant: 18),
            stack.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 18),
            stack.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -18),
            stack.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18),
            searchField.widthAnchor.constraint(equalTo: stack.widthAnchor),
            scrollView.widthAnchor.constraint(equalTo: stack.widthAnchor),
            scrollView.heightAnchor.constraint(greaterThanOrEqualToConstant: 150),
            buttonRow.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }

    override func viewWillDisappear() {
        super.viewWillDisappear()
        stopPolling()
    }

    // MARK: - Silent Fulfillment (No UI)

    override func provideCredentialWithoutUserInteraction(
        for credentialRequest: any ASCredentialRequest
    ) {
        let client = self.client
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.fulfillSync(request: credentialRequest, client: client)
            } catch IPCClient.ClientError.appNotRunning,
                    IPCClient.ClientError.vaultLocked,
                    IPCClient.ClientError.socketUnavailable {
                DispatchQueue.main.async {
                    self.extensionContext.cancelRequest(
                        withError: NSError(
                            domain: ASExtensionErrorDomain,
                            code: ASExtensionError.userInteractionRequired.rawValue
                        )
                    )
                }
            } catch IPCClient.ClientError.credentialNotFound {
                DispatchQueue.main.async {
                    self.extensionContext.cancelRequest(
                        withError: NSError(
                            domain: ASExtensionErrorDomain,
                            code: ASExtensionError.credentialIdentityNotFound.rawValue
                        )
                    )
                }
            } catch {
                DispatchQueue.main.async {
                    self.extensionContext.cancelRequest(
                        withError: NSError(
                            domain: ASExtensionErrorDomain,
                            code: ASExtensionError.failed.rawValue
                        )
                    )
                }
            }
        }
    }

    // MARK: - Interactive Fulfillment (Unlock Required)

    override func prepareInterfaceToProvideCredential(
        for credentialRequest: any ASCredentialRequest
    ) {
        _ = self.view
        mode = .provideRequest(credentialRequest)
        titleLabel.stringValue = "Unlock friendlypass"
        subtitleLabel.stringValue = "Open and unlock friendlypass to provide the selected credential."
        statusLabel.stringValue = "Waiting for friendlypass to unlock…"
        statusLabel.isHidden = false
        searchField.isHidden = true
        scrollView.isHidden = true
        openAppButton.isHidden = false
        retryButton.isHidden = false
        primaryButton.isHidden = true
        cancelButton.isHidden = false

        requestHostUnlockAsync()
        startPolling()
        tryFulfillPendingRequest()
    }

    // MARK: - Credential Pickers (Passwords, Passkeys, One-Time Codes)

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier]
    ) {
        _ = self.view
        let sids = serviceIdentifiers.map { $0.identifier }
        mode = .picker(kind: "password", serviceIdentifiers: sids, passkeyParams: nil)
        configurePickerUI(title: "Choose a Password", primaryTitle: "Fill Password")
        loadPickerItems()
    }

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        _ = self.view
        let sids = serviceIdentifiers.map { $0.identifier }
        mode = .picker(kind: "all", serviceIdentifiers: sids, passkeyParams: requestParameters)
        configurePickerUI(
            title: "Sign in to \(requestParameters.relyingPartyIdentifier)",
            primaryTitle: "Continue"
        )
        loadPickerItems()
    }

    @available(macOS 15.0, *)
    override func prepareOneTimeCodeCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier]
    ) {
        _ = self.view
        let sids = serviceIdentifiers.map { $0.identifier }
        mode = .picker(kind: "totp", serviceIdentifiers: sids, passkeyParams: nil)
        configurePickerUI(title: "Choose a One-Time Code", primaryTitle: "Fill Code")
        loadPickerItems()
    }

    // MARK: - Passkey Registration

    override func prepareInterface(
        forPasskeyRegistration registrationRequest: any ASCredentialRequest
    ) {
        _ = self.view
        guard let passkeyReq = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = passkeyReq.credentialIdentity as? ASPasskeyCredentialIdentity else {
            cancelWithCode(.failed)
            return
        }
        mode = .registerPasskey(passkeyReq)
        titleLabel.stringValue = "Save Passkey in friendlypass"
        let userDisplay = identity.userName.isEmpty ? "(unnamed account)" : identity.userName
        subtitleLabel.stringValue =
            "Website: \(identity.relyingPartyIdentifier)\nAccount: \(userDisplay)"
        statusLabel.isHidden = false
        searchField.isHidden = true
        scrollView.isHidden = true
        primaryButton.title = "Save Passkey"
        primaryButton.isHidden = false
        primaryButton.isEnabled = false
        cancelButton.isHidden = false
        retryButton.isHidden = false
        openAppButton.isHidden = false

        refreshRegistrationStatus()
        startPolling()
    }

    // MARK: - Extension Configuration UI (System Settings)

    override func prepareInterfaceForExtensionConfiguration() {
        _ = self.view
        mode = .configuration
        titleLabel.stringValue = "friendlypass AutoFill & Passkeys"
        subtitleLabel.stringValue =
            "friendlypass serves passkeys, passwords, and one-time codes from your open KDBX database."
        statusLabel.stringValue = "Checking connection to friendlypass…"
        statusLabel.isHidden = false
        searchField.isHidden = true
        scrollView.isHidden = true
        openAppButton.isHidden = false
        retryButton.isHidden = false
        cancelButton.isHidden = true
        primaryButton.title = "Done"
        primaryButton.isHidden = false
        primaryButton.isEnabled = true

        syncConfigurationIdentities()
    }

    // MARK: - Actions

    @objc private func cancelAction(_ sender: Any?) {
        stopPolling()
        if case .configuration = mode {
            extensionContext.completeExtensionConfigurationRequest()
        } else {
            cancelWithCode(.userCanceled)
        }
    }

    @objc private func openHostApp(_ sender: Any?) {
        let appURL = Bundle.main.bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let config = NSWorkspace.OpenConfiguration()
        config.activates = true
        NSWorkspace.shared.openApplication(at: appURL, configuration: config) { _, _ in }
        requestHostUnlockAsync()
    }

    @objc private func retryAction(_ sender: Any?) {
        switch mode {
        case .picker:
            loadPickerItems()
        case .provideRequest:
            tryFulfillPendingRequest()
        case .registerPasskey:
            refreshRegistrationStatus()
        case .configuration:
            syncConfigurationIdentities()
        case .idle:
            break
        }
    }

    @objc private func primaryAction(_ sender: Any?) {
        switch mode {
        case .configuration:
            stopPolling()
            extensionContext.completeExtensionConfigurationRequest()
        case .registerPasskey(let request):
            performPasskeyRegistration(request)
        case .picker(_, _, let passkeyParams):
            let row = tableView.selectedRow
            guard row >= 0, row < items.count else { return }
            completePickerSelection(items[row], passkeyParams: passkeyParams)
        case .provideRequest:
            tryFulfillPendingRequest()
        case .idle:
            break
        }
    }

    func controlTextDidChange(_ obj: Notification) {
        if case .picker = mode {
            loadPickerItems()
        }
    }

    // MARK: - Internal Helpers

    private func configurePickerUI(title: String, primaryTitle: String) {
        titleLabel.stringValue = title
        subtitleLabel.stringValue = ""
        statusLabel.isHidden = true
        searchField.stringValue = ""
        searchField.isHidden = false
        scrollView.isHidden = false
        openAppButton.isHidden = true
        retryButton.isHidden = true
        cancelButton.isHidden = false
        primaryButton.title = primaryTitle
        primaryButton.isHidden = false
        primaryButton.isEnabled = false
    }

    private func startPolling() {
        stopPolling()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.75, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                switch self.mode {
                case .provideRequest:
                    self.tryFulfillPendingRequest()
                case .registerPasskey:
                    self.refreshRegistrationStatus()
                case .picker:
                    if self.items.isEmpty && !self.openAppButton.isHidden {
                        self.loadPickerItems()
                    }
                default:
                    break
                }
            }
        }
    }

    private func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    private func requestHostUnlockAsync() {
        let client = self.client
        DispatchQueue.global(qos: .utility).async {
            _ = try? client.status(requestUnlock: true)
        }
    }

    private func tryFulfillPendingRequest() {
        guard case .provideRequest(let req) = mode else { return }
        let client = self.client
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try self.fulfillSync(request: req, client: client)
                DispatchQueue.main.async {
                    self.stopPolling()
                }
            } catch IPCClient.ClientError.appNotRunning, IPCClient.ClientError.socketUnavailable {
                DispatchQueue.main.async {
                    self.statusLabel.stringValue =
                        "friendlypass is not running. Click “Open friendlypass” and unlock your database."
                }
            } catch IPCClient.ClientError.vaultLocked {
                DispatchQueue.main.async {
                    self.statusLabel.stringValue =
                        "friendlypass is locked. Unlock your database to continue automatically."
                }
            } catch IPCClient.ClientError.credentialNotFound {
                DispatchQueue.main.async {
                    self.stopPolling()
                    self.cancelWithCode(.credentialIdentityNotFound)
                }
            } catch {
                DispatchQueue.main.async {
                    self.statusLabel.stringValue = "Unable to retrieve credential from friendlypass."
                }
            }
        }
    }

    private func loadPickerItems() {
        guard case .picker(let kind, let sids, let params) = mode else { return }
        let query = searchField.stringValue
        let rpId = params?.relyingPartyIdentifier
        let allowed = params?.allowedCredentials
        let client = self.client

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let fetched = try client.listCredentials(
                    kind: kind,
                    serviceIdentifiers: sids,
                    rpId: rpId,
                    allowedCredentialIDs: allowed,
                    query: query.isEmpty ? nil : query
                )
                DispatchQueue.main.async {
                    self.stopPolling()
                    self.items = fetched
                    self.tableView.reloadData()
                    self.openAppButton.isHidden = true
                    self.retryButton.isHidden = true
                    self.scrollView.isHidden = false
                    self.searchField.isHidden = false
                    if fetched.isEmpty {
                        self.statusLabel.stringValue = "No matching entries found."
                        self.statusLabel.isHidden = false
                        self.primaryButton.isEnabled = false
                    } else {
                        self.statusLabel.isHidden = true
                        self.tableView.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
                        self.primaryButton.isEnabled = true
                    }
                }
            } catch IPCClient.ClientError.appNotRunning, IPCClient.ClientError.socketUnavailable {
                DispatchQueue.main.async {
                    self.items = []
                    self.tableView.reloadData()
                    self.statusLabel.stringValue =
                        "friendlypass is not running. Open and unlock friendlypass to view credentials."
                    self.statusLabel.isHidden = false
                    self.openAppButton.isHidden = false
                    self.retryButton.isHidden = false
                    self.primaryButton.isEnabled = false
                    self.startPolling()
                }
            } catch IPCClient.ClientError.vaultLocked {
                DispatchQueue.main.async {
                    self.items = []
                    self.tableView.reloadData()
                    self.statusLabel.stringValue =
                        "friendlypass is locked. Unlock your database to view credentials."
                    self.statusLabel.isHidden = false
                    self.openAppButton.isHidden = false
                    self.retryButton.isHidden = false
                    self.primaryButton.isEnabled = false
                    self.requestHostUnlockAsync()
                    self.startPolling()
                }
            } catch {
                DispatchQueue.main.async {
                    self.statusLabel.stringValue = "Unable to load credentials from friendlypass."
                    self.statusLabel.isHidden = false
                    self.retryButton.isHidden = false
                }
            }
        }
    }

    private func completePickerSelection(
        _ item: IPCClient.CredentialItemDTO,
        passkeyParams: ASPasskeyCredentialRequestParameters?
    ) {
        let client = self.client
        primaryButton.isEnabled = false

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                switch item.kind {
                case "passkey":
                    guard let params = passkeyParams else {
                        throw IPCClient.ClientError.protocolError
                    }
                    let credId = item.credentialIdB64.flatMap { Data(base64Encoded: $0) }
                    let assertion = try client.assertPasskey(
                        uuid: item.uuid,
                        rpId: params.relyingPartyIdentifier,
                        credentialID: credId,
                        clientDataHash: params.clientDataHash
                    )
                    DispatchQueue.main.async {
                        let credential = ASPasskeyAssertionCredential(
                            userHandle: assertion.userHandle,
                            relyingParty: assertion.relyingParty,
                            signature: assertion.signature,
                            clientDataHash: params.clientDataHash,
                            authenticatorData: assertion.authenticatorData,
                            credentialID: assertion.credentialID
                        )
                        self.extensionContext.completeAssertionRequest(
                            using: credential,
                            completionHandler: nil
                        )
                    }
                case "totp":
                    let totp = try client.getTotp(uuid: item.uuid)
                    DispatchQueue.main.async {
                        if #available(macOS 15.0, *) {
                            let cred = ASOneTimeCodeCredential(code: totp.code)
                            self.extensionContext.completeOneTimeCodeRequest(
                                using: cred,
                                completionHandler: nil
                            )
                        } else {
                            self.cancelWithCode(.failed)
                        }
                    }
                default:
                    let pw = try client.getPassword(uuid: item.uuid)
                    let cred = ASPasswordCredential(user: pw.username, password: pw.password)
                    DispatchQueue.main.async {
                        self.extensionContext.completeRequest(
                            withSelectedCredential: cred,
                            completionHandler: nil
                        )
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self.statusLabel.stringValue = "Failed to fetch selected credential."
                    self.statusLabel.isHidden = false
                    self.primaryButton.isEnabled = true
                }
            }
        }
    }

    private func refreshRegistrationStatus() {
        let client = self.client
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let status = try client.status(requestUnlock: false)
                DispatchQueue.main.async {
                    if status.unlocked {
                        let name = status.dbName ?? "open database"
                        self.statusLabel.stringValue = "Will save into: \(name)"
                        self.primaryButton.isEnabled = true
                        self.openAppButton.isHidden = true
                        self.retryButton.isHidden = true
                    } else {
                        self.statusLabel.stringValue =
                            "friendlypass is locked. Unlock your database to save this passkey."
                        self.primaryButton.isEnabled = false
                        self.openAppButton.isHidden = false
                        self.retryButton.isHidden = false
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self.statusLabel.stringValue =
                        "friendlypass is not running. Open and unlock friendlypass to save this passkey."
                    self.primaryButton.isEnabled = false
                    self.openAppButton.isHidden = false
                    self.retryButton.isHidden = false
                }
            }
        }
    }

    private func performPasskeyRegistration(_ request: ASPasskeyCredentialRequest) {
        guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity else {
            cancelWithCode(.failed)
            return
        }
        stopPolling()
        primaryButton.isEnabled = false
        statusLabel.stringValue = "Generating and saving passkey…"

        let rpId = identity.relyingPartyIdentifier
        let username = identity.userName
        let userHandle = identity.userHandle
        let clientDataHash = request.clientDataHash
        let algorithms = request.supportedAlgorithms.map { Int64($0.rawValue) }
        var excluded: [Data] = []
        if #available(macOS 15.0, *), let descriptors = request.excludedCredentials {
            excluded = descriptors.map { $0.credentialID }
        }
        let client = self.client

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let reg = try client.registerPasskey(
                    rpId: rpId,
                    username: username,
                    userHandle: userHandle,
                    clientDataHash: clientDataHash,
                    algorithms: algorithms,
                    excludedCredentialIDs: excluded
                )
                // Best-effort identity store refresh before completing.
                if let ids = try? client.listIdentities() {
                    Task { _ = await IdentitySync.replaceAll(with: ids) }
                }
                DispatchQueue.main.async {
                    let credential = ASPasskeyRegistrationCredential(
                        relyingParty: reg.relyingParty,
                        clientDataHash: clientDataHash,
                        credentialID: reg.credentialID,
                        attestationObject: reg.attestationObject
                    )
                    self.extensionContext.completeRegistrationRequest(
                        using: credential,
                        completionHandler: nil
                    )
                }
            } catch IPCClient.ClientError.credentialExcluded {
                DispatchQueue.main.async {
                    if #available(macOS 15.0, *) {
                        self.cancelWithCode(.matchedExcludedCredential)
                    } else {
                        self.cancelWithCode(.failed)
                    }
                }
            } catch IPCClient.ClientError.vaultLocked, IPCClient.ClientError.appNotRunning {
                DispatchQueue.main.async {
                    self.statusLabel.stringValue = "Unlock friendlypass and try again."
                    self.openAppButton.isHidden = false
                    self.retryButton.isHidden = false
                    self.startPolling()
                }
            } catch {
                DispatchQueue.main.async {
                    self.statusLabel.stringValue = "Unable to save passkey in friendlypass."
                    self.primaryButton.isEnabled = true
                }
            }
        }
    }

    private func syncConfigurationIdentities() {
        let client = self.client
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let ids = try client.listIdentities()
                Task { @MainActor in
                    let synced = await IdentitySync.replaceAll(with: ids)
                    if synced {
                        self.statusLabel.stringValue =
                            "Synced \(ids.passkeys.count) passkeys, \(ids.passwords.count) passwords, and \(ids.totps.count) one-time codes with macOS AutoFill."
                    } else {
                        self.statusLabel.stringValue =
                            "Connected to friendlypass. Enable friendlypass in AutoFill & Passwords to sync credentials."
                    }
                }
            } catch IPCClient.ClientError.vaultLocked {
                DispatchQueue.main.async {
                    self.statusLabel.stringValue =
                        "friendlypass is locked. Unlock your database to sync passkeys, passwords, and one-time codes."
                }
            } catch {
                DispatchQueue.main.async {
                    self.statusLabel.stringValue =
                        "friendlypass is not running. Open and unlock friendlypass to sync your credentials."
                }
            }
        }
    }

    private nonisolated func fulfillSync(
        request: any ASCredentialRequest,
        client: IPCClient
    ) throws {
        if let passkeyReq = request as? ASPasskeyCredentialRequest,
           let identity = passkeyReq.credentialIdentity as? ASPasskeyCredentialIdentity {
            let assertion = try client.assertPasskey(
                uuid: identity.recordIdentifier,
                rpId: identity.relyingPartyIdentifier,
                credentialID: identity.credentialID,
                clientDataHash: passkeyReq.clientDataHash
            )
            let clientDataHash = passkeyReq.clientDataHash
            DispatchQueue.main.async {
                let credential = ASPasskeyAssertionCredential(
                    userHandle: assertion.userHandle,
                    relyingParty: assertion.relyingParty,
                    signature: assertion.signature,
                    clientDataHash: clientDataHash,
                    authenticatorData: assertion.authenticatorData,
                    credentialID: assertion.credentialID
                )
                self.extensionContext.completeAssertionRequest(
                    using: credential,
                    completionHandler: nil
                )
            }
            return
        }

        if let passwordReq = request as? ASPasswordCredentialRequest,
           let identity = passwordReq.credentialIdentity as? ASPasswordCredentialIdentity,
           let uuid = identity.recordIdentifier {
            let pw = try client.getPassword(uuid: uuid)
            let credential = ASPasswordCredential(user: pw.username, password: pw.password)
            DispatchQueue.main.async {
                self.extensionContext.completeRequest(
                    withSelectedCredential: credential,
                    completionHandler: nil
                )
            }
            return
        }

        if #available(macOS 15.0, *),
           let totpReq = request as? ASOneTimeCodeCredentialRequest,
           let identity = totpReq.credentialIdentity as? ASOneTimeCodeCredentialIdentity,
           let uuid = identity.recordIdentifier {
            let totp = try client.getTotp(uuid: uuid)
            let credential = ASOneTimeCodeCredential(code: totp.code)
            DispatchQueue.main.async {
                self.extensionContext.completeOneTimeCodeRequest(
                    using: credential,
                    completionHandler: nil
                )
            }
            return
        }

        throw IPCClient.ClientError.credentialNotFound
    }

    private func cancelWithCode(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(
            withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue)
        )
    }

    // MARK: - NSTableViewDataSource / NSTableViewDelegate

    func numberOfRows(in tableView: NSTableView) -> Int {
        items.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard row >= 0, row < items.count else { return nil }
        let item = items[row]
        let cellId = NSUserInterfaceItemIdentifier("FriendlyPassCredCell")
        let cell = (tableView.makeView(withIdentifier: cellId, owner: self) as? NSTableCellView)
            ?? {
                let v = NSTableCellView()
                v.identifier = cellId
                let main = NSTextField(labelWithString: "")
                main.font = NSFont.systemFont(ofSize: 13, weight: .medium)
                main.lineBreakMode = .byTruncatingTail
                let sub = NSTextField(labelWithString: "")
                sub.font = NSFont.systemFont(ofSize: 11)
                sub.textColor = .secondaryLabelColor
                sub.lineBreakMode = .byTruncatingTail
                let stack = NSStackView(views: [main, sub])
                stack.orientation = .vertical
                stack.alignment = .leading
                stack.spacing = 2
                stack.translatesAutoresizingMaskIntoConstraints = false
                v.addSubview(stack)
                v.textField = main
                sub.tag = 2
                NSLayoutConstraint.activate([
                    stack.leadingAnchor.constraint(equalTo: v.leadingAnchor, constant: 8),
                    stack.trailingAnchor.constraint(equalTo: v.trailingAnchor, constant: -8),
                    stack.centerYAnchor.constraint(equalTo: v.centerYAnchor),
                ])
                return v
            }()

        let badge: String
        switch item.kind {
        case "passkey": badge = "[Passkey] "
        case "totp": badge = "[OTP] "
        default: badge = ""
        }
        cell.textField?.stringValue = "\(badge)\(item.title.isEmpty ? item.subtitle : item.title)"
        if let sub = cell.viewWithTag(2) as? NSTextField {
            let parts = [item.username, item.subtitle].filter { !$0.isEmpty }
            sub.stringValue = parts.joined(separator: " — ")
        }
        return cell
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        primaryButton.isEnabled = tableView.selectedRow >= 0 && tableView.selectedRow < items.count
    }
}
