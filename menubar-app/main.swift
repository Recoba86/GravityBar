import Carbon
import Cocoa
import Foundation
import SwiftUI
@preconcurrency import UserNotifications

// MARK: - Store (Native Keychain + official Antigravity CLI)

@MainActor
final class SwitcherStore: ObservableObject {
    @Published var accounts: [AccountItem] = []
    @Published var activeKey: String?
    @Published var hasActiveSession: Bool = false
    @Published var activeSessionUnsaved: Bool = false
    @Published var activeEmail: String?
    @Published var bestSwitchCandidate: String?
    @Published var isLoading: Bool = false
    @Published var isRefreshing: Bool = false
    @Published var switchingKey: String?
    @Published var errorMessage: String?
    @Published var toastMessage: String?
    @Published var screen: ActiveScreen = .accounts
    @Published var lastUpdated: Date?

    @Published var selectedIndex: Int = 0
    @Published var isKeyboardNavigating: Bool = false
    @Published var expandedKeys: Set<String> = []
    @Published var pendingConfirmKey: String?

    @Published var wizardStep: Int = 1
    @Published var wizardMode: AddAccountMode = .agyCli
    @Published var wizardNewLabel: String = ""
    @Published var wizardDetectedEmail: String?
    @Published var wizardAuthURL: URL?
    @Published var wizardAuthCodeInput: String = ""
    @Published var wizardVerifyingCode: Bool = false
    @Published var wizardBusy: Bool = false

    @AppStorage("menuBarDisplayMode") var menuBarDisplayRaw: String = MenuBarDisplayMode.dualBars.rawValue {
        didSet { onStatusUpdated?(lastPayload) }
    }
    @AppStorage("accountSortMode") var sortModeRaw: String = AccountSortMode.bestQuota.rawValue
    @AppStorage("enableGlobalHotkey") var enableGlobalHotkey: Bool = true {
        didSet { onHotkeySettingChanged?(enableGlobalHotkey) }
    }
    @AppStorage("lowQuotaAlertsEnabled") var lowQuotaAlertsEnabled: Bool = true
    @AppStorage("confirmBeforeSwitch") var confirmBeforeSwitch: Bool = false
    @AppStorage("playSounds") var playSounds: Bool = true
    @Published var quotaProgress: String?
    @Published var quotaErrors: [String: String] = [:]
    @Published var launchAtLogin: Bool = false

    let manifestStore = NativeManifestStore()
    var onStatusUpdated: ((StatusPayload?) -> Void)?
    var onHotkeySettingChanged: ((Bool) -> Void)?
    var onRequestPopoverOpen: (() -> Void)?
    var onRequestPopoverClose: (() -> Void)?

    private var lastPayload: StatusPayload?
    private var statusRequestID = 0
    private var appliedStatusRequestID = 0
    private var refreshRequestID: Int?
    private var toastTask: Task<Void, Never>?
    private var wizardPollTask: Task<Void, Never>?
    private var agyTask: Task<Void, Never>?
    private var activeAgySession: OfficialAgyLoginSession?
    private var pendingOfficialToken: String?
    private var backedUpActiveTokenForWizard: String?
    private var wizardRun = UUID()
    private var desktopLoginPreparing = false
    private var wizardRestoration: Task<Bool, Never>?
    private var lastLowAlertKey: String?

    var menuBarDisplayMode: MenuBarDisplayMode {
        MenuBarDisplayMode(rawValue: menuBarDisplayRaw) ?? .dualBars
    }

    var sortMode: AccountSortMode {
        AccountSortMode(rawValue: sortModeRaw) ?? .bestQuota
    }

    var sortedAccounts: [AccountItem] {
        accounts.sorted { a, b in
            if a.pinned != b.pinned { return a.pinned && !b.pinned }
            switch sortMode {
            case .bestQuota:
                let sa = QuotaHelpers.minRemaining(for: a.usage)
                let sb = QuotaHelpers.minRemaining(for: b.usage)
                if sa != sb { return sa > sb }
                if a.isActive != b.isActive { return a.isActive && !b.isActive }
                return a.key.localizedCaseInsensitiveCompare(b.key) == .orderedAscending
            case .activeFirst:
                if a.isActive != b.isActive { return a.isActive && !b.isActive }
                return a.key.localizedCaseInsensitiveCompare(b.key) == .orderedAscending
            case .alphabetical:
                return a.key.localizedCaseInsensitiveCompare(b.key) == .orderedAscending
            }
        }
    }

    private var launchAgentURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/com.m4tinbeigi.gravitybar.plist")
    }

    private var legacyLaunchAgentURLs: [URL] {
        let agentsDir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents")
        return [
            agentsDir.appendingPathComponent("com.m4tinbeigi.antigravitymenubar.plist"),
            agentsDir.appendingPathComponent("com.m4tinbeigi.antigravityswitcher.plist")
        ]
    }

    init() {
        launchAtLogin = FileManager.default.fileExists(atPath: launchAgentURL.path)
    }

    func setLaunchAtLogin(_ enabled: Bool) {
        let fm = FileManager.default
        for legacyURL in legacyLaunchAgentURLs {
            try? fm.removeItem(at: legacyURL)
        }
        if enabled {
            let appExec = "/Applications/GravityBar.app/Contents/MacOS/GravityBar"
            let execPath = fm.fileExists(atPath: appExec)
                ? appExec
                : (Bundle.main.executablePath ?? appExec)
            let plist: [String: Any] = [
                "Label": "com.m4tinbeigi.gravitybar",
                "ProgramArguments": [execPath],
                "RunAtLoad": true
            ]
            do {
                try fm.createDirectory(at: launchAgentURL.deletingLastPathComponent(), withIntermediateDirectories: true)
                let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
                try data.write(to: launchAgentURL, options: .atomic)
                launchAtLogin = true
            } catch {
                errorMessage = "Could not enable Launch at Login: \(error.localizedDescription)"
                launchAtLogin = false
            }
        } else {
            try? fm.removeItem(at: launchAgentURL)
            launchAtLogin = false
        }
    }

    func toggleExpanded(_ key: String) {
        if expandedKeys.contains(key) {
            expandedKeys.remove(key)
        } else {
            expandedKeys.insert(key)
        }
    }

    func showToast(_ msg: String) {
        toastTask?.cancel()
        toastMessage = msg
        toastTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            if !Task.isCancelled {
                self?.toastMessage = nil
            }
        }
    }

    func playSystemSound(_ name: String) {
        guard playSounds else { return }
        NSSound(named: NSSound.Name(name))?.play()
    }

    /// Shows saved accounts with their last checked quotas. Never contacts Google.
    func loadInitial() async {
        guard !isRefreshing else { return }
        if accounts.isEmpty { isLoading = true }
        await fetchStatus()
    }

    /// Manual "Check Quotas": runs the official CLI once per account, a few seconds apart.
    func refresh() async {
        guard !isRefreshing else { return }
        await fetchStatus(checkQuotas: true)
    }

    private func fetchStatus(checkQuotas: Bool = false) async {
        if checkQuotas && isRefreshing { return }
        statusRequestID += 1
        let requestID = statusRequestID
        if checkQuotas {
            refreshRequestID = requestID
            isRefreshing = true
            quotaProgress = nil
            quotaErrors = [:]
        }
        let store = manifestStore
        let progress: @Sendable (Int, Int) -> Void = { [weak self] done, total in
            Task { @MainActor in
                guard let self, self.refreshRequestID == requestID else { return }
                self.quotaProgress = "Checking \(done)/\(total)…"
            }
        }
        let result = await Task.detached(priority: .userInitiated) {
            await NativeQuotaFetcher.loadStatusPayload(
                store: store, checkQuotas: checkQuotas, onProgress: checkQuotas ? progress : nil
            )
        }.value

        if refreshRequestID == requestID {
            refreshRequestID = nil
            isRefreshing = false
            quotaProgress = nil
        }
        isLoading = false
        if checkQuotas {
            quotaErrors = result.errors
        }
        guard requestID > appliedStatusRequestID else {
            if checkQuotas { await fetchStatus() }
            return
        }
        appliedStatusRequestID = requestID
        applyPayload(result.payload)
        if let key = result.payload.activeKey, result.checkedAccounts.contains(key) {
            evaluateLowQuotaNotification(result.payload)
        }
    }

    private func applyPayload(_ payload: StatusPayload) {
        lastPayload = payload
        accounts = payload.accounts
        activeKey = payload.activeKey
        hasActiveSession = payload.hasActiveSession
        activeSessionUnsaved = payload.activeSessionUnsaved
        activeEmail = payload.activeEmail
        bestSwitchCandidate = payload.bestSwitchCandidate
        lastUpdated = accounts.compactMap { $0.usage?.checkedAt }.max().map {
            Date(timeIntervalSince1970: TimeInterval($0))
        }
        if !accounts.isEmpty {
            isLoading = false
        }
        if selectedIndex >= sortedAccounts.count {
            selectedIndex = max(0, sortedAccounts.count - 1)
        }
        onStatusUpdated?(payload)
    }

    private func evaluateLowQuotaNotification(_ payload: StatusPayload) {
        guard lowQuotaAlertsEnabled, Bundle.main.bundleIdentifier != nil else { return }
        guard let active = payload.accounts.first(where: { $0.isActive }) else { return }
        let minRem = QuotaHelpers.minRemaining(for: active.usage)
        guard minRem >= 0 else { return }

        if minRem < 15.0 {
            if lastLowAlertKey != active.key {
                lastLowAlertKey = active.key
                let title = "GravityBar · Quota Low (\(Int(minRem.rounded()))% left)"
                let body: String
                if let best = payload.bestSwitchCandidate {
                    body = "\(active.label) is running low. Click GravityBar or press ⌥⌘A to switch to \(best)."
                } else {
                    body = "\(active.label) has less than 15% quota remaining."
                }
                sendLocalNotification(title: title, body: body)
            }
        } else if minRem >= 25.0 && lastLowAlertKey == active.key {
            lastLowAlertKey = nil
        }
    }

    private func sendLocalNotification(title: String, body: String) {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            let req = UNNotificationRequest(identifier: "ag_low_quota_\(UUID().uuidString)", content: content, trigger: nil)
            UNUserNotificationCenter.current().add(req, withCompletionHandler: nil)
        }
    }

    func switchTo(_ key: String, forceConfirmed: Bool = false) async {
        guard switchingKey == nil else { return }
        if key == activeKey {
            pendingConfirmKey = nil
            playSystemSound("Tink")
            showToast("Already on \(key)")
            return
        }
        if confirmBeforeSwitch && !forceConfirmed {
            pendingConfirmKey = (pendingConfirmKey == key) ? nil : key
            return
        }

        pendingConfirmKey = nil
        switchingKey = key
        errorMessage = nil

        let store = manifestStore
        let result: (Bool, String) = await Task.detached(priority: .userInitiated) {
            let manifest = store.loadManifest(migrate: true)
            guard let entry = manifest[key] else {
                return (false, "Account '\(key)' not found.")
            }
            guard let token = store.getAccountToken(entry) else {
                return (false, "Saved credential for '\(key)' is missing from Keychain.")
            }
            return NativeKeychain.setActiveToken(token, keychainPath: store.keychainPath)
        }.value

        if result.0 {
            let relaunched = await NativeAppRestarter.restartAntigravity()
            switchingKey = nil
            if relaunched {
                playSystemSound("Glass")
                showToast("Switched to \(key)")
            } else {
                errorMessage = "The active credential was updated. Open Antigravity to use \(key)."
            }
            await fetchStatus()
        } else {
            switchingKey = nil
            errorMessage = result.1.isEmpty ? "Failed to update Keychain." : result.1
        }
    }

    func saveCurrent(label: String?) async -> Bool {
        errorMessage = nil
        let store = manifestStore
        let currOpt = await Task.detached(priority: .userInitiated) {
            NativeKeychain.getActiveToken(keychainPath: store.keychainPath)
        }.value

        guard let token = currOpt else {
            errorMessage = "No active Antigravity session found in Keychain."
            return false
        }
        let email = NativeQuotaFetcher.emailFromToken(token)
            ?? label?.trimmingCharacters(in: .whitespacesAndNewlines)
            ?? "antigravity-account"

        let result = await Task.detached(priority: .userInitiated) {
            store.saveAccount(token: token, email: email, customLabel: label)
        }.value

        if result.0 {
            playSystemSound("Glass")
            showToast("Account saved to Keychain")
            await fetchStatus()
            return true
        } else {
            errorMessage = result.1
            return false
        }
    }

    func removeAccount(_ key: String) async {
        errorMessage = nil
        let store = manifestStore
        let result = await Task.detached(priority: .userInitiated) {
            store.removeAccount(key: key)
        }.value
        if result.0 {
            playSystemSound("Submarine")
            showToast("Removed \(key)")
            await fetchStatus()
        } else {
            errorMessage = result.1
        }
    }

    func renameAccount(from oldKey: String, to newKey: String) async -> Bool {
        errorMessage = nil
        let store = manifestStore
        let result = await Task.detached(priority: .userInitiated) {
            store.renameAccount(oldKey: oldKey, newKey: newKey)
        }.value
        if result.0 {
            playSystemSound("Glass")
            showToast("Renamed to \(newKey.trimmingCharacters(in: .whitespacesAndNewlines))")
            await fetchStatus()
            return true
        } else {
            errorMessage = result.1
            return false
        }
    }

    func togglePin(_ account: AccountItem) async {
        let store = manifestStore
        let nextPin = !account.pinned
        let res = await Task.detached(priority: .userInitiated) {
            store.setPinned(key: account.key, pinned: nextPin)
        }.value
        if res.0 {
            await fetchStatus()
        } else {
            errorMessage = res.1
        }
    }

    func setPlanLabel(_ key: String, plan: String) async {
        let store = manifestStore
        let res = await Task.detached(priority: .userInitiated) {
            store.setPlanLabel(key: key, planLabel: plan)
        }.value
        if res.0 {
            showToast(plan.isEmpty ? "Plan set to Auto" : "Plan: \(plan)")
            await fetchStatus()
        } else {
            errorMessage = res.1
        }
    }

    // MARK: - Add Account Wizard (Official Antigravity CLI --login + Desktop App Fallback)

    var hasOfficialAgyCLI: Bool {
        OfficialAgyLoginSession.findAgyExecutable() != nil
    }

    func beginWizard() {
        cancelWizardLogin()
        wizardStep = 1
        wizardMode = hasOfficialAgyCLI ? .agyCli : .antigravityIDE
        wizardNewLabel = ""
        wizardDetectedEmail = nil
        wizardAuthURL = nil
        wizardAuthCodeInput = ""
        wizardVerifyingCode = false
        pendingOfficialToken = nil
        backedUpActiveTokenForWizard = nil
        wizardBusy = false
        errorMessage = nil
        screen = .addWizard
    }

    func startOfficialAgyCLILogin() async {
        guard !wizardBusy, !desktopLoginPreparing else { return }
        cancelWizardLogin()
        let run = wizardRun
        wizardMode = .agyCli
        wizardBusy = true
        wizardAuthURL = nil
        wizardAuthCodeInput = ""
        wizardVerifyingCode = false
        errorMessage = nil
        _ = await wizardRestoration?.value
        guard run == wizardRun else { return }

        let session: OfficialAgyLoginSession
        do {
            session = try OfficialAgyLoginSession()
        } catch {
            wizardBusy = false
            errorMessage = error.localizedDescription
            return
        }

        activeAgySession = session
        wizardStep = 2

        agyTask = Task { @MainActor [weak self] in
            guard let self = self else { return }
            do {
                let authURL = try await session.waitForAuthorizationURL()
                guard !Task.isCancelled, self.activeAgySession === session else { return }
                self.wizardAuthURL = authURL
                self.wizardBusy = false
                if !NSWorkspace.shared.open(authURL) {
                    self.errorMessage = "Couldn't open the browser. Use Re-open Link to try again."
                }

                let res = try await session.waitForCompletion()
                guard !Task.isCancelled, self.activeAgySession === session else { return }
                self.activeAgySession = nil
                self.wizardVerifyingCode = false
                self.wizardBusy = false
                self.pendingOfficialToken = res.token
                self.wizardDetectedEmail = res.email
                self.wizardNewLabel = res.email
                self.wizardStep = 3
                self.playSystemSound("Hero")
                self.onRequestPopoverOpen?()
            } catch {
                guard !Task.isCancelled, self.activeAgySession === session else { return }
                self.activeAgySession = nil
                self.wizardBusy = false
                self.wizardVerifyingCode = false
                self.wizardStep = 1
                self.errorMessage = error.localizedDescription
                self.onRequestPopoverOpen?()
            }
        }
    }

    func reopenOfficialAgyURL() {
        if let url = wizardAuthURL {
            errorMessage = NSWorkspace.shared.open(url) ? nil : "Couldn't open the Google sign-in link."
        }
    }

    func submitOfficialAgyCode() {
        guard !wizardVerifyingCode, let session = activeAgySession else { return }
        let code = wizardAuthCodeInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !code.isEmpty else {
            errorMessage = "Paste the code or full URL from the Google Antigravity sign-in page."
            return
        }
        errorMessage = nil
        wizardVerifyingCode = true
        if !session.submitAuthorizationResponse(code) {
            wizardVerifyingCode = false
            errorMessage = "Could not deliver the code to Antigravity CLI. Start sign-in again."
        }
    }

    func cancelWizardLogin(restoreBackup: Bool = true) {
        wizardRun = UUID()
        stopWizardPolling()
        agyTask?.cancel()
        agyTask = nil
        activeAgySession?.cancel()
        activeAgySession = nil
        pendingOfficialToken = nil
        wizardAuthURL = nil
        wizardAuthCodeInput = ""
        wizardVerifyingCode = false
        wizardBusy = false
        wizardStep = 1

        if restoreBackup, let backup = backedUpActiveTokenForWizard {
            backedUpActiveTokenForWizard = nil
            let store = manifestStore
            let restoration = Task.detached(priority: .userInitiated) {
                NativeKeychain.restoreActiveTokenIfMissing(backup, keychainPath: store.keychainPath)
            }
            wizardRestoration = restoration
            Task { [weak self] in
                if !(await restoration.value) {
                    self?.errorMessage = "Could not restore the previous Antigravity session."
                }
            }
        } else {
            backedUpActiveTokenForWizard = nil
        }
    }

    func startWizardLogin() async {
        guard !wizardBusy, !desktopLoginPreparing else { return }
        cancelWizardLogin()
        let run = wizardRun
        desktopLoginPreparing = true
        defer { desktopLoginPreparing = false }
        wizardMode = .antigravityIDE
        wizardBusy = true
        errorMessage = nil
        _ = await wizardRestoration?.value
        guard run == wizardRun else { return }
        guard NativeAppRestarter.antigravityAppURL() != nil else {
            wizardBusy = false
            errorMessage = "Antigravity app was not found in /Applications. Use 'Sign in via Antigravity CLI' instead."
            return
        }
        let store = manifestStore
        let (prevTok, cleared) = await Task.detached(priority: .userInitiated) {
            NativeKeychain.clearActiveTokenForSignIn(keychainPath: store.keychainPath)
        }.value
        guard run == wizardRun else {
            if cleared, let prevTok {
                let restored = await Task.detached(priority: .userInitiated) {
                    NativeKeychain.restoreActiveTokenIfMissing(prevTok, keychainPath: store.keychainPath)
                }.value
                if !restored { errorMessage = "Could not restore the previous Antigravity session." }
            }
            return
        }
        guard cleared else {
            wizardBusy = false
            errorMessage = "Could not clear the current Antigravity credential."
            return
        }
        backedUpActiveTokenForWizard = prevTok
        let restarted = await NativeAppRestarter.restartAntigravity()
        guard run == wizardRun else { return }
        guard restarted else {
            cancelWizardLogin()
            errorMessage = "Antigravity could not restart for sign-in."
            return
        }
        playSystemSound("Blow")
        wizardBusy = false
        wizardStep = 2
        startWizardPolling()
    }

    func checkWizardSignInNow() async {
        let run = wizardRun
        wizardBusy = true
        await fetchStatus()
        guard run == wizardRun else { return }
        wizardBusy = false
        evaluateWizardDetection()
    }

    func stopWizardPolling() {
        wizardPollTask?.cancel()
        wizardPollTask = nil
    }

    private func startWizardPolling() {
        stopWizardPolling()
        wizardPollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                if Task.isCancelled { break }
                guard let self = self, self.screen == .addWizard, self.wizardStep == 2, self.wizardMode == .antigravityIDE else { break }
                await self.fetchStatus()
                if Task.isCancelled { break }
                if self.activeSessionUnsaved {
                    self.evaluateWizardDetection()
                    break
                }
            }
        }
    }

    private func evaluateWizardDetection() {
        if activeSessionUnsaved {
            stopWizardPolling()
            pendingOfficialToken = nil
            backedUpActiveTokenForWizard = nil
            wizardDetectedEmail = activeEmail
            wizardNewLabel = activeEmail ?? "Account \(accounts.count + 1)"
            playSystemSound("Hero")
            wizardStep = 3
        } else if hasActiveSession, let existing = activeKey {
            errorMessage = "Signed into already saved account (\(existing)). Please sign in with a different Google account."
        }
    }

    func finishWizardSave() async {
        wizardBusy = true
        var ok = false
        if let cliToken = pendingOfficialToken {
            let store = manifestStore
            let fallbackEmail = wizardDetectedEmail ?? "antigravity-account"
            let label = wizardNewLabel
            let res = await Task.detached(priority: .userInitiated) { () -> (Bool, String) in
                let saved = store.saveAccount(token: cliToken, email: fallbackEmail, customLabel: label)
                if saved.0 {
                    NativeKeychain.restoreActiveTokenIfMissing(cliToken, keychainPath: store.keychainPath)
                }
                return saved
            }.value
            if res.0 {
                ok = true
                playSystemSound("Glass")
                showToast("Account saved to Keychain")
                await fetchStatus()
            } else {
                errorMessage = res.1
            }
        } else {
            ok = await saveCurrent(label: wizardNewLabel)
        }
        wizardBusy = false
        if ok {
            cancelWizardLogin(restoreBackup: false)
            screen = .accounts
        }
    }

    func openAntigravity() {
        onRequestPopoverClose?()
        let res = NativeAppRestarter.openAntigravityApp()
        if !res.ok {
            errorMessage = res.errorMessage ?? "Failed to open Antigravity."
            onRequestPopoverOpen?()
        }
    }

    func openUsageDashboard() {
        DashboardBridge.openWebDashboard()
    }
}

// MARK: - Field Editor Keyboard Shortcuts

enum FieldEditorShortcut: Equatable {
    case paste
    case copy
    case cut
    case selectAll
    case undo
    case redo

    private static let ansiKeyLetters: [Int: String] = [
        kVK_ANSI_A: "a",
        kVK_ANSI_C: "c",
        kVK_ANSI_V: "v",
        kVK_ANSI_X: "x",
        kVK_ANSI_Z: "z"
    ]

    nonisolated static func resolve(
        charactersIgnoringModifiers: String?,
        keyCode: UInt16,
        modifierFlags: NSEvent.ModifierFlags
    ) -> FieldEditorShortcut? {
        let modifiers = modifierFlags.intersection([.command, .control, .option, .shift])
        let raw = (charactersIgnoringModifiers ?? "").lowercased()
        let letter: String?
        if raw.count == 1, let scalar = raw.unicodeScalars.first, scalar.value >= 0x20 && scalar.value < 0x7F {
            letter = raw
        } else {
            letter = ansiKeyLetters[Int(keyCode)]
        }
        guard let letter else { return nil }

        if modifiers == .command {
            switch letter {
            case "v": return .paste
            case "c": return .copy
            case "x": return .cut
            case "a": return .selectAll
            case "z": return .undo
            default: return nil
            }
        }
        if modifiers == [.command, .shift], letter == "z" {
            return .redo
        }
        if modifiers == .control, letter == "v" {
            return .paste
        }
        return nil
    }

    @MainActor
    func apply(to editor: NSTextView) -> Bool {
        switch self {
        case .paste:
            guard editor.isEditable else { return false }
            editor.paste(nil)
            return true
        case .copy:
            editor.copy(nil)
            return true
        case .cut:
            guard editor.isEditable else { return false }
            editor.cut(nil)
            return true
        case .selectAll:
            editor.selectAll(nil)
            return true
        case .undo:
            guard editor.isEditable else { return false }
            editor.undoManager?.undo()
            return true
        case .redo:
            guard editor.isEditable else { return false }
            editor.undoManager?.redo()
            return true
        }
    }
}

// MARK: - Unified AppDelegate (Single-Instance Menu Bar Popover + Optional Window Mode)

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private static let activateNotification = Notification.Name("com.m4tinbeigi.gravitybar.activate")

    private let store = SwitcherStore()
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var mainWindow: NSWindow?
    private var isWindowMode: Bool = false
    private var hotKeyRef: EventHotKeyRef?
    private var hotKeyHandlerRef: EventHandlerRef?
    private var keyMonitor: Any?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let args = CommandLine.arguments
        isWindowMode = args.contains("--window")

        // Single-instance check for unified Menu Bar / Spotlight app
        if !isWindowMode, let bid = Bundle.main.bundleIdentifier {
            let others = NSRunningApplication.runningApplications(withBundleIdentifier: bid)
                .filter { $0 != NSRunningApplication.current }
            if !others.isEmpty {
                DistributedNotificationCenter.default().postNotificationName(
                    Self.activateNotification,
                    object: nil,
                    userInfo: nil,
                    deliverImmediately: true
                )
                NSApp.terminate(nil)
                return
            }
            DistributedNotificationCenter.default().addObserver(
                self,
                selector: #selector(handleExternalActivate),
                name: Self.activateNotification,
                object: nil
            )
        }

        store.onStatusUpdated = { [weak self] payload in
            self?.updateStatusButton(payload: payload)
        }
        store.onHotkeySettingChanged = { [weak self] enabled in
            if enabled {
                self?.registerGlobalHotkey()
            } else {
                self?.unregisterGlobalHotkey()
            }
        }
        store.onRequestPopoverOpen = { [weak self] in
            self?.openPopover()
        }
        store.onRequestPopoverClose = { [weak self] in
            self?.closePopover()
        }

        NSApp.applicationIconImage = AppIconRenderer.renderIcon(size: 512)

        if isWindowMode {
            NSApp.setActivationPolicy(.regular)
            openStandaloneWindow()
        } else {
            NSApp.setActivationPolicy(.accessory)
            setupMenuBar()
            if !args.contains("--background") {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) { [weak self] in
                    self?.openPopover()
                }
            }
        }

        installKeyboardMonitor()
        if store.enableGlobalHotkey {
            registerGlobalHotkey()
        }
        UserDefaults.standard.removeObject(forKey: "autoRefreshMinutes")
        UserDefaults.standard.removeObject(forKey: "autoWarmup5hEnabled")
        try? FileManager.default.removeItem(at: store.manifestStore.accountsDir.appendingPathComponent("warmup_state.json"))
        Task {
            await store.loadInitial()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        unregisterGlobalHotkey()
        removeKeyboardMonitor()
        DistributedNotificationCenter.default().removeObserver(self)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if isWindowMode {
            openStandaloneWindow()
        } else {
            openPopover()
        }
        return true
    }

    @objc private func handleExternalActivate() {
        if isWindowMode {
            openStandaloneWindow()
        } else {
            openPopover()
        }
    }

    private func setupMenuBar() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = item.button {
            button.image = MenuBarGaugeRenderer.renderImage(geminiPct: nil, claudePct: nil)
            button.imagePosition = .imageLeading
            button.action = #selector(togglePopover(_:))
            button.target = self
            button.toolTip = "GravityBar · Antigravity Account Switcher (⌥⌘A)"
        }
        self.statusItem = item

        let hosting = NSHostingController(
            rootView: RootSwitcherView(store: store, isWindowMode: false) {
                NSApplication.shared.terminate(nil)
            }
        )
        hosting.sizingOptions = .preferredContentSize

        let pop = NSPopover()
        pop.behavior = .transient
        pop.animates = true
        pop.contentViewController = hosting
        self.popover = pop
    }

    private func openStandaloneWindow() {
        if let win = mainWindow {
            win.makeKeyAndOrderFront(nil)
            activateApp()
            return
        }

        let rootView = RootSwitcherView(store: store, isWindowMode: true) {
            NSApplication.shared.terminate(nil)
        }
        let hosting = NSHostingController(rootView: rootView)
        hosting.sizingOptions = .preferredContentSize

        let visualEffect = NSVisualEffectView()
        visualEffect.material = .popover
        visualEffect.blendingMode = .behindWindow
        visualEffect.state = .active

        hosting.view.translatesAutoresizingMaskIntoConstraints = false
        visualEffect.addSubview(hosting.view)
        NSLayoutConstraint.activate([
            hosting.view.topAnchor.constraint(equalTo: visualEffect.topAnchor),
            hosting.view.bottomAnchor.constraint(equalTo: visualEffect.bottomAnchor),
            hosting.view.leadingAnchor.constraint(equalTo: visualEffect.leadingAnchor),
            hosting.view.trailingAnchor.constraint(equalTo: visualEffect.trailingAnchor),
        ])

        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 428, height: 340),
            styleMask: [.titled, .closable, .miniaturizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        win.title = "GravityBar"
        win.titleVisibility = .hidden
        win.titlebarAppearsTransparent = true
        win.isMovableByWindowBackground = true
        win.isOpaque = false
        win.backgroundColor = .clear
        win.isReleasedWhenClosed = false
        win.contentView = visualEffect
        win.center()
        win.makeKeyAndOrderFront(nil)
        activateApp()
        self.mainWindow = win
    }

    @objc func togglePopover(_ sender: AnyObject?) {
        guard let pop = popover else { return }
        if pop.isShown {
            closePopover()
        } else {
            openPopover()
        }
    }

    private func openPopover() {
        guard let pop = popover, let button = statusItem?.button else { return }
        activateApp()
        if !pop.isShown {
            pop.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
        pop.contentViewController?.view.window?.makeKey()
        Task {
            await store.loadInitial()
        }
    }

    private func closePopover() {
        popover?.performClose(nil)
        store.isKeyboardNavigating = false
    }

    private func activateApp() {
        if #available(macOS 14.0, *) {
            NSApp.activate()
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    // MARK: - Keyboard Navigation & Global Hotkey (⌥⌘A)

    private func installKeyboardMonitor() {
        removeKeyboardMonitor()
        keyMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            guard let self = self else { return event }
            if let editor = (event.window?.firstResponder ?? NSApp.keyWindow?.firstResponder) as? NSTextView,
               editor.isFieldEditor,
               let shortcut = FieldEditorShortcut.resolve(
                   charactersIgnoringModifiers: event.charactersIgnoringModifiers,
                   keyCode: event.keyCode,
                   modifierFlags: event.modifierFlags
               ),
               shortcut.apply(to: editor) {
                return nil
            }
            if self.popover?.isShown == true, self.handleKeyDown(event) {
                return nil
            }
            return event
        }
    }

    private func removeKeyboardMonitor() {
        if let monitor = keyMonitor {
            NSEvent.removeMonitor(monitor)
            keyMonitor = nil
        }
    }

    private func handleKeyDown(_ event: NSEvent) -> Bool {
        // Do not hijack typing inside TextFields
        if let firstResp = NSApp.keyWindow?.firstResponder, firstResp is NSTextView {
            if event.keyCode == 53 { // Escape exits subviews or closes
                if store.screen != .accounts {
                    store.stopWizardPolling()
                    store.screen = .accounts
                    return true
                }
                closePopover()
                return true
            }
            return false
        }

        if event.keyCode == 53 { // Esc
            if store.screen != .accounts {
                store.stopWizardPolling()
                store.screen = .accounts
            } else {
                closePopover()
            }
            return true
        }

        guard store.screen == .accounts else { return false }
        let sorted = store.sortedAccounts
        guard !sorted.isEmpty else { return false }

        switch event.keyCode {
        case 126: // Up arrow
            store.isKeyboardNavigating = true
            store.selectedIndex = (store.selectedIndex - 1 + sorted.count) % sorted.count
            return true
        case 125: // Down arrow
            store.isKeyboardNavigating = true
            store.selectedIndex = (store.selectedIndex + 1) % sorted.count
            return true
        case 36, 76: // Return / Enter
            if store.isKeyboardNavigating && store.selectedIndex < sorted.count {
                let targetKey = sorted[store.selectedIndex].key
                Task { await store.switchTo(targetKey) }
                return true
            }
            return false
        default:
            if let chars = event.charactersIgnoringModifiers,
               chars.count == 1,
               let digit = Int(chars),
               digit >= 1 && digit <= 9 && digit <= sorted.count {
                let targetKey = sorted[digit - 1].key
                Task { await store.switchTo(targetKey) }
                return true
            }
            return false
        }
    }

    private func registerGlobalHotkey() {
        unregisterGlobalHotkey()
        var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        let selfPtr = Unmanaged.passUnretained(self).toOpaque()
        let handler: EventHandlerUPP = { _, _, userData -> OSStatus in
            guard let ptr = userData else { return noErr }
            let appDel = Unmanaged<AppDelegate>.fromOpaque(ptr).takeUnretainedValue()
            DispatchQueue.main.async {
                appDel.togglePopover(nil)
            }
            return noErr
        }
        InstallEventHandler(GetApplicationEventTarget(), handler, 1, &spec, selfPtr, &hotKeyHandlerRef)
        let hotKeyID = EventHotKeyID(signature: OSType(0x41475357), id: 1) // 'AGSW'
        RegisterEventHotKey(UInt32(kVK_ANSI_A), UInt32(cmdKey | optionKey), hotKeyID, GetApplicationEventTarget(), 0, &hotKeyRef)
    }

    private func unregisterGlobalHotkey() {
        if let hk = hotKeyRef {
            UnregisterEventHotKey(hk)
            hotKeyRef = nil
        }
        if let handler = hotKeyHandlerRef {
            RemoveEventHandler(handler)
            hotKeyHandlerRef = nil
        }
    }

    private func updateStatusButton(payload: StatusPayload?) {
        guard let button = statusItem?.button else { return }
        let mode = store.menuBarDisplayMode

        guard let payload = payload else {
            button.title = ""
            if mode == .dualBars {
                button.image = MenuBarGaugeRenderer.renderImage(geminiPct: nil, claudePct: nil)
            } else if let img = NSImage(systemSymbolName: "arrow.triangle.2.circlepath", accessibilityDescription: "GravityBar") {
                img.isTemplate = true
                button.image = img
            }
            return
        }

        if let active = payload.accounts.first(where: { $0.isActive }) {
            let gem = QuotaHelpers.findPool(active.usage, kind: "gemini")?.remainingPct
            let cla = QuotaHelpers.findPool(active.usage, kind: "claude")?.remainingPct

            switch mode {
            case .dualBars:
                button.image = MenuBarGaugeRenderer.renderImage(geminiPct: gem, claudePct: cla)
                button.title = ""
            case .percentage:
                if let img = NSImage(systemSymbolName: "arrow.triangle.2.circlepath", accessibilityDescription: "GravityBar") {
                    img.isTemplate = true
                    button.image = img
                }
                if let g = gem {
                    button.title = " \(Int(g.rounded()))%"
                    button.font = NSFont.monospacedDigitSystemFont(ofSize: 12, weight: .medium)
                } else {
                    button.title = ""
                }
            case .iconOnly:
                if let img = NSImage(systemSymbolName: "arrow.triangle.2.circlepath", accessibilityDescription: "GravityBar") {
                    img.isTemplate = true
                    button.image = img
                }
                button.title = ""
            }
            let argon = QuotaHelpers.argonPool(active.usage)?.remainingPct
            var tipParts = ["GravityBar", active.email]
            if let g = gem { tipParts.append("Gem \(Int(g.rounded()))%") }
            if let c = cla { tipParts.append("Cla \(Int(c.rounded()))%") }
            if let a = argon { tipParts.append("Argon \(Int(a.rounded()))%") }
            button.toolTip = "\(tipParts.joined(separator: " · ")) (⌥⌘A)"
        } else {
            if mode == .dualBars {
                button.image = MenuBarGaugeRenderer.renderImage(geminiPct: nil, claudePct: nil)
            } else if let img = NSImage(systemSymbolName: "arrow.triangle.2.circlepath", accessibilityDescription: "GravityBar") {
                img.isTemplate = true
                button.image = img
            }
            button.title = ""
            button.toolTip = payload.hasActiveSession
                ? "GravityBar · Active Session (Unsaved)"
                : "GravityBar · Not Signed In"
        }
    }
}

// MARK: - Entry Point

if CommandLine.arguments.contains("--self-test") {
    let result = NativeSelfTest.runAll()
    guard result == 0 else { exit(result) }
    Task.detached { exit(await NativeSelfTest.runQuotaProcessTests()) }
    dispatchMain()
}

if let idx = CommandLine.arguments.firstIndex(of: "--generate-iconset"),
   idx + 1 < CommandLine.arguments.count {
    let outDir = CommandLine.arguments[idx + 1]
    exit(AppIconRenderer.writeIconset(to: outDir) ? 0 : 1)
}

@MainActor
private var retainedAppDelegate: AppDelegate?

MainActor.assumeIsolated {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    retainedAppDelegate = delegate
    app.delegate = delegate
    app.run()
}
