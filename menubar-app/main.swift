import Carbon
import Cocoa
import Foundation
import SwiftUI
@preconcurrency import UserNotifications

// MARK: - Store (100% Native Keychain + Network Engine)

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
    @AppStorage("autoRefreshMinutes") var autoRefreshMinutes: Int = 5 {
        didSet { onAutoRefreshChanged?(autoRefreshMinutes) }
    }
    @AppStorage("enableGlobalHotkey") var enableGlobalHotkey: Bool = true {
        didSet { onHotkeySettingChanged?(enableGlobalHotkey) }
    }
    @AppStorage("lowQuotaAlertsEnabled") var lowQuotaAlertsEnabled: Bool = true
    @AppStorage("confirmBeforeSwitch") var confirmBeforeSwitch: Bool = false
    @AppStorage("playSounds") var playSounds: Bool = true
    @AppStorage("autoWarmup5hEnabled") var autoWarmup5hEnabled: Bool = true
    @Published var isWarmingUp: Bool = false
    @Published var lastWarmupStatus: String = ""
    @Published var launchAtLogin: Bool = false

    let manifestStore = NativeManifestStore()
    let warmupStore: WarmupStateStore
    var onStatusUpdated: ((StatusPayload?) -> Void)?
    var onAutoRefreshChanged: ((Int) -> Void)?
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
        warmupStore = WarmupStateStore(manifestStore: manifestStore)
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

    func loadInitial(forceRefresh: Bool = false) async {
        guard !isRefreshing else { return }
        if accounts.isEmpty { isLoading = true }
        await fetchStatus(forceRefresh: false, cachedOnly: true)
        await fetchStatus(forceRefresh: forceRefresh, cachedOnly: false)
    }

    func refresh(force: Bool = true) async {
        await fetchStatus(forceRefresh: force, cachedOnly: false)
    }

    private func fetchStatus(forceRefresh: Bool, cachedOnly: Bool, includeActiveSession: Bool = true) async {
        statusRequestID += 1
        let requestID = statusRequestID
        if !cachedOnly {
            refreshRequestID = requestID
            isRefreshing = true
        }
        let store = manifestStore
        let payload = await Task.detached(priority: .userInitiated) {
            await NativeQuotaFetcher.loadStatusPayload(
                store: store, forceRefresh: forceRefresh, cachedOnly: cachedOnly,
                includeActiveSession: includeActiveSession
            )
        }.value

        if refreshRequestID == requestID {
            refreshRequestID = nil
            isRefreshing = false
            isLoading = false
        }
        guard requestID > appliedStatusRequestID else { return }
        appliedStatusRequestID = requestID
        applyPayload(payload, fromCacheOnly: cachedOnly)
    }

    private func applyPayload(_ payload: StatusPayload, fromCacheOnly: Bool) {
        lastPayload = payload
        accounts = payload.accounts
        activeKey = payload.activeKey
        hasActiveSession = payload.hasActiveSession
        activeSessionUnsaved = payload.activeSessionUnsaved
        activeEmail = payload.activeEmail
        bestSwitchCandidate = payload.bestSwitchCandidate
        if !fromCacheOnly {
            lastUpdated = Date()
        }
        if !accounts.isEmpty {
            isLoading = false
        }
        if selectedIndex >= sortedAccounts.count {
            selectedIndex = max(0, sortedAccounts.count - 1)
        }
        onStatusUpdated?(payload)
        if !fromCacheOnly {
            evaluateLowQuotaNotification(payload)
            if autoWarmup5hEnabled { warmupStore.syncTrackedResets(accounts: payload.accounts) }
        }
    }

    func checkScheduledWarmupTick() async {
        guard autoWarmup5hEnabled, !isWarmingUp, let payload = lastPayload else { return }
        let states = warmupStore.loadAll()
        let targets = payload.accounts.filter { acc in
            WarmupStateStore.shouldCheckQuota(
                gemini5hPool: QuotaHelpers.gemini5hPool(acc.usage, requireReportedWindow: true),
                state: states[acc.key]
            )
        }.map(\.key)
        guard !targets.isEmpty else { return }
        await runWarmup(forKeys: targets, isManual: false)
    }

    func triggerManualWarmup() async {
        let targets = accounts.map(\.key)
        await runWarmup(forKeys: targets, isManual: true)
    }

    private func runWarmup(forKeys targetKeys: [String], isManual: Bool) async {
        guard !isWarmingUp, !targetKeys.isEmpty else { return }
        isWarmingUp = true
        defer { isWarmingUp = false }
        let mStore = manifestStore
        let wStore = warmupStore
        wStore.recordWarmupAttempts(keys: targetKeys)

        let eligibleKeys: [String]
        if isManual {
            eligibleKeys = targetKeys
        } else {
            let fresh = await Task.detached(priority: .utility) {
                await NativeQuotaFetcher.loadStatusPayload(
                    store: mStore, forceRefresh: true, cachedOnly: false, includeActiveSession: false
                )
            }.value
            guard autoWarmup5hEnabled else { return }
            wStore.syncTrackedResets(accounts: fresh.accounts)
            eligibleKeys = fresh.accounts.filter { acc in
                guard targetKeys.contains(acc.key) else { return false }
                let pool = QuotaHelpers.gemini5hPool(acc.usage, requireReportedWindow: true)
                let weekly = QuotaHelpers.geminiWeeklyPool(acc.usage)
                return WarmupStateStore.quotaIsIdle(pool) && (weekly?.remainingPct ?? 100) > 0
            }.map(\.key)
            guard !eligibleKeys.isEmpty else { return }
        }
        let results = await Task.detached(priority: .userInitiated) { () -> [(key: String, ok: Bool, model: String, err: String?)] in
            let manifest = mStore.loadManifest(migrate: false)
            return await withTaskGroup(of: (key: String, ok: Bool, model: String, err: String?).self) { group in
                for k in eligibleKeys {
                    guard let entry = manifest[k], let tok = mStore.getAccountToken(entry) else { continue }
                    group.addTask {
                        let res = await NativeQuotaFetcher.sendGeminiWarmupPing(tokenStr: tok) { newTok in
                            mStore.persistRefreshedToken(accountKey: k, newToken: newTok, replacingSavedToken: tok)
                        }
                        if res.ok {
                            wStore.recordWarmupPing(key: k, modelDisplay: res.modelDisplay)
                        }
                        return (key: k, ok: res.ok, model: res.modelDisplay, err: res.error)
                    }
                }
                var out: [(key: String, ok: Bool, model: String, err: String?)] = []
                for await r in group {
                    out.append(r)
                }
                return out
            }
        }.value

        let succeeded = results.filter { $0.ok }
        if let firstOk = succeeded.first {
            let fmt = DateFormatter()
            fmt.dateFormat = "HH:mm"
            lastWarmupStatus = "Last ping \(fmt.string(from: Date())) · \(firstOk.model) (\(succeeded.count)/\(eligibleKeys.count))"
            if isManual {
                playSystemSound("Glass")
                showToast("⚡️ Gemini ping sent (\(firstOk.model))")
            }
            await fetchStatus(forceRefresh: true, cachedOnly: false, includeActiveSession: false)
        } else {
            let errMsg = results.compactMap { $0.err }.first ?? "Could not send 5h warmup ping."
            lastWarmupStatus = "Ping failed: \(errMsg)"
            if isManual { errorMessage = errMsg }
        }
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
            await fetchStatus(forceRefresh: false, cachedOnly: true)
            await fetchStatus(forceRefresh: false, cachedOnly: false)
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
        let email = await NativeQuotaFetcher.extractEmailFromToken(token)
            ?? label?.trimmingCharacters(in: .whitespacesAndNewlines)
            ?? "antigravity-account"

        let result = await Task.detached(priority: .userInitiated) {
            store.saveAccount(token: token, email: email, customLabel: label)
        }.value

        if result.0 {
            playSystemSound("Glass")
            showToast("Account saved to Keychain")
            await fetchStatus(forceRefresh: false, cachedOnly: false)
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
            await fetchStatus(forceRefresh: false, cachedOnly: true)
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
            await fetchStatus(forceRefresh: false, cachedOnly: true)
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
            await fetchStatus(forceRefresh: false, cachedOnly: true)
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
            await fetchStatus(forceRefresh: false, cachedOnly: true)
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
        await fetchStatus(forceRefresh: false, cachedOnly: false)
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
                await self.fetchStatus(forceRefresh: false, cachedOnly: true)
                if Task.isCancelled { break }
                if self.activeSessionUnsaved {
                    await self.fetchStatus(forceRefresh: false, cachedOnly: false)
                    if Task.isCancelled { break }
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
                await fetchStatus(forceRefresh: true, cachedOnly: false)
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

// MARK: - Unified AppDelegate (Single-Instance Menu Bar Popover + Optional Window Mode)

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private static let activateNotification = Notification.Name("com.m4tinbeigi.gravitybar.activate")

    private let store = SwitcherStore()
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var mainWindow: NSWindow?
    private var refreshTimer: Timer?
    private var warmupCheckTimer: Timer?
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
        store.onAutoRefreshChanged = { [weak self] mins in
            self?.scheduleAutoRefresh(minutes: mins)
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

        if store.enableGlobalHotkey {
            registerGlobalHotkey()
        }
        scheduleAutoRefresh(minutes: store.autoRefreshMinutes)
        scheduleWarmupCheck()
        Task {
            await store.loadInitial(forceRefresh: store.autoWarmup5hEnabled)
            await store.checkScheduledWarmupTick()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        refreshTimer?.invalidate()
        warmupCheckTimer?.invalidate()
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
        installKeyboardMonitor()
        Task {
            await store.loadInitial()
        }
    }

    private func closePopover() {
        popover?.performClose(nil)
        store.isKeyboardNavigating = false
        removeKeyboardMonitor()
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
            if let pop = self.popover, !pop.isShown {
                self.removeKeyboardMonitor()
                return event
            }
            if self.handleKeyDown(event) {
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

    private func scheduleAutoRefresh(minutes: Int) {
        refreshTimer?.invalidate()
        refreshTimer = nil
        guard minutes > 0 else { return }
        let interval = TimeInterval(minutes * 60)
        refreshTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.store.refresh(force: false)
            }
        }
    }

    private func scheduleWarmupCheck() {
        warmupCheckTimer?.invalidate()
        warmupCheckTimer = Timer.scheduledTimer(withTimeInterval: 60.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.store.checkScheduledWarmupTick()
            }
        }
    }
}

// MARK: - Entry Point

if CommandLine.arguments.contains("--self-test") {
    exit(NativeSelfTest.runAll())
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
