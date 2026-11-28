import Cocoa
import CryptoKit
import Darwin
import Foundation
import Security

// MARK: - Models & Enums

enum AccountSortMode: String, CaseIterable, Sendable {
    case bestQuota = "best"
    case activeFirst = "active"
    case alphabetical = "alpha"

    var title: String {
        switch self {
        case .bestQuota: return "Best"
        case .activeFirst: return "Active"
        case .alphabetical: return "A–Z"
        }
    }
}

enum MenuBarDisplayMode: String, CaseIterable, Sendable {
    case dualBars = "dual"
    case percentage = "pct"
    case iconOnly = "icon"

    var title: String {
        switch self {
        case .dualBars: return "Dual Bars"
        case .percentage: return "Percent"
        case .iconOnly: return "Icon Only"
        }
    }
}

enum ActiveScreen: Equatable {
    case accounts
    case manage
    case addWizard
    case settings
}

struct StatusPayload: Codable, Sendable {
    let activeKey: String?
    let hasActiveSession: Bool
    let activeSessionUnsaved: Bool
    let activeEmail: String?
    let bestSwitchCandidate: String?
    let accounts: [AccountItem]
    let fetchedAt: Int
    let fromCache: Bool

    enum CodingKeys: String, CodingKey {
        case activeKey = "active_key"
        case hasActiveSession = "has_active_session"
        case activeSessionUnsaved = "active_session_unsaved"
        case activeEmail = "active_email"
        case bestSwitchCandidate = "best_switch_candidate"
        case accounts
        case fetchedAt = "fetched_at"
        case fromCache = "from_cache"
    }
}

struct AccountItem: Codable, Identifiable, Sendable {
    let key: String
    let label: String
    let email: String
    let savedAt: String
    let storage: String
    let isActive: Bool
    let pinned: Bool
    let planLabel: String
    let usage: UsageInfo?

    var id: String { key }

    enum CodingKeys: String, CodingKey {
        case key, label, email, storage, usage, pinned
        case savedAt = "saved_at"
        case isActive = "is_active"
        case planLabel = "plan_label"
    }

    init(
        key: String,
        label: String,
        email: String,
        savedAt: String,
        storage: String,
        isActive: Bool,
        pinned: Bool = false,
        planLabel: String = "",
        usage: UsageInfo? = nil
    ) {
        self.key = key
        self.label = label
        self.email = email
        self.savedAt = savedAt
        self.storage = storage
        self.isActive = isActive
        self.pinned = pinned
        self.planLabel = planLabel
        self.usage = usage
    }
}

struct UsageInfo: Codable, Sendable {
    let email: String?
    let tier: String?
    let daily: QuotaPool?
    let weekly: QuotaPool?
    let pools: [QuotaPool]?
    var checkedAt: Int? = nil

    enum CodingKeys: String, CodingKey {
        case email, tier, daily, weekly, pools
        case checkedAt = "checked_at"
    }
}

struct QuotaPool: Codable, Identifiable, Sendable {
    let name: String
    let groupName: String?
    let windowLabel: String?
    let usedPct: Double
    let remainingPct: Double
    let resetsIn: String?
    let resetTime: String?
    let resetShort: String?
    let resetSecs: Int?
    let resetIso: String?
    let models: [String]?
    let reportedWindow: Bool?

    var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, models
        case groupName = "group_name"
        case windowLabel = "window_label"
        case usedPct = "used_pct"
        case remainingPct = "remaining_pct"
        case resetsIn = "resets_in"
        case resetTime = "reset_time"
        case resetShort = "reset_short"
        case resetSecs = "reset_secs"
        case resetIso = "reset_iso"
        case reportedWindow = "reported_window"
    }

    init(
        name: String,
        groupName: String? = nil,
        windowLabel: String? = nil,
        usedPct: Double,
        remainingPct: Double,
        resetsIn: String?,
        resetTime: String?,
        resetShort: String?,
        resetSecs: Int?,
        resetIso: String?,
        models: [String]?,
        reportedWindow: Bool? = nil
    ) {
        self.name = name
        self.groupName = groupName
        self.windowLabel = windowLabel
        self.usedPct = usedPct
        self.remainingPct = remainingPct
        self.resetsIn = resetsIn
        self.resetTime = resetTime
        self.resetShort = resetShort
        self.resetSecs = resetSecs
        self.resetIso = resetIso
        self.models = models
        self.reportedWindow = reportedWindow
    }
}

struct ManifestEntry: Codable, Sendable {
    var label: String?
    var email: String?
    var secretID: String?
    var storage: String?
    var tokenSHA256: String?
    var savedAt: String?
    var tokenFile: String?
    var pinned: Bool?
    var planLabel: String?

    enum CodingKeys: String, CodingKey {
        case label, email, storage, pinned
        case secretID = "secret_id"
        case tokenSHA256 = "token_sha256"
        case savedAt = "saved_at"
        case tokenFile = "token_file"
        case planLabel = "plan_label"
    }
}

// MARK: - Native Keychain

enum NativeKeychain {
    static let activeService = "gemini"
    static let activeAccount = "antigravity"
    static let savedService = "gravitybar"
    static let legacySavedService = "antigravity-account-switcher"

    private static func isSafeSecurityArg(_ s: String) -> Bool {
        guard !s.isEmpty else { return false }
        for scalar in s.unicodeScalars {
            let v = scalar.value
            let ok = (v >= 48 && v <= 57)   // 0-9
                || (v >= 65 && v <= 90)     // A-Z
                || (v >= 97 && v <= 122)    // a-z
                || v == 46 || v == 95 || v == 58 || v == 64 || v == 43 || v == 47 || v == 61 || v == 45
            if !ok { return false }
        }
        return true
    }

    private static func runSecurity(args: [String], stdinText: String? = nil) -> (code: Int32, stdout: String, stderr: String) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        task.arguments = args

        let outPipe = Pipe()
        let errPipe = Pipe()
        task.standardOutput = outPipe
        task.standardError = errPipe

        if let inp = stdinText {
            let inPipe = Pipe()
            task.standardInput = inPipe
            do {
                try task.run()
                if let data = inp.data(using: .utf8) {
                    inPipe.fileHandleForWriting.write(data)
                }
                inPipe.fileHandleForWriting.closeFile()
            } catch {
                return (-1, "", error.localizedDescription)
            }
        } else {
            do {
                try task.run()
            } catch {
                return (-1, "", error.localizedDescription)
            }
        }

        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        let outStr = String(data: outData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let errStr = String(data: errData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return (task.terminationStatus, outStr, errStr)
    }

    static func get(service: String, account: String, keychainPath: String? = nil) -> String? {
        var args = ["find-generic-password", "-s", service, "-a", account, "-w"]
        if let kc = keychainPath { args.append(kc) }
        let res = runSecurity(args: args)
        return (res.code == 0 && !res.stdout.isEmpty) ? res.stdout : nil
    }

    static func set(service: String, account: String, secret: String, keychainPath: String? = nil) -> (Bool, String) {
        if isSafeSecurityArg(service) && isSafeSecurityArg(account) && isSafeSecurityArg(secret) {
            let cmdLine: String
            if let kc = keychainPath {
                let escapedKC = kc.replacingOccurrences(of: "\"", with: "\\\"")
                cmdLine = "add-generic-password -U -s \(service) -a \(account) -w \(secret) \"\(escapedKC)\"\n"
            } else {
                cmdLine = "add-generic-password -U -s \(service) -a \(account) -w \(secret)\n"
            }
            if cmdLine.utf8.count < 3800 {
                let res = runSecurity(args: ["-i"], stdinText: cmdLine)
                if res.code == 0 && !res.stderr.contains("returned -") && !res.stderr.contains("unknown command") {
                    return (true, "")
                }
                if keychainPath != nil {
                    return (false, res.stderr.isEmpty ? "security -i failed (\(res.code))" : res.stderr)
                }
            }
        }
        if keychainPath != nil {
            return (false, "Unsupported characters or length for isolated keychain path")
        }
        return setViaSecItem(service: service, account: account, secret: secret)
    }

    private static func setViaSecItem(service: String, account: String, secret: String) -> (Bool, String) {
        guard let secretData = secret.data(using: .utf8) else {
            return (false, "Invalid UTF-8 secret")
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let attrs: [String: Any] = [
            kSecValueData as String: secretData
        ]
        var status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = secretData
            status = SecItemAdd(addQuery as CFDictionary, nil)
        }
        if status == errSecSuccess {
            return (true, "")
        }
        return (false, "Security.framework OSStatus \(status)")
    }

    @discardableResult
    static func delete(service: String, account: String, keychainPath: String? = nil) -> Bool {
        var args = ["delete-generic-password", "-s", service, "-a", account]
        if let kc = keychainPath { args.append(kc) }
        return runSecurity(args: args).code == 0
    }

    static func getActiveToken(keychainPath: String? = nil) -> String? {
        guard let tok = get(service: activeService, account: activeAccount, keychainPath: keychainPath),
              tok.hasPrefix("go-keyring-base64:") else {
            return nil
        }
        return tok
    }

    private static let activeLock = NSLock()

    static func setActiveToken(_ token: String, keychainPath: String? = nil) -> (Bool, String) {
        activeLock.lock()
        defer { activeLock.unlock() }
        return set(service: activeService, account: activeAccount, secret: token, keychainPath: keychainPath)
    }

    static func clearActiveTokenForSignIn(keychainPath: String? = nil) -> (previous: String?, cleared: Bool) {
        activeLock.lock()
        defer { activeLock.unlock() }
        guard let previous = getActiveToken(keychainPath: keychainPath) else { return (nil, true) }
        return (previous, delete(service: activeService, account: activeAccount, keychainPath: keychainPath))
    }

    @discardableResult
    static func restoreActiveTokenIfMissing(_ token: String, keychainPath: String? = nil) -> Bool {
        activeLock.lock()
        defer { activeLock.unlock() }
        if getActiveToken(keychainPath: keychainPath) != nil { return true }
        return set(service: activeService, account: activeAccount, secret: token, keychainPath: keychainPath).0
    }

    static func getSavedToken(account: String, keychainPath: String? = nil) -> String? {
        get(service: savedService, account: account, keychainPath: keychainPath)
            ?? get(service: legacySavedService, account: account, keychainPath: keychainPath)
    }
}

// MARK: - Native Manifest & Secure Storage

final class NativeManifestStore: @unchecked Sendable {
    let accountsDir: URL
    let manifestURL: URL
    let cacheURL: URL
    let keychainPath: String?
    private let lock = NSLock()

    init(accountsDir: URL? = nil, keychainPath: String? = nil) {
        let dir = accountsDir ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".gemini/accounts")
        self.accountsDir = dir
        self.manifestURL = dir.appendingPathComponent("manifest.json")
        self.cacheURL = dir.appendingPathComponent("usage_cache.json")
        self.keychainPath = keychainPath
    }

    func ensureSecureAccountsDir() {
        let fm = FileManager.default
        if !fm.fileExists(atPath: accountsDir.path) {
            try? fm.createDirectory(at: accountsDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: accountsDir.path)
    }

    func writeSecureFile(url: URL, data: Data) throws {
        ensureSecureAccountsDir()
        let parent = url.deletingLastPathComponent()
        let tmp = parent.appendingPathComponent(".tmp_\(UUID().uuidString)")
        let fm = FileManager.default
        guard fm.createFile(atPath: tmp.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw NSError(domain: "GravityBar", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to create temp file"])
        }
        do {
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
            try data.write(to: tmp, options: .atomic)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
            _ = try fm.replaceItemAt(url, withItemAt: tmp)
        } catch {
            try? fm.removeItem(at: tmp)
            throw error
        }
    }

    static func sha256Hex(_ input: String) -> String {
        let data = Data(input.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    static func validateSecretID(_ sid: String?) -> Bool {
        guard let sid = sid else { return false }
        guard sid.hasPrefix("acct_") else { return false }
        let hexPart = sid.dropFirst(5)
        guard hexPart.count >= 16 && hexPart.count <= 64 else { return false }
        return hexPart.unicodeScalars.allSatisfy {
            ($0.value >= 48 && $0.value <= 57) || ($0.value >= 97 && $0.value <= 102)
        }
    }

    static func makeSecretID(for key: String, existing: Set<String>) -> String {
        let base = "acct_" + String(sha256Hex(key).prefix(16))
        if !existing.contains(base) { return base }
        var counter = 1
        while true {
            let cand = "acct_" + String(sha256Hex("\(key):\(counter)").prefix(16))
            if !existing.contains(cand) { return cand }
            counter += 1
        }
    }

    func resolveSafeAccountPath(_ pathStr: String?) -> String? {
        guard let pathStr = pathStr, !pathStr.isEmpty else { return nil }
        let fm = FileManager.default
        if let attrs = try? fm.attributesOfItem(atPath: pathStr),
           let type = attrs[.type] as? FileAttributeType,
           type == .typeSymbolicLink {
            return nil
        }
        let baseResolved = accountsDir.resolvingSymlinksInPath().path
        let targetResolved = URL(fileURLWithPath: pathStr).resolvingSymlinksInPath().path
        let prefix = baseResolved.hasSuffix("/") ? baseResolved : baseResolved + "/"
        guard targetResolved.hasPrefix(prefix), targetResolved != baseResolved else {
            return nil
        }
        var isDir: ObjCBool = false
        if fm.fileExists(atPath: targetResolved, isDirectory: &isDir), isDir.boolValue {
            return nil
        }
        return targetResolved
    }

    private func shredAndRemoveFile(_ path: String) {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              (attrs[.type] as? FileAttributeType) != .typeSymbolicLink else {
            return
        }
        if let size = (attrs[.size] as? NSNumber)?.intValue, size > 0 {
            let zeros = Data(repeating: 0, count: size)
            try? zeros.write(to: URL(fileURLWithPath: path))
        }
        try? fm.removeItem(atPath: path)
    }

    func loadManifest(migrate: Bool = true) -> [String: ManifestEntry] {
        lock.lock()
        defer { lock.unlock() }
        guard migrate, let storeLock = acquireManifestLock() else {
            return _loadManifestUnlocked(migrate: false)
        }
        defer { try? storeLock.close() }
        return _loadManifestUnlocked(migrate: true)
    }

    private func acquireManifestLock() -> FileHandle? {
        ensureSecureAccountsDir()
        let path = accountsDir.appendingPathComponent("manifest.lock").path
        let descriptor = Darwin.open(path, O_RDWR | O_CREAT | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { return nil }
        guard flock(descriptor, LOCK_EX) == 0 else {
            Darwin.close(descriptor)
            return nil
        }
        return FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }

    private func _loadManifestUnlocked(migrate: Bool) -> [String: ManifestEntry] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: manifestURL.path) else { return [:] }
        if migrate {
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifestURL.path)
        }
        guard let data = try? Data(contentsOf: manifestURL),
              var manifest = try? JSONDecoder().decode([String: ManifestEntry].self, from: data) else {
            return [:]
        }
        if migrate && !manifest.isEmpty {
            _migrateLegacyUnlocked(&manifest)
        }
        return manifest
    }

    private func _saveManifestUnlocked(_ manifest: [String: ManifestEntry]) throws {
        if FileManager.default.fileExists(atPath: manifestURL.path) {
            let existing = try Data(contentsOf: manifestURL)
            _ = try JSONDecoder().decode([String: ManifestEntry].self, from: existing)
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(manifest)
        try writeSecureFile(url: manifestURL, data: data)
    }

    private func _migrateLegacyUnlocked(_ manifest: inout [String: ManifestEntry]) {
        var usedIDs = Set(manifest.values.compactMap { Self.validateSecretID($0.secretID) ? $0.secretID : nil })
        var changed = false
        var filesToRemove: [String] = []

        for key in Array(manifest.keys) {
            guard var entry = manifest[key] else { continue }
            let sid = entry.secretID
            let hasValidSid = Self.validateSecretID(sid)

            if hasValidSid && entry.tokenSHA256 != nil && entry.tokenFile == nil {
                continue
            }
            if hasValidSid && entry.tokenFile == nil && entry.tokenSHA256 == nil {
                if let s = sid, let tok = NativeKeychain.getSavedToken(account: s, keychainPath: keychainPath) {
                    entry.tokenSHA256 = Self.sha256Hex(tok)
                    manifest[key] = entry
                    changed = true
                }
                continue
            }
            if let tf = entry.tokenFile {
                guard let safeTF = resolveSafeAccountPath(tf) else { continue }
                let fm = FileManager.default
                if fm.fileExists(atPath: safeTF) {
                    try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: safeTF)
                    guard let tok = try? String(contentsOfFile: safeTF, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
                          !tok.isEmpty else {
                        if hasValidSid {
                            entry.tokenFile = nil
                            manifest[key] = entry
                            filesToRemove.append(safeTF)
                            changed = true
                        }
                        continue
                    }
                    let targetSid = (hasValidSid ? sid : nil) ?? Self.makeSecretID(for: key, existing: usedIDs)
                    usedIDs.insert(targetSid)
                    let (ok, _) = NativeKeychain.set(service: NativeKeychain.savedService, account: targetSid, secret: tok, keychainPath: keychainPath)
                    let rb = ok ? NativeKeychain.get(service: NativeKeychain.savedService, account: targetSid, keychainPath: keychainPath) : nil
                    if ok && rb?.trimmingCharacters(in: .whitespacesAndNewlines) == tok {
                        entry.secretID = targetSid
                        entry.storage = "keychain"
                        entry.tokenSHA256 = Self.sha256Hex(tok)
                        entry.tokenFile = nil
                        manifest[key] = entry
                        filesToRemove.append(safeTF)
                        changed = true
                    }
                } else if hasValidSid {
                    entry.tokenFile = nil
                    manifest[key] = entry
                    changed = true
                }
            }
        }

        if changed {
            try? _saveManifestUnlocked(manifest)
            for path in filesToRemove {
                shredAndRemoveFile(path)
            }
        }
    }

    func getAccountToken(_ entry: ManifestEntry) -> String? {
        if let sid = entry.secretID, Self.validateSecretID(sid),
           let tok = NativeKeychain.getSavedToken(account: sid, keychainPath: keychainPath) {
            return tok
        }
        if let safeTF = resolveSafeAccountPath(entry.tokenFile),
           let tok = try? String(contentsOfFile: safeTF, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
           !tok.isEmpty {
            return tok
        }
        return nil
    }

    static func extractTokenIdentity(_ tokenStr: String) -> (email: String?, refreshToken: String?) {
        let clean = tokenStr.trimmingCharacters(in: .whitespacesAndNewlines)
        guard clean.hasPrefix("go-keyring-base64:") else { return (nil, nil) }
        let b64 = String(clean.dropFirst("go-keyring-base64:".count))
        guard let decoded = Data(base64Encoded: b64),
              let root = try? JSONSerialization.jsonObject(with: decoded) as? [String: Any] else {
            return (nil, nil)
        }
        let tObj = root["token"] as? [String: Any]
        let rawEmail = (root["id_token_email"] as? String)
            ?? (root["email"] as? String)
            ?? (tObj?["email"] as? String)
        let email = rawEmail?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let cleanEmail = (email?.isEmpty == false) ? email : nil
        let rf = (tObj?["refresh_token"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanRF = (rf?.isEmpty == false) ? rf : nil
        return (cleanEmail, cleanRF)
    }

    static func findAccountKeyByEmail(manifest: [String: ManifestEntry], email: String?) -> String? {
        guard let clean = email?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !clean.isEmpty else {
            return nil
        }
        for key in manifest.keys.sorted() {
            if let entryEmail = manifest[key]?.email?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
               entryEmail == clean {
                return key
            }
        }
        for key in manifest.keys.sorted() {
            if key.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == clean {
                return key
            }
        }
        return nil
    }

    func findActiveAccountKey(manifest: [String: ManifestEntry], currentToken: String?) -> String? {
        guard let curr = currentToken?.trimmingCharacters(in: .whitespacesAndNewlines), !curr.isEmpty else { return nil }
        let currHash = Self.sha256Hex(curr)
        for key in manifest.keys.sorted() {
            if let sha = manifest[key]?.tokenSHA256, sha.lowercased() == currHash {
                return key
            }
        }

        let currId = Self.extractTokenIdentity(curr)
        for key in manifest.keys.sorted() {
            guard let entry = manifest[key] else { continue }
            if entry.tokenSHA256 == nil {
                if let tok = getAccountToken(entry), tok.trimmingCharacters(in: .whitespacesAndNewlines) == curr {
                    return key
                }
            }
            if let currRF = currId.refreshToken, let tok = getAccountToken(entry) {
                let savedId = Self.extractTokenIdentity(tok)
                if savedId.refreshToken == currRF {
                    return key
                }
            }
        }

        return Self.findAccountKeyByEmail(manifest: manifest, email: currId.email)
    }

    func saveAccount(token: String, email: String, customLabel: String?) -> (Bool, String) {
        lock.lock()
        defer { lock.unlock() }
        guard let storeLock = acquireManifestLock() else { return (false, "Could not lock the saved account list.") }
        defer { try? storeLock.close() }

        let key = (customLabel?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false ? customLabel! : email)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !key.isEmpty else { return (false, "Account label cannot be empty.") }

        var manifest = _loadManifestUnlocked(migrate: true)
        let existing = manifest[key]
        let cleanToken = token.trimmingCharacters(in: .whitespacesAndNewlines)
        if let existing {
            let savedToken = getAccountToken(existing)
            let oldRefresh = savedToken.flatMap { Self.extractTokenIdentity($0).refreshToken }
            let newRefresh = Self.extractTokenIdentity(cleanToken).refreshToken
            let sameEmail = email.contains("@") && existing.email?.caseInsensitiveCompare(email) == .orderedSame
            guard savedToken == cleanToken || sameEmail || (oldRefresh != nil && oldRefresh == newRefresh) else {
                return (false, "Account label '\(key)' is already in use. Choose a different label.")
            }
        }
        let usedIDs = Set(manifest.filter { $0.key != key }.values.compactMap {
            Self.validateSecretID($0.secretID) ? $0.secretID : nil
        })
        let sid: String
        if let esid = existing?.secretID, Self.validateSecretID(esid), !usedIDs.contains(esid) {
            sid = esid
        } else {
            sid = Self.makeSecretID(for: key, existing: usedIDs)
        }

        let previousSecret = NativeKeychain.get(service: NativeKeychain.savedService, account: sid, keychainPath: keychainPath)
        func restoreSavedCredential() {
            if let previousSecret {
                _ = NativeKeychain.set(service: NativeKeychain.savedService, account: sid, secret: previousSecret, keychainPath: keychainPath)
            } else {
                NativeKeychain.delete(service: NativeKeychain.savedService, account: sid, keychainPath: keychainPath)
            }
        }
        let (ok, err) = NativeKeychain.set(service: NativeKeychain.savedService, account: sid, secret: cleanToken, keychainPath: keychainPath)
        let rb = ok ? NativeKeychain.get(service: NativeKeychain.savedService, account: sid, keychainPath: keychainPath) : nil
        guard ok && rb?.trimmingCharacters(in: .whitespacesAndNewlines) == cleanToken else {
            if ok { restoreSavedCredential() }
            return (false, err.isEmpty ? "Keychain verification failed." : err)
        }

        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd HH:mm:ss"

        let newEntry = ManifestEntry(
            label: key,
            email: email,
            secretID: sid,
            storage: "keychain",
            tokenSHA256: Self.sha256Hex(cleanToken),
            savedAt: df.string(from: Date()),
            tokenFile: nil,
            pinned: existing?.pinned,
            planLabel: existing?.planLabel
        )
        let oldTF = existing?.tokenFile
        manifest[key] = newEntry

        do {
            try _saveManifestUnlocked(manifest)
        } catch {
            restoreSavedCredential()
            return (false, error.localizedDescription)
        }

        if let safeOld = resolveSafeAccountPath(oldTF) {
            shredAndRemoveFile(safeOld)
        }
        return (true, "")
    }

    func removeAccount(key: String) -> (Bool, String) {
        lock.lock()
        defer { lock.unlock() }
        guard let storeLock = acquireManifestLock() else { return (false, "Could not lock the saved account list.") }
        defer { try? storeLock.close() }

        var manifest = _loadManifestUnlocked(migrate: true)
        guard let entry = manifest[key] else {
            return (false, "Account '\(key)' not found.")
        }
        manifest.removeValue(forKey: key)
        do {
            try _saveManifestUnlocked(manifest)
        } catch {
            return (false, error.localizedDescription)
        }
        if let sid = entry.secretID, Self.validateSecretID(sid),
           !manifest.values.contains(where: { $0.secretID == sid }) {
            for service in [NativeKeychain.savedService, NativeKeychain.legacySavedService] {
                NativeKeychain.delete(service: service, account: sid, keychainPath: keychainPath)
            }
        }
        if let safeTF = resolveSafeAccountPath(entry.tokenFile),
           !manifest.values.contains(where: { resolveSafeAccountPath($0.tokenFile) == safeTF }) {
            shredAndRemoveFile(safeTF)
        }
        _mutateCacheUnlocked { dict in
            dict.removeValue(forKey: key) != nil
        }
        return (true, "")
    }

    func renameAccount(oldKey: String, newKey: String) -> (Bool, String) {
        let cleanNew = newKey.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanNew.isEmpty else { return (false, "Label cannot be empty.") }

        lock.lock()
        defer { lock.unlock() }
        guard let storeLock = acquireManifestLock() else { return (false, "Could not lock the saved account list.") }
        defer { try? storeLock.close() }

        var manifest = _loadManifestUnlocked(migrate: true)
        guard var entry = manifest[oldKey] else {
            return (false, "Account '\(oldKey)' not found.")
        }
        if cleanNew == oldKey { return (true, "") }
        if manifest[cleanNew] != nil {
            return (false, "Account '\(cleanNew)' already exists.")
        }

        manifest.removeValue(forKey: oldKey)
        entry.label = cleanNew
        manifest[cleanNew] = entry
        do {
            try _saveManifestUnlocked(manifest)
        } catch {
            return (false, error.localizedDescription)
        }
        _mutateCacheUnlocked { dict in
            if let existing = dict.removeValue(forKey: oldKey) {
                dict[cleanNew] = existing
                return true
            }
            return false
        }
        return (true, "")
    }

    func setPinned(key: String, pinned: Bool) -> (Bool, String) {
        lock.lock()
        defer { lock.unlock() }
        guard let storeLock = acquireManifestLock() else { return (false, "Could not lock the saved account list.") }
        defer { try? storeLock.close() }

        var manifest = _loadManifestUnlocked(migrate: true)
        guard var entry = manifest[key] else {
            return (false, "Account '\(key)' not found.")
        }
        entry.pinned = pinned
        manifest[key] = entry
        do {
            try _saveManifestUnlocked(manifest)
            return (true, "")
        } catch {
            return (false, error.localizedDescription)
        }
    }

    func setPlanLabel(key: String, planLabel: String) -> (Bool, String) {
        let clean = planLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        lock.lock()
        defer { lock.unlock() }
        guard let storeLock = acquireManifestLock() else { return (false, "Could not lock the saved account list.") }
        defer { try? storeLock.close() }

        var manifest = _loadManifestUnlocked(migrate: true)
        guard var entry = manifest[key] else {
            return (false, "Account '\(key)' not found.")
        }
        entry.planLabel = clean.isEmpty ? nil : clean
        manifest[key] = entry
        do {
            try _saveManifestUnlocked(manifest)
        } catch {
            return (false, error.localizedDescription)
        }
        _mutateCacheUnlocked { dict in
            if let existing = dict[key] {
                let updated = UsageInfo(
                    email: existing.email,
                    tier: clean,
                    daily: existing.daily,
                    weekly: existing.weekly,
                    pools: existing.pools,
                    checkedAt: existing.checkedAt
                )
                dict[key] = updated
                return true
            }
            return false
        }
        return (true, "")
    }

    func persistRefreshedToken(
        accountKey: String?,
        newToken: String,
        replacingSavedToken: String? = nil
    ) {
        let cleanToken = newToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleanToken.hasPrefix("go-keyring-base64:") else { return }

        lock.lock()
        defer { lock.unlock() }
        guard let storeLock = acquireManifestLock() else { return }
        defer { try? storeLock.close() }

        let manifest = _loadManifestUnlocked(migrate: false)
        guard let key = accountKey, let entry = manifest[key], getAccountToken(entry) == replacingSavedToken else { return }
        _persistRefreshedTokenUnlocked(key: key, newToken: cleanToken, manifest: manifest)
    }

    private func _persistRefreshedTokenUnlocked(key: String, newToken: String, manifest: [String: ManifestEntry]) {
        guard var entry = manifest[key], let sid = entry.secretID, Self.validateSecretID(sid) else { return }
        let (ok, _) = NativeKeychain.set(service: NativeKeychain.savedService, account: sid, secret: newToken, keychainPath: keychainPath)
        guard ok, NativeKeychain.get(service: NativeKeychain.savedService, account: sid, keychainPath: keychainPath) == newToken else { return }
        entry.tokenSHA256 = Self.sha256Hex(newToken)
        var updated = manifest
        updated[key] = entry
        try? _saveManifestUnlocked(updated)
    }

    func recordQuota(key: String, entry: ManifestEntry, token: String, usage: UsageInfo, updatedToken: String?) throws -> String? {
        lock.lock()
        defer { lock.unlock() }
        guard let storeLock = acquireManifestLock() else { return nil }
        defer { try? storeLock.close() }

        let manifest = _loadManifestUnlocked(migrate: false)
        let candidates = entry.secretID.map { id in manifest.keys.filter { manifest[$0]?.secretID == id } } ?? [key]
        guard let currentKey = candidates.first(where: { candidate in
            manifest[candidate].flatMap(getAccountToken) == token
        }) else { return nil }

        var cache = loadUsageCache()
        var checked = usage
        checked.checkedAt = Int(Date().timeIntervalSince1970)
        cache[currentKey] = checked
        try writeSecureFile(url: cacheURL, data: JSONEncoder().encode(cache))
        if let updatedToken {
            _persistRefreshedTokenUnlocked(key: currentKey, newToken: updatedToken, manifest: manifest)
        }
        return currentKey
    }

    func loadUsageCache() -> [String: UsageInfo] {
        guard let raw = try? Data(contentsOf: cacheURL),
              let decoded = try? JSONDecoder().decode([String: UsageInfo].self, from: raw) else { return [:] }
        return decoded
    }

    private func _mutateCacheUnlocked(_ mutator: (inout [String: UsageInfo]) -> Bool) {
        guard FileManager.default.fileExists(atPath: cacheURL.path),
              let raw = try? Data(contentsOf: cacheURL),
              var decoded = try? JSONDecoder().decode([String: UsageInfo].self, from: raw) else {
            return
        }
        if mutator(&decoded), let data = try? JSONEncoder().encode(decoded) {
            try? writeSecureFile(url: cacheURL, data: data)
        }
    }
}

// MARK: - Quota via the official Antigravity CLI

// GravityBar never calls Google's internal APIs, refreshes OAuth tokens itself,
// or presents itself as another client. Quota comes only from `agy -p /quota`,
// run by the official CLI under its own identity and only on a user request.
enum NativeQuotaFetcher {
    /// Pause between accounts during a manual "check all" so requests don't arrive in a burst.
    static let interAccountDelaySeconds: UInt64 = 6
    static let quotaTimeoutSeconds: TimeInterval = 45

    static func parseISODate(_ isoStr: String) -> Date? {
        let f1 = ISO8601DateFormatter()
        f1.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f1.date(from: isoStr) { return d }
        let f2 = ISO8601DateFormatter()
        f2.formatOptions = [.withInternetDateTime]
        return f2.date(from: isoStr)
    }

    private static func tokenExpiry(_ credential: String?) -> Date {
        let prefix = "go-keyring-base64:"
        guard let credential, credential.hasPrefix(prefix),
              let data = Data(base64Encoded: String(credential.dropFirst(prefix.count))),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let token = object["token"] as? [String: Any],
              let expiry = token["expiry"] as? String,
              let date = parseISODate(expiry) else { return .distantPast }
        return date
    }

    static func formatCountdownAndShort(_ isoStr: String?) -> (countdown: String, localReset: String, resetShort: String, secs: Int, iso: String) {
        guard let isoStr = isoStr, !isoStr.isEmpty, let dt = parseISODate(isoStr) else {
            return ("N/A", "N/A", "", 0, "")
        }
        let secs = Int(dt.timeIntervalSinceNow)

        let localFmt = DateFormatter()
        localFmt.dateFormat = "EEE h:mm a"
        let localStr = localFmt.string(from: dt)

        if secs <= 0 {
            return ("Ready to reset", localStr, "Ready", 0, isoStr)
        }

        let d = secs / 86400
        let h = (secs % 86400) / 3600
        let m = (secs % 3600) / 60
        var parts: [String] = []
        if d > 0 { parts.append("\(d)d") }
        if h > 0 { parts.append("\(h)h") }
        if m > 0 && d == 0 { parts.append("\(m)m") }
        if parts.isEmpty { parts.append("1m") }

        let shortFmt = DateFormatter()
        shortFmt.dateFormat = secs < 86400 ? "HH:mm" : "MMM d, HH:mm"
        let shortStr = shortFmt.string(from: dt)

        return (parts.joined(separator: " "), localStr, shortStr, secs, isoStr)
    }


    /// Reads the email that the official client stored inside the credential. No network call.
    static func emailFromToken(_ tokenStr: String) -> String? {
        NativeManifestStore.extractTokenIdentity(tokenStr).email
    }

    private static func parseWindowLabel(windowRaw: String?, bucketId: String?, displayName: String?) -> String {
        let w = (windowRaw ?? "").lowercased()
        let bid = (bucketId ?? "").lowercased()
        let disp = (displayName ?? "").lowercased()
        if w == "5h" || bid.contains("5h") || disp.contains("five hour") || disp.contains("5-hour") || disp.contains("5h") {
            return "5h limit"
        }
        if w == "weekly" || bid.contains("weekly") || disp.contains("weekly") || disp.contains("7d") {
            return "Weekly limit"
        }
        let clean = (displayName ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        return clean.isEmpty ? "Limit" : clean
    }

    private static func parseGroupModels(description: String?) -> [String]? {
        guard let desc = description, !desc.isEmpty else { return nil }
        let marker = "models within this group:"
        guard let range = desc.range(of: marker, options: [.caseInsensitive]) else { return nil }
        let tail = String(desc[range.upperBound...])
        let items = tail
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        return items.isEmpty ? nil : items
    }

    private static func makeQuotaPool(
        name: String,
        groupName: String,
        windowLabel: String,
        rem: Double,
        resetTime: String?,
        models: [String]?,
        reportedWindow: Bool? = nil
    ) -> QuotaPool {
        let clamped = max(0.0, min(1.0, rem))
        let usedPct = ((1.0 - clamped) * 1000.0).rounded() / 10.0
        let remPct = (clamped * 1000.0).rounded() / 10.0
        let fmt = formatCountdownAndShort(resetTime)
        return QuotaPool(
            name: name,
            groupName: groupName,
            windowLabel: windowLabel,
            usedPct: usedPct,
            remainingPct: remPct,
            resetsIn: fmt.countdown,
            resetTime: fmt.localReset,
            resetShort: fmt.resetShort,
            resetSecs: fmt.secs,
            resetIso: resetTime ?? fmt.iso,
            models: models,
            reportedWindow: reportedWindow
        )
    }

    // MARK: Official CLI runner

    enum QuotaCheckError: LocalizedError {
        case cliNotFound
        case badCredential
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .cliNotFound:
                return "Official Antigravity CLI (agy) was not found. Install it to check quotas."
            case .badCredential:
                return "Saved credential could not be prepared for the Antigravity CLI."
            case .failed(let m):
                return m
            }
        }
    }

    /// Converts a stored `go-keyring-base64:` credential into the JSON file format the official CLI writes.
    static func credentialFileData(from tokenStr: String) -> Data? {
        let prefix = "go-keyring-base64:"
        let clean = tokenStr.trimmingCharacters(in: .whitespacesAndNewlines)
        guard clean.hasPrefix(prefix),
              let decoded = Data(base64Encoded: String(clean.dropFirst(prefix.count))),
              let obj = try? JSONSerialization.jsonObject(with: decoded) as? [String: Any],
              obj["token"] is [String: Any] else { return nil }
        return decoded
    }

    /// Isolates the CLI profile and intercepts browser launches that use BROWSER or PATH.
    static func quotaEnvironment(home: String, shimDir: String, baseEnv: [String: String] = ProcessInfo.processInfo.environment) -> [String: String] {
        var env: [String: String] = [:]
        for key in ["LANG", "LC_ALL", "LC_CTYPE", "USER", "LOGNAME", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"] {
            if let v = baseEnv[key] { env[key] = v }
        }
        env["HOME"] = home
        env["TMPDIR"] = home + "/tmp"
        env["PATH"] = shimDir + ":/usr/bin:/bin:/usr/sbin:/sbin"
        env["BROWSER"] = shimDir + "/open"
        env["AGY_CLI_FORCE_FILE_TOKEN_STORAGE"] = "1"
        env["AGY_CLI_DISABLE_AUTO_UPDATE"] = "1"
        return env
    }

    /// Runs `agy -p /quota --output-format json` for one credential in an isolated profile.
    /// Returns the parsed usage plus the credential the CLI left behind (it may have refreshed it).
    static func runQuotaCheck(
        tokenStr: String,
        knownEmail: String?,
        savedPlanLabel: String?,
        executable: String? = OfficialAgyLoginSession.findAgyExecutable(),
        timeout: TimeInterval = quotaTimeoutSeconds
    ) async -> Result<(usage: UsageInfo, updatedToken: String?), QuotaCheckError> {
        guard let agy = executable else { return .failure(.cliNotFound) }
        guard let credData = credentialFileData(from: tokenStr) else { return .failure(.badCredential) }

        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("gravitybar_quota_\(UUID().uuidString)")
        defer { try? fm.removeItem(at: root) }
        let shimDir = root.appendingPathComponent("bin")
        let cliDir = root.appendingPathComponent(".gemini/antigravity-cli")
        let tokenURL = cliDir.appendingPathComponent("antigravity-oauth-token")
        let stdoutURL = root.appendingPathComponent("stdout")
        let stderrURL = root.appendingPathComponent("stderr")
        let stdout: FileHandle
        let stderr: FileHandle
        do {
            for dir in [root, shimDir, cliDir, root.appendingPathComponent("tmp")] {
                try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            }
            let shim = shimDir.appendingPathComponent("open")
            try Data("#!/bin/sh\nexit 0\n".utf8).write(to: shim)
            try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: shim.path)
            try credData.write(to: tokenURL, options: .atomic)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenURL.path)
            try Data().write(to: stdoutURL)
            try Data().write(to: stderrURL)
            stdout = try FileHandle(forWritingTo: stdoutURL)
            stderr = try FileHandle(forWritingTo: stderrURL)
        } catch {
            return .failure(.failed("Could not prepare a temporary profile: \(error.localizedDescription)"))
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: agy)
        proc.arguments = ["-p", "/quota", "--output-format", "json", "--print-timeout", "30s"]
        proc.currentDirectoryURL = root
        proc.environment = quotaEnvironment(home: root.path, shimDir: shimDir.path)
        // Files let the check finish even when a child of agy inherits the output descriptors.
        proc.standardOutput = stdout
        proc.standardError = stderr
        proc.standardInput = FileHandle.nullDevice

        do {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                let deadline = DispatchWorkItem {
                    if proc.isRunning { kill(proc.processIdentifier, SIGKILL) }
                }
                proc.terminationHandler = { _ in
                    deadline.cancel()
                    cont.resume()
                }
                do {
                    try proc.run()
                } catch {
                    proc.terminationHandler = nil
                    cont.resume(throwing: error)
                    return
                }
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: deadline)
            }
        } catch {
            return .failure(.failed("Could not start the Antigravity CLI: \(error.localizedDescription)"))
        }

        if proc.terminationReason == .uncaughtSignal && proc.terminationStatus == SIGKILL {
            return .failure(.failed("The Antigravity CLI timed out."))
        }
        let output = readQuotaOutput(stdoutURL)
        guard proc.terminationStatus == 0,
              let usage = parseQuotaJSON(output, resolvedEmail: knownEmail, savedPlanLabel: savedPlanLabel) else {
            let text = String(decoding: output + readQuotaOutput(stderrURL), as: UTF8.self)
            if text.contains("accounts.google.com") || text.localizedCaseInsensitiveContains("authentication") {
                return .failure(.failed("Sign-in expired. Add this account again."))
            }
            return .failure(.failed("The Antigravity CLI did not report a quota."))
        }

        var updated: String?
        if let newData = try? Data(contentsOf: tokenURL), newData != credData,
           let obj = try? JSONSerialization.jsonObject(with: newData) as? [String: Any],
           obj["token"] is [String: Any] {
            updated = "go-keyring-base64:" + newData.base64EncodedString()
        }
        return .success((usage, updated))
    }

    private static func readQuotaOutput(_ url: URL) -> Data {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return Data() }
        defer { try? handle.close() }
        return (try? handle.read(upToCount: 1_000_000)) ?? Data()
    }

    /// Parses `agy -p /quota --output-format json` output (`command.data.groups[].buckets[]`).
    static func parseQuotaJSON(_ data: Data, resolvedEmail: String?, savedPlanLabel: String?) -> UsageInfo? {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (root["status"] as? String)?.uppercased() == "SUCCESS",
              let command = root["command"] as? [String: Any],
              let name = command["name"] as? String, name == "usage" || name == "quota",
              let payload = command["data"] as? [String: Any],
              let groups = payload["groups"] as? [[String: Any]] else {
            return nil
        }

        var pools: [QuotaPool] = []
        for grp in groups {
            let groupName = (grp["name"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !groupName.isEmpty else { continue }
            let models = parseGroupModels(description: grp["description"] as? String)
            var grpPools: [QuotaPool] = []
            for b in (grp["buckets"] as? [[String: Any]]) ?? [] {
                let winLabel = parseWindowLabel(
                    windowRaw: b["window"] as? String,
                    bucketId: b["id"] as? String,
                    displayName: b["name"] as? String
                )
                let rem: Double
                if let value = b["remaining_fraction"] {
                    guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
                          number.doubleValue.isFinite else { continue }
                    rem = number.doubleValue
                } else {
                    rem = 0 // The CLI omits zero-valued fractions in its JSON.
                }
                var resetTime = b["reset_time"] as? String
                // An unused window reports the Unix epoch; treat that as "no reset scheduled".
                if let rt = resetTime, let d = parseISODate(rt), d.timeIntervalSince1970 <= 0 {
                    resetTime = nil
                }
                grpPools.append(makeQuotaPool(
                    name: "\(groupName) — \(winLabel)",
                    groupName: groupName,
                    windowLabel: winLabel,
                    rem: rem,
                    resetTime: resetTime,
                    models: models,
                    reportedWindow: true
                ))
            }
            grpPools.sort { a, b in
                let rank: (String?) -> Int = { lbl in
                    let l = (lbl ?? "").lowercased()
                    if l.contains("5h") { return 0 }
                    if l.contains("weekly") { return 1 }
                    return 2
                }
                return rank(a.windowLabel) < rank(b.windowLabel)
            }
            pools.append(contentsOf: grpPools)
        }

        guard !pools.isEmpty else { return nil }

        let groupRank: (QuotaPool) -> Int = { pool in
            let g = (pool.groupName ?? pool.name).lowercased()
            if g.contains("argon") { return 2 }
            if g.contains("gemini") { return 0 }
            if g.contains("claude") || g.contains("gpt") { return 1 }
            return 3
        }
        pools = pools.enumerated().sorted { a, b in
            let ra = groupRank(a.element), rb = groupRank(b.element)
            return ra != rb ? ra < rb : a.offset < b.offset
        }.map(\.element)

        let tier = savedPlanLabel?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let usage = UsageInfo(email: resolvedEmail, tier: tier, daily: nil, weekly: nil, pools: pools)
        return UsageInfo(
            email: resolvedEmail ?? "Unknown",
            tier: tier,
            daily: QuotaHelpers.gemini5hPool(usage),
            weekly: QuotaHelpers.geminiWeeklyPool(usage),
            pools: pools
        )
    }

    static func computeBestSwitchCandidate(accounts: [AccountItem], activeKey: String?) -> String? {
        func score(for usage: UsageInfo?) -> (minRem: Double, gemRem: Double)? {
            guard let usage = usage else { return nil }
            let gem = QuotaHelpers.gemini5hPool(usage)?.remainingPct
            let allVals = (usage.pools ?? []).map { $0.remainingPct }
            let vals = usage.pools != nil ? allVals : [usage.daily?.remainingPct, usage.weekly?.remainingPct].compactMap { $0 }
            guard let m = vals.min() else { return nil }
            return (m, gem ?? m)
        }

        var activeScore: (minRem: Double, gemRem: Double)?
        var bestKey: String?
        var bestScore: (minRem: Double, gemRem: Double)?

        for acc in accounts {
            guard let sc = score(for: acc.usage) else { continue }
            if acc.key == activeKey {
                activeScore = sc
            } else {
                let isBetter: Bool
                if let bs = bestScore {
                    isBetter = (sc.minRem > bs.minRem) || (sc.minRem == bs.minRem && sc.gemRem > bs.gemRem)
                } else {
                    isBetter = true
                }
                if isBetter {
                    bestKey = acc.key
                    bestScore = sc
                }
            }
        }

        guard let chosenKey = bestKey, let bs = bestScore else { return nil }
        guard let act = activeScore else { return chosenKey }
        if act.minRem < 25.0 && bs.minRem > act.minRem { return chosenKey }
        if (bs.minRem - act.minRem) >= 20.0 { return chosenKey }
        return nil
    }


    /// Builds the account list. Network work happens only when `checkQuotas` is true
    /// (the user pressed "Check Quotas"); otherwise the last saved results are shown.
    static func loadStatusPayload(
        store: NativeManifestStore,
        checkQuotas: Bool,
        onProgress: (@Sendable (Int, Int) -> Void)? = nil
    ) async -> (payload: StatusPayload, errors: [String: String], checkedAccounts: Set<String>) {
        var manifest = store.loadManifest(migrate: true)
        let initialToken = NativeKeychain.getActiveToken(keychainPath: store.keychainPath)
        if let initialToken, let key = store.findActiveAccountKey(manifest: manifest, currentToken: initialToken),
           let entry = manifest[key] {
            let savedToken = store.getAccountToken(entry)
            if savedToken != initialToken, tokenExpiry(savedToken) < tokenExpiry(initialToken) {
                store.persistRefreshedToken(accountKey: key, newToken: initialToken, replacingSavedToken: savedToken)
            }
        }

        var errors: [String: String] = [:]
        var checkedAccounts: Set<String> = []

        if checkQuotas {
            let keys = manifest.keys.sorted()
            for (idx, key) in keys.enumerated() {
                if idx > 0 {
                    try? await Task.sleep(nanoseconds: interAccountDelaySeconds * 1_000_000_000)
                }
                if Task.isCancelled { break }
                onProgress?(idx + 1, keys.count)
                guard let entry = manifest[key], let tok = store.getAccountToken(entry) else {
                    errors[key] = "Saved credential is missing from Keychain."
                    continue
                }
                let result = await runQuotaCheck(
                    tokenStr: tok,
                    knownEmail: entry.email,
                    savedPlanLabel: entry.planLabel
                )
                switch result {
                case .success(let r):
                    do {
                        if let recordedKey = try store.recordQuota(key: key, entry: entry, token: tok, usage: r.usage, updatedToken: r.updatedToken) {
                            checkedAccounts.insert(recordedKey)
                        } else {
                            errors[key] = "Saved account changed during the check. Check again."
                        }
                    } catch {
                        errors[key] = "Could not save the quota result."
                    }
                case .failure(let err):
                    errors[key] = err.localizedDescription
                }
                if case .failure(let error) = result, case .cliNotFound = error {
                    for unchecked in keys.dropFirst(idx + 1) {
                        errors[unchecked] = error.localizedDescription
                    }
                    break
                }
            }
            manifest = store.loadManifest(migrate: false)
        }

        let usageByKey = store.loadUsageCache()
        let currToken = NativeKeychain.getActiveToken(keychainPath: store.keychainPath)
        let activeKey = store.findActiveAccountKey(manifest: manifest, currentToken: currToken)
        let activeEmail = activeKey.flatMap { manifest[$0]?.email } ?? currToken.flatMap(emailFromToken)

        var accountsOut: [AccountItem] = []
        for k in manifest.keys.sorted() {
            let entry = manifest[k]
            let planLbl = entry?.planLabel?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            var uObj = usageByKey[k]
            if let u = uObj {
                uObj = UsageInfo(email: u.email, tier: planLbl, daily: u.daily, weekly: u.weekly, pools: u.pools, checkedAt: u.checkedAt)
            }
            let resolvedEmail: String
            if let me = entry?.email, !me.isEmpty {
                resolvedEmail = me
            } else if let ue = uObj?.email, ue != "Unknown", !ue.isEmpty {
                resolvedEmail = ue
            } else {
                resolvedEmail = k
            }
            accountsOut.append(AccountItem(
                key: k,
                label: entry?.label ?? k,
                email: resolvedEmail,
                savedAt: entry?.savedAt ?? "",
                storage: entry?.storage ?? "keychain",
                isActive: (k == activeKey),
                pinned: entry?.pinned ?? false,
                planLabel: planLbl,
                usage: uObj
            ))
        }

        let payload = StatusPayload(
            activeKey: activeKey,
            hasActiveSession: currToken != nil,
            activeSessionUnsaved: (currToken != nil && activeKey == nil),
            activeEmail: activeEmail,
            bestSwitchCandidate: computeBestSwitchCandidate(accounts: accountsOut, activeKey: activeKey),
            accounts: accountsOut,
            fetchedAt: Int(Date().timeIntervalSince1970),
            fromCache: checkedAccounts.isEmpty
        )
        return (payload, errors, checkedAccounts)
    }
}

// MARK: - Official First-Party Antigravity CLI Login

enum AddAccountMode: Equatable {
    case agyCli
    case antigravityIDE
}

enum OfficialAgyLoginError: LocalizedError {
    case cliNotFound
    case launchFailed(String)
    case missingCredential
    case invalidState(String)
    case cancelled

    var errorDescription: String? {
        switch self {
        case .cliNotFound:
            return "Official Antigravity CLI (agy) was not found (~/.gemini/bin/agy). Use 'Antigravity Desktop App' instead."
        case .launchFailed(let m):
            return "Could not complete Antigravity CLI sign-in: \(m)"
        case .missingCredential:
            return "Antigravity CLI finished, but no credential was written."
        case .invalidState(let m):
            return m
        case .cancelled:
            return "Sign-in cancelled."
        }
    }
}

final class OfficialAgyLoginSession: @unchecked Sendable {
    private static let strippedEnvKeys: Set<String> = [
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_LOCATION",
        "GOOGLE_CLOUD_QUOTA_PROJECT",
        "GOOGLE_GENAI_USE_VERTEXAI",
        "GCLOUD_PROJECT",
        "CLOUDSDK_CORE_PROJECT",
        "AGY_ACP_CCPA_PROJECT",
        "AGY_ACP_ENABLE_OAUTH",
        "GEMINI_HOME",
        "AGY_ACP_FORCE_FILE_STORAGE",
        "AGY_CLI_FORCE_FILE_TOKEN_STORAGE",
        "AGY_CLI_DISABLE_AUTO_UPDATE",
        "SSH_CONNECTION",
        "SSH_CLIENT",
        "SSH_TTY",
        "BROWSER",
        "PYTHONUNBUFFERED",
        "ELECTRON_RUN_AS_NODE",
        "CHROME_CRASHPAD_PIPE_NAME",
        "DISPLAY",
        "WAYLAND_DISPLAY"
    ]

    let agyPath: String
    let profileURL: URL
    let acpDirURL: URL
    private let lock = NSLock()
    private let process: Process
    private let stdinPipe = Pipe()
    private let stdoutPipe = Pipe()
    private let stderrPipe = Pipe()
    private var stdoutBuffer = ""
    private var stderrBuffer = ""
    private var emittedAuthURL = false
    private var finished = false
    private var cancelled = false
    private var cachedCompletion: Result<(token: String, email: String), Error>?
    private var completionCont: CheckedContinuation<(token: String, email: String), Error>?
    private var authURLCont: CheckedContinuation<URL, Error>?
    private var cachedAuthURL: URL?

    static func findAgyExecutable() -> String? {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser.path
        var candidates = [
            "\(home)/.gemini/bin/agy",
            "/opt/homebrew/bin/agy",
            "/usr/local/bin/agy",
            "\(home)/.local/bin/agy"
        ]
        if let pathEnv = ProcessInfo.processInfo.environment["PATH"] {
            for dir in pathEnv.split(separator: ":") where !dir.isEmpty {
                candidates.append(URL(fileURLWithPath: String(dir)).appendingPathComponent("agy").path)
            }
        }
        for path in candidates where fm.isExecutableFile(atPath: path) {
            return path
        }
        return nil
    }

    static func buildIsolatedEnvironment(
        baseEnv: [String: String] = ProcessInfo.processInfo.environment,
        profilePath: String,
        tempPath: String
    ) -> [String: String] {
        var env: [String: String] = [:]
        for (k, v) in baseEnv {
            if !strippedEnvKeys.contains(k.uppercased()) {
                env[k] = v
            }
        }
        // AGY_CLI_FORCE_FILE_TOKEN_STORAGE is agy's own switch for file-based token storage,
        // so sign-in lands in the temporary profile and never touches the IDE's Keychain login.
        env["AGY_CLI_FORCE_FILE_TOKEN_STORAGE"] = "1"
        env["AGY_CLI_DISABLE_AUTO_UPDATE"] = "1"
        env["TMPDIR"] = tempPath
        return env
    }

    static func normalizeCredentialData(_ rawData: Data, fallbackEmail: String = "") -> String? {
        guard let rawStr = String(data: rawData, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              !rawStr.isEmpty else {
            return nil
        }
        if rawStr.hasPrefix("go-keyring-base64:") {
            return rawStr
        }
        guard let json = try? JSONSerialization.jsonObject(with: Data(rawStr.utf8)) as? [String: Any] else {
            return nil
        }
        if let tObj = json["token"] as? [String: Any],
           let access = tObj["access_token"] as? String, !access.isEmpty {
            var root = json
            if (root["auth_method"] as? String)?.isEmpty != false {
                root["auth_method"] = "consumer"
            }
            if !fallbackEmail.isEmpty && (root["id_token_email"] as? String)?.isEmpty != false {
                root["id_token_email"] = fallbackEmail
            }
            if let encoded = try? JSONSerialization.data(withJSONObject: root, options: [.sortedKeys]) {
                return "go-keyring-base64:" + encoded.base64EncodedString()
            }
        } else if let access = json["access_token"] as? String, !access.isEmpty {
            var tokenDict: [String: Any] = [
                "access_token": access,
                "token_type": (json["token_type"] as? String) ?? "Bearer"
            ]
            if let rf = json["refresh_token"] as? String, !rf.isEmpty {
                tokenDict["refresh_token"] = rf
            }
            if let exp = json["expiry"] {
                tokenDict["expiry"] = exp
            }
            if let expIn = json["expires_in"] {
                tokenDict["expires_in"] = expIn
            }
            var root: [String: Any] = [
                "token": tokenDict,
                "auth_method": "consumer",
                "writer_id": "antigravity"
            ]
            if !fallbackEmail.isEmpty {
                root["id_token_email"] = fallbackEmail
            }
            if let encoded = try? JSONSerialization.data(withJSONObject: root, options: [.sortedKeys]) {
                return "go-keyring-base64:" + encoded.base64EncodedString()
            }
        }
        return nil
    }

    static func readIsolatedCredential(in acpDirURL: URL) -> String? {
        for name in ["acp_token.json", "antigravity-oauth-token"] {
            let url = acpDirURL.appendingPathComponent(name)
            if let data = try? Data(contentsOf: url), let token = normalizeCredentialData(data) {
                return token
            }
        }

        guard let files = FileManager.default.enumerator(at: acpDirURL, includingPropertiesForKeys: nil) else {
            return nil
        }
        for case let url as URL in files where url.pathExtension == "json" && url.lastPathComponent != "settings.json" {
            if let data = try? Data(contentsOf: url), let token = normalizeCredentialData(data) {
                return token
            }
        }
        return nil
    }

    init() throws {
        guard let exe = Self.findAgyExecutable() else {
            throw OfficialAgyLoginError.cliNotFound
        }
        self.agyPath = exe

        let fm = FileManager.default
        let rootURL = fm.temporaryDirectory.appendingPathComponent("ag_agy_login_\(UUID().uuidString)")
        let acpURL = rootURL.appendingPathComponent("antigravity-acp")
        let tmpURL = acpURL.appendingPathComponent("tmp")
        self.profileURL = rootURL
        self.acpDirURL = acpURL

        try fm.createDirectory(at: tmpURL, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let settingsData = Data("{\"auth\":{\"type\":\"oauth-personal\"}}\n".utf8)
        let settingsURL = acpURL.appendingPathComponent("settings.json")
        try settingsData.write(to: settingsURL, options: .atomic)
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: rootURL.path)
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: acpURL.path)

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: exe)
        proc.arguments = [
            "acp",
            "--gemini-dir", rootURL.path,
            "--app-data-dir", "antigravity-acp",
            "--login"
        ]
        proc.currentDirectoryURL = rootURL
        proc.environment = Self.buildIsolatedEnvironment(
            profilePath: rootURL.path,
            tempPath: tmpURL.path
        )
        proc.standardInput = stdinPipe
        proc.standardOutput = stdoutPipe
        proc.standardError = stderrPipe
        self.process = proc

        stdoutPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard let self = self else { return }
            if data.isEmpty {
                handle.readabilityHandler = nil
                return
            }
            if let chunk = String(data: data, encoding: .utf8) {
                self.consumeStdout(chunk)
            }
        }

        stderrPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard let self = self else { return }
            if data.isEmpty {
                handle.readabilityHandler = nil
                return
            }
            if let chunk = String(data: data, encoding: .utf8) {
                self.lock.lock()
                if self.stderrBuffer.count < 4096 {
                    self.stderrBuffer += chunk
                }
                self.lock.unlock()
            }
        }

        proc.terminationHandler = { [weak self] endedProc in
            self?.handleProcessExit(status: endedProc.terminationStatus)
        }

        do {
            try proc.run()
        } catch {
            try? fm.removeItem(at: rootURL)
            throw OfficialAgyLoginError.launchFailed(error.localizedDescription)
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 15) { [weak self] in
            self?.expireIfPending(awaitingURL: true)
        }
    }

    deinit {
        cancel()
    }

    private func consumeStdout(_ chunk: String) {
        var foundURL: URL?
        var waitingAuthCont: CheckedContinuation<URL, Error>?

        lock.lock()
        stdoutBuffer += chunk
        let normalized = stdoutBuffer.replacingOccurrences(of: "\r\n", with: "\n")
        var lines = normalized.components(separatedBy: "\n")
        stdoutBuffer = lines.popLast() ?? ""
        for rawLine in lines {
            let trimmed = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.hasPrefix("https://accounts.google.com/"),
               let parsed = URL(string: trimmed),
               !emittedAuthURL {
                emittedAuthURL = true
                cachedAuthURL = parsed
                foundURL = parsed
                waitingAuthCont = authURLCont
                authURLCont = nil
                break
            }
        }
        lock.unlock()

        if let url = foundURL, let cont = waitingAuthCont {
            cont.resume(returning: url)
        }
    }

    func waitForAuthorizationURL() async throws -> URL {
        try await withCheckedThrowingContinuation { cont in
            lock.lock()
            if cancelled {
                lock.unlock()
                cont.resume(throwing: OfficialAgyLoginError.cancelled)
                return
            }
            if let u = cachedAuthURL {
                lock.unlock()
                cont.resume(returning: u)
                return
            }
            if let completion = cachedCompletion {
                lock.unlock()
                switch completion {
                case .failure(let error):
                    cont.resume(throwing: error)
                case .success:
                    cont.resume(throwing: OfficialAgyLoginError.invalidState("Antigravity CLI did not provide an authorization link."))
                }
                return
            }
            authURLCont = cont
            lock.unlock()
        }
    }

    func submitAuthorizationResponse(_ raw: String) -> Bool {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, process.isRunning else { return false }
        let payload = Data("\(trimmed)\n".utf8)
        do {
            try stdinPipe.fileHandleForWriting.write(contentsOf: payload)
            DispatchQueue.global().asyncAfter(deadline: .now() + 30) { [weak self] in
                self?.expireIfPending(awaitingURL: false)
            }
            return true
        } catch {
            return false
        }
    }

    private func expireIfPending(awaitingURL: Bool) {
        lock.lock()
        let expired = !finished && (!awaitingURL || !emittedAuthURL)
        lock.unlock()
        guard expired else { return }
        let detail = awaitingURL ? "Timed out waiting for the authorization link." : "Antigravity sign-in timed out."
        complete(.failure(OfficialAgyLoginError.invalidState(detail)))
        if process.isRunning { process.terminate() }
    }

    func waitForCompletion() async throws -> (token: String, email: String) {
        try await withCheckedThrowingContinuation { cont in
            lock.lock()
            if let existing = cachedCompletion {
                lock.unlock()
                cont.resume(with: existing)
                return
            }
            completionCont = cont
            lock.unlock()
        }
    }

    func cancel() {
        lock.lock()
        let alreadyFinished = finished
        cancelled = true
        let running = process.isRunning
        lock.unlock()

        if running {
            process.terminate()
        }
        if !alreadyFinished {
            complete(.failure(OfficialAgyLoginError.cancelled))
        }
    }

    private func handleProcessExit(status: Int32) {
        stdoutPipe.fileHandleForReading.readabilityHandler = nil
        stderrPipe.fileHandleForReading.readabilityHandler = nil

        lock.lock()
        let wasCancelled = cancelled
        let errOut = stderrBuffer.trimmingCharacters(in: .whitespacesAndNewlines)
        lock.unlock()

        defer {
            try? FileManager.default.removeItem(at: profileURL)
        }

        if wasCancelled {
            complete(.failure(OfficialAgyLoginError.cancelled))
            return
        }

        guard status == 0 else {
            let detail = errOut.isEmpty ? "Antigravity CLI exited with status \(status)." : errOut
            complete(.failure(OfficialAgyLoginError.launchFailed(detail)))
            return
        }

        guard let tok = Self.readIsolatedCredential(in: acpDirURL) else {
            complete(.failure(OfficialAgyLoginError.missingCredential))
            return
        }

        let email = NativeQuotaFetcher.emailFromToken(tok) ?? "antigravity-account"
        complete(.success((tok, email)))
    }

    private func complete(_ result: Result<(token: String, email: String), Error>) {
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        cachedCompletion = result
        let cont = completionCont
        completionCont = nil
        let urlCont = authURLCont
        authURLCont = nil
        lock.unlock()

        if let urlCont {
            switch result {
            case .failure(let error):
                urlCont.resume(throwing: error)
            case .success:
                urlCont.resume(throwing: OfficialAgyLoginError.invalidState("Antigravity CLI did not provide an authorization link."))
            }
        }
        cont?.resume(with: result)
    }
}

// MARK: - Native App Restarter

enum NativeAppRestarter {
    static func antigravityAppURL() -> URL? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let candidates = [
            "/Applications/Antigravity.app",
            "/Applications/Antigravity IDE.app",
            "\(home)/Applications/Antigravity.app",
            "\(home)/Applications/Antigravity IDE.app"
        ]
        for path in candidates where FileManager.default.fileExists(atPath: path) {
            return URL(fileURLWithPath: path)
        }
        for bid in ["com.google.antigravity", "com.google.antigravity-ide", "com.antigravity.ide", "com.todesktop.antigravity"] {
            if let found = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bid) {
                return found
            }
        }
        return nil
    }

    @discardableResult
    static func openAntigravityApp() -> (ok: Bool, errorMessage: String?) {
        guard let appURL = antigravityAppURL() else {
            return (false, "Antigravity app was not found in /Applications. Use 'Sign in via Antigravity CLI' instead.")
        }

        // Trigger LaunchServices open so an already-running Electron app reopens/surfaces a window
        let status = runProc("/usr/bin/open", ["-a", appURL.path])
        guard status == 0 else { return (false, "macOS could not open Antigravity.") }
        DispatchQueue.main.async {
            for app in NSWorkspace.shared.runningApplications where isTargetAntigravityApp(app, appPath: appURL.path) {
                app.unhide()
                app.activate()
            }
        }
        return (true, nil)
    }

    private static func runProc(_ exe: String, _ args: [String]) -> Int32 {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: exe)
        task.arguments = args
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
            return task.terminationStatus
        } catch {
            return -1
        }
    }

    private static func isAnyRunning(_ checks: [[String]]) -> Bool {
        checks.contains { runProc("/usr/bin/pgrep", $0) == 0 }
    }

    private static func isTargetAntigravityApp(_ app: NSRunningApplication, appPath: String) -> Bool {
        let target = URL(fileURLWithPath: appPath).resolvingSymlinksInPath()
        return app.bundleURL?.resolvingSymlinksInPath().path == target.path
    }

    @MainActor
    private static func activateAntigravityOnMain(appPath: String) {
        for app in NSWorkspace.shared.runningApplications where isTargetAntigravityApp(app, appPath: appPath) {
            app.unhide()
            app.activate()
        }
    }

    static func restartAntigravity() async -> Bool {
        guard let appPath = antigravityAppURL()?.path else { return false }
        let root = "^" + NSRegularExpression.escapedPattern(for: appPath)
        let mainChecks = [["-f", "\(root)/Contents/MacOS/"]]
        let helperChecks = [["-f", "\(root)/Contents/Frameworks/"]]
        let lsPatterns = ["\(root)/Contents/Resources/.*/language_server"]
        let allChecks = mainChecks + helperChecks + lsPatterns.map { ["-f", $0] }

        // Terminate running Antigravity GUI instances gracefully on main actor first
        let runningApps = await MainActor.run { () -> [NSRunningApplication] in
            NSWorkspace.shared.runningApplications.filter { isTargetAntigravityApp($0, appPath: appPath) }
        }
        for app in runningApps {
            _ = app.terminate()
        }

        let relaunched = await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            DispatchQueue.global(qos: .userInitiated).async {
                if !runningApps.isEmpty || isAnyRunning(allChecks) {
                    for lsPat in lsPatterns {
                        _ = runProc("/usr/bin/pkill", ["-TERM", "-f", lsPat])
                    }
                    let deadline = Date().addingTimeInterval(5.0)
                    while Date() < deadline {
                        if !isAnyRunning(allChecks) && runningApps.allSatisfy({ $0.isTerminated }) {
                            break
                        }
                        Thread.sleep(forTimeInterval: 0.2)
                    }
                    if isAnyRunning(allChecks) || !runningApps.allSatisfy({ $0.isTerminated }) {
                        for app in runningApps where !app.isTerminated {
                            _ = app.forceTerminate()
                        }
                        for chk in allChecks {
                            _ = runProc("/usr/bin/pkill", ["-9"] + chk)
                        }
                        let forceDeadline = Date().addingTimeInterval(1.0)
                        while Date() < forceDeadline {
                            if !isAnyRunning(allChecks) && runningApps.allSatisfy({ $0.isTerminated }) {
                                break
                            }
                            Thread.sleep(forTimeInterval: 0.1)
                        }
                    }
                }

                // Allow LaunchServices to finish unregistering the exiting instance and Electron to release SingletonLock.
                Thread.sleep(forTimeInterval: 0.45)

                for options in [[], ["-n"]] {
                    if runProc("/usr/bin/open", options + ["-a", appPath]) != 0 { continue }
                    for _ in 0..<13 {
                        if isAnyRunning(mainChecks) {
                            cont.resume(returning: true)
                            return
                        }
                        Thread.sleep(forTimeInterval: 0.2)
                    }
                }
                cont.resume(returning: false)
            }
        }

        if relaunched {
            await MainActor.run {
                activateAntigravityOnMain(appPath: appPath)
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                activateAntigravityOnMain(appPath: appPath)
            }
        }
        return relaunched
    }
}

// MARK: - Menu Bar Retina Gauge Renderer

enum MenuBarGaugeRenderer {
    static func renderImage(geminiPct: Double?, claudePct: Double?) -> NSImage {
        let size = NSSize(width: 24, height: 18)
        let image = NSImage(size: size, flipped: false) { _ in
            func barColor(for pct: Double?) -> NSColor {
                guard let pct = pct else { return NSColor.tertiaryLabelColor }
                if pct < 20 { return NSColor.systemRed }
                if pct < 45 { return NSColor.systemOrange }
                return NSColor.systemBlue
            }

            func drawBar(y: CGFloat, pct: Double?) {
                let trackRect = NSRect(x: 2, y: y, width: 20, height: 4.5)
                let trackPath = NSBezierPath(roundedRect: trackRect, xRadius: 2.25, yRadius: 2.25)
                NSColor.labelColor.withAlphaComponent(0.22).setFill()
                trackPath.fill()

                if let p = pct {
                    let frac = max(0.0, min(1.0, p / 100.0))
                    let fillWidth = max(frac > 0 ? 4.5 : 0.0, 20.0 * frac)
                    if fillWidth > 0 {
                        let fillRect = NSRect(x: 2, y: y, width: fillWidth, height: 4.5)
                        let fillPath = NSBezierPath(roundedRect: fillRect, xRadius: 2.25, yRadius: 2.25)
                        barColor(for: p).setFill()
                        fillPath.fill()
                    }
                }
            }

            // Top bar = Gemini (daily), Bottom bar = Claude (weekly)
            drawBar(y: 10.5, pct: geminiPct)
            drawBar(y: 3.0, pct: claudePct)
            return true
        }
        image.isTemplate = false
        return image
    }
}

// MARK: - Custom GravityBar App Icon Renderer (macOS Squircle + Account Swap + Dual Bars)

enum AppIconRenderer {
    private static let iconsetEntries: [(name: String, pixels: Int)] = [
        ("icon_16x16.png", 16),
        ("icon_16x16@2x.png", 32),
        ("icon_32x32.png", 32),
        ("icon_32x32@2x.png", 64),
        ("icon_128x128.png", 128),
        ("icon_128x128@2x.png", 256),
        ("icon_256x256.png", 256),
        ("icon_256x256@2x.png", 512),
        ("icon_512x512.png", 512),
        ("icon_512x512@2x.png", 1024)
    ]

    private static func drawRightArrow(centerY: CGFloat, startX: CGFloat, endX: CGFloat, thickness: CGFloat, headLen: CGFloat, headHalfH: CGFloat, color: NSColor) {
        let shaftEndX = endX - headLen * 0.72
        let path = NSBezierPath()
        let halfT = thickness * 0.5
        path.move(to: NSPoint(x: startX + halfT, y: centerY + halfT))
        path.line(to: NSPoint(x: shaftEndX, y: centerY + halfT))
        path.line(to: NSPoint(x: shaftEndX, y: centerY + headHalfH))
        path.line(to: NSPoint(x: endX, y: centerY))
        path.line(to: NSPoint(x: shaftEndX, y: centerY - headHalfH))
        path.line(to: NSPoint(x: shaftEndX, y: centerY - halfT))
        path.line(to: NSPoint(x: startX + halfT, y: centerY - halfT))
        path.appendArc(withCenter: NSPoint(x: startX + halfT, y: centerY), radius: halfT, startAngle: 270, endAngle: 90, clockwise: true)
        path.close()
        color.setFill()
        path.fill()
    }

    private static func drawLeftArrow(centerY: CGFloat, startX: CGFloat, endX: CGFloat, thickness: CGFloat, headLen: CGFloat, headHalfH: CGFloat, color: NSColor) {
        let shaftStartX = startX + headLen * 0.72
        let path = NSBezierPath()
        let halfT = thickness * 0.5
        path.move(to: NSPoint(x: endX - halfT, y: centerY - halfT))
        path.line(to: NSPoint(x: shaftStartX, y: centerY - halfT))
        path.line(to: NSPoint(x: shaftStartX, y: centerY - headHalfH))
        path.line(to: NSPoint(x: startX, y: centerY))
        path.line(to: NSPoint(x: shaftStartX, y: centerY + headHalfH))
        path.line(to: NSPoint(x: shaftStartX, y: centerY + halfT))
        path.line(to: NSPoint(x: endX - halfT, y: centerY + halfT))
        path.appendArc(withCenter: NSPoint(x: endX - halfT, y: centerY), radius: halfT, startAngle: 90, endAngle: 270, clockwise: true)
        path.close()
        color.setFill()
        path.fill()
    }

    private static func drawArtwork(in size: CGFloat) {
        let inset = size * 0.08
        let rectSize = size - inset * 2.0
        let squircleRect = NSRect(x: inset, y: inset, width: rectSize, height: rectSize)
        let cornerRadius = rectSize * 0.225
        let squircle = NSBezierPath(roundedRect: squircleRect, xRadius: cornerRadius, yRadius: cornerRadius)

        NSGraphicsContext.saveGraphicsState()
        let shadow = NSShadow()
        shadow.shadowColor = NSColor.black.withAlphaComponent(0.32)
        shadow.shadowBlurRadius = size * 0.045
        shadow.shadowOffset = NSSize(width: 0, height: -size * 0.022)
        shadow.set()
        NSColor(calibratedRed: 0.12, green: 0.10, blue: 0.30, alpha: 1.0).setFill()
        squircle.fill()
        NSGraphicsContext.restoreGraphicsState()

        NSGraphicsContext.saveGraphicsState()
        squircle.addClip()

        // Deep violet -> electric purple -> cyan-teal diagonal gradient (distinct from Antigravity icon)
        let grad = NSGradient(colorsAndLocations:
            (NSColor(calibratedRed: 0.10, green: 0.09, blue: 0.28, alpha: 1.0), 0.0),
            (NSColor(calibratedRed: 0.43, green: 0.16, blue: 0.85, alpha: 1.0), 0.54),
            (NSColor(calibratedRed: 0.04, green: 0.58, blue: 0.72, alpha: 1.0), 1.0)
        )
        grad?.draw(in: squircleRect, angle: -42.0)

        // Subtle radial glow at top-left
        let glow = NSGradient(
            starting: NSColor.white.withAlphaComponent(0.20),
            ending: NSColor.white.withAlphaComponent(0.0)
        )
        glow?.draw(
            fromCenter: NSPoint(x: inset + rectSize * 0.25, y: inset + rectSize * 0.86),
            radius: 0,
            toCenter: NSPoint(x: inset + rectSize * 0.25, y: inset + rectSize * 0.86),
            radius: rectSize * 0.72,
            options: []
        )

        // Crisp inner glass border
        let innerBorder = NSBezierPath(
            roundedRect: squircleRect.insetBy(dx: max(0.5, size * 0.008), dy: max(0.5, size * 0.008)),
            xRadius: cornerRadius - size * 0.008,
            yRadius: cornerRadius - size * 0.008
        )
        innerBorder.lineWidth = max(1.0, size * 0.015)
        NSColor.white.withAlphaComponent(0.26).setStroke()
        innerBorder.stroke()

        // Upper swap arrows: crisp white right arrow + warm amber left arrow
        let arrowStartX = size * 0.24
        let arrowEndX = size * 0.76
        let arrowThickness = max(1.5, size * 0.056)
        let arrowHeadLen = size * 0.115
        let arrowHeadHalfH = size * 0.068
        drawRightArrow(
            centerY: size * 0.715,
            startX: arrowStartX,
            endX: arrowEndX,
            thickness: arrowThickness,
            headLen: arrowHeadLen,
            headHalfH: arrowHeadHalfH,
            color: NSColor.white.withAlphaComponent(0.96)
        )
        drawLeftArrow(
            centerY: size * 0.580,
            startX: arrowStartX,
            endX: arrowEndX,
            thickness: arrowThickness,
            headLen: arrowHeadLen,
            headHalfH: arrowHeadHalfH,
            color: NSColor(calibratedRed: 0.99, green: 0.76, blue: 0.22, alpha: 1.0)
        )

        // Lower dark tray housing GravityBar's dual quota gauge bars
        let trayRect = NSRect(x: size * 0.185, y: size * 0.175, width: size * 0.63, height: size * 0.30)
        let trayPath = NSBezierPath(roundedRect: trayRect, xRadius: size * 0.078, yRadius: size * 0.078)
        NSColor(calibratedRed: 0.04, green: 0.05, blue: 0.14, alpha: 0.42).setFill()
        trayPath.fill()
        trayPath.lineWidth = max(0.75, size * 0.011)
        NSColor.white.withAlphaComponent(0.18).setStroke()
        trayPath.stroke()

        let barX = size * 0.24
        let barW = size * 0.52
        let barH = max(1.5, size * 0.078)
        let barR = barH * 0.5
        let topBarY = size * 0.348
        let botBarY = size * 0.224

        let bars: [(y: CGFloat, frac: CGFloat, color: NSColor)] = [
            (topBarY, 0.84, NSColor(calibratedRed: 0.22, green: 0.75, blue: 0.98, alpha: 1.0)),
            (botBarY, 0.62, NSColor(calibratedRed: 0.20, green: 0.84, blue: 0.62, alpha: 1.0))
        ]
        for bar in bars {
            let track = NSBezierPath(roundedRect: NSRect(x: barX, y: bar.y, width: barW, height: barH), xRadius: barR, yRadius: barR)
            NSColor.white.withAlphaComponent(0.20).setFill()
            track.fill()

            let fill = NSBezierPath(roundedRect: NSRect(x: barX, y: bar.y, width: barW * bar.frac, height: barH), xRadius: barR, yRadius: barR)
            bar.color.setFill()
            fill.fill()
        }

        NSGraphicsContext.restoreGraphicsState()
    }

    static func renderIcon(size: CGFloat) -> NSImage {
        let image = NSImage(size: NSSize(width: size, height: size), flipped: false) { _ in
            drawArtwork(in: size)
            return true
        }
        image.isTemplate = false
        return image
    }

    static func renderPNGData(pixelSize: Int) -> Data? {
        guard let rep = NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: pixelSize,
            pixelsHigh: pixelSize,
            bitsPerSample: 8,
            samplesPerPixel: 4,
            hasAlpha: true,
            isPlanar: false,
            colorSpaceName: .deviceRGB,
            bytesPerRow: 0,
            bitsPerPixel: 0
        ) else {
            return nil
        }
        rep.size = NSSize(width: pixelSize, height: pixelSize)
        guard let ctx = NSGraphicsContext(bitmapImageRep: rep) else { return nil }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = ctx
        drawArtwork(in: CGFloat(pixelSize))
        ctx.flushGraphics()
        NSGraphicsContext.restoreGraphicsState()
        return rep.representation(using: .png, properties: [:])
    }

    static func writeIconset(to dirPath: String) -> Bool {
        let fm = FileManager.default
        let dirURL = URL(fileURLWithPath: dirPath)
        do {
            try fm.createDirectory(at: dirURL, withIntermediateDirectories: true)
            for entry in iconsetEntries {
                guard let png = renderPNGData(pixelSize: entry.pixels) else { return false }
                try png.write(to: dirURL.appendingPathComponent(entry.name))
            }
            return true
        } catch {
            return false
        }
    }
}

// MARK: - Helper Utilities

enum QuotaHelpers {
    static func monogram(for item: AccountItem) -> String {
        let source = (item.label.isEmpty ? item.email : item.label).trimmingCharacters(in: .whitespacesAndNewlines)
        let words = source.split(whereSeparator: { $0 == " " || $0 == "-" || $0 == "_" })
        if words.count >= 2, let a = words[0].first, let b = words[1].first, !source.contains("@") {
            return String([a, b]).uppercased()
        }
        if let first = source.first {
            return String(first).uppercased()
        }
        return "A"
    }

    private static func isArgonPool(_ p: QuotaPool) -> Bool {
        let g = (p.groupName ?? p.name).lowercased()
        return g.contains("argon")
    }

    private static func isGeminiGroup(_ p: QuotaPool) -> Bool {
        let g = (p.groupName ?? p.name).lowercased()
        return g.contains("gemini") && !isArgonPool(p)
    }

    private static func isClaudeGroup(_ p: QuotaPool) -> Bool {
        let g = (p.groupName ?? p.name).lowercased()
        return g.contains("claude") || g.contains("gpt")
    }

    private static func is5hWindow(_ p: QuotaPool) -> Bool {
        let w = (p.windowLabel ?? p.name).lowercased()
        return w.contains("5h") || w.contains("five hour")
    }

    private static func isWeeklyWindow(_ p: QuotaPool) -> Bool {
        let w = (p.windowLabel ?? p.name).lowercased()
        return w.contains("weekly") || w.contains("7d")
    }

    static func gemini5hPool(_ usage: UsageInfo?, requireReportedWindow: Bool = false) -> QuotaPool? {
        guard let usage = usage else { return nil }
        let exactPool = usage.pools?.first {
            isGeminiGroup($0) && is5hWindow($0) && (!requireReportedWindow || $0.reportedWindow == true)
        }
        if requireReportedWindow { return exactPool }
        if let pools = usage.pools {
            return exactPool ?? pools.first { isGeminiGroup($0) && $0.windowLabel == nil && !isWeeklyWindow($0) }
        }
        return usage.daily.flatMap { isGeminiGroup($0) && !isWeeklyWindow($0) ? $0 : nil }
    }

    static func geminiWeeklyPool(_ usage: UsageInfo?) -> QuotaPool? {
        guard let usage = usage else { return nil }
        if let pools = usage.pools {
            return pools.first { isGeminiGroup($0) && isWeeklyWindow($0) }
        }
        if let w = usage.weekly, isGeminiGroup(w) && isWeeklyWindow(w) {
            return w
        }
        return nil
    }

    static func claude5hPool(_ usage: UsageInfo?) -> QuotaPool? {
        guard let usage = usage else { return nil }
        if let pools = usage.pools {
            return pools.first { isClaudeGroup($0) && is5hWindow($0) }
                ?? pools.first { isClaudeGroup($0) && $0.windowLabel == nil && !isWeeklyWindow($0) }
        }
        if let w = usage.weekly, isClaudeGroup(w), !isWeeklyWindow(w) {
            return w
        }
        return nil
    }

    static func claudeWeeklyPool(_ usage: UsageInfo?) -> QuotaPool? {
        guard let usage = usage else { return nil }
        return usage.pools?.first(where: { isClaudeGroup($0) && isWeeklyWindow($0) })
    }

    static func argonPool(_ usage: UsageInfo?) -> QuotaPool? {
        guard let usage = usage else { return nil }
        return usage.pools?.first(where: { isArgonPool($0) })
    }

    static func findPool(_ usage: UsageInfo?, kind: String) -> QuotaPool? {
        guard let usage = usage else { return nil }
        if kind == "gemini" {
            return gemini5hPool(usage)
        }
        if kind == "claude" {
            return claude5hPool(usage) ?? claudeWeeklyPool(usage)
        }
        if kind == "gpt" {
            return usage.pools?.first(where: { $0.name.localizedCaseInsensitiveContains("gpt") })
        }
        if kind == "argon" {
            return argonPool(usage)
        }
        return nil
    }

    static func minRemaining(for usage: UsageInfo?) -> Double {
        guard let usage = usage else { return -1.0 }
        let poolVals = (usage.pools ?? []).map(\.remainingPct)
        if usage.pools != nil {
            return poolVals.min() ?? -1.0
        }
        let vals = [usage.daily?.remainingPct, usage.weekly?.remainingPct].compactMap { $0 }
        return vals.min() ?? -1.0
    }

    static func formatResetBadge(_ pool: QuotaPool?, isSyncing: Bool) -> String {
        guard let pool = pool else {
            return isSyncing ? "Syncing..." : "Unavailable"
        }
        if let short = pool.resetShort, !short.isEmpty {
            return short == "Ready" ? "Ready" : "Resets \(short)"
        }
        if let rIn = pool.resetsIn, rIn != "N/A", !rIn.isEmpty {
            return rIn == "Ready to reset" ? "Ready" : "In \(rIn)"
        }
        return "Ready"
    }

    static func formatLiveCountdown(isoStr: String?) -> String? {
        guard let isoStr = isoStr, !isoStr.isEmpty,
              let dt = NativeQuotaFetcher.parseISODate(isoStr) else {
            return nil
        }
        let diff = Int(dt.timeIntervalSinceNow)
        if diff <= 0 { return "Ready" }
        let d = diff / 86400
        let h = (diff % 86400) / 3600
        let m = (diff % 3600) / 60
        let s = diff % 60
        if d > 0 { return "\(d)d \(h)h \(m)m" }
        if h > 0 { return "\(h)h \(m)m \(s)s" }
        return "\(m)m \(s)s"
    }

    static func shortDate(_ savedAt: String) -> String {
        savedAt.split(separator: " ").first.map(String.init) ?? savedAt
    }

    static func relativeSyncText(lastUpdated: Date?, isRefreshing: Bool) -> String {
        if isRefreshing { return "Checking quotas..." }
        guard let dt = lastUpdated else { return "Press Check for quotas" }
        let secs = Int(Date().timeIntervalSince(dt))
        if secs < 60 { return "Checked just now" }
        if secs < 3600 { return "Checked \(secs / 60)m ago" }
        if secs < 86400 { return "Checked \(secs / 3600)h ago" }
        return "Checked \(secs / 86400)d ago"
    }
}

// MARK: - Optional Python Dashboard Launcher

enum DashboardBridge {
    static func openWebDashboard() {
        var candidates: [String] = []
        if let resURL = Bundle.main.resourceURL {
            candidates.append(resURL.appendingPathComponent("switcher_core.py").path)
        }
        candidates.append(contentsOf: [
            "/opt/homebrew/bin/gravitybar",
            "/usr/local/bin/gravitybar",
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin/gravitybar").path,
            "/opt/homebrew/bin/agy-switch",
            "/usr/local/bin/agy-switch",
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin/agy-switch").path,
            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("GravityBar/switcher_core.py").path
        ])
        let target = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) ?? "gravitybar"
        let task = Process()
        if target.hasSuffix(".py") {
            task.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            task.arguments = [target, "--usage-gui"]
        } else if target.hasPrefix("/") {
            task.executableURL = URL(fileURLWithPath: target)
            task.arguments = ["--usage-gui"]
        } else {
            task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            task.arguments = [target, "--usage-gui"]
        }
        try? task.run()
    }
}

// MARK: - Self-Test Runner (Headless & Isolated)

enum NativeSelfTest {
    private static func check(_ cond: Bool, _ msg: String) -> Bool {
        if !cond {
            fputs("FAIL: \(msg)\n", stderr)
            return false
        }
        return true
    }

    static func runQuotaProcessTests() async -> Int32 {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("gravitybar_quota_test_\(UUID().uuidString)")
        defer { try? fm.removeItem(at: dir) }

        do {
            try fm.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let stub = dir.appendingPathComponent("agy")
            let token = "go-keyring-base64:" + Data(#"{"token":{"access_token":"fixture"}}"#.utf8).base64EncodedString()
            let response = #"{"status":"SUCCESS","command":{"name":"usage","data":{"groups":[{"name":"Gemini","buckets":[{"window":"5h","remaining_fraction":0.5}]}]}}}"#

            func run(_ script: String, timeout: TimeInterval = 5) async throws -> String? {
                try ("#!/bin/sh\n" + script).write(to: stub, atomically: true, encoding: .utf8)
                try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: stub.path)
                switch await NativeQuotaFetcher.runQuotaCheck(tokenStr: token, knownEmail: nil, savedPlanLabel: nil, executable: stub.path, timeout: timeout) {
                case .success(let result):
                    return result.usage.daily?.remainingPct == 50 ? nil : "Unexpected quota"
                case .failure(let error):
                    return error.localizedDescription
                }
            }

            let deadlineError = try await run("trap '' TERM\nexec /bin/sleep 2", timeout: 0.1)
            let unauthorized = try await run("echo 'Authentication required' >&2\necho '\(response)'\nexit 1")
            let started = ProcessInfo.processInfo.systemUptime
            let inheritedOutput = try await run("/bin/sleep 3 &\necho '\(response)'")
            guard check(deadlineError == "The Antigravity CLI timed out.", "quota deadline stops a CLI that ignores TERM"),
                  check(unauthorized == "Sign-in expired. Add this account again.", "quota rejects success JSON from a failed CLI"),
                  check(inheritedOutput == nil && ProcessInfo.processInfo.systemUptime - started < 2,
                        "quota result does not wait for inherited output to close") else { return 1 }
            print("PASS: native quota CLI execution, timeout, and diagnostics")
            return 0
        } catch {
            fputs("FAIL: Could not run quota process fixtures: \(error)\n", stderr)
            return 1
        }
    }

    static func runAll() -> Int32 {
        let fm = FileManager.default
        let tmpRoot = fm.temporaryDirectory.appendingPathComponent("ag_native_selftest_\(UUID().uuidString)")
        let acctDir = tmpRoot.appendingPathComponent("accounts")
        let outsideDir = tmpRoot.appendingPathComponent("outside")
        let kcPath = tmpRoot.appendingPathComponent("test.keychain-db").path

        defer {
            try? fm.removeItem(at: tmpRoot)
        }

        do {
            try fm.createDirectory(at: acctDir, withIntermediateDirectories: true)
            try fm.createDirectory(at: outsideDir, withIntermediateDirectories: true)
        } catch {
            fputs("FAIL: Could not create temp dirs: \(error)\n", stderr)
            return 1
        }

        // 1. Create isolated temp keychain
        let kcCreate = Process()
        kcCreate.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        kcCreate.arguments = ["create-keychain", "-p", "testpass", kcPath]
        try? kcCreate.run()
        kcCreate.waitUntilExit()
        guard check(kcCreate.terminationStatus == 0, "create temp keychain") else { return 1 }

        let kcUnlock = Process()
        kcUnlock.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        kcUnlock.arguments = ["unlock-keychain", "-p", "testpass", kcPath]
        try? kcUnlock.run()
        kcUnlock.waitUntilExit()

        let store = NativeManifestStore(accountsDir: acctDir, keychainPath: kcPath)

        // 2. Test resolveSafeAccountPath
        let insideFile = acctDir.appendingPathComponent("inside.token").path
        let outsideFile = outsideDir.appendingPathComponent("outside.txt").path
        let symOut = acctDir.appendingPathComponent("sym_out.token").path
        try? "tok".write(toFile: insideFile, atomically: true, encoding: .utf8)
        try? "secret".write(toFile: outsideFile, atomically: true, encoding: .utf8)
        try? fm.createSymbolicLink(atPath: symOut, withDestinationPath: outsideFile)

        guard check(store.resolveSafeAccountPath(insideFile) != nil, "inside file accepted") else { return 1 }
        guard check(store.resolveSafeAccountPath(outsideFile) == nil, "outside file rejected") else { return 1 }
        guard check(store.resolveSafeAccountPath(symOut) == nil, "symlink rejected") else { return 1 }
        guard check(store.resolveSafeAccountPath(acctDir.path + "/../outside/outside.txt") == nil, "traversal rejected") else { return 1 }
        print("PASS: NativeManifestStore.resolveSafeAccountPath")

        // 3. Test secret_id validation & collision handling
        let sid1 = NativeManifestStore.makeSecretID(for: "user@example.invalid", existing: [])
        let sid2 = NativeManifestStore.makeSecretID(for: "user@example.invalid", existing: [sid1])
        guard check(NativeManifestStore.validateSecretID(sid1), "valid sid1") else { return 1 }
        guard check(NativeManifestStore.validateSecretID(sid2) && sid1 != sid2, "collision resolved") else { return 1 }
        guard check(!NativeManifestStore.validateSecretID("acct_$(id)"), "bad sid rejected") else { return 1 }
        print("PASS: secret_id validation & collision handling")

        // 4. Test NativeKeychain add / update / read on isolated keychain
        let t1 = "go-keyring-base64:dGVzdF9vbmU="
        let t2 = "go-keyring-base64:dGVzdF90d28="
        let (ok1, err1) = NativeKeychain.setActiveToken(t1, keychainPath: kcPath)
        guard check(ok1, "keychain add failed: \(err1)") else { return 1 }
        let (ok2, err2) = NativeKeychain.setActiveToken(t2, keychainPath: kcPath)
        guard check(ok2, "keychain update failed: \(err2)") else { return 1 }
        guard check(NativeKeychain.getActiveToken(keychainPath: kcPath) == t2, "keychain roundtrip") else { return 1 }
        let snapshot = NativeKeychain.clearActiveTokenForSignIn(keychainPath: kcPath)
        guard check(snapshot.previous == t2 && snapshot.cleared, "desktop sign-in can capture and clear its prior session"),
              check(NativeKeychain.getActiveToken(keychainPath: kcPath) == nil, "desktop sign-in clears the active credential"),
              check(NativeKeychain.restoreActiveTokenIfMissing(t2, keychainPath: kcPath), "cancel restores the prior credential"),
              check(NativeKeychain.restoreActiveTokenIfMissing(t1, keychainPath: kcPath), "restore accepts a newer existing session"),
              check(NativeKeychain.getActiveToken(keychainPath: kcPath) == t2, "restore preserves the newer session") else { return 1 }
        print("PASS: NativeKeychain isolated set/update/get")

        // 5. Test legacy migration, permissions, save, rename, pin, plan, remove
        try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: acctDir.path)
        let legacyFile = acctDir.appendingPathComponent("legacy.token").path
        let legacyTok = "go-keyring-base64:bGVnYWN5"
        try? legacyTok.write(toFile: legacyFile, atomically: true, encoding: .utf8)
        let seedJSON: [String: Any] = [
            "legacy@example.invalid": ["label": "legacy@example.invalid", "email": "legacy@example.invalid", "token_file": legacyFile],
            "bad_sym": ["label": "bad_sym", "email": "x@y.com", "token_file": symOut]
        ]
        if let seedData = try? JSONSerialization.data(withJSONObject: seedJSON) {
            try? seedData.write(to: store.manifestURL)
        }

        let migrated = store.loadManifest(migrate: true)
        let dirAttrs = try? fm.attributesOfItem(atPath: acctDir.path)
        let dirPerm = (dirAttrs?[.posixPermissions] as? NSNumber)?.intValue ?? 0
        guard check((dirPerm & 0o777) == 0o700, "accounts dir 0700") else { return 1 }
        guard check(!fm.fileExists(atPath: legacyFile), "legacy .token migrated and removed") else { return 1 }
        guard check(fm.fileExists(atPath: outsideFile), "outside file untouched") else { return 1 }
        guard check(migrated["legacy@example.invalid"]?.tokenFile == nil, "token_file cleared") else { return 1 }
        guard check(NativeManifestStore.validateSecretID(migrated["legacy@example.invalid"]?.secretID), "secret_id assigned") else { return 1 }

        let (svOk, svErr) = store.saveAccount(token: t2, email: "work@company.com", customLabel: "Work")
        guard check(svOk, "saveAccount failed: \(svErr)") else { return 1 }
        guard check(store.setPinned(key: "Work", pinned: true).0, "setPinned") else { return 1 }
        guard check(store.setPlanLabel(key: "Work", planLabel: "Antigravity Pro").0, "setPlanLabel") else { return 1 }
        guard check(store.renameAccount(oldKey: "Work", newKey: "Work Pro").0, "renameAccount") else { return 1 }
        let postManifest = store.loadManifest(migrate: false)
        guard check(store.findActiveAccountKey(manifest: postManifest, currentToken: t2) == "Work Pro", "active match by sha256") else { return 1 }

        // Test matching when active access_token rotates while id_token_email/refresh_token matches saved account
        let tSavedJSON = "{\"token\":{\"access_token\":\"ya29.old\",\"refresh_token\":\"1//same_rf\"},\"id_token_email\":\"rot@example.invalid\"}"
        let tRotatedJSON = "{\"token\":{\"access_token\":\"ya29.rotated_by_ide\",\"refresh_token\":\"1//same_rf\"},\"id_token_email\":\"rot@example.invalid\"}"
        let tSaved = "go-keyring-base64:" + Data(tSavedJSON.utf8).base64EncodedString()
        let tRotated = "go-keyring-base64:" + Data(tRotatedJSON.utf8).base64EncodedString()
        guard check(store.saveAccount(token: tSaved, email: "rot@example.invalid", customLabel: "rot@example.invalid").0, "save rotated fixture") else { return 1 }
        let rotManifest = store.loadManifest(migrate: false)
        guard check(store.findActiveAccountKey(manifest: rotManifest, currentToken: tRotated) == "rot@example.invalid", "active match after IDE token rotation") else { return 1 }
        guard check(store.removeAccount(key: "rot@example.invalid").0, "remove rotated fixture") else { return 1 }

        guard check(postManifest["Work Pro"]?.pinned == true && postManifest["Work Pro"]?.planLabel == "Antigravity Pro", "preserved pin & plan") else { return 1 }
        guard check(store.removeAccount(key: "Work Pro").0, "removeAccount") else { return 1 }
        print("PASS: NativeManifestStore migration, CRUD, pin, plan, permissions")

        // 6. Test best switch candidate
        let poolLow = QuotaPool(name: "Gemini", usedPct: 90, remainingPct: 10, resetsIn: "1h", resetTime: "10:00", resetShort: "10:00", resetSecs: 3600, resetIso: "", models: nil)
        let poolHigh = QuotaPool(name: "Gemini", usedPct: 10, remainingPct: 90, resetsIn: "1h", resetTime: "10:00", resetShort: "10:00", resetSecs: 3600, resetIso: "", models: nil)
        let accts = [
            AccountItem(key: "A", label: "A", email: "a@x.com", savedAt: "", storage: "keychain", isActive: true, usage: UsageInfo(email: "a@x.com", tier: "", daily: poolLow, weekly: poolLow, pools: [poolLow])),
            AccountItem(key: "B", label: "B", email: "b@x.com", savedAt: "", storage: "keychain", isActive: false, usage: UsageInfo(email: "b@x.com", tier: "", daily: poolHigh, weekly: poolHigh, pools: [poolHigh]))
        ]
        guard check(NativeQuotaFetcher.computeBestSwitchCandidate(accounts: accts, activeKey: "A") == "B", "best switch candidate") else { return 1 }
        print("PASS: best switch candidate")

        // 7. Test MenuBarGaugeRenderer
        let img = MenuBarGaugeRenderer.renderImage(geminiPct: 85.0, claudePct: 15.0)
        guard check(img.size.width == 24 && img.size.height == 18, "gauge image dimensions") else { return 1 }
        print("PASS: MenuBarGaugeRenderer")

        // 8. Test parsing of `agy -p /quota --output-format json`
        let quotaJSON = Data(#"""
        {"status":"SUCCESS","response":"","command":{"name":"usage","data":{"groups":[
          {"name":"Gemini Models","description":"Models within this group: Gemini 4 Hydrogen, Gemini 3.8 Flash","buckets":[
            {"id":"gemini-weekly","name":"Weekly Limit Remaining","window":"weekly","remaining_fraction":0.79,"reset_time":"2099-01-07T00:00:00Z"},
            {"id":"gemini-5h","name":"Five Hour Limit Remaining","window":"5h","reset_time":"2099-01-01T05:00:00Z"}]},
          {"name":"Claude and GPT models","buckets":[
            {"id":"3p-weekly","name":"Weekly Limit Remaining","window":"weekly","remaining_fraction":1,"reset_time":"1970-01-01T00:00:00Z"},
            {"id":"3p-5h","name":"Five Hour Limit Remaining","window":"5h","remaining_fraction":1,"reset_time":"1970-01-01T00:00:00Z"}]}]}}}
        """#.utf8)
        guard let parsedUsage = NativeQuotaFetcher.parseQuotaJSON(quotaJSON, resolvedEmail: "user@example.invalid", savedPlanLabel: "Pro") else {
            fputs("FAIL: parseQuotaJSON returned nil\n", stderr)
            return 1
        }
        let failedRun = Data(#"{"status":"ERROR","response":"Authentication required"}"#.utf8)
        guard check(parsedUsage.tier == "Pro", "saved plan label is the tier"),
              check(QuotaHelpers.gemini5hPool(parsedUsage)?.remainingPct == 0.0, "omitted remaining_fraction reads as 0"),
              check(QuotaHelpers.geminiWeeklyPool(parsedUsage)?.remainingPct == 79.0, "gemini weekly 79%"),
              check(QuotaHelpers.claude5hPool(parsedUsage)?.remainingPct == 100.0, "claude 5h 100%"),
              check(QuotaHelpers.claude5hPool(parsedUsage)?.resetIso?.isEmpty != false, "epoch reset means no reset scheduled"),
              check(QuotaHelpers.gemini5hPool(parsedUsage)?.models?.first == "Gemini 4 Hydrogen", "group models parsed"),
              check(NativeQuotaFetcher.parseQuotaJSON(failedRun, resolvedEmail: nil, savedPlanLabel: nil) == nil, "failed CLI run yields no quota"),
              check(NativeQuotaFetcher.parseQuotaJSON(Data("not json".utf8), resolvedEmail: nil, savedPlanLabel: nil) == nil, "garbage yields no quota") else { return 1 }

        let qEnv = NativeQuotaFetcher.quotaEnvironment(home: "/tmp/q", shimDir: "/tmp/q/bin", baseEnv: ["SSH_CONNECTION": "x", "GEMINI_API_KEY": "bad", "LANG": "en_US.UTF-8"])
        let sampleCred = "go-keyring-base64:" + Data(#"{"token":{"access_token":"a","refresh_token":"r"},"id_token_email":"q@example.invalid"}"#.utf8).base64EncodedString()
        guard check(qEnv["HOME"] == "/tmp/q" && qEnv["BROWSER"] == "/tmp/q/bin/open", "quota run isolates the profile and sets a browser shim"),
              check(qEnv["PATH"]?.hasPrefix("/tmp/q/bin:") == true, "quota run uses the no-op open shim"),
              check(qEnv["SSH_CONNECTION"] == nil && qEnv["GEMINI_API_KEY"] == nil && qEnv["LANG"] != nil, "quota run drops unrelated env"),
              check(qEnv["AGY_CLI_FORCE_FILE_TOKEN_STORAGE"] == "1", "quota run uses agy file token storage"),
              check(NativeQuotaFetcher.credentialFileData(from: sampleCred) != nil, "stored credential converts to CLI file"),
              check(NativeQuotaFetcher.credentialFileData(from: "garbage") == nil, "bad credential is rejected"),
              check(NativeQuotaFetcher.emailFromToken(sampleCred) == "q@example.invalid", "email read locally from credential") else { return 1 }
        print("PASS: official CLI quota parsing and isolated environment")

        // 9. Test OfficialAgyLoginSession isolated env + credential normalization
        let testEnv = OfficialAgyLoginSession.buildIsolatedEnvironment(
            baseEnv: ["PATH": "/usr/bin", "GEMINI_API_KEY": "bad", "DISPLAY": ":0", "SSH_CONNECTION": "1 2 3 4"],
            profilePath: "/tmp/ag_prof",
            tempPath: "/tmp/ag_prof/tmp"
        )
        guard check(testEnv["GEMINI_API_KEY"] == nil && testEnv["DISPLAY"] == nil, "stripped env vars"),
              check(testEnv["AGY_CLI_FORCE_FILE_TOKEN_STORAGE"] == "1", "agy file token storage"),
              check(testEnv["SSH_CONNECTION"] == nil, "no fake SSH session") else { return 1 }

        let flatData = Data("{\"access_token\":\"ya29.test\",\"refresh_token\":\"1//rf\"}".utf8)
        let normFlat = OfficialAgyLoginSession.normalizeCredentialData(flatData, fallbackEmail: "u@example.invalid")
        let wrapData = Data("{\"token\":{\"access_token\":\"ya29.test2\"}}".utf8)
        let normWrap = OfficialAgyLoginSession.normalizeCredentialData(wrapData)
        guard check(normFlat?.hasPrefix("go-keyring-base64:") == true, "normalize flat acp_token.json"),
              check(normWrap?.hasPrefix("go-keyring-base64:") == true, "normalize envelope acp_token.json") else { return 1 }
        print("PASS: OfficialAgyLoginSession isolated env & credential normalization")

        let cliProfile = tmpRoot.appendingPathComponent("antigravity-acp")
        do {
            try fm.createDirectory(at: cliProfile, withIntermediateDirectories: true)
            try Data(#"{"refresh_token":"fixture"}"#.utf8)
                .write(to: cliProfile.appendingPathComponent("acp_token.json"))
            try wrapData.write(to: cliProfile.appendingPathComponent("antigravity-oauth-token"))
        } catch {
            fputs("FAIL: Could not write CLI credential fixtures: \(error)\n", stderr)
            return 1
        }
        let cliToken = OfficialAgyLoginSession.readIsolatedCredential(in: cliProfile)
        guard check(cliToken != nil && cliToken == normWrap, "read the extensionless CLI credential") else { return 1 }
        print("PASS: OfficialAgyLoginSession extensionless credential lookup")

        // 10. Test AppIconRenderer custom bundle icon dimensions
        let appIconImg = AppIconRenderer.renderIcon(size: 128)
        guard check(appIconImg.size == NSSize(width: 128, height: 128), "AppIconRenderer dimensions"),
              check(AppIconRenderer.renderPNGData(pixelSize: 64) != nil, "AppIconRenderer PNG output") else { return 1 }
        print("PASS: AppIconRenderer custom squircle logo")

        // 11. Refreshed credentials only replace their own unchanged saved entry
        guard check(NativeKeychain.setActiveToken(t2, keychainPath: kcPath).0, "set second active credential") else { return 1 }
        guard check(store.saveAccount(token: t1, email: "refresh@example.invalid", customLabel: "Refresh Test").0,
                    "save refresh test credential") else { return 1 }
        let refreshed = "go-keyring-base64:dGVzdF9yZWZyZXNoZWQ="
        store.persistRefreshedToken(accountKey: "Refresh Test", newToken: refreshed, replacingSavedToken: t1)
        store.persistRefreshedToken(accountKey: "Refresh Test", newToken: t1, replacingSavedToken: t1)
        let savedEntry = store.loadManifest(migrate: false)["Refresh Test"]
        let savedToken = savedEntry.flatMap(store.getAccountToken)
        guard check(savedToken == refreshed && NativeKeychain.getActiveToken(keychainPath: kcPath) == t2,
                    "CLI refresh saves only to its own unchanged credential"),
              check(!store.saveAccount(token: t2, email: "other@example.invalid", customLabel: "Refresh Test").0,
                    "another account cannot replace a saved label") else { return 1 }
        print("PASS: credential refresh preserves active account")

        guard let savedEntry else { return 1 }
        guard check(store.renameAccount(oldKey: "Refresh Test", newKey: "Renamed").0, "rename during quota check") else { return 1 }
        let recordedKey = try? store.recordQuota(key: "Refresh Test", entry: savedEntry, token: refreshed, usage: parsedUsage, updatedToken: nil)
        let renamedCache = store.loadUsageCache()
        guard check(recordedKey == "Renamed" && renamedCache["Renamed"]?.checkedAt != nil && renamedCache["Refresh Test"] == nil,
                    "quota follows a renamed account and records a timestamp") else { return 1 }
        guard check(store.removeAccount(key: "Renamed").0, "remove during quota check") else { return 1 }
        let removedKey = try? store.recordQuota(key: "Refresh Test", entry: savedEntry, token: refreshed, usage: parsedUsage, updatedToken: nil)
        guard check(removedKey == nil && store.loadUsageCache()["Renamed"] == nil,
                    "quota cannot recreate a removed cache entry") else { return 1 }
        print("PASS: quota cache respects concurrent account changes")

        // 12. Test FieldEditorShortcut Latin, Persian, and Control+V shortcuts
        let shortcutChecks = [
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "v", keyCode: 9, modifierFlags: .command) == .paste, "English Cmd+V resolves to paste"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "v", keyCode: 9, modifierFlags: .control) == .paste, "English Ctrl+V resolves to paste"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "\u{16}", keyCode: 9, modifierFlags: .control) == .paste, "Control-char Ctrl+V resolves to paste"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "ر", keyCode: 9, modifierFlags: .command) == .paste, "Persian Cmd+V resolves to paste"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "ر", keyCode: 9, modifierFlags: .control) == .paste, "Persian Ctrl+V resolves to paste"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "ش", keyCode: 0, modifierFlags: .command) == .selectAll, "Persian Cmd+A resolves to selectAll"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "ز", keyCode: 8, modifierFlags: .command) == .copy, "Persian Cmd+C resolves to copy"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "ط", keyCode: 7, modifierFlags: .command) == .cut, "Persian Cmd+X resolves to cut"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "ظ", keyCode: 6, modifierFlags: .command) == .undo, "Persian Cmd+Z resolves to undo"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "ك", keyCode: 6, modifierFlags: [.command, .shift]) == .redo, "Persian Cmd+Shift+Z resolves to redo"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "Z", keyCode: 6, modifierFlags: [.command, .shift]) == .redo, "English Cmd+Shift+Z resolves to redo"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "k", keyCode: 9, modifierFlags: .command) == nil, "Dvorak Cmd+K at keyCode 9 does not trigger paste"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "v", keyCode: 47, modifierFlags: .command) == .paste, "Dvorak Cmd+V at keyCode 47 resolves to paste"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: ".", keyCode: 9, modifierFlags: .command) == nil, "Dvorak Cmd+. at keyCode 9 does not trigger paste"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "a", keyCode: 0, modifierFlags: .control) == nil, "Ctrl+A stays native line-start navigation"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "v", keyCode: 9, modifierFlags: [.command, .option]) == nil, "Cmd+Opt+V is ignored"),
            check(FieldEditorShortcut.resolve(charactersIgnoringModifiers: "v", keyCode: 9, modifierFlags: []) == nil, "Plain v is ignored")
        ]
        guard shortcutChecks.allSatisfy({ $0 }) else { return 1 }
        print("PASS: FieldEditorShortcut Latin, Persian, and Control+V shortcuts")

        return 0
    }
}
