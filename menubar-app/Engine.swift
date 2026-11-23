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
                    pools: existing.pools
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

        if let key = accountKey {
            var manifest = _loadManifestUnlocked(migrate: false)
            if var entry = manifest[key], let sid = entry.secretID, Self.validateSecretID(sid),
               replacingSavedToken == nil || getAccountToken(entry) == replacingSavedToken {
                let (ok, _) = NativeKeychain.set(service: NativeKeychain.savedService, account: sid, secret: cleanToken, keychainPath: keychainPath)
                let rb = ok ? NativeKeychain.get(service: NativeKeychain.savedService, account: sid, keychainPath: keychainPath) : nil
                if ok && rb?.trimmingCharacters(in: .whitespacesAndNewlines) == cleanToken {
                    entry.tokenSHA256 = Self.sha256Hex(cleanToken)
                    manifest[key] = entry
                    try? _saveManifestUnlocked(manifest)
                }
            }
        }
    }

    func loadUsageCache() -> (data: [String: UsageInfo], mtime: Date?) {
        lock.lock()
        defer { lock.unlock() }
        let fm = FileManager.default
        guard fm.fileExists(atPath: cacheURL.path) else { return ([:], nil) }
        let attrs = try? fm.attributesOfItem(atPath: cacheURL.path)
        let mtime = attrs?[.modificationDate] as? Date
        guard let raw = try? Data(contentsOf: cacheURL),
              let decoded = try? JSONDecoder().decode([String: UsageInfo].self, from: raw) else {
            return ([:], mtime)
        }
        return (decoded, mtime)
    }

    func saveUsageCache(_ cache: [String: UsageInfo]) {
        lock.lock()
        defer { lock.unlock() }
        if let data = try? JSONEncoder().encode(cache) {
            try? writeSecureFile(url: cacheURL, data: data)
        }
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

// MARK: - Native Quota Fetcher & OAuth Token Refresh

enum NativeQuotaFetcher {
    private static let cidBytes: [UInt8] = [49, 48, 55, 49, 48, 48, 54, 48, 54, 48, 53, 57, 49, 45, 116, 109, 104, 115, 115, 105, 110, 50, 104, 50, 49, 108, 99, 114, 101, 50, 51, 53, 118, 116, 111, 108, 111, 106, 104, 52, 103, 52, 48, 51, 101, 112, 46, 97, 112, 112, 115, 46, 103, 111, 111, 103, 108, 101, 117, 115, 101, 114, 99, 111, 110, 116, 101, 110, 116, 46, 99, 111, 109]
    private static let secBytes: [UInt8] = [71, 79, 67, 83, 80, 88, 45, 75, 53, 56, 70, 87, 82, 52, 56, 54, 76, 100, 76, 74, 49, 109, 76, 66, 56, 115, 88, 67, 52, 122, 54, 113, 68, 65, 102]

    static var clientID: String { String(decoding: cidBytes, as: UTF8.self) }
    static var clientSecret: String { String(decoding: secBytes, as: UTF8.self) }

    private static let session: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 4.0
        cfg.timeoutIntervalForResource = 5.5
        return URLSession(configuration: cfg)
    }()

    static func formEscape(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

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

    private static let dailyCloudCodeBase = "https://daily-cloudcode-pa.googleapis.com"
    private static let prodCloudCodeBase = "https://cloudcode-pa.googleapis.com"
    private static let minimumClientVersion = "2.25.0"
    private static let defaultFallbackVersion = "2.33.0"
    private static let nodeClientUA = "google-api-nodejs-client/10.3.0"
    private static let nodeAPIClient = "gl-node/22.21.1"
    private static let placeholderProject = "aicode-consumers"

    private static func compareDottedVersions(_ a: String, _ b: String) -> Int {
        func parseParts(_ v: String) -> [Int]? {
            let core = v.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "-", maxSplits: 1).first.map(String.init) ?? ""
            let rawParts = core.split(separator: ".")
            guard !rawParts.isEmpty else { return nil }
            var nums: [Int] = []
            for p in rawParts {
                guard let n = Int(p), n >= 0 else { return nil }
                nums.append(n)
            }
            return nums
        }
        guard let pa = parseParts(a) else { return parseParts(b) == nil ? 0 : -1 }
        guard let pb = parseParts(b) else { return 1 }
        let count = max(pa.count, pb.count)
        for i in 0..<count {
            let x = i < pa.count ? pa[i] : 0
            let y = i < pb.count ? pb[i] : 0
            if x != y { return x < y ? -1 : 1 }
        }
        return 0
    }

    static func detectClientVersion() -> String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let plistPaths = [
            "/Applications/Antigravity.app/Contents/Info.plist",
            "/Applications/Antigravity IDE.app/Contents/Info.plist",
            "\(home)/Applications/Antigravity.app/Contents/Info.plist"
        ]
        for path in plistPaths {
            if let dict = NSDictionary(contentsOfFile: path),
               let v = (dict["CFBundleShortVersionString"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
               !v.isEmpty {
                return compareDottedVersions(v, minimumClientVersion) < 0 ? minimumClientVersion : v
            }
        }
        return defaultFallbackVersion
    }

    private static func clientMetadata(version: String) -> [String: Any] {
        [
            "ideName": "antigravity",
            "ideType": "ANTIGRAVITY",
            "ideVersion": version,
            "pluginVersion": version,
            "platform": "DARWIN_ARM64",
            "updateChannel": "stable",
            "pluginType": "GEMINI"
        ]
    }

    private static func assistHeaders(version: String) -> [String: String] {
        [
            "User-Agent": "antigravity/\(version) darwin/arm64 \(nodeClientUA)",
            "x-goog-api-client": nodeAPIClient
        ]
    }

    // Identifies the desktop hub subclient so Cloud Code exposes the separate Gemini 4 Argon pool.
    static func quotaHeaders(version: String) -> [String: String] {
        [
            "User-Agent": "antigravity/hub/\(version) (aidev_client; os_type=darwin; arch=arm64)"
        ]
    }

    private static func resolveQuotaTarget(from codeAssistData: [String: Any]?) -> (baseURL: String, body: Data) {
        var proj = ""
        if let rawProj = codeAssistData?["cloudaicompanionProject"] as? String {
            proj = rawProj.trimmingCharacters(in: .whitespacesAndNewlines)
        } else if let projDict = codeAssistData?["cloudaicompanionProject"] as? [String: Any],
                  let pid = projDict["id"] as? String {
            proj = pid.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        if proj == placeholderProject {
            proj = ""
        }

        var usesGcpTos = false
        if let currentTier = codeAssistData?["currentTier"] as? [String: Any] {
            if (currentTier["usesGcpTos"] as? Bool) == true {
                usesGcpTos = true
            } else if let currentId = currentTier["id"] as? String,
                      let allowed = codeAssistData?["allowedTiers"] as? [[String: Any]] {
                usesGcpTos = allowed.contains { ($0["id"] as? String) == currentId && ($0["usesGcpTos"] as? Bool) == true }
            }
        }

        let base = (usesGcpTos && !proj.isEmpty) ? prodCloudCodeBase : dailyCloudCodeBase
        let bodyObj: [String: Any] = proj.isEmpty ? [:] : ["project": proj]
        let bodyData = (try? JSONSerialization.data(withJSONObject: bodyObj)) ?? Data("{}".utf8)
        return (base, bodyData)
    }

    private static func postCloudCode(
        _ endpoint: String,
        baseURL: String = dailyCloudCodeBase,
        body: Data = Data("{}".utf8),
        headers: [String: String] = [:],
        accessToken: String
    ) async -> (status: Int, data: Data?) {
        let trimmedBase = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        guard let url = URL(string: "\(trimmedBase)/v1internal:\(endpoint)") else {
            return (-1, nil)
        }
        var req = URLRequest(url: url, timeoutInterval: 4.5)
        req.httpMethod = "POST"
        for (k, v) in headers {
            req.setValue(v, forHTTPHeaderField: k)
        }
        req.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue(endpoint == "streamGenerateContent?alt=sse" ? "text/event-stream" : "application/json",
                     forHTTPHeaderField: "Accept")
        req.httpBody = body

        guard let (data, resp) = try? await session.data(for: req),
              let http = resp as? HTTPURLResponse else {
            return (-1, nil)
        }
        return (http.statusCode, data)
    }

    static func detectTierName(
        modelsData: [String: Any],
        codeAssistData: [String: Any]? = nil,
        savedPlanLabel: String?
    ) -> String {
        if let saved = savedPlanLabel?.trimmingCharacters(in: .whitespacesAndNewlines), !saved.isEmpty {
            return saved
        }
        var rawCandidates: [Any?] = []
        if let paidTier = codeAssistData?["paidTier"] {
            rawCandidates.append(paidTier)
        }
        rawCandidates.append(contentsOf: [
            modelsData["userTier"],
            modelsData["tier"],
            modelsData["plan"],
            modelsData["planType"],
            modelsData["subscriptionTier"]
        ])
        if let userStatus = modelsData["userStatus"] as? [String: Any],
           let planStatus = userStatus["planStatus"] as? [String: Any],
           let planInfo = planStatus["planInfo"] as? [String: Any] {
            rawCandidates.append(planInfo["planName"])
            rawCandidates.append(planInfo["tierName"])
        }
        if let currentTier = codeAssistData?["currentTier"] {
            rawCandidates.append(currentTier)
        }

        for item in rawCandidates {
            var strVal: String?
            if let dict = item as? [String: Any] {
                strVal = (dict["displayName"] as? String)
                    ?? (dict["name"] as? String)
                    ?? (dict["tierName"] as? String)
                    ?? (dict["planName"] as? String)
                    ?? (dict["id"] as? String)
            } else if let s = item as? String {
                strVal = s
            }
            if let trimmed = strVal?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty {
                switch trimmed.uppercased() {
                case "FREE", "FREE-TIER", "FREE_TIER", "STANDARD", "STANDARD-TIER", "DEFAULT": return "Free"
                case "PRO", "INDIVIDUAL_PRO", "GOOGLE_AI_PRO": return "Antigravity Pro"
                case "G1-PRO-TIER", "G1_PRO_TIER": return "Google AI Pro"
                case "ULTRA", "GOOGLE_AI_ULTRA": return "Antigravity Ultra"
                case "G1-ULTRA-TIER", "G1_ULTRA_TIER": return "Google AI Ultra"
                case "TEAMS", "ENTERPRISE", "BUSINESS": return "Antigravity Teams"
                default: return trimmed
                }
            }
        }
        return ""
    }

    static func extractEmailFromToken(_ tokenStr: String) async -> String? {
        guard tokenStr.hasPrefix("go-keyring-base64:") else { return nil }
        let b64 = String(tokenStr.dropFirst("go-keyring-base64:".count))
        guard let decoded = Data(base64Encoded: b64),
              let root = try? JSONSerialization.jsonObject(with: decoded) as? [String: Any],
              let tObj = root["token"] as? [String: Any],
              let accessToken = tObj["access_token"] as? String, !accessToken.isEmpty else {
            return nil
        }
        return await fetchUserInfoEmail(accessToken: accessToken)
    }

    private static func fetchUserInfoEmail(accessToken: String) async -> String? {
        guard let url = URL(string: "https://www.googleapis.com/oauth2/v3/userinfo") else { return nil }
        var req = URLRequest(url: url, timeoutInterval: 2.5)
        req.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        guard let (data, resp) = try? await session.data(for: req),
              let http = resp as? HTTPURLResponse, http.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return json["email"] as? String
    }

    private static func refreshAccessToken(refreshToken: String) async -> (accessToken: String, expiresIn: Int?)? {
        guard let url = URL(string: "https://oauth2.googleapis.com/token") else { return nil }
        var req = URLRequest(url: url, timeoutInterval: 4.0)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        let body = [
            "client_id=\(formEscape(clientID))",
            "client_secret=\(formEscape(clientSecret))",
            "grant_type=refresh_token",
            "refresh_token=\(formEscape(refreshToken))"
        ].joined(separator: "&")
        req.httpBody = body.data(using: .utf8)

        guard let (data, resp) = try? await session.data(for: req),
              let http = resp as? HTTPURLResponse, http.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let access = json["access_token"] as? String, !access.isEmpty else {
            return nil
        }
        let exp = (json["expires_in"] as? NSNumber)?.intValue
        return (access, exp)
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

    static func fetchUsage(
        tokenStr: String,
        knownEmail: String?,
        savedPlanLabel: String?,
        onTokenRefreshed: ((String) -> Void)? = nil
    ) async -> UsageInfo? {
        guard tokenStr.hasPrefix("go-keyring-base64:") else { return nil }
        let b64 = String(tokenStr.dropFirst("go-keyring-base64:".count))
        guard let rawData = Data(base64Encoded: b64),
              var rootObj = try? JSONSerialization.jsonObject(with: rawData) as? [String: Any],
              var tObj = rootObj["token"] as? [String: Any],
              var accessToken = tObj["access_token"] as? String else {
            return nil
        }
        let refreshToken = tObj["refresh_token"] as? String

        var summaryJSON: [String: Any]?
        var modelsJSON: [String: Any]?
        var codeAssistJSON: [String: Any]?
        var refreshedTokenString: String?
        let clientVersion = detectClientVersion()

        for attempt in 0..<2 {
            let tokenForAttempt = accessToken
            let lcaBodyObj: [String: Any] = [
                "metadata": clientMetadata(version: clientVersion),
                "mode": "FULL_ELIGIBILITY_CHECK"
            ]
            let lcaBody = (try? JSONSerialization.data(withJSONObject: lcaBodyObj))
                ?? Data("{\"metadata\":{\"ideType\":\"ANTIGRAVITY\"},\"mode\":\"FULL_ELIGIBILITY_CHECK\"}".utf8)
            let lcaRes = await postCloudCode(
                "loadCodeAssist",
                baseURL: dailyCloudCodeBase,
                body: lcaBody,
                headers: assistHeaders(version: clientVersion),
                accessToken: tokenForAttempt
            )
            if lcaRes.status == 200, let ld = lcaRes.data,
               let parsedLca = try? JSONSerialization.jsonObject(with: ld) as? [String: Any] {
                codeAssistJSON = parsedLca
            }

            if !(attempt == 0 && lcaRes.status == 401) {
                let target = resolveQuotaTarget(from: codeAssistJSON)
                let qHeaders = quotaHeaders(version: clientVersion)
                async let sumTask = postCloudCode(
                    "retrieveUserQuotaSummary",
                    baseURL: target.baseURL,
                    body: target.body,
                    headers: qHeaders,
                    accessToken: tokenForAttempt
                )
                async let modTask = postCloudCode(
                    "fetchAvailableModels",
                    baseURL: target.baseURL,
                    body: target.body,
                    headers: qHeaders,
                    accessToken: tokenForAttempt
                )
                let (sumRes, modRes) = await (sumTask, modTask)

                if sumRes.status == 200, let sd = sumRes.data,
                   let parsedSum = try? JSONSerialization.jsonObject(with: sd) as? [String: Any] {
                    summaryJSON = parsedSum
                }
                if modRes.status == 200, let md = modRes.data,
                   let parsedMod = try? JSONSerialization.jsonObject(with: md) as? [String: Any] {
                    modelsJSON = parsedMod
                }

                if summaryJSON != nil || modelsJSON != nil {
                    break
                }
            }

            if attempt == 0, let rf = refreshToken, !rf.isEmpty,
               let refreshed = await refreshAccessToken(refreshToken: rf) {
                accessToken = refreshed.accessToken
                tObj["access_token"] = refreshed.accessToken
                if let expSecs = refreshed.expiresIn {
                    let expDate = Date().addingTimeInterval(TimeInterval(expSecs))
                    let fmt = ISO8601DateFormatter()
                    fmt.formatOptions = [.withInternetDateTime]
                    tObj["expiry"] = fmt.string(from: expDate)
                }
                rootObj["token"] = tObj
                if let reencoded = try? JSONSerialization.data(withJSONObject: rootObj) {
                    refreshedTokenString = "go-keyring-base64:" + reencoded.base64EncodedString()
                }
            } else {
                return nil
            }
        }

        guard summaryJSON != nil || modelsJSON != nil else { return nil }

        if let rfTok = refreshedTokenString {
            onTokenRefreshed?(rfTok)
        }

        var resolvedEmail = knownEmail
        if resolvedEmail == nil || resolvedEmail?.isEmpty == true {
            resolvedEmail = await fetchUserInfoEmail(accessToken: accessToken)
        }

        return parseUsage(
            summaryJSON: summaryJSON,
            modelsJSON: modelsJSON,
            codeAssistJSON: codeAssistJSON,
            resolvedEmail: resolvedEmail,
            savedPlanLabel: savedPlanLabel
        )
    }

    static func extractRawProjectID(from codeAssistData: [String: Any]?) -> String {
        if let rawProj = codeAssistData?["cloudaicompanionProject"] as? String {
            let clean = rawProj.trimmingCharacters(in: .whitespacesAndNewlines)
            return clean == placeholderProject ? "" : clean
        }
        if let projDict = codeAssistData?["cloudaicompanionProject"] as? [String: Any],
           let pid = projDict["id"] as? String {
            let clean = pid.trimmingCharacters(in: .whitespacesAndNewlines)
            return clean == placeholderProject ? "" : clean
        }
        return ""
    }

    static func warmupGeminiModels(from modelsJSON: [String: Any]?) -> [(modelId: String, displayName: String)] {
        let models = modelsJSON?["models"] as? [String: Any] ?? [:]
        var ranked: [Int: (String, String)] = [:]
        for id in models.keys.sorted() {
            guard let info = models[id] as? [String: Any], info["isInternal"] as? Bool != true else { continue }
            let display = (info["displayName"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            let name = (id + " " + display).lowercased()
            guard name.contains("gemini"),
                  !["argon", "claude", "gpt", "tab_"].contains(where: name.contains) else { continue }

            let priority: Int
            if name.contains("hydrogen") {
                priority = 0
            } else if !name.contains("flash") {
                continue
            } else if name.contains("3.8") {
                priority = name.contains("low") || name.contains("lite") ? 1 : 2
            } else {
                priority = 3
            }
            if ranked[priority] == nil {
                ranked[priority] = (id, display.isEmpty ? id : display)
            }
        }
        return ranked.keys.sorted().compactMap { ranked[$0] }
    }

    static func hasWarmupGeneration(_ data: Data?, streaming: Bool) -> Bool {
        func hasCandidates(_ data: Data) -> Bool {
            guard let body = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  body["error"] == nil else { return false }
            let response = body["response"] as? [String: Any] ?? body
            return (response["candidates"] as? [[String: Any]])?.isEmpty == false
        }

        guard let data else { return false }
        if !streaming { return hasCandidates(data) }
        guard let text = String(data: data, encoding: .utf8) else { return false }
        return text.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n\n").contains { event in
            let json = event.split(separator: "\n")
                .filter { $0.hasPrefix("data:") }
                .map { $0.dropFirst(5) }
                .joined(separator: "\n")
            return hasCandidates(Data(json.utf8))
        }
    }

    static func sendGeminiWarmupPing(
        tokenStr: String,
        onTokenRefreshed: ((String) -> Void)? = nil
    ) async -> (ok: Bool, modelDisplay: String, error: String?) {
        guard tokenStr.hasPrefix("go-keyring-base64:") else {
            return (false, "", "Invalid credential format")
        }
        let b64 = String(tokenStr.dropFirst("go-keyring-base64:".count))
        guard let rawData = Data(base64Encoded: b64),
              var rootObj = try? JSONSerialization.jsonObject(with: rawData) as? [String: Any],
              var tObj = rootObj["token"] as? [String: Any],
              var accessToken = tObj["access_token"] as? String else {
            return (false, "", "Malformed credential payload")
        }
        let refreshToken = tObj["refresh_token"] as? String
        let clientVersion = detectClientVersion()

        var codeAssistJSON: [String: Any]?
        var refreshedTokenString: String?
        var loadStatus = -1

        for attempt in 0..<2 {
            let lcaBodyObj: [String: Any] = [
                "metadata": clientMetadata(version: clientVersion),
                "mode": "FULL_ELIGIBILITY_CHECK"
            ]
            let lcaBody = (try? JSONSerialization.data(withJSONObject: lcaBodyObj))
                ?? Data("{\"metadata\":{\"ideType\":\"ANTIGRAVITY\"},\"mode\":\"FULL_ELIGIBILITY_CHECK\"}".utf8)
            let lcaRes = await postCloudCode(
                "loadCodeAssist",
                baseURL: dailyCloudCodeBase,
                body: lcaBody,
                headers: assistHeaders(version: clientVersion),
                accessToken: accessToken
            )
            if lcaRes.status == 401 && attempt == 0 {
                if let rf = refreshToken, !rf.isEmpty,
                   let refreshed = await refreshAccessToken(refreshToken: rf) {
                    accessToken = refreshed.accessToken
                    tObj["access_token"] = refreshed.accessToken
                    if let expSecs = refreshed.expiresIn {
                        let expDate = Date().addingTimeInterval(TimeInterval(expSecs))
                        let fmt = ISO8601DateFormatter()
                        fmt.formatOptions = [.withInternetDateTime]
                        tObj["expiry"] = fmt.string(from: expDate)
                    }
                    rootObj["token"] = tObj
                    if let reencoded = try? JSONSerialization.data(withJSONObject: rootObj) {
                        refreshedTokenString = "go-keyring-base64:" + reencoded.base64EncodedString()
                    }
                    continue
                } else {
                    return (false, "", "OAuth token expired and refresh failed")
                }
            }
            if lcaRes.status == 200, let ld = lcaRes.data,
               let parsed = try? JSONSerialization.jsonObject(with: ld) as? [String: Any] {
                codeAssistJSON = parsed
            }
            loadStatus = lcaRes.status
            break
        }

        if let rfTok = refreshedTokenString {
            onTokenRefreshed?(rfTok)
        }
        guard let codeAssistJSON else {
            return (false, "", "Could not load Cloud Code account (status \(loadStatus))")
        }

        let target = resolveQuotaTarget(from: codeAssistJSON)
        let rawProject = extractRawProjectID(from: codeAssistJSON)
        let modRes = await postCloudCode(
            "fetchAvailableModels",
            baseURL: target.baseURL,
            body: target.body,
            headers: quotaHeaders(version: clientVersion),
            accessToken: accessToken
        )
        guard modRes.status == 200, let modelData = modRes.data,
              let models = try? JSONSerialization.jsonObject(with: modelData) as? [String: Any] else {
            return (false, "", "Could not fetch Cloud Code models (status \(modRes.status))")
        }
        let candidates = warmupGeminiModels(from: models)
        guard let first = candidates.first else {
            return (false, "", "No eligible Gemini warmup model was advertised")
        }

        let headers = assistHeaders(version: clientVersion)
        var endpoint = "generateContent"
        var lastStatus = -1
        for candidate in candidates {
            var payload: [String: Any] = [
                "model": candidate.modelId,
                "request": [
                    "contents": [["role": "user", "parts": [["text": "ok"]]]],
                    "generationConfig": [
                        "maxOutputTokens": 1,
                        "temperature": 0.0,
                        "thinkingConfig": ["thinkingLevel": "LOW"]
                    ]
                ]
            ]
            if !rawProject.isEmpty { payload["project"] = rawProject }
            guard let data = try? JSONSerialization.data(withJSONObject: payload) else {
                return (false, candidate.displayName, "Could not encode warmup request")
            }

            func post(_ method: String) async -> (status: Int, data: Data?) {
                await postCloudCode(method, baseURL: target.baseURL, body: data, headers: headers, accessToken: accessToken)
            }
            var streaming = endpoint != "generateContent"
            var reply = await post(endpoint)
            if !streaming && [404, 405, 501].contains(reply.status) {
                let streamEndpoint = "streamGenerateContent?alt=sse"
                reply = await post(streamEndpoint)
                streaming = true
                if reply.status != 404 { endpoint = streamEndpoint }
            }
            lastStatus = reply.status
            if reply.status == 200 {
                if hasWarmupGeneration(reply.data, streaming: streaming) {
                    return (true, candidate.displayName, nil)
                }
                return (false, candidate.displayName, "Cloud Code did not confirm generation")
            }
            if reply.status != 400 && reply.status != 404 {
                return (false, candidate.displayName, "Cloud Code returned status \(reply.status)")
            }
        }
        return (false, first.displayName, "Cloud Code returned status \(lastStatus)")
    }

    static func parseUsage(
        summaryJSON: [String: Any]?,
        modelsJSON: [String: Any]?,
        codeAssistJSON: [String: Any]?,
        resolvedEmail: String?,
        savedPlanLabel: String?
    ) -> UsageInfo? {
        guard summaryJSON != nil || modelsJSON != nil else { return nil }
        let modelsData = modelsJSON ?? [:]
        let tierName = detectTierName(modelsData: modelsData, codeAssistData: codeAssistJSON, savedPlanLabel: savedPlanLabel)

        func fallbackGroupName(forBucketID bid: String) -> String {
            let low = bid.lowercased()
            if low.contains("argon") { return "Gemini 4 Argon" }
            if low.contains("claude") || low.contains("3p") || low.contains("gpt") { return "Claude and GPT models" }
            if low.contains("gemini") { return "Gemini Models" }
            return "Models"
        }

        var pools: [QuotaPool] = []

        if let groups = summaryJSON?["groups"] as? [[String: Any]], !groups.isEmpty {
            for grp in groups {
                let dispGroup = (grp["displayName"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                let groupModels = parseGroupModels(description: grp["description"] as? String)
                let buckets = (grp["buckets"] as? [[String: Any]]) ?? []
                var grpPools: [QuotaPool] = []

                for b in buckets {
                    let bid = (b["bucketId"] as? String) ?? ""
                    let rawGroupName = !dispGroup.isEmpty ? dispGroup : fallbackGroupName(forBucketID: bid)
                    let winLabel = parseWindowLabel(
                        windowRaw: b["window"] as? String,
                        bucketId: bid,
                        displayName: b["displayName"] as? String
                    )
                    // Cloud Code omits remainingFraction in proto3 JSON when 0 remaining (exhausted).
                    let rem = (b["remainingFraction"] as? NSNumber)?.doubleValue ?? 0.0
                    let resetTime = b["resetTime"] as? String
                    grpPools.append(makeQuotaPool(
                        name: "\(rawGroupName) — \(winLabel)",
                        groupName: rawGroupName,
                        windowLabel: winLabel,
                        rem: rem,
                        resetTime: resetTime,
                        models: groupModels,
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
        }

        // Check top-level summary buckets (if any standalone bucket is returned outside groups)
        if let topBuckets = summaryJSON?["buckets"] as? [[String: Any]] {
            for b in topBuckets {
                let disp = (b["displayName"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                let bid = (b["bucketId"] as? String) ?? ""
                let rawName = !disp.isEmpty ? disp : fallbackGroupName(forBucketID: bid)
                let alreadyExists = pools.contains(where: { ($0.groupName ?? $0.name).localizedCaseInsensitiveCompare(rawName) == .orderedSame })
                if alreadyExists { continue }
                let winLabel = parseWindowLabel(
                    windowRaw: b["window"] as? String,
                    bucketId: bid,
                    displayName: disp
                )
                let rem = (b["remainingFraction"] as? NSNumber)?.doubleValue ?? 0.0
                let resetTime = b["resetTime"] as? String
                pools.append(makeQuotaPool(
                    name: "\(rawName) — \(winLabel)",
                    groupName: rawName,
                    windowLabel: winLabel,
                    rem: rem,
                    resetTime: resetTime,
                    models: nil,
                    reportedWindow: true
                ))
            }
        }

        // Fallback to fetchAvailableModels only when summary groups/buckets are empty
        let modelsMap = (modelsData["models"] as? [String: Any]) ?? [:]
        if pools.isEmpty {
            var bucketsMap: [String: (rem: Double, resetTime: String?, models: [String])] = [:]
            for (mID, rawInfo) in modelsMap {
                guard let mInfo = rawInfo as? [String: Any] else { continue }
                if (mInfo["isInternal"] as? Bool) == true { continue }
                guard let quota = mInfo["quotaInfo"] as? [String: Any] else { continue }

                let rem = (quota["remainingFraction"] as? NSNumber)?.doubleValue ?? 0.0
                let resetTime = quota["resetTime"] as? String
                let disp = (mInfo["displayName"] as? String) ?? mID
                let idLow = mID.lowercased()
                let dispLow = disp.lowercased()

                let grp: String
                if idLow.contains("argon") || dispLow.contains("argon") {
                    grp = "Gemini 4 Argon"
                } else if idLow.contains("claude") || dispLow.contains("claude") || idLow.contains("gpt") {
                    grp = "Claude and GPT models"
                } else if idLow.contains("gemini") || idLow.contains("flash") || idLow.contains("pro") {
                    if (idLow.contains("preview") || idLow.contains("tab_")) && rem == 1.0 && (resetTime == nil || resetTime?.isEmpty == true) {
                        continue
                    }
                    grp = "Gemini Models"
                } else {
                    grp = "Other Models"
                }

                if var existing = bucketsMap[grp] {
                    if rem < existing.rem {
                        existing.rem = rem
                        if let rt = resetTime { existing.resetTime = rt }
                    }
                    if !existing.models.contains(disp) {
                        existing.models.append(disp)
                    }
                    bucketsMap[grp] = existing
                } else {
                    bucketsMap[grp] = (rem, resetTime, [disp])
                }
            }

            let orderedGrps = ["Gemini Models", "Claude and GPT models", "Gemini 4 Argon"] + bucketsMap.keys.sorted().filter {
                $0 != "Gemini Models" && $0 != "Claude and GPT models" && $0 != "Gemini 4 Argon"
            }
            for grp in orderedGrps {
                guard let p = bucketsMap[grp] else { continue }
                let fmt = formatCountdownAndShort(p.resetTime)
                let winLabel = (grp == "Gemini 4 Argon" && fmt.secs > 21600) ? "Weekly limit" : "5h limit"
                pools.append(makeQuotaPool(
                    name: "\(grp) — \(winLabel)",
                    groupName: grp,
                    windowLabel: winLabel,
                    rem: p.rem,
                    resetTime: p.resetTime,
                    models: p.models
                ))
            }
        }

        // Order groups consistently: Gemini Models, Claude and GPT models, Gemini 4 Argon, then others
        let groupRank: (QuotaPool) -> Int = { pool in
            let g = (pool.groupName ?? pool.name).lowercased()
            if g.contains("argon") { return 2 }
            if g.contains("gemini") { return 0 }
            if g.contains("claude") || g.contains("gpt") { return 1 }
            return 3
        }
        let indexedPools = pools.enumerated().map { ($0.offset, $0.element) }
        pools = indexedPools.sorted { a, b in
            let ra = groupRank(a.1)
            let rb = groupRank(b.1)
            if ra != rb { return ra < rb }
            return a.0 < b.0
        }.map { $0.1 }

        let usage = UsageInfo(email: resolvedEmail, tier: tierName, daily: nil, weekly: nil, pools: pools)

        return UsageInfo(
            email: resolvedEmail ?? "Unknown",
            tier: tierName,
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

    static func loadStatusPayload(
        store: NativeManifestStore,
        forceRefresh: Bool,
        cachedOnly: Bool,
        includeActiveSession: Bool = true
    ) async -> StatusPayload {
        let manifest = store.loadManifest(migrate: !cachedOnly)
        let currToken = NativeKeychain.getActiveToken(keychainPath: store.keychainPath)
        var activeKey = store.findActiveAccountKey(manifest: manifest, currentToken: currToken)

        func syncSavedCredential(key: String, from activeToken: String) {
            guard includeActiveSession, !cachedOnly, let entry = manifest[key] else { return }
            let savedToken = store.getAccountToken(entry)
            guard savedToken != activeToken, tokenExpiry(savedToken) <= tokenExpiry(activeToken) else { return }
            store.persistRefreshedToken(accountKey: key, newToken: activeToken, replacingSavedToken: savedToken)
        }
        if let ak = activeKey, let curr = currToken {
            syncSavedCredential(key: ak, from: curr)
        }

        let cachedResult = store.loadUsageCache()
        let cachedData = cachedResult.data
        let cacheAge = cachedResult.mtime.map { Date().timeIntervalSince($0) } ?? Double.infinity
        let allSavedCached = manifest.keys.allSatisfy { cachedData[$0] != nil }
        let isModernCache = cachedData.values.allSatisfy { u in
            let ps = u.pools ?? []
            return !ps.isEmpty && ps.allSatisfy { $0.windowLabel != nil }
        }

        var usedCache = false
        var usageByKey: [String: UsageInfo] = [:]
        var unsavedUsage: UsageInfo?

        if cachedOnly {
            if !cachedData.isEmpty && cacheAge < 86400 && isModernCache {
                usedCache = true
                for k in manifest.keys {
                    if let u = cachedData[k] { usageByKey[k] = u }
                }
            }
        } else if !forceRefresh && !cachedData.isEmpty && cacheAge < 45 && allSavedCached && isModernCache {
            usedCache = true
            for k in manifest.keys {
                if let u = cachedData[k] { usageByKey[k] = u }
            }
        } else {
            var tasks: [(key: String?, token: String, email: String?, planLabel: String)] = []
            for (k, entry) in manifest {
                if let tok = store.getAccountToken(entry) {
                    tasks.append((k, tok, entry.email, entry.planLabel ?? ""))
                }
            }
            if includeActiveSession, let curr = currToken, activeKey == nil {
                tasks.append((nil, curr, nil, ""))
            }

            await withTaskGroup(of: (String?, UsageInfo?).self) { group in
                for item in tasks {
                    group.addTask {
                        let usage = await fetchUsage(
                            tokenStr: item.token,
                            knownEmail: item.email,
                            savedPlanLabel: item.planLabel
                        ) { newTok in
                            store.persistRefreshedToken(
                                accountKey: item.key,
                                newToken: newTok,
                                replacingSavedToken: item.token
                            )
                        }
                        return (item.key, usage)
                    }
                }
                for await (key, usage) in group {
                    guard let key else {
                        unsavedUsage = usage
                        continue
                    }
                    if let u = usage {
                        usageByKey[key] = u
                    } else if !forceRefresh, let stale = cachedData[key] {
                        usageByKey[key] = stale
                    }
                }
            }

            if !usageByKey.isEmpty {
                store.saveUsageCache(usageByKey)
            }
        }

        var activeEmail: String?
        if let ak = activeKey {
            if let ue = usageByKey[ak]?.email, ue != "Unknown", !ue.isEmpty {
                activeEmail = ue
            } else {
                activeEmail = manifest[ak]?.email
            }
        } else if let curr = currToken {
            if let ue = unsavedUsage?.email, ue != "Unknown", !ue.isEmpty {
                activeEmail = ue
            } else if includeActiveSession && !cachedOnly {
                activeEmail = await extractEmailFromToken(curr)
            }
            if let matchedKey = NativeManifestStore.findAccountKeyByEmail(manifest: manifest, email: activeEmail) {
                activeKey = matchedKey
                syncSavedCredential(key: matchedKey, from: curr)
                if let u = unsavedUsage, usageByKey[matchedKey] == nil {
                    usageByKey[matchedKey] = u
                    store.saveUsageCache(usageByKey)
                }
            }
        }

        var accountsOut: [AccountItem] = []
        for k in manifest.keys.sorted() {
            let entry = manifest[k]
            let planLbl = entry?.planLabel?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            var uObj = usageByKey[k]
            if let u = uObj, !planLbl.isEmpty {
                uObj = UsageInfo(email: u.email, tier: planLbl, daily: u.daily, weekly: u.weekly, pools: u.pools)
            }
            let resolvedEmail: String
            if let ue = uObj?.email, ue != "Unknown", !ue.isEmpty {
                resolvedEmail = ue
            } else if let me = entry?.email, !me.isEmpty {
                resolvedEmail = me
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

        return StatusPayload(
            activeKey: activeKey,
            hasActiveSession: currToken != nil,
            activeSessionUnsaved: (currToken != nil && activeKey == nil),
            activeEmail: activeEmail,
            bestSwitchCandidate: computeBestSwitchCandidate(accounts: accountsOut, activeKey: activeKey),
            accounts: accountsOut,
            fetchedAt: Int(Date().timeIntervalSince1970),
            fromCache: usedCache
        )
    }
}

// MARK: - Official First-Party Antigravity CLI Login (T3 Code Pattern)

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
        "AGY_CLI_DISABLE_AUTO_UPDATE",
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
        // Exact environment flags from T3 Code (antigravityAuthSupport.ts):
        // SSH_CONNECTION + AGY_ACP_FORCE_FILE_STORAGE isolates agy login into acp_token.json
        // without touching the active Antigravity IDE keychain login.
        env["SSH_CONNECTION"] = baseEnv["SSH_CONNECTION"] ?? "127.0.0.1 0 127.0.0.1 0"
        env["GEMINI_HOME"] = profilePath
        env["AGY_ACP_FORCE_FILE_STORAGE"] = "1"
        env["AGY_CLI_DISABLE_AUTO_UPDATE"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        env["ELECTRON_RUN_AS_NODE"] = "1"
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

        Task { [weak self] in
            let email = await NativeQuotaFetcher.extractEmailFromToken(tok) ?? "antigravity-account"
            self?.complete(.success((tok, email)))
        }
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
        if isRefreshing { return "Syncing quotas..." }
        guard let dt = lastUpdated else { return "Live quotas" }
        let secs = Int(Date().timeIntervalSince(dt))
        if secs < 15 { return "Updated just now" }
        if secs < 60 { return "Updated \(secs)s ago" }
        return "Updated \(secs / 60)m ago"
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

// MARK: - 5h Quota Timer Warmup State Store

struct WarmupAccountState: Codable, Sendable {
    var lastPingAt: Int
    var trackedResetIso: String?
    var lastModel: String?
    var lastAttemptAt: Int? = nil
}

final class WarmupStateStore: @unchecked Sendable {
    private let manifestStore: NativeManifestStore
    let stateURL: URL
    private let lock = NSLock()

    init(manifestStore: NativeManifestStore) {
        self.manifestStore = manifestStore
        self.stateURL = manifestStore.accountsDir.appendingPathComponent("warmup_state.json")
    }

    func loadAll() -> [String: WarmupAccountState] {
        lock.lock()
        defer { lock.unlock() }
        return _loadUnlocked()
    }

    private func _loadUnlocked() -> [String: WarmupAccountState] {
        let fm = FileManager.default
        guard fm.fileExists(atPath: stateURL.path),
              let data = try? Data(contentsOf: stateURL),
              let decoded = try? JSONDecoder().decode([String: WarmupAccountState].self, from: data) else {
            return [:]
        }
        return decoded
    }

    private func _saveUnlocked(_ states: [String: WarmupAccountState]) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(states) {
            try? manifestStore.writeSecureFile(url: stateURL, data: data)
        }
    }

    func syncTrackedResets(accounts: [AccountItem], now: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        var states = _loadUnlocked()
        var changed = false
        for acc in accounts {
            guard let pool = QuotaHelpers.gemini5hPool(acc.usage, requireReportedWindow: true),
                  let iso = pool.resetIso, !iso.isEmpty,
                  let resetDt = NativeQuotaFetcher.parseISODate(iso),
                  resetDt > now else {
                continue
            }
            var entry = states[acc.key] ?? WarmupAccountState(lastPingAt: 0, trackedResetIso: nil, lastModel: nil)
            if entry.trackedResetIso != iso {
                entry.trackedResetIso = iso
                states[acc.key] = entry
                changed = true
            }
        }
        if changed {
            _saveUnlocked(states)
        }
    }

    func recordWarmupAttempts(keys: [String], at date: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        var states = _loadUnlocked()
        for key in keys {
            var entry = states[key] ?? WarmupAccountState(lastPingAt: 0, trackedResetIso: nil, lastModel: nil)
            entry.lastAttemptAt = Int(date.timeIntervalSince1970)
            states[key] = entry
        }
        _saveUnlocked(states)
    }

    func recordWarmupPing(key: String, modelDisplay: String, at date: Date = Date()) {
        lock.lock()
        defer { lock.unlock() }
        var states = _loadUnlocked()
        var entry = states[key] ?? WarmupAccountState(lastPingAt: 0, trackedResetIso: nil, lastModel: nil)
        entry.lastPingAt = Int(date.timeIntervalSince1970)
        entry.lastModel = modelDisplay
        if let iso = entry.trackedResetIso,
           let dt = NativeQuotaFetcher.parseISODate(iso),
           date >= dt {
            entry.trackedResetIso = nil
        }
        states[key] = entry
        _saveUnlocked(states)
    }

    static func shouldCheckQuota(
        gemini5hPool: QuotaPool?,
        state: WarmupAccountState?,
        now: Date = Date()
    ) -> Bool {
        let lastPing = Double(state?.lastPingAt ?? 0)
        let lastAttempt = Double(state?.lastAttemptAt ?? 0)
        let elapsed = now.timeIntervalSince1970 - max(lastPing, lastAttempt)
        guard max(lastPing, lastAttempt) == 0 || elapsed >= 300 else { return false }

        let resets = [gemini5hPool?.resetIso, state?.trackedResetIso]
            .compactMap { $0.flatMap(NativeQuotaFetcher.parseISODate) }
        if let reset = resets.max() {
            guard reset <= now else { return false }
            if lastPing < reset.timeIntervalSince1970 { return true }
        }
        guard now.timeIntervalSince1970 - lastPing >= 18_000 else { return false }
        return quotaIsIdle(gemini5hPool, now: now) || (gemini5hPool == nil && lastPing > 0)
    }

    static func quotaIsIdle(_ pool: QuotaPool?, now: Date = Date()) -> Bool {
        guard let pool, pool.remainingPct == 100, pool.usedPct == 0 else { return false }
        guard let iso = pool.resetIso, !iso.isEmpty else { return true }
        guard let reset = NativeQuotaFetcher.parseISODate(iso) else { return false }
        return reset <= now
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

        // 6. Test tier detection & best switch candidate
        let detected = NativeQuotaFetcher.detectTierName(modelsData: ["userTier": "PRO"], savedPlanLabel: nil)
        let blankTier = NativeQuotaFetcher.detectTierName(modelsData: [:], savedPlanLabel: nil)
        guard check(detected == "Antigravity Pro" && blankTier == "", "tier detection") else { return 1 }

        let poolLow = QuotaPool(name: "Gemini", usedPct: 90, remainingPct: 10, resetsIn: "1h", resetTime: "10:00", resetShort: "10:00", resetSecs: 3600, resetIso: "", models: nil)
        let poolHigh = QuotaPool(name: "Gemini", usedPct: 10, remainingPct: 90, resetsIn: "1h", resetTime: "10:00", resetShort: "10:00", resetSecs: 3600, resetIso: "", models: nil)
        let accts = [
            AccountItem(key: "A", label: "A", email: "a@x.com", savedAt: "", storage: "keychain", isActive: true, usage: UsageInfo(email: "a@x.com", tier: "", daily: poolLow, weekly: poolLow, pools: [poolLow])),
            AccountItem(key: "B", label: "B", email: "b@x.com", savedAt: "", storage: "keychain", isActive: false, usage: UsageInfo(email: "b@x.com", tier: "", daily: poolHigh, weekly: poolHigh, pools: [poolHigh]))
        ]
        guard check(NativeQuotaFetcher.computeBestSwitchCandidate(accounts: accts, activeKey: "A") == "B", "best switch candidate") else { return 1 }
        print("PASS: tier detection & best switch candidate")

        // 7. Test MenuBarGaugeRenderer
        let img = MenuBarGaugeRenderer.renderImage(geminiPct: 85.0, claudePct: 15.0)
        guard check(img.size.width == 24 && img.size.height == 18, "gauge image dimensions") else { return 1 }
        print("PASS: MenuBarGaugeRenderer")

        // 8. Test Cloud Code summary parsing (Gemini 5h/Weekly, Claude 5h/Weekly, Gemini 4 Argon, omitted=0)
        let hubUA = NativeQuotaFetcher.quotaHeaders(version: "2.33.0")["User-Agent"] ?? ""
        guard check(hubUA.hasPrefix("antigravity/hub/"), "hub User-Agent identity") else { return 1 }
        let sampleSummary: [String: Any] = [
            "groups": [
                [
                    "displayName": "Gemini Models",
                    "description": "Models within this group: Gemini 4 Hydrogen, Gemini 3.8 Flash",
                    "buckets": [
                        ["bucketId": "gemini-weekly", "window": "weekly", "remainingFraction": 0.79, "resetTime": "2099-01-07T00:00:00Z"],
                        ["bucketId": "gemini-5h", "window": "5h", "resetTime": "2099-01-01T05:00:00Z"]
                    ]
                ],
                [
                    "displayName": "Claude and GPT models",
                    "buckets": [
                        ["bucketId": "3p-weekly", "window": "weekly", "remainingFraction": 1.0],
                        ["bucketId": "3p-5h", "window": "5h", "remainingFraction": 1.0]
                    ]
                ],
                [
                    "displayName": "Gemini 4 Argon",
                    "buckets": [
                        ["bucketId": "gemini-argon-wtu-weekly", "displayName": "Gemini 4 Argon Weekly Limit", "window": "weekly", "remainingFraction": 0.87, "resetTime": "2099-01-07T22:00:00Z"]
                    ]
                ]
            ]
        ]
        guard let parsedUsage = NativeQuotaFetcher.parseUsage(
            summaryJSON: sampleSummary,
            modelsJSON: nil,
            codeAssistJSON: ["paidTier": ["id": "g1-pro-tier", "name": "Google AI Pro"]],
            resolvedEmail: "user@example.invalid",
            savedPlanLabel: nil
        ) else {
            fputs("FAIL: parseUsage returned nil\n", stderr)
            return 1
        }
        guard check(parsedUsage.tier == "Google AI Pro", "paidTier resolved"),
              check(QuotaHelpers.gemini5hPool(parsedUsage)?.remainingPct == 0.0, "omitted remainingFraction reads as 0.0"),
              check(QuotaHelpers.geminiWeeklyPool(parsedUsage)?.remainingPct == 79.0, "gemini weekly 79%"),
              check(QuotaHelpers.argonPool(parsedUsage)?.remainingPct == 87.0, "argon weekly 87%"),
              check(QuotaHelpers.argonPool(parsedUsage)?.windowLabel == "Weekly limit", "argon windowLabel") else { return 1 }
        print("PASS: Cloud Code hub parsing & Gemini 4 Argon")

        // 9. Test OfficialAgyLoginSession isolated env + credential normalization
        let testEnv = OfficialAgyLoginSession.buildIsolatedEnvironment(
            baseEnv: ["PATH": "/usr/bin", "GEMINI_API_KEY": "bad", "DISPLAY": ":0"],
            profilePath: "/tmp/ag_prof",
            tempPath: "/tmp/ag_prof/tmp"
        )
        guard check(testEnv["GEMINI_API_KEY"] == nil && testEnv["DISPLAY"] == nil, "stripped env vars"),
              check(testEnv["AGY_ACP_FORCE_FILE_STORAGE"] == "1" && testEnv["SSH_CONNECTION"] != nil, "T3 Code agy isolated env") else { return 1 }

        let flatData = Data("{\"access_token\":\"ya29.test\",\"refresh_token\":\"1//rf\"}".utf8)
        let normFlat = OfficialAgyLoginSession.normalizeCredentialData(flatData, fallbackEmail: "u@example.invalid")
        let wrapData = Data("{\"token\":{\"access_token\":\"ya29.test2\"}}".utf8)
        let normWrap = OfficialAgyLoginSession.normalizeCredentialData(wrapData)
        guard check(normFlat?.hasPrefix("go-keyring-base64:") == true, "normalize flat acp_token.json"),
              check(normWrap?.hasPrefix("go-keyring-base64:") == true, "normalize envelope acp_token.json") else { return 1 }
        print("PASS: OfficialAgyLoginSession T3 Code isolated env & credential normalization")

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

        // 11. Test 5h Gemini Warmup model selection & window scheduling
        let withHydrogen: [String: Any] = [
            "models": [
                "gemini-3.8-flash-low": ["displayName": "Gemini 3.8 Flash", "quotaInfo": [:]] as [String: Any],
                "gemini-4-hydrogen": ["displayName": "Gemini 4 Hydrogen", "quotaInfo": [:]] as [String: Any],
                "claude-opus-5-5": ["displayName": "Claude Opus 5.5", "quotaInfo": [:]] as [String: Any]
            ]
        ]
        let pickH = NativeQuotaFetcher.warmupGeminiModels(from: withHydrogen).map(\.modelId)
        let withoutHydrogen: [String: Any] = [
            "models": [
                "gemini-3.8-flash": ["displayName": "Gemini 3.8 Flash", "quotaInfo": [:]] as [String: Any],
                "gemini-4-argon": ["displayName": "Gemini 4 Argon", "quotaInfo": [:]] as [String: Any]
            ]
        ]
        let pickF = NativeQuotaFetcher.warmupGeminiModels(from: withoutHydrogen).map(\.modelId)
        let stream = Data("event: message\r\ndata: {\"response\":{\"candidates\":[{\"finishReason\":\"STOP\"}]}}\r\n\r\n".utf8)
        let generationError = Data("{\"error\":{\"message\":\"Rejected\"}}".utf8)
        guard check(pickH == ["gemini-4-hydrogen", "gemini-3.8-flash-low"], "warmup prefers Hydrogen then advertised Flash Low"),
              check(pickF == ["gemini-3.8-flash"], "warmup falls back to 3.8 Flash"),
              check(NativeQuotaFetcher.warmupGeminiModels(from: [:]).isEmpty, "warmup requires an advertised model"),
              check(NativeQuotaFetcher.hasWarmupGeneration(stream, streaming: true), "warmup accepts an SSE generation response"),
              check(!NativeQuotaFetcher.hasWarmupGeneration(generationError, streaming: false), "warmup rejects a 200 error response") else { return 1 }

        let now = Date()
        let idlePool = QuotaPool(name: "Gemini Models — 5h limit", usedPct: 0.0, remainingPct: 100.0, resetsIn: "N/A", resetTime: "N/A", resetShort: "", resetSecs: 0, resetIso: "", models: nil)
        let usedPool = QuotaPool(name: "Gemini Models — 5h limit", usedPct: 12.0, remainingPct: 88.0, resetsIn: "3h", resetTime: "18:00", resetShort: "18:00", resetSecs: 10800, resetIso: ISO8601DateFormatter().string(from: now.addingTimeInterval(10800)), models: nil)
        let pastIso = ISO8601DateFormatter().string(from: now.addingTimeInterval(-60))
        let pastState = WarmupAccountState(lastPingAt: Int(now.timeIntervalSince1970) - 400, trackedResetIso: pastIso, lastModel: "Gemini 4 Hydrogen")
        let recentState = WarmupAccountState(lastPingAt: Int(now.timeIntervalSince1970) - 60, trackedResetIso: pastIso, lastModel: "Gemini 4 Hydrogen")
        guard check(WarmupStateStore.shouldCheckQuota(gemini5hPool: idlePool, state: nil, now: now), "warmup checks idle 100% pool"),
              check(!WarmupStateStore.shouldCheckQuota(gemini5hPool: usedPool, state: pastState, now: now), "current active window takes precedence over old reset"),
              check(!WarmupStateStore.shouldCheckQuota(gemini5hPool: idlePool, state: recentState, now: now), "warmup respects success cooldown") else { return 1 }
        print("PASS: 5h Gemini Warmup model priority & scheduling")

        let futureISO = ISO8601DateFormatter().string(from: now.addingTimeInterval(3600))
        func fixturePool(group: String, window: String, remaining: Double, reset: String?) -> QuotaPool? {
            var bucket: [String: Any] = ["window": window, "remainingFraction": remaining]
            if let reset { bucket["resetTime"] = reset }
            let groups: [[String: Any]] = group.isEmpty ? [] : [["displayName": group, "buckets": [bucket]]]
            let usage = NativeQuotaFetcher.parseUsage(
                summaryJSON: ["groups": groups], modelsJSON: nil, codeAssistJSON: nil,
                resolvedEmail: nil, savedPlanLabel: nil
            )
            return QuotaHelpers.gemini5hPool(usage, requireReportedWindow: true)
        }
        let noQuota = fixturePool(group: "", window: "5h", remaining: 1, reset: nil)
        let weeklyOnly = fixturePool(group: "Gemini Models", window: "weekly", remaining: 1, reset: nil)
        let claudeOnly = fixturePool(group: "Claude and GPT models", window: "5h", remaining: 1, reset: nil)
        let futureFull = fixturePool(group: "Gemini Models", window: "5h", remaining: 1, reset: futureISO)
        let staleExhausted = fixturePool(group: "Gemini Models", window: "5h", remaining: 0, reset: pastIso)
        let freshIdle = fixturePool(group: "Gemini Models", window: "5h", remaining: 1, reset: nil)
        let inferredUsage = NativeQuotaFetcher.parseUsage(
            summaryJSON: nil, modelsJSON: ["models": ["gemini-3.8-flash": ["quotaInfo": ["remainingFraction": 1.0]]]],
            codeAssistJSON: nil, resolvedEmail: nil, savedPlanLabel: nil
        )
        let warmup = WarmupStateStore(manifestStore: store)
        warmup.recordWarmupAttempts(keys: ["a"], at: now)
        let afterFailure = WarmupStateStore(manifestStore: store).loadAll()["a"]
        let schedulerChecks = [
            check(noQuota == nil, "missing quota cannot schedule a warmup"),
            check(weeklyOnly == nil, "weekly quota cannot schedule a warmup"),
            check(claudeOnly == nil, "Claude quota cannot schedule a Gemini warmup"),
            check(QuotaHelpers.gemini5hPool(inferredUsage, requireReportedWindow: true) == nil, "inferred quota cannot schedule warmup"),
            check(!WarmupStateStore.shouldCheckQuota(gemini5hPool: futureFull, state: nil, now: now), "future reset takes precedence over 100 percent"),
            check(WarmupStateStore.shouldCheckQuota(gemini5hPool: staleExhausted, state: pastState, now: now), "expired reset prompts a quota recheck even at cached zero"),
            check(!WarmupStateStore.quotaIsIdle(staleExhausted, now: now), "exhausted quota cannot send generation after preflight"),
            check(WarmupStateStore.quotaIsIdle(freshIdle, now: now), "confirmed idle window permits generation"),
            check(!WarmupStateStore.shouldCheckQuota(gemini5hPool: freshIdle, state: afterFailure, now: now.addingTimeInterval(60)), "failed attempt persists cooldown across restart"),
            check(WarmupStateStore.shouldCheckQuota(gemini5hPool: freshIdle, state: afterFailure, now: now.addingTimeInterval(300)), "failed attempt can retry after cooldown")
        ]
        guard check(NativeKeychain.setActiveToken(t2, keychainPath: kcPath).0, "set second active credential") else { return 1 }
        guard check(store.saveAccount(token: t1, email: "warmup@example.invalid", customLabel: "Warmup Test").0,
                    "save warmup test credential") else { return 1 }
        let refreshed = "go-keyring-base64:dGVzdF9yZWZyZXNoZWQ="
        store.persistRefreshedToken(accountKey: "Warmup Test", newToken: refreshed, replacingSavedToken: t1)
        store.persistRefreshedToken(accountKey: "Warmup Test", newToken: t1, replacingSavedToken: t1)
        let savedEntry = store.loadManifest(migrate: false)["Warmup Test"]
        let savedToken = savedEntry.flatMap(store.getAccountToken)
        let savedRefresh = check(savedToken == refreshed && NativeKeychain.getActiveToken(keychainPath: kcPath) == t2,
                                 "warmup refresh saves only to its own unchanged credential")
        let duplicateRejected = check(!store.saveAccount(token: t2, email: "other@example.invalid", customLabel: "Warmup Test").0,
                                      "another account cannot replace a saved label")
        let empty = NativeQuotaFetcher.parseUsage(
            summaryJSON: ["groups": []], modelsJSON: nil, codeAssistJSON: nil,
            resolvedEmail: nil, savedPlanLabel: nil
        )
        let unavailable = check(empty != nil && empty?.daily == nil && empty?.weekly == nil && QuotaHelpers.minRemaining(for: empty) < 0,
                                "empty quota response has no percentage or recommendation score")
        guard schedulerChecks.allSatisfy({ $0 }), savedRefresh, duplicateRejected, unavailable else { return 1 }
        print("PASS: Warmup quota guards and active account preservation")

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
