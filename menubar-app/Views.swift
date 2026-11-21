import Cocoa
import Foundation
import SwiftUI

// MARK: - View State Models (Zero @State macro dependency for CommandLineTools compatibility)

final class HoverState: ObservableObject {
    @Published var isHovered = false
}

final class BannerSavingState: ObservableObject {
    @Published var isSaving = false
}

final class ManageViewState: ObservableObject {
    @Published var showSaveSheet = false
    @Published var saveLabelInput = ""
    @Published var isSaving = false
    @Published var renamingKey: String?
    @Published var renameDraft = ""
    @Published var editingPlanKey: String?
    @Published var confirmingDeleteKey: String?
}

// MARK: - Adaptive Liquid Glass (macOS 26+) & Vibrancy Fallback (macOS 13-15)

extension View {
    @ViewBuilder
    func adaptiveGlassCard(cornerRadius: CGFloat, tint: Color?, border: Color) -> some View {
        if #available(macOS 26.0, *) {
            if let tint = tint {
                self
                    .background(
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .fill(tint.opacity(0.24))
                    )
                    .glassEffect(.regular.tint(tint.opacity(0.28)), in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .stroke(border, lineWidth: 1)
                    )
            } else {
                self
                    .overlay(
                        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                            .stroke(border, lineWidth: 1)
                    )
            }
        } else {
            self
                .background(
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .fill(tint ?? Color.clear)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .stroke(border, lineWidth: 1)
                )
        }
    }

    @ViewBuilder
    func adaptiveGlassPill(fallbackFill: Color) -> some View {
        if #available(macOS 26.0, *) {
            self.glassEffect(.regular.interactive(), in: Capsule())
        } else {
            self.background(Capsule().fill(fallbackFill))
        }
    }
}

// MARK: - Root Container

struct RootSwitcherView: View {
    @ObservedObject var store: SwitcherStore
    let isWindowMode: Bool
    let onQuit: () -> Void
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        VStack(spacing: 0) {
            if isWindowMode {
                HStack(spacing: 6) {
                    Spacer()
                    Image(systemName: "arrow.triangle.2.circlepath")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.secondary)
                    Text("GravityBar")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(.secondary)
                    Spacer()
                }
                .frame(height: 28)
                .padding(.top, 2)
            }

            if let err = store.errorMessage {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.orange)
                        .font(.system(size: 12))
                    Text(err)
                        .font(.system(size: 11.5))
                        .foregroundColor(.primary)
                        .lineLimit(2)
                    Spacer(minLength: 4)
                    Button {
                        store.errorMessage = nil
                    } label: {
                        Image(systemName: "xmark")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.orange.opacity(colorScheme == .dark ? 0.16 : 0.12))
                Divider().opacity(0.45)
            }

            switch store.screen {
            case .accounts:
                AccountsMainView(store: store, onQuit: onQuit)
            case .manage:
                ManageAccountsView(store: store)
            case .addWizard:
                AddAccountWizardView(store: store)
            case .settings:
                SettingsView(store: store)
            }
        }
        .frame(width: 428)
        .overlay(alignment: .top) {
            if let toast = store.toastMessage {
                Text(toast)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundColor(.primary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(.ultraThickMaterial, in: Capsule())
                    .overlay(Capsule().stroke(Color.primary.opacity(0.12), lineWidth: 0.5))
                    .shadow(color: Color.black.opacity(0.18), radius: 8, y: 3)
                    .padding(.top, isWindowMode ? 32 : 10)
                    .transition(.move(edge: .top).combined(with: .opacity))
            }
        }
        .animation(.easeInOut(duration: 0.18), value: store.toastMessage)
        .animation(.easeInOut(duration: 0.16), value: store.screen)
    }
}

// MARK: - Main Accounts View

struct AccountsMainView: View {
    @ObservedObject var store: SwitcherStore
    let onQuit: () -> Void
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        let sorted = store.sortedAccounts
        let isAlreadySaved = !(store.activeEmail ?? "").isEmpty && sorted.contains(where: {
            $0.email.caseInsensitiveCompare(store.activeEmail ?? "") == .orderedSame
                || $0.key.caseInsensitiveCompare(store.activeEmail ?? "") == .orderedSame
        })
        VStack(spacing: 0) {
            if store.activeSessionUnsaved && !isAlreadySaved {
                UnsavedSessionBanner(store: store)
                    .padding(.horizontal, 10)
                    .padding(.top, 10)
            }

            if sorted.count > 1 {
                HStack(spacing: 6) {
                    Text("Accounts (\(sorted.count))")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.secondary)

                    Spacer()

                    HStack(spacing: 2) {
                        ForEach(AccountSortMode.allCases, id: \.self) { mode in
                            Button {
                                store.sortModeRaw = mode.rawValue
                            } label: {
                                Text(mode.title)
                                    .font(.system(size: 10.5, weight: store.sortMode == mode ? .semibold : .medium))
                                    .foregroundColor(store.sortMode == mode ? .primary : .secondary)
                                    .padding(.horizontal, 7)
                                    .padding(.vertical, 3)
                                    .background(
                                        RoundedRectangle(cornerRadius: 6, style: .continuous)
                                            .fill(store.sortMode == mode ? Color.primary.opacity(colorScheme == .dark ? 0.14 : 0.10) : Color.clear)
                                    )
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(2)
                    .background(
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(Color.primary.opacity(colorScheme == .dark ? 0.05 : 0.04))
                    )
                }
                .padding(.horizontal, 14)
                .padding(.top, 10)
                .padding(.bottom, 2)
            }

            if sorted.isEmpty {
                EmptyAccountsView(store: store)
                    .padding(16)
            } else {
                ScrollView(.vertical, showsIndicators: sorted.count > 3) {
                    VStack(spacing: 6) {
                        ForEach(Array(sorted.enumerated()), id: \.element.id) { idx, account in
                            AccountCardView(
                                account: account,
                                indexHint: idx < 9 ? "\(idx + 1)" : nil,
                                isKeyboardFocused: store.isKeyboardNavigating && store.selectedIndex == idx,
                                isExpanded: store.expandedKeys.contains(account.key),
                                isPendingConfirm: store.pendingConfirmKey == account.key,
                                isSwitching: store.switchingKey == account.key,
                                isAnySwitching: store.switchingKey != nil,
                                isSyncing: store.isLoading || store.isRefreshing,
                                onToggleExpand: { store.toggleExpanded(account.key) },
                                onConfirmSwitch: {
                                    store.pendingConfirmKey = nil
                                    Task { await store.switchTo(account.key, forceConfirmed: true) }
                                },
                                onCancelConfirm: { store.pendingConfirmKey = nil },
                                onTap: {
                                    if account.isActive && (account.usage?.pools?.isEmpty == false) {
                                        store.toggleExpanded(account.key)
                                    } else {
                                        Task { await store.switchTo(account.key) }
                                    }
                                }
                            )
                        }
                    }
                    .padding(10)
                }
                .frame(maxHeight: sorted.count > 3 ? 460 : nil)
            }

            Divider().opacity(0.55)

            // Telemetry & Quick Action Strip
            HStack(spacing: 6) {
                Image(systemName: "clock.arrow.circlepath")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.secondary)
                Text(QuotaHelpers.relativeSyncText(lastUpdated: store.lastUpdated, isRefreshing: store.isRefreshing))
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundColor(.primary)
                    .lineLimit(1)

                Spacer(minLength: 4)

                if let bestKey = store.bestSwitchCandidate {
                    Button {
                        Task { await store.switchTo(bestKey) }
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "sparkles")
                                .font(.system(size: 10.5, weight: .semibold))
                            Text("Best")
                                .font(.system(size: 11, weight: .semibold))
                        }
                        .foregroundColor(.white)
                        .padding(.horizontal, 9)
                        .padding(.vertical, 4.5)
                        .background(
                            Capsule().fill(Color.accentColor)
                        )
                    }
                    .buttonStyle(.plain)
                    .disabled(store.switchingKey != nil)
                    .help("Switch to \(bestKey) (highest remaining quota)")
                }

                QuickStripPill(
                    title: "Refresh",
                    systemImage: "arrow.clockwise",
                    isBusy: store.isRefreshing
                ) {
                    Task { await store.refresh(force: true) }
                }
                .keyboardShortcut("r", modifiers: .command)

                QuickStripPill(
                    title: "IDE",
                    systemImage: "macwindow",
                    isBusy: false
                ) {
                    store.openAntigravity()
                }

                Button {
                    store.openUsageDashboard()
                } label: {
                    Image(systemName: "arrow.up.right")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(.secondary)
                        .frame(width: 24, height: 24)
                        .background(
                            RoundedRectangle(cornerRadius: 6, style: .continuous)
                                .fill(Color.primary.opacity(colorScheme == .dark ? 0.06 : 0.045))
                        )
                }
                .buttonStyle(.plain)
                .help("Open web dashboard")
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)

            Divider().opacity(0.55)

            // Bottom Footer Bar
            HStack(spacing: 4) {
                FooterActionButton(title: "Manage Accounts", systemImage: "person.2") {
                    store.screen = .manage
                }
                Spacer(minLength: 4)
                FooterActionButton(title: "Settings", systemImage: "gearshape") {
                    store.screen = .settings
                }
                Spacer(minLength: 4)
                FooterActionButton(title: "Quit", systemImage: "power") {
                    onQuit()
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
        }
    }
}

struct UnsavedSessionBanner: View {
    @ObservedObject var store: SwitcherStore
    @StateObject private var local = BannerSavingState()
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: "person.crop.circle.badge.exclamationmark")
                .font(.system(size: 16))
                .foregroundColor(.accentColor)

            VStack(alignment: .leading, spacing: 1) {
                Text(store.activeEmail ?? "Unsaved Active Session")
                    .font(.system(size: 12, weight: .semibold))
                    .lineLimit(1)
                Text("Currently signed into Antigravity")
                    .font(.system(size: 10.5))
                    .foregroundColor(.secondary)
            }

            Spacer(minLength: 4)

            Button {
                guard !local.isSaving else { return }
                local.isSaving = true
                Task {
                    _ = await store.saveCurrent(label: store.activeEmail)
                    local.isSaving = false
                }
            } label: {
                if local.isSaving {
                    ProgressView().controlSize(.small)
                } else {
                    Text("Save")
                        .font(.system(size: 11.5, weight: .semibold))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 11, style: .continuous)
                .fill(Color.accentColor.opacity(colorScheme == .dark ? 0.14 : 0.09))
                .overlay(
                    RoundedRectangle(cornerRadius: 11, style: .continuous)
                        .stroke(Color.accentColor.opacity(0.26), lineWidth: 0.75)
                )
        )
    }
}

struct AccountCardView: View {
    let account: AccountItem
    let indexHint: String?
    let isKeyboardFocused: Bool
    let isExpanded: Bool
    let isPendingConfirm: Bool
    let isSwitching: Bool
    let isAnySwitching: Bool
    let isSyncing: Bool
    let onToggleExpand: () -> Void
    let onConfirmSwitch: () -> Void
    let onCancelConfirm: () -> Void
    let onTap: () -> Void

    @StateObject private var hover = HoverState()
    @Environment(\.colorScheme) private var colorScheme

    private var gemini5hPool: QuotaPool? { QuotaHelpers.gemini5hPool(account.usage) }
    private var geminiWeeklyPool: QuotaPool? { QuotaHelpers.geminiWeeklyPool(account.usage) }
    private var claude5hPool: QuotaPool? { QuotaHelpers.claude5hPool(account.usage) }
    private var claudeWeeklyPool: QuotaPool? { QuotaHelpers.claudeWeeklyPool(account.usage) }
    private var argonPool: QuotaPool? { QuotaHelpers.argonPool(account.usage) }

    private var footerSummaryText: String {
        var parts: [String] = []
        if let c5 = claude5hPool, let cw = claudeWeeklyPool, c5.id != cw.id {
            parts.append("Claude/GPT: \(Int(c5.remainingPct.rounded()))% 5h · \(Int(cw.remainingPct.rounded()))% 7d")
        } else if let c5 = claude5hPool {
            parts.append("Claude/GPT: \(Int(c5.remainingPct.rounded()))% left")
        } else if let cw = claudeWeeklyPool {
            parts.append("Claude/GPT: \(Int(cw.remainingPct.rounded()))% 7d")
        }
        if let argon = argonPool {
            parts.append("Argon: \(Int(argon.remainingPct.rounded()))%")
        }
        if !parts.isEmpty {
            return parts.joined(separator: " · ")
        }
        return "Keychain · \(QuotaHelpers.shortDate(account.savedAt))"
    }

    private var cardTint: Color? {
        if account.isActive {
            return Color.accentColor.opacity(colorScheme == .dark ? 0.18 : 0.105)
        }
        if hover.isHovered || isKeyboardFocused {
            return Color.primary.opacity(colorScheme == .dark ? 0.065 : 0.045)
        }
        return nil
    }

    private var cardBorder: Color {
        if isKeyboardFocused {
            return Color.accentColor.opacity(0.68)
        }
        if account.isActive {
            return Color.accentColor.opacity(colorScheme == .dark ? 0.35 : 0.24)
        }
        if hover.isHovered {
            return Color.primary.opacity(colorScheme == .dark ? 0.13 : 0.09)
        }
        return Color.clear
    }

    private var resolvedTierText: String? {
        if !account.planLabel.isEmpty { return account.planLabel }
        if let t = account.usage?.tier, !t.isEmpty { return t }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ZStack(alignment: .topTrailing) {
                Button(action: onTap) {
                    HStack(alignment: .top, spacing: 11) {
                        ZStack(alignment: .bottomTrailing) {
                            Circle()
                                .fill(Color.primary.opacity(colorScheme == .dark ? 0.10 : 0.075))
                                .frame(width: 36, height: 36)
                                .overlay(
                                    Text(QuotaHelpers.monogram(for: account))
                                        .font(.system(size: 14, weight: .semibold, design: .rounded))
                                        .foregroundColor(.primary)
                                )

                            if account.isActive {
                                Circle()
                                    .fill(Color.green)
                                    .frame(width: 10, height: 10)
                                    .overlay(
                                        Circle()
                                            .stroke(colorScheme == .dark ? Color(white: 0.14) : Color.white, lineWidth: 1.5)
                                    )
                                    .offset(x: 1, y: 1)
                            }
                        }
                        .padding(.top, 2)

                        VStack(alignment: .leading, spacing: 5) {
                            // Title Row (leaving trailing 22pt space for chevron button)
                            HStack(alignment: .center, spacing: 5) {
                                if account.pinned {
                                    Image(systemName: "pin.fill")
                                        .font(.system(size: 9.5))
                                        .foregroundColor(.accentColor)
                                }

                                Text(account.email.isEmpty ? account.label : account.email)
                                    .font(.system(size: 13.5, weight: .semibold))
                                    .foregroundColor(.primary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)

                                if !account.label.isEmpty && account.label != account.email {
                                    Text(account.label)
                                        .font(.system(size: 10, weight: .medium))
                                        .foregroundColor(.secondary)
                                        .padding(.horizontal, 5)
                                        .padding(.vertical, 1)
                                        .background(Capsule().fill(Color.primary.opacity(0.07)))
                                        .lineLimit(1)
                                }

                                Spacer(minLength: 4)

                                if isSwitching {
                                    HStack(spacing: 4) {
                                        ProgressView().controlSize(.mini)
                                        Text("Switching")
                                            .font(.system(size: 10.5, weight: .semibold))
                                            .foregroundColor(.accentColor)
                                    }
                                } else if account.isActive {
                                    Text("Active")
                                        .font(.system(size: 10.5, weight: .semibold))
                                        .foregroundColor(.accentColor)
                                } else if hover.isHovered || isKeyboardFocused {
                                    HStack(spacing: 3) {
                                        if let idx = indexHint {
                                            Text("⌘/\(idx)")
                                                .font(.system(size: 9.5, weight: .semibold).monospacedDigit())
                                                .foregroundColor(.secondary)
                                        }
                                        Text("Switch →")
                                            .font(.system(size: 10.5, weight: .semibold))
                                            .foregroundColor(.accentColor)
                                    }
                                }
                            }
                            .padding(.trailing, 22)

                            if isExpanded {
                                HStack(spacing: 6) {
                                    Text(account.isActive ? "Active · Showing all quotas" : "All quotas breakdown")
                                        .font(.system(size: 10.5))
                                        .foregroundColor(.secondary)
                                        .lineLimit(1)
                                    Spacer(minLength: 4)
                                    if let tier = resolvedTierText {
                                        Text(tier)
                                            .font(.system(size: 10.5, weight: .medium))
                                            .foregroundColor(.secondary)
                                            .lineLimit(1)
                                            .layoutPriority(1)
                                    }
                                }
                            } else {
                                QuotaBarRow(title: "Gem 5h", pool: gemini5hPool, isSyncing: isSyncing)
                                QuotaBarRow(title: "Gem 7d", pool: geminiWeeklyPool, isSyncing: isSyncing)

                                HStack(spacing: 6) {
                                    Text(footerSummaryText)
                                        .font(.system(size: 10.5))
                                        .foregroundColor(.secondary)
                                        .lineLimit(1)
                                        .truncationMode(.tail)

                                    Spacer(minLength: 4)

                                    if let tier = resolvedTierText {
                                        Text(tier)
                                            .font(.system(size: 10.5, weight: .medium))
                                            .foregroundColor(.secondary)
                                            .lineLimit(1)
                                            .layoutPriority(1)
                                    }
                                }
                                .padding(.top, 1)
                            }
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .contentShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                }
                .buttonStyle(.plain)
                .disabled(isAnySwitching && !isSwitching)

                // Separate sibling button for expanding model breakdown (no nested Button!)
                if (account.usage?.pools?.isEmpty == false) {
                    Button(action: onToggleExpand) {
                        Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundColor(.secondary)
                            .frame(width: 24, height: 24)
                            .background(
                                Circle().fill(Color.primary.opacity(hover.isHovered ? 0.08 : 0.0))
                            )
                            .contentShape(Circle())
                    }
                    .buttonStyle(.plain)
                    .padding(.top, 8)
                    .padding(.trailing, 8)
                    .help(isExpanded ? "Hide all quotas" : "Show all quotas (Gemini, Claude & GPT, Argon)")
                }
            }

            if isPendingConfirm {
                HStack(spacing: 8) {
                    Text("Restart Antigravity and switch?")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                    Spacer()
                    Button("Cancel", action: onCancelConfirm)
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    Button("Switch", action: onConfirmSwitch)
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                }
                .padding(.horizontal, 12)
                .padding(.bottom, 10)
            }

            if isExpanded, let pools = account.usage?.pools, !pools.isEmpty {
                Divider().opacity(0.35).padding(.horizontal, 12)
                ExpandedBreakdownView(pools: pools)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 9)
            }
        }
        .adaptiveGlassCard(cornerRadius: 14, tint: cardTint, border: cardBorder)
        .onHover { hovering in
            withAnimation(.easeInOut(duration: 0.12)) {
                hover.isHovered = hovering
            }
        }
    }
}

struct ExpandedBreakdownView: View {
    let pools: [QuotaPool]
    @Environment(\.colorScheme) private var colorScheme

    private struct GroupSection: Identifiable {
        let title: String
        let modelsSubtitle: String?
        let items: [QuotaPool]
        var id: String { title }
    }

    private var sections: [GroupSection] {
        var order: [String] = []
        var grouped: [String: [QuotaPool]] = [:]
        for p in pools {
            let key = (p.groupName?.isEmpty == false ? p.groupName! : p.name)
            if grouped[key] == nil {
                order.append(key)
                grouped[key] = [p]
            } else {
                grouped[key]?.append(p)
            }
        }
        return order.map { title in
            let items = grouped[title] ?? []
            let models = items.first(where: { $0.models?.isEmpty == false })?.models
            let subtitle = models.map { $0.prefix(4).joined(separator: " · ") }
            return GroupSection(title: title, modelsSubtitle: subtitle, items: items)
        }
    }

    private func barColor(for pct: Double) -> Color {
        if pct < 20 { return .red }
        if pct < 45 { return .orange }
        return .accentColor
    }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1.0)) { _ in
            VStack(alignment: .leading, spacing: 7) {
                ForEach(sections) { section in
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 6) {
                            Text(section.title)
                                .font(.system(size: 11.5, weight: .semibold))
                                .foregroundColor(.primary)
                                .lineLimit(1)
                            Spacer()
                            if let sub = section.modelsSubtitle, !sub.isEmpty {
                                Text(sub)
                                    .font(.system(size: 9.5))
                                    .foregroundColor(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.tail)
                            }
                        }

                        ForEach(section.items) { pool in
                            let label = pool.windowLabel ?? pool.name
                            let frac = max(0.0, min(1.0, pool.remainingPct / 100.0))
                            HStack(spacing: 7) {
                                Text(label)
                                    .font(.system(size: 10.5, weight: .medium))
                                    .foregroundColor(.secondary)
                                    .frame(width: 72, alignment: .leading)
                                    .lineLimit(1)

                                GeometryReader { geo in
                                    ZStack(alignment: .leading) {
                                        Capsule()
                                            .fill(Color.primary.opacity(colorScheme == .dark ? 0.13 : 0.09))
                                        Capsule()
                                            .fill(barColor(for: pool.remainingPct))
                                            .frame(width: max(frac > 0 ? 4 : 0, geo.size.width * frac))
                                    }
                                }
                                .frame(height: 4.5)

                                Text("\(Int(pool.remainingPct.rounded()))% left")
                                    .font(.system(size: 10.5, weight: .semibold).monospacedDigit())
                                    .foregroundColor(barColor(for: pool.remainingPct))
                                    .lineLimit(1)
                                    .frame(width: 62, alignment: .trailing)

                                if let live = QuotaHelpers.formatLiveCountdown(isoStr: pool.resetIso) {
                                    Text("· \(live)")
                                        .font(.system(size: 10).monospacedDigit())
                                        .foregroundColor(.secondary)
                                        .lineLimit(1)
                                        .frame(width: 78, alignment: .trailing)
                                } else {
                                    Text("")
                                        .font(.system(size: 10).monospacedDigit())
                                        .frame(width: 78, alignment: .trailing)
                                }
                            }
                            .frame(height: 14)
                        }
                    }
                    .padding(.horizontal, 9)
                    .padding(.vertical, 7)
                    .background(
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .fill(Color.primary.opacity(colorScheme == .dark ? 0.045 : 0.035))
                    )
                }
            }
        }
    }
}

struct QuotaBarRow: View {
    let title: String
    let pool: QuotaPool?
    let isSyncing: Bool
    @Environment(\.colorScheme) private var colorScheme

    private var remainingFraction: Double {
        guard let p = pool else { return 0 }
        return max(0, min(1, p.remainingPct / 100.0))
    }

    private var barColor: Color {
        guard let p = pool else { return Color.secondary.opacity(0.3) }
        if p.remainingPct < 20 { return .red }
        if p.remainingPct < 45 { return .orange }
        return .accentColor
    }

    private var pctText: String {
        guard let p = pool else { return "--" }
        return "\(Int(p.remainingPct.rounded()))%"
    }

    var body: some View {
        HStack(spacing: 8) {
            Text(title)
                .font(.system(size: 11.5, weight: .medium))
                .foregroundColor(.secondary)
                .frame(width: 50, alignment: .leading)

            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule()
                        .fill(Color.primary.opacity(colorScheme == .dark ? 0.13 : 0.10))
                    if pool != nil {
                        Capsule()
                            .fill(barColor)
                            .frame(width: max(remainingFraction > 0 ? 4 : 0, geo.size.width * remainingFraction))
                            .animation(.easeOut(duration: 0.3), value: remainingFraction)
                    }
                }
            }
            .frame(height: 5)

            Text(pctText)
                .font(.system(size: 11.5, weight: .medium).monospacedDigit())
                .foregroundColor(.secondary)
                .frame(width: 34, alignment: .trailing)

            Text(QuotaHelpers.formatResetBadge(pool, isSyncing: isSyncing))
                .font(.system(size: 11))
                .foregroundColor(.secondary)
                .lineLimit(1)
                .frame(minWidth: 112, alignment: .trailing)
        }
        .frame(height: 16)
    }
}

struct EmptyAccountsView: View {
    @ObservedObject var store: SwitcherStore
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "person.2.circle")
                .font(.system(size: 34, weight: .light))
                .foregroundColor(.accentColor)

            VStack(spacing: 4) {
                Text("No Saved Accounts Yet")
                    .font(.system(size: 14, weight: .semibold))
                Text("Save your currently signed-in Antigravity account or sign in with a new Google account for 1-click switching.")
                    .font(.system(size: 11.5))
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }

            HStack(spacing: 8) {
                if store.hasActiveSession {
                    Button("Save Active Session") {
                        Task { _ = await store.saveCurrent(label: store.activeEmail) }
                    }
                    .buttonStyle(.borderedProminent)
                }
                Button("Add Account") {
                    store.beginWizard()
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(Color.primary.opacity(colorScheme == .dark ? 0.05 : 0.035))
        )
    }
}

struct QuickStripPill: View {
    let title: String
    let systemImage: String
    let isBusy: Bool
    let action: () -> Void

    @StateObject private var hover = HoverState()
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                if isBusy {
                    ProgressView().controlSize(.mini)
                } else {
                    Image(systemName: systemImage)
                        .font(.system(size: 10.5, weight: .semibold))
                }
                Text(title)
                    .font(.system(size: 11, weight: .medium))
            }
            .foregroundColor(.primary)
            .padding(.horizontal, 9)
            .padding(.vertical, 4.5)
            .adaptiveGlassPill(
                fallbackFill: Color.primary.opacity(hover.isHovered ? (colorScheme == .dark ? 0.12 : 0.085) : (colorScheme == .dark ? 0.07 : 0.048))
            )
        }
        .buttonStyle(.plain)
        .disabled(isBusy)
        .onHover { hover.isHovered = $0 }
    }
}

struct FooterActionButton: View {
    let title: String
    let systemImage: String
    let action: () -> Void

    @StateObject private var hover = HoverState()
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .font(.system(size: 12, weight: .medium))
                .foregroundColor(hover.isHovered ? .primary : .primary.opacity(0.88))
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .fill(hover.isHovered ? Color.primary.opacity(colorScheme == .dark ? 0.08 : 0.055) : Color.clear)
                )
        }
        .buttonStyle(.plain)
        .onHover { hover.isHovered = $0 }
    }
}

// MARK: - Manage Accounts View

struct ManageAccountsView: View {
    @ObservedObject var store: SwitcherStore
    @StateObject private var local = ManageViewState()
    @Environment(\.colorScheme) private var colorScheme

    private let planChoices = ["", "Antigravity Pro", "Antigravity Ultra", "Free"]

    var body: some View {
        VStack(spacing: 0) {
            SubViewHeader(title: "Manage Accounts") {
                store.screen = .accounts
            }

            Divider().opacity(0.55)

            VStack(spacing: 10) {
                HStack(spacing: 8) {
                    Button {
                        store.beginWizard()
                    } label: {
                        Label("Add Account", systemImage: "plus")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)

                    Button {
                        local.saveLabelInput = store.activeEmail ?? ""
                        local.showSaveSheet.toggle()
                    } label: {
                        Label("Save Current", systemImage: "square.and.arrow.down")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .disabled(!store.hasActiveSession)
                }

                if local.showSaveSheet {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Save active Antigravity session to Keychain:")
                            .font(.system(size: 11.5, weight: .medium))
                            .foregroundColor(.secondary)

                        HStack(spacing: 6) {
                            TextField("Account label or email", text: $local.saveLabelInput)
                                .textFieldStyle(.roundedBorder)
                            Button("Save") {
                                guard !local.isSaving else { return }
                                local.isSaving = true
                                Task {
                                    let ok = await store.saveCurrent(label: local.saveLabelInput)
                                    local.isSaving = false
                                    if ok { local.showSaveSheet = false }
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(local.isSaving)

                            Button("Cancel") {
                                local.showSaveSheet = false
                            }
                            .buttonStyle(.bordered)
                        }
                    }
                    .padding(10)
                    .background(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(Color.primary.opacity(colorScheme == .dark ? 0.06 : 0.04))
                    )
                }

                if store.accounts.isEmpty {
                    Text("No saved accounts.")
                        .font(.system(size: 12))
                        .foregroundColor(.secondary)
                        .padding(.vertical, 24)
                } else {
                    ScrollView {
                        VStack(spacing: 6) {
                            ForEach(store.sortedAccounts) { acc in
                                manageRow(for: acc)
                            }
                        }
                    }
                    .frame(maxHeight: 330)
                }
            }
            .padding(12)
        }
    }

    @ViewBuilder
    private func manageRow(for acc: AccountItem) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Circle()
                    .fill(acc.isActive ? Color.green : Color.secondary.opacity(0.35))
                    .frame(width: 8, height: 8)

                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 4) {
                        Text(acc.label)
                            .font(.system(size: 12.5, weight: .semibold))
                            .lineLimit(1)
                        if !acc.planLabel.isEmpty {
                            Text(acc.planLabel)
                                .font(.system(size: 9.5, weight: .medium))
                                .foregroundColor(.secondary)
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(Capsule().fill(Color.primary.opacity(0.07)))
                        }
                    }
                    if acc.email != acc.label {
                        Text(acc.email)
                            .font(.system(size: 10.5))
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                }

                Spacer()

                if local.confirmingDeleteKey == acc.key {
                    Button("Delete") {
                        local.confirmingDeleteKey = nil
                        Task { await store.removeAccount(acc.key) }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                    .controlSize(.small)

                    Button("Cancel") {
                        local.confirmingDeleteKey = nil
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                } else {
                    Button {
                        Task { await store.togglePin(acc) }
                    } label: {
                        Image(systemName: acc.pinned ? "pin.fill" : "pin")
                            .font(.system(size: 11.5))
                            .foregroundColor(acc.pinned ? .accentColor : .secondary)
                    }
                    .buttonStyle(.borderless)
                    .help(acc.pinned ? "Unpin account" : "Pin account to top")

                    Button {
                        local.editingPlanKey = (local.editingPlanKey == acc.key) ? nil : acc.key
                        local.renamingKey = nil
                        local.confirmingDeleteKey = nil
                    } label: {
                        Image(systemName: "tag")
                            .font(.system(size: 11.5))
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.borderless)
                    .help("Set plan label")

                    Button {
                        local.renamingKey = acc.key
                        local.renameDraft = acc.label
                        local.confirmingDeleteKey = nil
                        local.editingPlanKey = nil
                    } label: {
                        Image(systemName: "pencil")
                            .font(.system(size: 12))
                    }
                    .buttonStyle(.borderless)
                    .help("Rename label")

                    Button {
                        local.confirmingDeleteKey = acc.key
                        local.renamingKey = nil
                        local.editingPlanKey = nil
                    } label: {
                        Image(systemName: "trash")
                            .font(.system(size: 12))
                            .foregroundColor(.red.opacity(0.85))
                    }
                    .buttonStyle(.borderless)
                    .help("Remove account")
                }
            }

            if local.editingPlanKey == acc.key {
                HStack(spacing: 5) {
                    Text("Plan:")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                    ForEach(planChoices, id: \.self) { choice in
                        let title = choice.isEmpty ? "Auto" : choice.replacingOccurrences(of: "Antigravity ", with: "")
                        let selected = acc.planLabel == choice
                        Button(title) {
                            Task {
                                await store.setPlanLabel(acc.key, plan: choice)
                                local.editingPlanKey = nil
                            }
                        }
                        .buttonStyle(.bordered)
                        .tint(selected ? .accentColor : nil)
                        .controlSize(.mini)
                    }
                }
            }

            if local.renamingKey == acc.key {
                HStack(spacing: 6) {
                    TextField("New label", text: $local.renameDraft)
                        .textFieldStyle(.roundedBorder)
                    Button("Save") {
                        Task {
                            if await store.renameAccount(from: acc.key, to: local.renameDraft) {
                                local.renamingKey = nil
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)

                    Button("Cancel") {
                        local.renamingKey = nil
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.primary.opacity(colorScheme == .dark ? 0.055 : 0.04))
        )
    }
}

// MARK: - Guided Add Account Wizard

struct AddAccountWizardView: View {
    @ObservedObject var store: SwitcherStore

    var body: some View {
        VStack(spacing: 0) {
            SubViewHeader(title: "Add New Account") {
                store.cancelWizardLogin(restoreBackup: true)
                store.screen = .accounts
            }

            Divider().opacity(0.55)

            VStack(alignment: .leading, spacing: 12) {
                if store.wizardStep == 1 {
                    if store.hasOfficialAgyCLI {
                        WizardStepRow(num: "1", text: "Uses Google's Antigravity CLI with a temporary sign-in profile.")
                        WizardStepRow(num: "2", text: "Your active Antigravity session stays signed in while you authorize the new Google account.")
                        WizardStepRow(num: "3", text: "Paste the code from antigravity.google to store your official credential in Keychain.")

                        Button {
                            Task { await store.startOfficialAgyCLILogin() }
                        } label: {
                            HStack(spacing: 6) {
                                if store.wizardBusy && store.wizardMode == .agyCli {
                                    ProgressView().controlSize(.small)
                                } else {
                                    Image(systemName: "checkmark.shield")
                                }
                                Text("Sign in via Antigravity CLI (Official)")
                            }
                            .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(store.wizardBusy)
                    } else {
                        WizardStepRow(num: "1", text: "Antigravity restarts cleanly in signed-out login mode.")
                        WizardStepRow(num: "2", text: "Sign in with your new Google account inside Antigravity.")
                        WizardStepRow(num: "3", text: "GravityBar detects the new session automatically and stores it in Keychain.")
                    }

                    Button {
                        Task { await store.startWizardLogin() }
                    } label: {
                        HStack(spacing: 5) {
                            if store.wizardBusy && store.wizardMode == .antigravityIDE {
                                ProgressView().controlSize(.small)
                            }
                            Text(store.hasOfficialAgyCLI ? "Or sign in inside Antigravity Desktop App" : "Start Login in Antigravity App")
                                .font(.system(size: 11.5))
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(store.hasOfficialAgyCLI ? .small : .regular)
                    .disabled(store.wizardBusy)

                } else if store.wizardStep == 2 {
                    VStack(spacing: 11) {
                        if store.wizardMode == .agyCli {
                            if store.wizardAuthURL == nil {
                                ProgressView()
                                    .controlSize(.regular)
                                    .padding(.top, 6)
                                Text("Starting Official Antigravity CLI...")
                                    .font(.system(size: 13.5, weight: .semibold))
                                Text("Waiting for the Google sign-in link.")
                                    .font(.system(size: 11.5))
                                    .foregroundColor(.secondary)
                                    .multilineTextAlignment(.center)
                                Button("Cancel") {
                                    store.cancelWizardLogin(restoreBackup: true)
                                }
                                .buttonStyle(.bordered)
                            } else {
                                if store.wizardVerifyingCode {
                                    ProgressView().controlSize(.small)
                                }
                                Text("Complete Official Antigravity Sign-In")
                                    .font(.system(size: 13.5, weight: .semibold))
                                Text("Sign in in your browser, then paste the code (or full URL) shown on antigravity.google below:")
                                    .font(.system(size: 11.5))
                                    .foregroundColor(.secondary)
                                    .multilineTextAlignment(.center)

                                TextField("Paste authorization code or redirect URL...", text: $store.wizardAuthCodeInput)
                                    .textFieldStyle(.roundedBorder)
                                    .onSubmit {
                                        store.submitOfficialAgyCode()
                                    }

                                HStack(spacing: 8) {
                                    Button("Cancel") {
                                        store.cancelWizardLogin(restoreBackup: true)
                                    }
                                    .buttonStyle(.bordered)

                                    Button("Re-open Link") {
                                        store.reopenOfficialAgyURL()
                                    }
                                    .buttonStyle(.bordered)

                                    Button("Verify & Continue") {
                                        store.submitOfficialAgyCode()
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .disabled(store.wizardVerifyingCode || store.wizardAuthCodeInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                                }
                            }
                        } else {
                            ProgressView()
                                .controlSize(.regular)
                                .padding(.top, 6)

                            Text("Waiting for Google Sign-In...")
                                .font(.system(size: 13.5, weight: .semibold))

                            Text("Complete login in the Antigravity app window. Cancel restores your previous session.")
                                .font(.system(size: 11.5))
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)

                            HStack(spacing: 8) {
                                Button("Cancel") {
                                    store.cancelWizardLogin(restoreBackup: true)
                                }
                                .buttonStyle(.bordered)

                                Button("Open Antigravity") {
                                    store.openAntigravity()
                                }
                                .buttonStyle(.bordered)

                                Button("Check Sign-In") {
                                    Task { await store.checkWizardSignInNow() }
                                }
                                .buttonStyle(.borderedProminent)
                                .disabled(store.wizardBusy)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)

                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.green)
                                .font(.system(size: 18))
                            VStack(alignment: .leading, spacing: 1) {
                                Text("Account Detected")
                                    .font(.system(size: 13, weight: .semibold))
                                if let em = store.wizardDetectedEmail {
                                    Text(em)
                                        .font(.system(size: 11.5))
                                        .foregroundColor(.secondary)
                                }
                            }
                        }

                        TextField("Account label (e.g. Work, Personal)", text: $store.wizardNewLabel)
                            .textFieldStyle(.roundedBorder)

                        Button {
                            Task { await store.finishWizardSave() }
                        } label: {
                            HStack {
                                if store.wizardBusy { ProgressView().controlSize(.small) }
                                Text("Save to Keychain")
                                    .frame(maxWidth: .infinity)
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(store.wizardBusy)
                    }
                }
            }
            .padding(14)
        }
    }
}

struct WizardStepRow: View {
    let num: String
    let text: String
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        HStack(alignment: .top, spacing: 9) {
            Text(num)
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(.accentColor)
                .frame(width: 20, height: 20)
                .background(Circle().fill(Color.accentColor.opacity(0.16)))
            Text(text)
                .font(.system(size: 12))
                .foregroundColor(.secondary)
        }
        .padding(9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.primary.opacity(colorScheme == .dark ? 0.05 : 0.035))
        )
    }
}

// MARK: - Settings View

struct SettingsView: View {
    @ObservedObject var store: SwitcherStore
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        VStack(spacing: 0) {
            SubViewHeader(title: "Settings") {
                store.screen = .accounts
            }

            Divider().opacity(0.55)

            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Menu Bar display")
                        .font(.system(size: 12.5))
                    Spacer()
                    Picker("", selection: $store.menuBarDisplayRaw) {
                        ForEach(MenuBarDisplayMode.allCases, id: \.self) { m in
                            Text(m.title).tag(m.rawValue)
                        }
                    }
                    .labelsHidden()
                    .frame(width: 115)
                }

                Toggle("Global shortcut (⌥⌘A)", isOn: $store.enableGlobalHotkey)
                    .font(.system(size: 12.5))

                Toggle("Low-quota alerts (< 15%)", isOn: $store.lowQuotaAlertsEnabled)
                    .font(.system(size: 12.5))

                Toggle("Confirm before switching", isOn: $store.confirmBeforeSwitch)
                    .font(.system(size: 12.5))

                Toggle("Launch at login", isOn: Binding(
                    get: { store.launchAtLogin },
                    set: { store.setLaunchAtLogin($0) }
                ))
                .font(.system(size: 12.5))

                Toggle("Play macOS sound effects", isOn: $store.playSounds)
                    .font(.system(size: 12.5))

                Toggle("Auto-start 5h Gemini timer (Hydrogen / Flash)", isOn: $store.autoWarmup5hEnabled)
                    .font(.system(size: 12.5))

                HStack(spacing: 8) {
                    Text(store.lastWarmupStatus.isEmpty ? "Sends a short ping when the 5h quota is idle" : store.lastWarmupStatus)
                        .font(.system(size: 10.5))
                        .foregroundColor(.secondary)
                        .lineLimit(2)
                    Spacer(minLength: 6)
                    Button {
                        Task { await store.triggerManualWarmup() }
                    } label: {
                        HStack(spacing: 4) {
                            if store.isWarmingUp {
                                ProgressView().controlSize(.mini)
                            }
                            Text(store.isWarmingUp ? "Pinging..." : "Ping Now")
                                .font(.system(size: 11, weight: .medium))
                        }
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .disabled(store.isWarmingUp || store.accounts.isEmpty)
                }

                HStack {
                    Text("Auto-refresh quotas")
                        .font(.system(size: 12.5))
                    Spacer()
                    Picker("", selection: $store.autoRefreshMinutes) {
                        Text("Manual").tag(0)
                        Text("2 min").tag(2)
                        Text("5 min").tag(5)
                        Text("10 min").tag(10)
                    }
                    .labelsHidden()
                    .frame(width: 115)
                }

                Divider().opacity(0.45)

                HStack(spacing: 8) {
                    Image(systemName: "lock.shield.fill")
                        .foregroundColor(.green)
                        .font(.system(size: 16))
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Native macOS Keychain Protected")
                            .font(.system(size: 12, weight: .semibold))
                        Text("Zero plaintext .token files · Native Swift engine")
                            .font(.system(size: 10.5))
                            .foregroundColor(.secondary)
                    }
                }
                .padding(9)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color.green.opacity(colorScheme == .dark ? 0.12 : 0.09))
                )

                HStack {
                    Text("Keys: ⌥⌘A toggle · ↑↓ select · ↵ / 1–9 switch · ⌘R refresh")
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                    Spacer()
                    Button("GitHub") {
                        if let url = URL(string: "https://github.com/Recoba86/GravityBar") {
                            NSWorkspace.shared.open(url)
                        }
                    }
                    .buttonStyle(.link)
                    .font(.system(size: 11))
                }
            }
            .padding(14)
        }
    }
}

struct SubViewHeader: View {
    let title: String
    let onBack: () -> Void

    var body: some View {
        HStack {
            Button(action: onBack) {
                HStack(spacing: 3) {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 11.5, weight: .semibold))
                    Text("Back")
                        .font(.system(size: 12, weight: .medium))
                }
                .foregroundColor(.accentColor)
            }
            .buttonStyle(.plain)

            Spacer()

            Text(title)
                .font(.system(size: 13, weight: .semibold))

            Spacer()

            Text("Back")
                .font(.system(size: 12))
                .opacity(0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}
