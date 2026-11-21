const vscode = require('vscode');
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

let statusBarItem;
let statusUpdatePending = false;

function getAgySwitchBin() {
    const candidates = [
        '/Applications/GravityBar.app/Contents/Resources/switcher_core.py',
        '/opt/homebrew/bin/gravitybar',
        '/usr/local/bin/gravitybar',
        path.join(os.homedir(), '.local/bin/gravitybar'),
        '/opt/homebrew/bin/agy-switch',
        '/usr/local/bin/agy-switch',
        path.join(os.homedir(), '.local/bin/agy-switch'),
        path.join(os.homedir(), 'GravityBar/switcher_core.py')
    ];
    for (const p of candidates) {
        if (fs.existsSync(p)) return p;
    }
    return 'gravitybar';
}

function runFile(file, args = [], options = {}) {
    return new Promise((resolve) => {
        execFile(file, args, { windowsHide: true, ...options }, (err, stdout, stderr) => {
            let code = 0;
            if (err) {
                code = typeof err.code === 'number' ? err.code : 1;
            }
            resolve({
                code,
                stdout: stdout ? stdout.trim() : '',
                stderr: stderr ? stderr.trim() : ''
            });
        });
    });
}

function extractQuotaSummary(usage) {
    if (!usage || typeof usage !== 'object') return null;
    const hasPools = Array.isArray(usage.pools);
    const pools = hasPools ? usage.pools.filter(p => p && typeof p === 'object') : [];
    const isArgon = p => {
        const g = (p.group_name || p.name || '').toLowerCase();
        return g.includes('argon');
    };
    const isGemini = p => {
        const g = (p.group_name || p.name || '').toLowerCase();
        return g.includes('gemini') && !isArgon(p);
    };
    const isClaudeGroup = p => {
        const g = (p.group_name || p.name || '').toLowerCase();
        return g.includes('claude') || g.includes('gpt');
    };
    const is5h = p => {
        const w = (p.window_label || p.name || '').toLowerCase();
        return w.includes('5h') || w.includes('five hour');
    };
    const isWeekly = p => {
        const w = (p.window_label || p.name || '').toLowerCase();
        return w.includes('weekly') || w.includes('7d');
    };

    const gem5hPool = pools.find(p => p && isGemini(p) && is5h(p))
        || pools.find(p => isGemini(p) && !p.window_label && !isWeekly(p))
        || (!hasPools && usage.daily && !isWeekly(usage.daily) ? usage.daily : null);
    const gemWeeklyPool = pools.find(p => isGemini(p) && isWeekly(p));
    const cla5hPool = pools.find(p => p && isClaudeGroup(p) && is5h(p))
        || pools.find(p => isClaudeGroup(p) && !p.window_label && !isWeekly(p))
        || (!hasPools && usage.weekly && isClaudeGroup(usage.weekly) && !isWeekly(usage.weekly) ? usage.weekly : null);
    const claWeeklyPool = pools.find(p => p && isClaudeGroup(p) && isWeekly(p));
    const argonPool = pools.find(p => p && isArgon(p));
    const gptPool = pools.find(p => p && typeof p.name === 'string' && p.name.toLowerCase().includes('gpt'));

    const gemRem = (gem5hPool && typeof gem5hPool.remaining_pct === 'number') ? gem5hPool.remaining_pct : null;
    const gemWeeklyRem = (gemWeeklyPool && typeof gemWeeklyPool.remaining_pct === 'number') ? gemWeeklyPool.remaining_pct : null;
    const claRem = (cla5hPool && typeof cla5hPool.remaining_pct === 'number') ? cla5hPool.remaining_pct : null;
    const claWeeklyRem = (claWeeklyPool && typeof claWeeklyPool.remaining_pct === 'number') ? claWeeklyPool.remaining_pct : null;
    const argonRem = (argonPool && typeof argonPool.remaining_pct === 'number') ? argonPool.remaining_pct : null;
    const gptRem = (gptPool && typeof gptPool.remaining_pct === 'number') ? gptPool.remaining_pct : null;

    const vals = [gemRem, gemWeeklyRem, claRem, claWeeklyRem, argonRem].filter(v => v !== null);
    if (vals.length === 0) return null;

    return {
        gemRem,
        gemReset: gem5hPool ? (gem5hPool.reset_short || gem5hPool.resets_in || '') : '',
        gemWeeklyRem,
        gemWeeklyReset: gemWeeklyPool ? (gemWeeklyPool.reset_short || gemWeeklyPool.resets_in || '') : '',
        claRem,
        claReset: cla5hPool ? (cla5hPool.reset_short || cla5hPool.resets_in || '') : '',
        claWeeklyRem,
        claWeeklyReset: claWeeklyPool ? (claWeeklyPool.reset_short || claWeeklyPool.resets_in || '') : '',
        argonRem,
        gptRem,
        minRem: Math.min(...vals),
        tier: typeof usage.tier === 'string' ? usage.tier : ''
    };
}

async function readStatus(bin = getAgySwitchBin()) {
    const result = await runFile(bin, ['--status-json', '--cached-only'], { timeout: 5000 });
    if (result.code !== 0) throw new Error('Could not read GravityBar status. Check the CLI installation.');
    const payload = JSON.parse(result.stdout);
    if (!Array.isArray(payload?.accounts)) throw new Error('GravityBar returned invalid account data.');
    return payload;
}

async function runAction(file, args, failureMessage) {
    const result = await runFile(file, args);
    if (result.code !== 0) {
        vscode.window.showErrorMessage(result.stderr || failureMessage);
        return false;
    }
    return true;
}

async function updateStatusBar() {
    if (!statusBarItem || statusUpdatePending) return;
    const item = statusBarItem;
    statusUpdatePending = true;
    try {
        const payload = await readStatus();
        if (item !== statusBarItem) return;
        const activeKey = payload.active_key;
        if (activeKey) {
            const q = extractQuotaSummary(payload.accounts.find(account => account.key === activeKey)?.usage);
            const gemini = q?.gemRem ?? q?.gemWeeklyRem;
            const isLow = q && q.minRem < 15;
            const icon = isLow ? '$(warning)' : '$(account)';
            if (gemini != null) {
                statusBarItem.text = `${icon} GravityBar: ${activeKey} (${Math.round(gemini)}%)`;
            } else {
                statusBarItem.text = `${icon} GravityBar: ${activeKey}`;
            }

            const lines = [`Active Account: ${activeKey}`];
            if (q) {
                if (q.gemRem !== null) {
                    let gLine = `Gemini: ${Math.round(q.gemRem)}% left${q.gemReset ? ` (Resets ${q.gemReset})` : ''}`;
                    if (q.gemWeeklyRem !== null) gLine += ` · Weekly: ${Math.round(q.gemWeeklyRem)}%`;
                    lines.push(gLine);
                } else if (q.gemWeeklyRem !== null) {
                    lines.push(`Gemini weekly: ${Math.round(q.gemWeeklyRem)}% left`);
                }
                if (q.claRem !== null) {
                    let cLine = `Claude/GPT: ${Math.round(q.claRem)}% left${q.claReset ? ` (Resets ${q.claReset})` : ''}`;
                    if (q.claWeeklyRem !== null) cLine += ` · Weekly: ${Math.round(q.claWeeklyRem)}%`;
                    lines.push(cLine);
                }
                if (q.argonRem !== null) lines.push(`Gemini 4 Argon: ${Math.round(q.argonRem)}% left`);
                if (q.gptRem !== null && q.claRem === null) lines.push(`GPT-OSS: ${Math.round(q.gptRem)}% left`);
            }
            lines.push('Click to switch accounts or view limits');
            statusBarItem.tooltip = lines.join('\n');
        } else if (payload.has_active_session) {
            statusBarItem.text = `$(account) GravityBar: Active Session`;
            statusBarItem.tooltip = `GravityBar Session Active (Unsaved). Click to save or switch.`;
        } else {
            statusBarItem.text = `$(account) GravityBar: Not Signed In`;
            statusBarItem.tooltip = `No active Antigravity account. Click to sign in.`;
        }
    } catch {
        if (item === statusBarItem) {
            item.text = '$(warning) GravityBar';
            item.tooltip = 'Could not read GravityBar status. Check the CLI installation.';
        }
    } finally {
        statusUpdatePending = false;
    }
}

function activate(context) {
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'antigravitySwitcher.openMenu';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    updateStatusBar();
    const interval = setInterval(updateStatusBar, 15000);
    context.subscriptions.push({ dispose: () => clearInterval(interval) });

    const disposable = vscode.commands.registerCommand('antigravitySwitcher.openMenu', async () => {
        const bin = getAgySwitchBin();
        let payload;
        try {
            payload = await readStatus(bin);
        } catch (error) {
            vscode.window.showErrorMessage(error.message);
            return;
        }
        const { active_key: activeKey, has_active_session: hasActiveToken, accounts } = payload;
        const items = [];

        const bestCandidate = payload.best_switch_candidate;
        if (bestCandidate) {
            const bq = extractQuotaSummary(accounts.find(account => account.key === bestCandidate)?.usage);
            const desc = bq && bq.gemRem !== null
                ? `Gem ${Math.round(bq.gemRem)}%${bq.claRem !== null ? ` · Cla ${Math.round(bq.claRem)}%` : ''}${bq.argonRem !== null ? ` · Argon ${Math.round(bq.argonRem)}%` : ''} (Recommended)`
                : 'Highest available quota';
            items.push({
                label: `✨ Switch to Best Available: ${bestCandidate}`,
                description: desc,
                action: 'switch',
                target: bestCandidate
            });
            items.push({ label: '─────────────────────────────', kind: vscode.QuickPickItemKind.Separator });
        }

        // 1. Saved Accounts (pinned first, then alphabetical)
        const sorted = [...accounts].sort((a, b) => Number(b.pinned) - Number(a.pinned) || a.key.localeCompare(b.key));
        for (const account of sorted) {
            const k = account.key;
            const isActive = k === activeKey;
            const isPinned = account.pinned;
            const q = extractQuotaSummary(account.usage);
            const quotaParts = [];
            if (q?.gemRem != null) quotaParts.push(`Gem ${Math.round(q.gemRem)}%`);
            else if (q?.gemWeeklyRem != null) quotaParts.push(`Gem weekly ${Math.round(q.gemWeeklyRem)}%`);
            if (q && q.claRem !== null) quotaParts.push(`Cla ${Math.round(q.claRem)}%`);
            if (q && q.argonRem !== null) quotaParts.push(`Argon ${Math.round(q.argonRem)}%`);
            if (isPinned) quotaParts.push('📌');
            if (isActive) quotaParts.push('Active');
            items.push({
                label: `${isActive ? '🟢' : '⚡️'} Switch to: ${k}`,
                description: quotaParts.join(' · '),
                action: 'switch',
                target: k
            });
        }

        if (items.length > 0) {
            items.push({ label: '─────────────────────────────', kind: vscode.QuickPickItemKind.Separator });
        }

        // 2. Action Buttons
        items.push({
            label: '➕ Add New Account (Wizard)',
            description: 'Step-by-step sign in with another Gmail',
            action: 'wizard'
        });

        items.push({
            label: '📊 View Quotas & Limits',
            description: 'Live model limits dashboard',
            action: 'usage'
        });

        const activeDisplay = activeKey || (hasActiveToken ? 'Current Session' : null);
        if (activeDisplay) {
            items.push({
                label: `💾 Save Current Account (${activeDisplay})`,
                description: 'Save active session into account list',
                action: 'save'
            });
        }

        items.push({
            label: '🚀 Open GravityBar App',
            description: 'Launch native macOS GravityBar UI',
            action: 'app'
        });

        const selected = await vscode.window.showQuickPick(items, {
            placeHolder: `GravityBar [Active: ${activeKey || 'Unsaved'}] - Choose an action:`
        });

        if (!selected || !selected.action) return;

        if (selected.action === 'switch') {
            vscode.window.showInformationMessage(`Switching to '${selected.target}'... Antigravity will reload.`);
            const args = [`--switch=${selected.target}`, '--quiet'];
            const appRoot = vscode.env?.appRoot;
            if (process.platform === 'darwin' && appRoot) {
                const bundle = path.resolve(appRoot, '../../..');
                if (bundle.endsWith('.app')) args.push(`--restart-bundle=${bundle}`);
            }
            if (await runAction(bin, args, 'GravityBar could not switch accounts.')) {
                updateStatusBar();
            }
        } else if (selected.action === 'wizard') {
            vscode.window.showInformationMessage('Starting Add Account Wizard...');
            await runAction(bin, ['--wizard'], 'GravityBar could not open the sign-in wizard.');
        } else if (selected.action === 'usage') {
            await runAction(bin, ['--usage-gui', '--force-refresh', '--quiet'], 'GravityBar could not open the quota dashboard.');
        } else if (selected.action === 'save') {
            const label = await vscode.window.showInputBox({
                prompt: 'Enter a name or label for this account:',
                value: activeKey || ''
            });
            if (label && label.trim()) {
                if (await runAction(bin, [`--save=${label.trim()}`, '--quiet'], 'GravityBar could not save the account.')) {
                    vscode.window.showInformationMessage(`Account '${label.trim()}' saved!`);
                    updateStatusBar();
                }
            }
        } else if (selected.action === 'app') {
            if (process.platform === 'darwin' && fs.existsSync('/Applications/GravityBar.app')) {
                await runAction('open', ['/Applications/GravityBar.app'], 'Could not open GravityBar.');
            } else if (process.platform === 'darwin' && fs.existsSync('/Applications/AntigravitySwitcher.app')) {
                await runAction('open', ['/Applications/AntigravitySwitcher.app'], 'Could not open Antigravity Switcher.');
            } else {
                await runAction(bin, [], 'Could not open GravityBar.');
            }
        }
    });

    context.subscriptions.push(disposable);
}

function deactivate() {
    if (statusBarItem) {
        statusBarItem.dispose();
        statusBarItem = undefined;
    }
}

module.exports = {
    activate,
    deactivate,
    extractQuotaSummary
};
