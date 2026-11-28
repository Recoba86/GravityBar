const assert = require('assert');
const fs = require('fs');
const Module = require('module');
const os = require('os');
const path = require('path');

const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'ag_ext_test_'));
const accountsDir = path.join(tmpHome, '.gemini', 'accounts');
fs.mkdirSync(accountsDir, { recursive: true });

const activeAccount = 'work"; touch /tmp/pwn; #';
const altAccount = 'personal';
const label = '--my-label';

fs.writeFileSync(path.join(accountsDir, 'manifest.json'), JSON.stringify({
    [activeAccount]: { pinned: true },
    [altAccount]: { pinned: false }
}));

fs.writeFileSync(path.join(accountsDir, 'usage_cache.json'), JSON.stringify({
    [activeAccount]: {
        daily: { remaining_pct: 12.0, reset_short: '11:37' },
        weekly: { remaining_pct: 40.0, reset_short: 'Nov 21 at 00:49' },
        pools: [
            { name: 'Gemini (Pro & Flash)', remaining_pct: 12.0, reset_short: '11:37' },
            { name: 'Claude 4.6 (Sonnet & Opus)', remaining_pct: 40.0, reset_short: 'Nov 21 at 00:49' },
            { name: 'Gemini 4 Argon — Weekly limit', group_name: 'Gemini 4 Argon', window_label: 'Weekly limit', remaining_pct: 87.0, reset_short: 'Nov 27 at 12:36' }
        ]
    },
    [altAccount]: {
        daily: { remaining_pct: 92.0, reset_short: '18:00' },
        weekly: { remaining_pct: 88.0, reset_short: 'Nov 24 at 10:00' },
        pools: [
            { name: 'Gemini (Pro & Flash)', remaining_pct: 92.0, reset_short: '18:00' },
            { name: 'Claude 4.6 (Sonnet & Opus)', remaining_pct: 88.0, reset_short: 'Nov 24 at 10:00' },
            { name: 'Gemini 4 Argon — Weekly limit', group_name: 'Gemini 4 Argon', window_label: 'Weekly limit', remaining_pct: 95.0, reset_short: 'Nov 27 at 12:36' }
        ]
    }
}));

const execCalls = [];
const errors = [];
let quickPickItemsSeen = null;
let quickPickResult = null;
let inputBoxResult = null;
let registeredCmd = null;
const statusBarMock = { show: () => {}, dispose: () => {}, text: '', tooltip: '', command: '' };

const fakeVscode = {
    env: { appRoot: '/Applications/Antigravity IDE.app/Contents/Resources/app' },
    StatusBarAlignment: { Right: 2 },
    ProgressLocation: { Notification: 15 },
    QuickPickItemKind: { Separator: -1 },
    window: {
        createStatusBarItem: () => statusBarMock,
        showQuickPick: async (items) => { quickPickItemsSeen = items; return quickPickResult; },
        showInputBox: async () => inputBoxResult,
        showInformationMessage: () => {},
        withProgress: async (_opts, task) => task(),
        showErrorMessage: message => errors.push(message)
    },
    commands: {
        registerCommand: (name, fn) => { registeredCmd = fn; return { dispose: () => {} }; }
    }
};

const origLoad = Module._load;
const childProcess = require('child_process');
const origExecFile = childProcess.execFile;
const origHomedir = os.homedir;

let activeKey = activeAccount;
let switchFailure = false;
os.homedir = () => tmpHome;
childProcess.execFile = (file, args, opts, cb) => {
    if (typeof opts === 'function') { cb = opts; }
    execCalls.push({ file, args: Array.from(args || []) });
    if (args[0] === '--status-json') {
        const accounts = JSON.parse(fs.readFileSync(path.join(accountsDir, 'manifest.json'), 'utf8'));
        const quota = JSON.parse(fs.readFileSync(path.join(accountsDir, 'usage_cache.json'), 'utf8'));
        cb(null, JSON.stringify({
            active_key: activeKey,
            has_active_session: Boolean(activeKey),
            best_switch_candidate: activeKey === activeAccount ? altAccount : null,
            accounts: Object.entries(accounts).map(([key, account]) => ({
                key, pinned: account.pinned, usage: quota[key]
            }))
        }), '');
        return;
    }
    if (switchFailure && args[0].startsWith('--switch=')) {
        cb({ code: 1 }, '', 'Saved credential is missing.');
        return;
    }
    cb(null, '', '');
};
Module._load = function (request, parent, isMain) {
    if (request === 'vscode') return fakeVscode;
    return origLoad.apply(this, arguments);
};

const ctx = { subscriptions: [] };
let ext;
(async () => {
    try {
        ext = require('../editor-extension/extension.js');
        ext.activate(ctx);
        await new Promise(r => setTimeout(r, 60));

        // 1. Status bar displays low-quota warning icon and remaining %
        assert(statusBarMock.text.includes('$(warning)'), `Expected warning icon in ${statusBarMock.text}`);
        assert(statusBarMock.text.includes('(12%)'), `Expected (12%) in ${statusBarMock.text}`);
        assert(statusBarMock.tooltip.includes('Gemini: 12% left'), `Expected Gemini tooltip in ${statusBarMock.tooltip}`);
        assert(statusBarMock.tooltip.includes('Gemini 4 Argon: 87% left'), `Expected Argon tooltip in ${statusBarMock.tooltip}`);

        // 2. QuickPick shows "Switch to Best Available" + per-account quotas + execFile args safety
        quickPickResult = { action: 'switch', target: activeAccount };
        await registeredCmd();
        assert(quickPickItemsSeen.some(i => i.label && i.label.includes('Switch to Best Available: personal')));
        assert(quickPickItemsSeen.some(i => i.description && i.description.includes('Gem 92%') && i.description.includes('Argon 95%')));

        const switchCall = execCalls.find(c => c.args[0].startsWith('--switch='));
        assert(switchCall, 'Expected --switch execFile call');
        const expectedSwitch = [`--switch=${activeAccount}`, '--quiet'];
        if (process.platform === 'darwin') {
            expectedSwitch.push('--restart-bundle=/Applications/Antigravity IDE.app');
        }
        assert.deepStrictEqual(switchCall.args, expectedSwitch);

        // 3. Save passes raw un-interpolated label via execFile
        quickPickResult = { action: 'save' };
        inputBoxResult = label;
        await registeredCmd();
        const saveCall = execCalls.find(c => c.args[0].startsWith('--save='));
        assert(saveCall, 'Expected --save execFile call');
        assert.deepStrictEqual(saveCall.args, [`--save=${label}`, '--quiet']);

        // 3b. Quota check is a single manual action with progress
        quickPickResult = { action: 'usage' };
        await registeredCmd();
        const usageCall = execCalls.find(c => c.args[0] === '--usage-gui');
        assert(usageCall, 'Expected --usage-gui execFile call');
        assert.deepStrictEqual(usageCall.args, ['--usage-gui', '--force-refresh', '--quiet']);
        const statusCalls = execCalls.filter(c => c.args[0] === '--status-json');
        assert(statusCalls.every(c => c.args.includes('--cached-only')), 'Status polling must never check quotas');

        // 4. Modern 5h/Weekly + Argon schema extraction
        const modernSummary = ext.extractQuotaSummary({
            tier: 'Google AI Pro',
            pools: [
                { name: 'Gemini Models — 5h limit', group_name: 'Gemini Models', window_label: '5h limit', remaining_pct: 67.0, reset_short: '18:10' },
                { name: 'Gemini Models — Weekly limit', group_name: 'Gemini Models', window_label: 'Weekly limit', remaining_pct: 79.0, reset_short: 'Nov 27 at 02:48' },
                { name: 'Claude and GPT models — 5h limit', group_name: 'Claude and GPT models', window_label: '5h limit', remaining_pct: 100.0, reset_short: '20:13' },
                { name: 'Claude and GPT models — Weekly limit', group_name: 'Claude and GPT models', window_label: 'Weekly limit', remaining_pct: 95.0, reset_short: 'Nov 27 at 15:18' },
                { name: 'Gemini 4 Argon — Weekly limit', group_name: 'Gemini 4 Argon', window_label: 'Weekly limit', remaining_pct: 87.0, reset_short: 'Nov 27 at 22:00' },
            ]
        });
        assert.strictEqual(modernSummary.gemRem, 67.0);
        assert.strictEqual(modernSummary.gemWeeklyRem, 79.0);
        assert.strictEqual(modernSummary.claRem, 100.0);
        assert.strictEqual(modernSummary.claWeeklyRem, 95.0);
        assert.strictEqual(modernSummary.argonRem, 87.0);

        const weeklyOnly = ext.extractQuotaSummary({
            daily: { remaining_pct: 100 },
            pools: [{ group_name: 'Gemini Models', window_label: 'Weekly limit', remaining_pct: 42 }]
        });
        assert.strictEqual(weeklyOnly.gemRem, null);
        assert.strictEqual(weeklyOnly.gemWeeklyRem, 42);
        assert.strictEqual(ext.extractQuotaSummary({ daily: { remaining_pct: 100 }, pools: [] }), null);

        activeKey = altAccount;
        switchFailure = true;
        quickPickResult = { action: 'switch', target: '--second-account' };
        await registeredCmd();
        assert(quickPickItemsSeen.some(i => i.label === '🟢 Switch to: personal'));
        assert(execCalls.some(c => c.args[0] === '--switch=--second-account'));
        assert(errors.includes('Saved credential is missing.'));
        assert(execCalls.every(c => c.file !== 'security' && !c.args.includes('--get-token')));
        assert(execCalls.some(c => c.args.join(' ') === '--status-json --cached-only'));

        console.log('PASS: IDE extension tests');
    } catch (err) {
        console.error(err);
        process.exitCode = 1;
    } finally {
        Module._load = origLoad;
        childProcess.execFile = origExecFile;
        os.homedir = origHomedir;
        for (const sub of ctx.subscriptions) {
            if (sub && sub.dispose) sub.dispose();
        }
        fs.rmSync(tmpHome, { recursive: true, force: true });
    }
})();
