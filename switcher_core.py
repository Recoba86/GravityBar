#!/usr/bin/env python3
"""
GravityBar — Antigravity Account Switcher
Created by Rick Sanchez (https://github.com/m4tinbeigi-official)
Native Apple Silicon (arm64) 1-click Google account switcher for Google Antigravity on macOS.
Interacts directly with macOS Keychain (service: 'gemini', account: 'antigravity').
"""

import os
import sys
import json
import base64
from contextlib import contextmanager
from functools import wraps
import fcntl
import subprocess
import urllib.error
import urllib.request
import urllib.parse
import time
import argparse
import platform
import ctypes
import ctypes.util
import hashlib
import pathlib
import plistlib
import re
import selectors
import tempfile
import threading

ACCOUNTS_DIR = os.path.expanduser('~/.gemini/accounts')
MANIFEST_PATH = os.path.join(ACCOUNTS_DIR, 'manifest.json')
GITHUB_REPO_URL = "https://github.com/Recoba86/GravityBar"
AUTHOR_NAME = "Rick Sanchez (@m4tinbeigi-official)"

IS_MACOS = platform.system() == 'Darwin'

KEYCHAIN_ACTIVE_SERVICE = 'gemini'
KEYCHAIN_ACTIVE_ACCOUNT = 'antigravity'
KEYCHAIN_SAVED_SERVICE = 'gravitybar'
KEYCHAIN_LEGACY_SAVED_SERVICE = 'antigravity-account-switcher'
_SAFE_SECRET_ID_RE = re.compile(r'^acct_[a-f0-9]{16,64}$')
_SAFE_SECURITY_ARG_RE = re.compile(r'^[A-Za-z0-9._:@+/=-]+$')

_CID_CODES = [49, 48, 55, 49, 48, 48, 54, 48, 54, 48, 53, 57, 49, 45, 116, 109, 104, 115, 115, 105, 110, 50, 104, 50, 49, 108, 99, 114, 101, 50, 51, 53, 118, 116, 111, 108, 111, 106, 104, 52, 103, 52, 48, 51, 101, 112, 46, 97, 112, 112, 115, 46, 103, 111, 111, 103, 108, 101, 117, 115, 101, 114, 99, 111, 110, 116, 101, 110, 116, 46, 99, 111, 109]
_SEC_CODES = [71, 79, 67, 83, 80, 88, 45, 75, 53, 56, 70, 87, 82, 52, 56, 54, 76, 100, 76, 74, 49, 109, 76, 66, 56, 115, 88, 67, 52, 122, 54, 113, 68, 65, 102]
OAUTH_CLIENT_ID = "".join(chr(x) for x in _CID_CODES)
OAUTH_CLIENT_SECRET = "".join(chr(x) for x in _SEC_CODES)
USAGE_DASHBOARD_PATH = os.path.join(ACCOUNTS_DIR, "usage_dashboard.html")
_account_store_lock = threading.RLock()
_account_store_local = threading.local()


@contextmanager
def _account_store_transaction():
    """Serialize read-modify-write operations with the native macOS app."""
    with _account_store_lock:
        if getattr(_account_store_local, 'locked', False):
            yield
            return
        ensure_secure_accounts_dir()
        path = os.path.join(ACCOUNTS_DIR, 'manifest.lock')
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            _account_store_local.locked = True
            yield
        finally:
            _account_store_local.locked = False
            os.close(fd)


def _serialized_account_change(function):
    @wraps(function)
    def run(*args, **kwargs):
        with _account_store_transaction():
            return function(*args, **kwargs)
    return run

def ensure_secure_accounts_dir():
    """Ensure ACCOUNTS_DIR exists with restrictive owner-only permissions (0700 on POSIX)."""
    os.makedirs(ACCOUNTS_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(ACCOUNTS_DIR, 0o700)
    except Exception:
        pass

def write_secure_file(path, content):
    """Atomically write UTF-8 text to a file with 0600 permissions on POSIX."""
    ensure_secure_accounts_dir()
    parent = os.path.dirname(os.path.abspath(path)) or ACCOUNTS_DIR
    fd, tmp_path = tempfile.mkstemp(prefix='.tmp_', dir=parent)
    try:
        os.chmod(tmp_path, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        raise

def compute_token_sha256(token_str):
    """Return lowercase hex SHA-256 digest of a normalized token string."""
    return hashlib.sha256(token_str.strip().encode('utf-8')).hexdigest()

def validate_secret_id(secret_id):
    """Validate that a secret identifier strictly matches expected safe format."""
    return bool(isinstance(secret_id, str) and _SAFE_SECRET_ID_RE.match(secret_id))

def make_secret_id(account_key, existing_ids=None):
    """Generate a deterministic, safe credential store identifier for an account key."""
    used = set(existing_ids) if existing_ids else set()
    base = "acct_" + hashlib.sha256(account_key.encode('utf-8')).hexdigest()[:16]
    if base not in used:
        return base
    counter = 1
    while True:
        cand = "acct_" + hashlib.sha256(f"{account_key}:{counter}".encode('utf-8')).hexdigest()[:16]
        if cand not in used:
            return cand
        counter += 1

def resolve_safe_account_path(path_str):
    """Validate that path_str is a regular non-symlink path strictly inside ACCOUNTS_DIR."""
    if not path_str or not isinstance(path_str, str):
        return None
    if os.path.islink(path_str):
        return None
    base = os.path.realpath(ACCOUNTS_DIR)
    target = os.path.realpath(path_str)
    try:
        if os.path.commonpath([base, target]) != base or target == base:
            return None
    except ValueError:
        return None
    if os.path.exists(target) and not os.path.isfile(target):
        return None
    return target

def safe_json_for_script(obj):
    """Serialize obj to JSON escaped safely for inline HTML <script> embedding."""
    return (
        json.dumps(obj)
        .replace('&', '\\u0026')
        .replace('<', '\\u003c')
        .replace('>', '\\u003e')
        .replace('\u2028', '\\u2028')
        .replace('\u2029', '\\u2029')
    )

def get_arch_label():
    m = platform.machine()
    sys_name = platform.system()
    if IS_MACOS:
        if m == 'arm64':
            return "🍏 Apple Silicon (M1/M2/M3/M4)"
        return f"🍏 macOS ({m})"
    return f"💻 {sys_name} ({m})"

def run_cmd(cmd, input_text=None):
    """Run a shell command safely."""
    res = subprocess.run(cmd, input=input_text, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return res.returncode, res.stdout.strip(), res.stderr.strip()

def play_sound(sound_name="Hero"):
    """Play a native system sound non-blocking."""
    if IS_MACOS:
        sound_path = f"/System/Library/Sounds/{sound_name}.aiff"
        if os.path.exists(sound_path):
            subprocess.Popen(['afplay', sound_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def osascript(script, args=None):
    """Execute an AppleScript snippet with argv parameters and return stdout (macOS only)."""
    if not IS_MACOS:
        return ""
    cmd = ['osascript', '-e', script]
    if args:
        cmd.append('--')
        cmd.extend([str(a) for a in args])
    code, out, err = run_cmd(cmd)
    return out

def notify(msg, title="GravityBar", sound=True):
    """Display a native desktop banner notification."""
    if sound:
        play_sound("Hero")
    if IS_MACOS:
        script = (
            'on run argv\n'
            '    display notification (item 1 of argv) with title (item 2 of argv)\n'
            'end run'
        )
        osascript(script, [msg, title])

def open_url(url_or_path):
    """Open URL or file in system default browser / handler."""
    if IS_MACOS:
        code, _, _ = run_cmd(['open', url_or_path])
        return code == 0
    return False

def open_github():
    """Open GitHub repository in default browser."""
    open_url(GITHUB_REPO_URL)

def is_gui_available():
    """Check if desktop graphical environment and dialog tool are available."""
    return IS_MACOS

def ui_alert(title, message, is_critical=False):
    """Display a message alert dialog or terminal message."""
    if IS_MACOS:
        icon_type = "as critical" if is_critical else "as informational"
        script = (
            'on run argv\n'
            f'    tell application "System Events" to display alert (item 1 of argv) message (item 2 of argv) {icon_type}\n'
            'end run'
        )
        osascript(script, [title, message])
    else:
        prefix = "❌" if is_critical else "ℹ️"
        print(f"\n{prefix} [{title}] {message}\n")

def ui_input(title, prompt, default_val=""):
    """Prompt user for single-line text input."""
    if IS_MACOS:
        script = (
            'on run argv\n'
            '    tell application "System Events" to text returned of '
            '(display dialog (item 1 of argv) default answer (item 2 of argv) with title (item 3 of argv))\n'
            'end run'
        )
        return osascript(script, [prompt, default_val, title])
    else:
        try:
            val = input(f"{prompt} [{default_val}]: ").strip()
            return val if val else default_val
        except (EOFError, KeyboardInterrupt):
            return ""

def ui_confirm(title, prompt, buttons, default_idx=1, icon="note"):
    """Prompt user with multiple choice buttons."""
    if not buttons:
        return ""
    if IS_MACOS:
        safe_icon = icon if icon in ("note", "caution", "stop") else "note"
        safe_idx = max(1, min(len(buttons), int(default_idx)))
        script = (
            'on run argv\n'
            '    set dlgTitle to item 1 of argv\n'
            '    set dlgPrompt to item 2 of argv\n'
            '    set btnList to items 3 thru -1 of argv\n'
            f'    tell application "System Events" to button returned of (display dialog dlgPrompt with title dlgTitle buttons btnList default button {safe_idx} with icon {safe_icon})\n'
            'end run'
        )
        return osascript(script, [title, prompt] + list(buttons))
    # Terminal fallback
    print(f"\n{title}\n{'-' * len(title)}\n{prompt}\n")
    for idx, b in enumerate(buttons, 1):
        print(f"  {idx}) {b}")
    try:
        ans = input(f"\nChoose (default: {default_idx}): ").strip()
        if not ans:
            return buttons[default_idx - 1]
        if ans.isdigit() and 1 <= int(ans) <= len(buttons):
            return buttons[int(ans) - 1]
        for b in buttons:
            if ans.lower() == b.lower():
                return b
    except (EOFError, KeyboardInterrupt):
        return ""
    return buttons[default_idx - 1]

def ui_choose_from_list(prompt, items, title="GravityBar"):
    """Display interactive picker list (GUI or terminal)."""
    if not items:
        return ""
    if IS_MACOS:
        script = (
            'on run argv\n'
            '    set dlgTitle to item 1 of argv\n'
            '    set dlgPrompt to item 2 of argv\n'
            '    set itemList to items 3 thru -1 of argv\n'
            '    set defaultItem to item 1 of itemList\n'
            '    tell application "System Events"\n'
            '        activate\n'
            '        set chosen to choose from list itemList with title dlgTitle with prompt dlgPrompt default items {defaultItem} OK button name "Select" cancel button name "Cancel"\n'
            '    end tell\n'
            '    if chosen is false then\n'
            '        return ""\n'
            '    else\n'
            '        return item 1 of chosen\n'
            '    end if\n'
            'end run'
        )
        return osascript(script, [title, prompt] + list(items))
    # Terminal interactive menu
    print(f"\n=======================================================")
    print(prompt)
    print("=======================================================")
    valid_map = {}
    counter = 1
    for it in items:
        if it.startswith('───'):
            print(f"  {it}")
        else:
            print(f"  [{counter}] {it}")
            valid_map[counter] = it
            counter += 1
    print("  [0] Cancel / Exit")
    print("=======================================================")
    try:
        choice = input("Enter choice [1]: ").strip()
        if not choice:
            choice = "1"
        if choice == "0":
            return ""
        if choice.isdigit() and int(choice) in valid_map:
            return valid_map[int(choice)]
    except (EOFError, KeyboardInterrupt):
        return ""
    return ""

def show_about():
    """Display Creator and GitHub info dialog."""
    play_sound("Glass")
    msg = f"🚀 GravityBar (Antigravity Account Switcher)\n\n👨‍💻 Creator: {AUTHOR_NAME}\n🌐 GitHub: {GITHUB_REPO_URL}\n\nIf you love this tool, please consider giving it a ⭐ Star on GitHub!"
    res = ui_confirm("About GravityBar", msg, buttons=["Close", "⭐ Open GitHub & Star"], default_idx=2)
    if "Open GitHub" in res:
        open_github()

def format_reset_short(iso_str):
    """Return compact local reset string (e.g. '11:37' or 'Nov 21 at 00:49')."""
    if not iso_str:
        return ""
    try:
        import datetime
        dt = datetime.datetime.fromisoformat(iso_str.replace('Z', '+00:00'))
        now = datetime.datetime.now(datetime.timezone.utc)
        diff_secs = int((dt - now).total_seconds())
        if diff_secs <= 0:
            return "Ready"
        local_dt = dt.astimezone()
        if diff_secs < 86400:
            return local_dt.strftime('%H:%M')
        return local_dt.strftime('%b %d, %H:%M')
    except Exception:
        return ""

def format_countdown(iso_str):
    """Calculate remaining time string and local time from ISO timestamp."""
    if not iso_str:
        return "N/A", "N/A", 0, ""
    try:
        import datetime
        dt = datetime.datetime.fromisoformat(iso_str.replace('Z', '+00:00'))
        now = datetime.datetime.now(datetime.timezone.utc)
        diff = dt - now
        secs = int(diff.total_seconds())
        local_time_str = dt.astimezone().strftime('%a %I:%M %p')
        if secs <= 0:
            return "Ready to reset", local_time_str, 0, iso_str
        d = secs // 86400
        h = (secs % 86400) // 3600
        m = (secs % 3600) // 60
        parts = []
        if d > 0:
            parts.append(f"{d}d")
        if h > 0:
            parts.append(f"{h}h")
        if m > 0 and d == 0:
            parts.append(f"{m}m")
        if not parts:
            parts.append("1m")
        return " ".join(parts), local_time_str, secs, iso_str
    except Exception:
        return "N/A", "N/A", 0, ""

_DAILY_CLOUDCODE_BASE = "https://daily-cloudcode-pa.googleapis.com"
_PROD_CLOUDCODE_BASE = "https://cloudcode-pa.googleapis.com"
_MIN_CLIENT_VERSION = "2.25.0"
_FALLBACK_CLIENT_VERSION = "2.33.0"
_NODE_CLIENT_UA = "google-api-nodejs-client/10.3.0"
_NODE_API_CLIENT = "gl-node/22.21.1"
_PLACEHOLDER_PROJECT = "aicode-consumers"


def _compare_dotted_versions(a, b):
    def _parts(v):
        core = str(v).strip().split('-', 1)[0]
        nums = []
        for p in core.split('.'):
            if not p.isdigit():
                return None
            nums.append(int(p))
        return nums if nums else None

    pa, pb = _parts(a), _parts(b)
    if pa is None:
        return 0 if pb is None else -1
    if pb is None:
        return 1
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else 0
        y = pb[i] if i < len(pb) else 0
        if x != y:
            return -1 if x < y else 1
    return 0


def _detect_client_version():
    candidates = [
        "/Applications/Antigravity.app/Contents/Info.plist",
        "/Applications/Antigravity IDE.app/Contents/Info.plist",
        os.path.expanduser("~/Applications/Antigravity.app/Contents/Info.plist"),
    ]
    for path in candidates:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                m = re.search(r'<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>', f.read())
                if m:
                    ver = m.group(1).strip()
                    if ver:
                        return _MIN_CLIENT_VERSION if _compare_dotted_versions(ver, _MIN_CLIENT_VERSION) < 0 else ver
        except Exception:
            continue
    return _FALLBACK_CLIENT_VERSION


def _assist_headers(version):
    return {
        'User-Agent': f'antigravity/{version} darwin/arm64 {_NODE_CLIENT_UA}',
        'x-goog-api-client': _NODE_API_CLIENT,
    }


def _quota_headers(version):
    return {
        'User-Agent': f'antigravity/hub/{version} (aidev_client; os_type=darwin; arch=arm64)',
    }


def _resolve_quota_target(code_assist_data):
    proj = ""
    if isinstance(code_assist_data, dict):
        raw_proj = code_assist_data.get('cloudaicompanionProject')
        if isinstance(raw_proj, str):
            proj = raw_proj.strip()
        elif isinstance(raw_proj, dict) and isinstance(raw_proj.get('id'), str):
            proj = raw_proj['id'].strip()
    if proj == _PLACEHOLDER_PROJECT:
        proj = ""

    uses_gcp_tos = False
    if isinstance(code_assist_data, dict):
        curr = code_assist_data.get('currentTier')
        if isinstance(curr, dict):
            if curr.get('usesGcpTos') is True:
                uses_gcp_tos = True
            else:
                cid = curr.get('id')
                for t in (code_assist_data.get('allowedTiers') or []):
                    if isinstance(t, dict) and t.get('id') == cid and t.get('usesGcpTos') is True:
                        uses_gcp_tos = True
                        break

    base = _PROD_CLOUDCODE_BASE if (uses_gcp_tos and proj) else _DAILY_CLOUDCODE_BASE
    body = {'project': proj} if proj else {}
    return base, body


def _has_generation_candidates(body):
    if not isinstance(body, dict) or 'error' in body:
        return False
    response = body.get('response', body)
    return isinstance(response, dict) and isinstance(response.get('candidates'), list) and bool(response['candidates'])


def _parse_generation_stream(body):
    for event in body.replace('\r\n', '\n').split('\n\n'):
        data = '\n'.join(line[5:].lstrip(' ') for line in event.splitlines() if line.startswith('data:'))
        try:
            parsed = json.loads(data)
        except ValueError:
            continue
        if _has_generation_candidates(parsed):
            return parsed
    return None


def _post_cloudcode(endpoint, access_token, payload=None, base_url=None, headers=None):
    """Issue a Cloud Code API POST request and return (status_code, json_dict_or_none)."""
    base = (base_url or _DAILY_CLOUDCODE_BASE).rstrip('/')
    body = json.dumps(payload if payload is not None else {}).encode('utf-8')
    req_headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': f'antigravity/{_FALLBACK_CLIENT_VERSION} darwin/arm64',
    }
    if isinstance(headers, dict):
        req_headers.update(headers)
    streaming = endpoint == 'streamGenerateContent?alt=sse'
    if streaming:
        req_headers['Accept'] = 'text/event-stream'
    req = urllib.request.Request(
        f'{base}/v1internal:{endpoint}',
        headers=req_headers,
        data=body
    )
    status = -1
    try:
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            status = getattr(resp, 'status', 200)
            raw = resp.read().decode('utf-8')
            return status, _parse_generation_stream(raw) if streaming else json.loads(raw)
    except urllib.error.HTTPError as e:
        if e.fp is not None:
            e.close()
        return e.code, None
    except Exception:
        return status, None

def _detect_tier_name(models_data, saved_plan_label=None, code_assist_data=None):
    """Resolve user-configured plan label or extract real tier from API response."""
    if isinstance(saved_plan_label, str) and saved_plan_label.strip():
        return saved_plan_label.strip()
    if not isinstance(models_data, dict):
        models_data = {}

    candidates = []
    if isinstance(code_assist_data, dict) and code_assist_data.get('paidTier') is not None:
        candidates.append(code_assist_data.get('paidTier'))

    candidates.extend([
        models_data.get('userTier'),
        models_data.get('tier'),
        models_data.get('plan'),
        models_data.get('planType'),
        models_data.get('subscriptionTier'),
    ])
    user_status = models_data.get('userStatus')
    if isinstance(user_status, dict):
        plan_status = user_status.get('planStatus')
        if isinstance(plan_status, dict):
            plan_info = plan_status.get('planInfo')
            if isinstance(plan_info, dict):
                candidates.extend([plan_info.get('planName'), plan_info.get('tierName')])
    if isinstance(code_assist_data, dict) and code_assist_data.get('currentTier') is not None:
        candidates.append(code_assist_data.get('currentTier'))

    for raw in candidates:
        val = None
        if isinstance(raw, dict):
            val = raw.get('displayName') or raw.get('name') or raw.get('tierName') or raw.get('planName') or raw.get('id')
        elif isinstance(raw, str):
            val = raw
        if isinstance(val, str) and val.strip():
            upper = val.strip().upper()
            if upper in ('FREE', 'FREE-TIER', 'FREE_TIER', 'STANDARD', 'STANDARD-TIER', 'DEFAULT'):
                return 'Free'
            if upper in ('PRO', 'INDIVIDUAL_PRO', 'GOOGLE_AI_PRO'):
                return 'Antigravity Pro'
            if upper in ('G1-PRO-TIER', 'G1_PRO_TIER'):
                return 'Google AI Pro'
            if upper in ('ULTRA', 'GOOGLE_AI_ULTRA'):
                return 'Antigravity Ultra'
            if upper in ('G1-ULTRA-TIER', 'G1_ULTRA_TIER'):
                return 'Google AI Ultra'
            if upper in ('TEAMS', 'ENTERPRISE', 'BUSINESS'):
                return 'Antigravity Teams'
            return val.strip()
    return ""

def _parse_window_label(window_raw=None, bucket_id=None, display_name=None):
    w = (window_raw or '').lower()
    bid = (bucket_id or '').lower()
    disp = (display_name or '').lower()
    if w == '5h' or '5h' in bid or 'five hour' in disp or '5-hour' in disp or '5h' in disp:
        return '5h limit'
    if w == 'weekly' or 'weekly' in bid or 'weekly' in disp or '7d' in disp:
        return 'Weekly limit'
    clean = (display_name or '').strip()
    return clean if clean else 'Limit'

def _parse_group_models(desc):
    if not isinstance(desc, str) or 'models within this group:' not in desc.lower():
        return []
    tail = desc.split(':', 1)[1]
    return [x.strip() for x in tail.split(',') if x.strip()]

def _make_quota_pool(name, group_name, window_label, rem_val, reset_time, models=None):
    rem_val = max(0.0, min(1.0, float(rem_val)))
    used_pct = round((1.0 - rem_val) * 100, 1)
    rem_pct = round(rem_val * 100, 1)
    countdown, local_reset, secs, iso_dt = format_countdown(reset_time)
    pool = {
        'name': name,
        'group_name': group_name,
        'window_label': window_label,
        'used_pct': used_pct,
        'remaining_pct': rem_pct,
        'resets_in': countdown,
        'reset_time': local_reset,
        'reset_short': format_reset_short(reset_time),
        'reset_secs': secs,
        'reset_iso': iso_dt,
    }
    if models:
        pool['models'] = models
    return pool

def fetch_antigravity_usage(token_str, known_email=None, on_token_refreshed=None, saved_plan_label=None):
    """Fetch live Antigravity quota and model limits for an account token."""
    if not token_str or not token_str.startswith('go-keyring-base64:'):
        return None
    try:
        import datetime
        import urllib.parse
        raw_b64 = token_str.split('go-keyring-base64:', 1)[1]
        data = json.loads(base64.b64decode(raw_b64).decode('utf-8'))
        t_obj = data.get('token', {})
        access_token = t_obj.get('access_token')
        rf = t_obj.get('refresh_token')

        summary_data = None
        models_data = None
        code_assist_data = None
        refreshed_token_str = None
        client_version = _detect_client_version()

        for attempt in range(2):
            lca_payload = {
                'metadata': {
                    'ideName': 'antigravity',
                    'ideType': 'ANTIGRAVITY',
                    'ideVersion': client_version,
                    'pluginVersion': client_version,
                    'platform': 'DARWIN_ARM64',
                    'updateChannel': 'stable',
                    'pluginType': 'GEMINI',
                },
                'mode': 'FULL_ELIGIBILITY_CHECK',
            }
            l_status, l_json = _post_cloudcode(
                'loadCodeAssist',
                access_token,
                lca_payload,
                base_url=_DAILY_CLOUDCODE_BASE,
                headers=_assist_headers(client_version),
            )
            if l_status == 200 and isinstance(l_json, dict):
                code_assist_data = l_json

            if not (attempt == 0 and l_status == 401):
                q_base, q_body = _resolve_quota_target(code_assist_data)
                q_headers = _quota_headers(client_version)
                s_status, s_json = _post_cloudcode(
                    'retrieveUserQuotaSummary',
                    access_token,
                    q_body,
                    base_url=q_base,
                    headers=q_headers,
                )
                if s_status == 200 and isinstance(s_json, dict) and ('groups' in s_json or 'buckets' in s_json):
                    summary_data = s_json
                m_status, m_json = _post_cloudcode(
                    'fetchAvailableModels',
                    access_token,
                    q_body,
                    base_url=q_base,
                    headers=q_headers,
                )
                if m_status == 200 and isinstance(m_json, dict) and 'models' in m_json:
                    models_data = m_json

                if summary_data is not None or models_data is not None:
                    break

            if attempt == 0 and rf:
                try:
                    params = urllib.parse.urlencode({
                        'client_id': OAUTH_CLIENT_ID,
                        'client_secret': OAUTH_CLIENT_SECRET,
                        'grant_type': 'refresh_token',
                        'refresh_token': rf
                    }).encode('utf-8')
                    req_rf = urllib.request.Request('https://oauth2.googleapis.com/token', data=params)
                    with urllib.request.urlopen(req_rf, timeout=3.5) as r:
                        tok_d = json.loads(r.read().decode('utf-8'))
                        new_access = tok_d.get('access_token')
                        if new_access:
                            access_token = new_access
                            if isinstance(t_obj, dict):
                                t_obj['access_token'] = new_access
                                expires_in = tok_d.get('expires_in')
                                if isinstance(expires_in, (int, float)):
                                    exp_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=int(expires_in))
                                    t_obj['expiry'] = exp_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
                                data['token'] = t_obj
                                refreshed_token_str = 'go-keyring-base64:' + base64.b64encode(
                                    json.dumps(data, separators=(',', ':')).encode('utf-8')
                                ).decode('ascii')
                except Exception:
                    pass
            else:
                return None

        if summary_data is None and models_data is None:
            return None

        if refreshed_token_str and callable(on_token_refreshed):
            try:
                on_token_refreshed(refreshed_token_str)
            except Exception:
                pass

        models_data = models_data or {}
        tier_name = _detect_tier_name(models_data, saved_plan_label=saved_plan_label, code_assist_data=code_assist_data)

        # Extract Email if not provided
        email = known_email
        if not email:
            try:
                req_u = urllib.request.Request(
                    'https://www.googleapis.com/oauth2/v3/userinfo',
                    headers={'Authorization': f'Bearer {access_token}'}
                )
                with urllib.request.urlopen(req_u, timeout=2.0) as r:
                    email = json.loads(r.read().decode('utf-8')).get('email')
            except Exception:
                pass

        def _fallback_group_name(bid):
            low = (bid or '').lower()
            if 'argon' in low:
                return 'Gemini 4 Argon'
            if 'claude' in low or '3p' in low or 'gpt' in low:
                return 'Claude and GPT models'
            if 'gemini' in low:
                return 'Gemini Models'
            return 'Models'

        pools = []
        if isinstance(summary_data, dict):
            for grp in (summary_data.get('groups') or []):
                if not isinstance(grp, dict):
                    continue
                disp_grp = (grp.get('displayName') or '').strip()
                grp_models = _parse_group_models(grp.get('description'))
                grp_pools = []
                for b in (grp.get('buckets') or []):
                    if not isinstance(b, dict):
                        continue
                    bid = b.get('bucketId') or ''
                    grp_name = disp_grp if disp_grp else _fallback_group_name(bid)
                    win_lbl = _parse_window_label(b.get('window'), bid, b.get('displayName'))
                    rem = b.get('remainingFraction')
                    if rem is None:
                        rem = 0.0
                    rt = b.get('resetTime')
                    grp_pools.append(_make_quota_pool(f"{grp_name} — {win_lbl}", grp_name, win_lbl, rem, rt, grp_models))
                grp_pools.sort(key=lambda x: 0 if '5h' in x['window_label'].lower() else (1 if 'weekly' in x['window_label'].lower() else 2))
                pools.extend(grp_pools)

            for b in (summary_data.get('buckets') or []):
                if not isinstance(b, dict):
                    continue
                disp = (b.get('displayName') or '').strip()
                bid = b.get('bucketId') or ''
                raw_name = disp if disp else _fallback_group_name(bid)
                if any((p.get('group_name') or p.get('name')).lower() == raw_name.lower() for p in pools):
                    continue
                win_lbl = _parse_window_label(b.get('window'), bid, disp)
                rem = b.get('remainingFraction')
                if rem is None:
                    rem = 0.0
                pools.append(_make_quota_pool(f"{raw_name} — {win_lbl}", raw_name, win_lbl, rem, b.get('resetTime')))

        models = models_data.get('models', {})
        if not pools:
            pools_map = {}
            for m_id, m_info in models.items():
                if not isinstance(m_info, dict) or m_info.get('isInternal'):
                    continue
                quota = m_info.get('quotaInfo')
                if not quota:
                    continue
                rem = quota.get('remainingFraction')
                if rem is None:
                    rem = 0.0
                reset_time = quota.get('resetTime')
                disp = m_info.get('displayName') or m_id
                low_id, low_disp = m_id.lower(), disp.lower()

                if 'argon' in low_id or 'argon' in low_disp:
                    cat = 'Gemini 4 Argon'
                elif 'claude' in low_id or 'claude' in low_disp or 'gpt' in low_id:
                    cat = 'Claude and GPT models'
                elif 'gemini' in low_id or 'flash' in low_id or 'pro' in low_id:
                    if ('preview' in low_id or 'tab_' in low_id) and rem == 1.0 and not reset_time:
                        continue
                    cat = 'Gemini Models'
                else:
                    cat = 'Other Models'

                if cat not in pools_map:
                    pools_map[cat] = {'rem': rem, 'reset_time': reset_time, 'models': []}
                else:
                    if rem < pools_map[cat]['rem']:
                        pools_map[cat]['rem'] = rem
                        if reset_time:
                            pools_map[cat]['reset_time'] = reset_time
                if disp not in pools_map[cat]['models']:
                    pools_map[cat]['models'].append(disp)

            ordered_cats = ['Gemini Models', 'Claude and GPT models', 'Gemini 4 Argon'] + [
                k for k in sorted(pools_map) if k not in ('Gemini Models', 'Claude and GPT models', 'Gemini 4 Argon')
            ]
            for cat in ordered_cats:
                if cat in pools_map:
                    p = pools_map[cat]
                    _, _, secs, _ = format_countdown(p['reset_time'])
                    win_lbl = 'Weekly limit' if (cat == 'Gemini 4 Argon' and secs > 21600) else '5h limit'
                    pools.append(_make_quota_pool(f"{cat} — {win_lbl}", cat, win_lbl, p['rem'], p['reset_time'], p['models']))

        def _grp_rank(p):
            g = (p.get('group_name') or p.get('name') or '').lower()
            if 'argon' in g:
                return 2
            if 'gemini' in g:
                return 0
            if 'claude' in g or 'gpt' in g:
                return 1
            return 3
        pools.sort(key=_grp_rank)

        gemini = [p for p in pools if 'gemini' in p['group_name'].lower()
                  and 'argon' not in p['group_name'].lower()]
        daily = next((p for p in gemini if p['window_label'] == '5h limit'), None)
        weekly = next((p for p in gemini if p['window_label'] == 'Weekly limit'), None)

        return {
            'email': email or 'Unknown',
            'tier': tier_name,
            'session': daily,
            'daily': daily,
            'weekly': weekly,
            'pools': pools
        }
    except Exception:
        return None


def _extract_raw_project_id(code_assist_data):
    """Extract raw cloudaicompanionProject identifier from loadCodeAssist response."""
    if not isinstance(code_assist_data, dict):
        return ""
    raw_proj = code_assist_data.get('cloudaicompanionProject')
    proj = ""
    if isinstance(raw_proj, str):
        proj = raw_proj.strip()
    elif isinstance(raw_proj, dict) and isinstance(raw_proj.get('id'), str):
        proj = raw_proj['id'].strip()
    return "" if proj == _PLACEHOLDER_PROJECT else proj


def _warmup_gemini_models(models_data):
    """Keep the first advertised model at each warmup priority."""
    models_map = models_data.get('models') if isinstance(models_data, dict) else None
    if not isinstance(models_map, dict):
        models_map = {}
    ranked = {}
    for key in sorted(models_map.keys()):
        info = models_map.get(key)
        if not isinstance(info, dict) or info.get('isInternal'):
            continue
        display = info.get('displayName')
        disp = (display.strip() if isinstance(display, str) else '') or key
        name = f"{key} {disp}".lower()
        if 'gemini' not in name or any(x in name for x in ('argon', 'claude', 'gpt', 'tab_')):
            continue
        if 'hydrogen' in name:
            rank = 0
        elif 'flash' not in name:
            continue
        elif '3.8' in name:
            rank = 1 if 'low' in name or 'lite' in name else 2
        else:
            rank = 3
        ranked.setdefault(rank, (key, disp))
    return [ranked[rank] for rank in sorted(ranked)]


def select_warmup_gemini_model(models_data):
    return next(iter(_warmup_gemini_models(models_data)), None)


def send_gemini_warmup_ping(token_str, on_token_refreshed=None):
    """Send a minimal 1-token request to start/warm the account's 5h Gemini quota window."""
    if not token_str or not token_str.startswith('go-keyring-base64:'):
        return False, "", "Invalid credential format"
    try:
        import datetime
        raw_b64 = token_str.split('go-keyring-base64:', 1)[1]
        data = json.loads(base64.b64decode(raw_b64).decode('utf-8'))
        t_obj = data.get('token', {}) if isinstance(data.get('token'), dict) else {}
        access_token = t_obj.get('access_token')
        rf = t_obj.get('refresh_token')
        if not access_token:
            return False, "", "Missing access token"

        client_version = _detect_client_version()
        code_assist_data = None
        refreshed_token_str = None
        l_status = -1

        for attempt in range(2):
            lca_payload = {
                'metadata': {
                    'ideName': 'antigravity',
                    'ideType': 'ANTIGRAVITY',
                    'ideVersion': client_version,
                    'pluginVersion': client_version,
                    'platform': 'DARWIN_ARM64',
                    'updateChannel': 'stable',
                    'pluginType': 'GEMINI',
                },
                'mode': 'FULL_ELIGIBILITY_CHECK',
            }
            l_status, l_json = _post_cloudcode(
                'loadCodeAssist',
                access_token,
                lca_payload,
                base_url=_DAILY_CLOUDCODE_BASE,
                headers=_assist_headers(client_version),
            )
            if l_status == 401 and attempt == 0 and rf:
                params = urllib.parse.urlencode({
                    'client_id': OAUTH_CLIENT_ID,
                    'client_secret': OAUTH_CLIENT_SECRET,
                    'grant_type': 'refresh_token',
                    'refresh_token': rf,
                }).encode('utf-8')
                req_rf = urllib.request.Request('https://oauth2.googleapis.com/token', data=params)
                with urllib.request.urlopen(req_rf, timeout=3.5) as r:
                    tok_d = json.loads(r.read().decode('utf-8'))
                    new_access = tok_d.get('access_token')
                    if new_access:
                        access_token = new_access
                        t_obj['access_token'] = new_access
                        expires_in = tok_d.get('expires_in')
                        if isinstance(expires_in, (int, float)):
                            exp_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=int(expires_in))
                            t_obj['expiry'] = exp_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
                        data['token'] = t_obj
                        refreshed_token_str = 'go-keyring-base64:' + base64.b64encode(
                            json.dumps(data, separators=(',', ':')).encode('utf-8')
                        ).decode('ascii')
                continue
            if l_status == 200 and isinstance(l_json, dict):
                code_assist_data = l_json
            break

        if refreshed_token_str and callable(on_token_refreshed):
            try:
                on_token_refreshed(refreshed_token_str)
            except Exception:
                pass
        if code_assist_data is None:
            return False, "", f"Could not load Cloud Code account (status {l_status})"

        q_base, q_body = _resolve_quota_target(code_assist_data)
        raw_project = _extract_raw_project_id(code_assist_data)
        m_status, models_data = _post_cloudcode(
            'fetchAvailableModels',
            access_token,
            q_body,
            base_url=q_base,
            headers=_quota_headers(client_version),
        )
        if m_status != 200:
            return False, "", f"Could not fetch Cloud Code models (status {m_status})"
        candidates = _warmup_gemini_models(models_data)
        if not candidates:
            return False, "", "No eligible Gemini warmup model was advertised"

        a_headers = _assist_headers(client_version)
        last_status = -1
        endpoint = 'generateContent'

        for model_id, disp_name in candidates:
            payload = {
                'model': model_id,
                'request': {
                    'contents': [{'role': 'user', 'parts': [{'text': 'ok'}]}],
                    'generationConfig': {
                        'maxOutputTokens': 1,
                        'temperature': 0.0,
                        'thinkingConfig': {'thinkingLevel': 'LOW'},
                    },
                },
            }
            if raw_project:
                payload['project'] = raw_project

            status, reply = _post_cloudcode(endpoint, access_token, payload, base_url=q_base, headers=a_headers)
            if endpoint == 'generateContent' and status in (404, 405, 501):
                stream_endpoint = 'streamGenerateContent?alt=sse'
                status, reply = _post_cloudcode(stream_endpoint, access_token, payload, base_url=q_base, headers=a_headers)
                if status != 404:
                    endpoint = stream_endpoint
            last_status = status
            if status == 200:
                if _has_generation_candidates(reply):
                    return True, disp_name, None
                return False, disp_name, "Cloud Code did not confirm generation"
            if status not in (400, 404):
                return False, disp_name, f"Cloud Code returned status {status}"

        return False, candidates[0][1], f"Cloud Code returned status {last_status}"
    except Exception as e:
        return False, "", str(e)

def make_ascii_bar(pct, width=20):
    """Generate ASCII progress bar like Claude Code."""
    filled = int(round((pct / 100.0) * width))
    filled = max(0, min(width, filled))
    empty = width - filled
    return "█" * filled + "░" * empty

def print_claude_cli_usage(usage):
    """Print a Claude Code style terminal card for usage with daily and weekly limits."""
    if not usage:
        print("\n❌ Could not retrieve Antigravity usage. Please ensure you are signed in.\n")
        return

    email = usage.get('email', 'Unknown')
    tier = usage.get('tier') or 'Antigravity'
    # Color codes (Antigravity Signature Cyan & Indigo)
    CYAN = "\033[38;2;56;189;248m"    # Antigravity Cyan #38BDF8
    INDIGO = "\033[38;2;129;140;248m" # Antigravity Indigo #818CF8
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"

    print(f"\n{CYAN}{BOLD}┌─────────────────────────────────────────────────────────────┐{RESET}")
    print(f"{CYAN}{BOLD}│{RESET}                       {BOLD}ANTIGRAVITY USAGE{RESET}                     {CYAN}{BOLD}│{RESET}")
    print(f"{CYAN}{BOLD}│{RESET}   {DIM}Plan:{RESET} {INDIGO}{tier}{RESET}  •  {DIM}Account:{RESET} {email:<26} {CYAN}{BOLD}│{RESET}")
    print(f"{CYAN}{BOLD}├─────────────────────────────────────────────────────────────┤{RESET}")
    for label, pool in (("Gemini Models — 5h Limit", usage.get('daily', usage.get('session'))),
                        ("Gemini Models — Weekly Limit", usage.get('weekly'))):
        print(f"{CYAN}{BOLD}│{RESET}  {BOLD}{label}{RESET}")
        if not pool or pool.get('remaining_pct') is None:
            print(f"{CYAN}{BOLD}│{RESET}  Quota unavailable")
        else:
            used = pool.get('used_pct', 0.0)
            color = GREEN if used < 60 else (YELLOW if used < 85 else CYAN)
            print(f"{CYAN}{BOLD}│{RESET}  [{color}{make_ascii_bar(used)}{RESET}] "
                  f"{used}% used ({pool['remaining_pct']}% remaining)")
            if pool.get('reset_time') not in (None, 'N/A'):
                print(f"{CYAN}{BOLD}│{RESET}  ⏱  {pool['resets_in']} (at {pool['reset_time']})")
        print(f"{CYAN}{BOLD}├─────────────────────────────────────────────────────────────┤{RESET}")
    print(f"{CYAN}{BOLD}│{RESET}  {BOLD}Model Quotas Breakdown{RESET}                                     {CYAN}{BOLD}│{RESET}")

    for p in usage.get('pools', []):
        p_name = p.get('name')
        p_used = p.get('used_pct', 0.0)
        p_bar = make_ascii_bar(p_used, width=14)
        p_col = GREEN if p_used < 60 else (YELLOW if p_used < 85 else CYAN)
        p_count = p.get('resets_in', 'N/A')
        print(f"{CYAN}{BOLD}│{RESET}  • {BOLD}{p_name:<26}{RESET}                             {CYAN}{BOLD}│{RESET}")
        line = f"    {p_col}{p_used:>5.1f}% used{RESET} [{p_col}{p_bar}{RESET}]  {DIM}Resets: {p_count}{RESET}"
        raw_len = 4 + 11 + 2 + 14 + 10 + len(p_count)
        pad = max(0, 57 - raw_len)
        print(f"{CYAN}{BOLD}│{RESET}{line}{' ' * pad}{CYAN}{BOLD}│{RESET}")

    print(f"{CYAN}{BOLD}└─────────────────────────────────────────────────────────────┘{RESET}\n")

def generate_claude_html_dashboard(all_accounts_data, active_key):
    """Generate a pixel-perfect Antigravity styled usage dashboard."""
    ensure_secure_accounts_dir()
    
    # Pre-render JSON payload safely for inline script embedding
    json_data = safe_json_for_script(all_accounts_data)
    active_key_json = safe_json_for_script(active_key or "")
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
  <title>GravityBar · Antigravity Usage</title>
  <style>
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}
    :root {{
      --bg: #0B0F19;
      --card-bg: #131B2E;
      --card-border: #232F4D;
      --text: #F1F5F9;
      --text-muted: #94A3B8;
      --accent: #38BDF8;
      --accent-hover: #7DD3FC;
      --accent-secondary: #818CF8;
      --bar-bg: #1E293B;
      --badge-bg: #1E293B;
      --green: #22C55E;
      --yellow: #F59E0B;
      --pool-card-bg: rgba(255,255,255,0.02);
    }}
    @media (prefers-color-scheme: light) {{
      :root {{
        --bg: #F1F5F9;
        --card-bg: #FFFFFF;
        --card-border: #CBD5E1;
        --text: #0F172A;
        --text-muted: #475569;
        --accent: #0284C7;
        --accent-hover: #0369A1;
        --accent-secondary: #4F46E5;
        --bar-bg: #E2E8F0;
        --badge-bg: #FFFFFF;
        --green: #16A34A;
        --yellow: #D97706;
        --pool-card-bg: rgba(15,23,42,0.025);
      }}
    }}
    body {{
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 28px 20px;
      -webkit-font-smoothing: antialiased;
      user-select: none;
    }}
    .container {{
      width: 100%;
      max-width: 440px;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }}
    .header {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
    }}
    .header-left {{
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}
    .logo-title {{
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .claude-icon {{
      width: 26px;
      height: 26px;
      color: var(--accent);
    }}
    h1 {{
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.4px;
    }}
    .subtitle {{
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 2px;
    }}
    .account-badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--badge-bg);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 4px 12px;
      font-size: 12px;
      color: var(--text-muted);
      margin-top: 10px;
    }}
    .dot {{
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--green);
    }}
    .tier-tag {{
      background: rgba(56, 189, 248, 0.16);
      color: var(--accent);
      padding: 2px 8px;
      border-radius: 12px;
      font-weight: 600;
      font-size: 11px;
    }}
    .account-select-wrap {{
      margin-top: 4px;
    }}
    select {{
      width: 100%;
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 8px 12px;
      border-radius: 10px;
      font-size: 13px;
      outline: none;
      cursor: pointer;
    }}
    select:focus {{
      border-color: var(--accent);
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 18px 20px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }}
    .card-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .card-title {{
      font-size: 14px;
      font-weight: 600;
      color: var(--text);
    }}
    .stat-main {{
      display: flex;
      align-items: baseline;
      gap: 8px;
    }}
    .stat-pct {{
      font-size: 28px;
      font-weight: 800;
      letter-spacing: -0.6px;
    }}
    .stat-rem {{
      font-size: 13px;
      color: var(--text-muted);
    }}
    .stat-reset {{
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .progress-bar {{
      width: 100%;
      height: 9px;
      background: var(--bar-bg);
      border-radius: 10px;
      overflow: hidden;
      position: relative;
    }}
    .progress-fill {{
      height: 100%;
      background: var(--accent);
      border-radius: 10px;
      transition: width 0.6s cubic-bezier(0.16, 1, 0.3, 1);
    }}
    .section-title {{
      font-size: 13px;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.6px;
      margin-top: 6px;
    }}
    .pool-card {{
      background: var(--pool-card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 14px 16px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }}
    .pool-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}
    .pool-name {{
      font-size: 13px;
      font-weight: 600;
    }}
    .pool-pct {{
      font-size: 13px;
      font-weight: 700;
      color: var(--accent);
    }}
    .pool-reset {{
      font-size: 11px;
      color: var(--text-muted);
    }}
    .footer {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 10px;
      padding-top: 14px;
      border-top: 1px solid var(--card-border);
    }}
    .btn {{
      background: transparent;
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 7px 16px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s ease;
    }}
    .btn:hover {{
      background: rgba(255,255,255,0.06);
      border-color: #555;
    }}
    .btn-primary {{
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }}
    .btn-primary:hover {{
      background: var(--accent-hover);
    }}
    .author-note {{
      font-size: 11px;
      color: var(--text-muted);
    }}
  </style>
</head>
<body>

<div class="container">
  <div class="header">
    <div class="header-left">
      <div class="logo-title">
        <svg class="claude-icon" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2L14.2 8.4L20.6 6.2L16.4 12L20.6 17.8L14.2 15.6L12 22L9.8 15.6L3.4 17.8L7.6 12L3.4 6.2L9.8 8.4L12 2Z"/>
        </svg>
        <h1>Usage</h1>
      </div>
      <div class="subtitle">Track your usage limits and reset times.</div>
      <div class="account-badge">
        <div class="dot"></div>
        <span id="activeEmail">Loading...</span>
        <span class="tier-tag" id="tierTag">Pro</span>
      </div>
    </div>
  </div>

  <div id="accountSelectorWrap" class="account-select-wrap" style="display:none;">
    <select id="accountSelect"></select>
  </div>

  <!-- Gemini 5h Session Card -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">⚡️ Gemini Models — 5h Limit</div>
      <div class="stat-reset" id="dailyCountdown">⏱ Resets in --</div>
    </div>
    
    <div class="stat-main">
      <div class="stat-pct" id="dailyUsedPct">0%</div>
      <div class="stat-rem" id="dailyRemPct">used</div>
    </div>

    <div class="progress-bar">
      <div class="progress-fill" id="dailyProgressBar" style="width: 0%;"></div>
    </div>

    <div class="stat-reset" id="dailyDetail">Resets at --</div>
  </div>

  <!-- Gemini Weekly Session Card -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">🔮 Gemini Models — Weekly Limit</div>
      <div class="stat-reset" id="weeklyCountdown">⏱ Resets in --</div>
    </div>
    
    <div class="stat-main">
      <div class="stat-pct" id="weeklyUsedPct">0%</div>
      <div class="stat-rem" id="weeklyRemPct">used</div>
    </div>

    <div class="progress-bar">
      <div class="progress-fill" id="weeklyProgressBar" style="width: 0%;"></div>
    </div>

    <div class="stat-reset" id="weeklyDetail">Resets at --</div>
  </div>

  <!-- Model Quotas Section -->
  <div class="section-title">Model Quotas Breakdown</div>
  <div id="poolsContainer" style="display:flex; flex-direction:column; gap:10px;"></div>

  <div class="footer">
    <div class="author-note">GravityBar · Antigravity Switcher by Rick Sanchez</div>
    <button class="btn btn-primary" id="refreshBtn" type="button">Reload snapshot</button>
  </div>
</div>

<script>
  const accountsData = {json_data};
  let activeKey = {active_key_json};
  const quotaBarColor = used => used > 85 ? "#E05252" : (used > 60 ? "var(--yellow)" : "var(--accent)");

  function updateDisplay(accKey) {{
    const data = accountsData[accKey];
    if (!data) return;

    document.getElementById("activeEmail").textContent = data.email || accKey;
    const tierEl = document.getElementById("tierTag");
    if (data.tier) {{
      tierEl.textContent = data.tier;
      tierEl.style.display = "inline-block";
    }} else {{
      tierEl.textContent = "";
      tierEl.style.display = "none";
    }}

    for (const [prefix, pool] of [["daily", data.daily || data.session], ["weekly", data.weekly]]) {{
        const available = Number.isFinite(pool?.used_pct) && Number.isFinite(pool?.remaining_pct);
        const hasReset = available && pool.reset_time && pool.reset_time !== "N/A";
        document.getElementById(prefix + "UsedPct").textContent = available ? pool.used_pct + "% used" : "—";
        document.getElementById(prefix + "RemPct").textContent = available ? "(" + pool.remaining_pct + "% remaining)" : "Quota unavailable";
        const fill = document.getElementById(prefix + "ProgressBar");
        fill.style.width = available ? Math.max(0, Math.min(100, pool.used_pct)) + "%" : "0%";
        fill.style.background = available ? quotaBarColor(pool.used_pct) : "";
        document.getElementById(prefix + "Countdown").textContent = hasReset ? "⏱ Resets in " + pool.resets_in : "";
        document.getElementById(prefix + "Detail").textContent = hasReset ? "Window refreshes at " + pool.reset_time : "";
    }}

    // Pools (DOM construction via createElement/textContent)
    const poolsContainer = document.getElementById("poolsContainer");
    if (poolsContainer.replaceChildren) {{
      poolsContainer.replaceChildren();
    }} else {{
      while (poolsContainer.firstChild) poolsContainer.removeChild(poolsContainer.firstChild);
    }}
    (data.pools || []).forEach(p => {{
      const poolDiv = document.createElement("div");
      poolDiv.className = "pool-card";

      const pUsedRaw = Number(p.used_pct);
      const pUsedNum = Number.isFinite(pUsedRaw) ? Math.min(100, Math.max(0, pUsedRaw)) : 0;
      const pUsedDisplay = Number.isFinite(pUsedRaw) ? p.used_pct : 0;
      const pColor = quotaBarColor(pUsedNum);
      const pReset = (p.resets_in && p.resets_in !== "N/A")
        ? ("Resets in " + p.resets_in + (p.reset_time && p.reset_time !== "N/A" ? " (" + p.reset_time + ")" : ""))
        : "Ready to use";

      const headerDiv = document.createElement("div");
      headerDiv.className = "pool-header";

      const nameDiv = document.createElement("div");
      nameDiv.className = "pool-name";
      nameDiv.textContent = p.name || "";

      const pctDiv = document.createElement("div");
      pctDiv.className = "pool-pct";
      pctDiv.style.color = pColor;
      pctDiv.textContent = pUsedDisplay + "% used";

      headerDiv.appendChild(nameDiv);
      headerDiv.appendChild(pctDiv);

      const barDiv = document.createElement("div");
      barDiv.className = "progress-bar";

      const fillDiv = document.createElement("div");
      fillDiv.className = "progress-fill";
      fillDiv.style.width = pUsedNum + "%";
      fillDiv.style.background = pColor;

      barDiv.appendChild(fillDiv);

      const resetDiv = document.createElement("div");
      resetDiv.className = "pool-reset";
      resetDiv.textContent = pReset;

      poolDiv.appendChild(headerDiv);
      poolDiv.appendChild(barDiv);
      poolDiv.appendChild(resetDiv);
      poolsContainer.appendChild(poolDiv);
    }});
  }}

  // Setup account selector if multiple accounts
  const keys = Object.keys(accountsData);
  if (keys.length > 1) {{
    const select = document.getElementById("accountSelect");
    keys.forEach(k => {{
      const opt = document.createElement("option");
      opt.value = k;
      opt.text = (k === activeKey ? "🟢 " : "") + k;
      if (k === activeKey) opt.selected = true;
      select.appendChild(opt);
    }});
    document.getElementById("accountSelectorWrap").style.display = "block";
  }}

  function onAccountChange() {{
    const sel = document.getElementById("accountSelect");
    updateDisplay(sel.value);
  }}

  const accountSelectEl = document.getElementById("accountSelect");
  if (accountSelectEl) {{
    accountSelectEl.addEventListener("change", onAccountChange);
  }}
  const refreshBtnEl = document.getElementById("refreshBtn");
  if (refreshBtnEl) {{
    refreshBtnEl.addEventListener("click", () => location.reload());
  }}

  updateDisplay(activeKey);

  // Real-time ticking countdown for both daily and weekly
  setInterval(() => {{
    const sel = document.getElementById("accountSelect");
    const currentKey = sel ? sel.value : activeKey;
    const data = accountsData[currentKey];
    if (!data) return;

    function tickTimer(elemId, isoStr) {{
      if (!isoStr) return;
      const target = new Date(isoStr).getTime();
      const now = new Date().getTime();
      const diff = Math.floor((target - now) / 1000);
      if (diff > 0) {{
        const d = Math.floor(diff / 86400);
        const h = Math.floor((diff % 86400) / 3600);
        const m = Math.floor((diff % 3600) / 60);
        const s = diff % 60;
        let str = "";
        if (d > 0) str += d + "d ";
        if (h > 0 || d > 0) str += h + "h ";
        str += m + "m " + s + "s";
        const el = document.getElementById(elemId);
        if (el) el.textContent = "⏱ Resets in " + str;
      }}
    }}

    if (data.daily && data.daily.reset_iso) tickTimer("dailyCountdown", data.daily.reset_iso);
    if (data.weekly && data.weekly.reset_iso) tickTimer("weeklyCountdown", data.weekly.reset_iso);
  }}, 1000);
</script>

</body>
</html>
"""
    write_secure_file(USAGE_DASHBOARD_PATH, html_content)
    return USAGE_DASHBOARD_PATH

def open_claude_usage_window(target_key=None, force_refresh=False, quiet=False):
    """Fetch usage and open the Claude-style HTML desktop window fast."""
    payload = get_status_payload(force_refresh=force_refresh, include_unsaved_usage=True)
    all_data = {account['key']: account['usage'] for account in payload['accounts'] if account['usage']}
    active_key = payload['active_key']
    if payload['active_session_unsaved'] and payload['unsaved_usage']:
        active_key = 'Active Session'
        while active_key in all_data:
            active_key += ' (unsaved)'
        all_data[active_key] = payload['unsaved_usage']

    if not all_data:
        _report_error("Usage unavailable", "Could not retrieve Antigravity usage.", quiet=quiet)
        return False

    chosen_key = next(key for key in (target_key, active_key, next(iter(all_data))) if key in all_data)
    try:
        dashboard_path = generate_claude_html_dashboard(all_data, chosen_key)
    except OSError as exc:
        _report_error("Usage unavailable", f"Could not write the quota dashboard: {exc}", quiet=quiet)
        return False
    dashboard_uri = pathlib.Path(os.path.abspath(dashboard_path)).as_uri()
    if not open_url(dashboard_uri):
        _report_error("Usage unavailable", "Could not open the quota dashboard in the default browser.", quiet=quiet)
        return False
    if not quiet:
        play_sound("Glass")
    return True

def _macos_keychain_set_ctypes(service, account, secret):
    """Write or update a macOS Keychain generic password via Security.framework without argv exposure."""
    try:
        sec_path = ctypes.util.find_library("Security")
        cf_path = ctypes.util.find_library("CoreFoundation")
        if not sec_path or not cf_path:
            return False, "Security or CoreFoundation framework not found"
        sec = ctypes.CDLL(sec_path)
        cf = ctypes.CDLL(cf_path)

        sec.SecKeychainFindGenericPassword.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sec.SecKeychainFindGenericPassword.restype = ctypes.c_int32

        sec.SecKeychainItemModifyAttributesAndData.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        sec.SecKeychainItemModifyAttributesAndData.restype = ctypes.c_int32

        sec.SecKeychainAddGenericPassword.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        sec.SecKeychainAddGenericPassword.restype = ctypes.c_int32

        cf.CFRelease.argtypes = [ctypes.c_void_p]
        cf.CFRelease.restype = None

        svc_b = service.encode('utf-8')
        acct_b = account.encode('utf-8')
        sec_b = secret.encode('utf-8')
        sec_buf = ctypes.create_string_buffer(sec_b, len(sec_b))

        item_ref = ctypes.c_void_p()
        status = sec.SecKeychainFindGenericPassword(
            None,
            len(svc_b), svc_b,
            len(acct_b), acct_b,
            None, None,
            ctypes.byref(item_ref)
        )
        if status == 0:
            try:
                mod_status = sec.SecKeychainItemModifyAttributesAndData(
                    item_ref, None, len(sec_b), ctypes.cast(sec_buf, ctypes.c_void_p)
                )
            finally:
                if item_ref.value:
                    cf.CFRelease(item_ref)
            return mod_status == 0, ("" if mod_status == 0 else f"Security.framework OSStatus {mod_status}")
        elif status == -25300:
            add_status = sec.SecKeychainAddGenericPassword(
                None,
                len(svc_b), svc_b,
                len(acct_b), acct_b,
                len(sec_b), ctypes.cast(sec_buf, ctypes.c_void_p),
                None
            )
            return add_status == 0, ("" if add_status == 0 else f"Security.framework OSStatus {add_status}")
        return False, f"Security.framework OSStatus {status}"
    except Exception as e:
        return False, str(e)

def _macos_keychain_set(service, account, secret, keychain_path=None):
    """Write a generic password on macOS without exposing secret in command-line argv."""
    if (
        _SAFE_SECURITY_ARG_RE.match(service or "")
        and _SAFE_SECURITY_ARG_RE.match(account or "")
        and _SAFE_SECURITY_ARG_RE.match(secret or "")
    ):
        if keychain_path:
            safe_kc = keychain_path.replace('"', '\\"')
            cmd_line = f'add-generic-password -U -s {service} -a {account} -w {secret} "{safe_kc}"\n'
        else:
            cmd_line = f'add-generic-password -U -s {service} -a {account} -w {secret}\n'
        # security -i truncates lines >= 4096 bytes; route large secrets to Security.framework
        if len(cmd_line.encode('utf-8')) < 3800:
            code, _, err = run_cmd(['/usr/bin/security', '-i'], input_text=cmd_line)
            if code == 0 and 'returned -' not in err and 'unknown command' not in err:
                return True, ""
            if keychain_path is not None:
                return False, err or f"security -i failed with exit code {code}"
    if keychain_path is not None:
        return False, "Unsupported characters or length for isolated keychain path"
    return _macos_keychain_set_ctypes(service, account, secret)

def _macos_keychain_get(service, account):
    """Read a generic password from macOS Keychain without passing secrets in argv."""
    code, out, _ = run_cmd(['/usr/bin/security', 'find-generic-password', '-s', service, '-a', account, '-w'])
    if code == 0 and out:
        return out
    return None

def _macos_keychain_delete(service, account):
    """Delete a generic password from macOS Keychain."""
    code, _, _ = run_cmd(['/usr/bin/security', 'delete-generic-password', '-s', service, '-a', account])
    return code == 0

def get_storage_backend_name():
    """Return canonical storage backend name for macOS."""
    return "keychain"

def get_credential_secret(service, account):
    """Retrieve a secret from macOS Keychain."""
    if IS_MACOS:
        return _macos_keychain_get(service, account)
    return None

def set_credential_secret(service, account, secret, label=None):
    """Store a secret in macOS Keychain."""
    if IS_MACOS:
        return _macos_keychain_set(service, account, secret)
    return False, "Unsupported OS credential backend"

def delete_credential_secret(service, account):
    """Delete a secret from macOS Keychain."""
    if IS_MACOS:
        return _macos_keychain_delete(service, account)
    return False

def get_current_keychain_token():
    """Retrieve raw base64 Go-keyring string from OS credential store."""
    tok = get_credential_secret(KEYCHAIN_ACTIVE_SERVICE, KEYCHAIN_ACTIVE_ACCOUNT)
    if tok and tok.startswith('go-keyring-base64:'):
        return tok
    return None

def set_keychain_token(token):
    """Write token to native OS credential store."""
    return set_credential_secret(
        KEYCHAIN_ACTIVE_SERVICE,
        KEYCHAIN_ACTIVE_ACCOUNT,
        token,
        label="Password for 'antigravity' on 'gemini'"
    )

def delete_keychain_token():
    """Delete token from native OS credential store."""
    return delete_credential_secret(KEYCHAIN_ACTIVE_SERVICE, KEYCHAIN_ACTIVE_ACCOUNT)

def get_saved_account_token(secret_id):
    """Retrieve a saved account token from OS credential store by secret_id."""
    if not validate_secret_id(secret_id):
        return None
    tok = get_credential_secret(KEYCHAIN_SAVED_SERVICE, secret_id)
    if tok is None:
        tok = get_credential_secret(KEYCHAIN_LEGACY_SAVED_SERVICE, secret_id)
    return tok

def set_saved_account_token(secret_id, token, label=None):
    """Store a saved account token in OS credential store by secret_id."""
    if not validate_secret_id(secret_id):
        return False, "Invalid secret identifier"
    return set_credential_secret(KEYCHAIN_SAVED_SERVICE, secret_id, token, label=label)

def delete_saved_account_token(secret_id):
    """Delete a saved account token from OS credential store by secret_id."""
    if not validate_secret_id(secret_id):
        return False
    return delete_credential_secret(KEYCHAIN_SAVED_SERVICE, secret_id)

def get_account_token(entry):
    """Retrieve token for a manifest entry from OS credential store or safe legacy fallback."""
    if not isinstance(entry, dict):
        return None
    secret_id = entry.get('secret_id')
    if validate_secret_id(secret_id):
        tok = get_saved_account_token(secret_id)
        if tok:
            return tok
    tf = entry.get('token_file')
    safe_tf = resolve_safe_account_path(tf)
    if safe_tf and os.path.exists(safe_tf):
        try:
            with open(safe_tf, 'r', encoding='utf-8') as f:
                tok = f.read().strip()
            return tok if tok else None
        except Exception:
            return None
    return None

def _extract_token_identity(token_str):
    """Extract normalized (email, refresh_token) from a go-keyring-base64 token without network calls."""
    if not token_str or not isinstance(token_str, str):
        return None, None
    clean = token_str.strip()
    if not clean.startswith('go-keyring-base64:'):
        return None, None
    try:
        raw_b64 = clean.split('go-keyring-base64:', 1)[1]
        root = json.loads(base64.b64decode(raw_b64).decode('utf-8'))
        if not isinstance(root, dict):
            return None, None
        t_obj = root.get('token') if isinstance(root.get('token'), dict) else {}
        raw_email = root.get('id_token_email') or root.get('email') or t_obj.get('email')
        email = raw_email.strip().lower() if isinstance(raw_email, str) and raw_email.strip() else None
        raw_rf = t_obj.get('refresh_token')
        rf = raw_rf.strip() if isinstance(raw_rf, str) and raw_rf.strip() else None
        return email, rf
    except Exception:
        return None, None


def _find_account_key_by_email(manifest, email):
    """Find saved manifest key matching email or key case-insensitively."""
    if not email or not isinstance(email, str) or not isinstance(manifest, dict):
        return None
    clean = email.strip().lower()
    if not clean:
        return None
    for k in sorted(manifest.keys()):
        v = manifest.get(k)
        if isinstance(v, dict) and isinstance(v.get('email'), str) and v['email'].strip().lower() == clean:
            return k
    for k in sorted(manifest.keys()):
        if isinstance(k, str) and k.strip().lower() == clean:
            return k
    return None


def find_active_account_key(manifest, curr_token):
    """Match active token against manifest using SHA-256 first, then refresh_token and email."""
    if not curr_token or not isinstance(manifest, dict):
        return None
    curr_clean = curr_token.strip()
    curr_hash = compute_token_sha256(curr_clean)
    for k in sorted(manifest.keys()):
        v = manifest.get(k)
        if not isinstance(v, dict):
            continue
        sha = v.get('token_sha256')
        if isinstance(sha, str) and sha.lower() == curr_hash:
            return k

    curr_email, curr_rf = _extract_token_identity(curr_clean)
    for k in sorted(manifest.keys()):
        v = manifest.get(k)
        if not isinstance(v, dict):
            continue
        if not v.get('token_sha256'):
            tok = get_account_token(v)
            if tok and tok.strip() == curr_clean:
                return k
        if curr_rf:
            tok = get_account_token(v)
            _, saved_rf = _extract_token_identity(tok)
            if saved_rf and saved_rf == curr_rf:
                return k

    return _find_account_key_by_email(manifest, curr_email)

def extract_email_from_token(token_str):
    """Query Google userinfo API to get email associated with access token."""
    if not token_str or not token_str.startswith('go-keyring-base64:'):
        return None
    try:
        raw_b64 = token_str.split('go-keyring-base64:', 1)[1]
        data = json.loads(base64.b64decode(raw_b64).decode('utf-8'))
        access_token = data.get('token', {}).get('access_token')
        if access_token:
            req = urllib.request.Request(
                'https://www.googleapis.com/oauth2/v3/userinfo',
                headers={'Authorization': f'Bearer {access_token}'}
            )
            with urllib.request.urlopen(req, timeout=2.5) as r:
                info = json.loads(r.read().decode('utf-8'))
                return info.get('email')
    except Exception:
        pass
    return None

def _shred_and_remove_file(file_path):
    """Best-effort overwrite and delete of a validated regular file."""
    try:
        if os.path.exists(file_path) and os.path.isfile(file_path) and not os.path.islink(file_path):
            sz = os.path.getsize(file_path)
            if sz > 0:
                with open(file_path, 'wb') as wf:
                    wf.write(b'\x00' * sz)
                    wf.flush()
            os.remove(file_path)
    except Exception:
        pass

def save_manifest(manifest):
    """Save the manifest of accounts atomically with 0600 permissions."""
    if os.path.exists(MANIFEST_PATH):
        try:
            with open(MANIFEST_PATH, 'r', encoding='utf-8') as handle:
                if not isinstance(json.load(handle), dict):
                    raise ValueError("expected an account object")
        except (ValueError, UnicodeError) as exc:
            raise OSError("Existing account list is invalid; it was preserved.") from exc
    write_secure_file(MANIFEST_PATH, json.dumps(manifest, indent=2))

def migrate_legacy_tokens(manifest):
    """Migrate plaintext .token files inside ACCOUNTS_DIR to OS credential store."""
    if not isinstance(manifest, dict) or not manifest:
        return manifest

    used_ids = {
        v.get('secret_id')
        for v in manifest.values()
        if isinstance(v, dict) and validate_secret_id(v.get('secret_id'))
    }
    changed = False
    files_to_remove = []

    for key, entry in manifest.items():
        if not isinstance(entry, dict):
            continue
        sid = entry.get('secret_id')
        has_valid_sid = validate_secret_id(sid)
        tf = entry.get('token_file')

        if has_valid_sid and entry.get('token_sha256') and not tf:
            continue

        if has_valid_sid and not tf and not entry.get('token_sha256'):
            tok = get_saved_account_token(sid)
            if tok:
                entry['token_sha256'] = compute_token_sha256(tok)
                changed = True
            continue

        if tf:
            safe_tf = resolve_safe_account_path(tf)
            if not safe_tf:
                print(f"⚠️ Skipping unsafe token_file path for '{key}'", file=sys.stderr)
                continue
            if os.path.exists(safe_tf):
                try:
                    os.chmod(safe_tf, 0o600)
                except Exception:
                    pass
                try:
                    with open(safe_tf, 'r', encoding='utf-8') as f:
                        tok = f.read().strip()
                except Exception as e:
                    print(f"⚠️ Failed reading legacy token file for '{key}': {e}", file=sys.stderr)
                    continue

                if tok:
                    target_sid = sid if has_valid_sid else make_secret_id(key, used_ids)
                    used_ids.add(target_sid)
                    ok, err = set_saved_account_token(target_sid, tok, label=f"Antigravity Switcher ({key})")
                    roundtrip = get_saved_account_token(target_sid) if ok else None
                    if ok and roundtrip and roundtrip.strip() == tok:
                        entry['secret_id'] = target_sid
                        entry['storage'] = get_storage_backend_name()
                        entry['token_sha256'] = compute_token_sha256(tok)
                        entry.pop('token_file', None)
                        files_to_remove.append(safe_tf)
                        changed = True
                    else:
                        print(f"⚠️ Could not migrate '{key}' to OS credential store ({err or 'verification failed'}); keeping protected legacy file.", file=sys.stderr)
                elif has_valid_sid:
                    entry.pop('token_file', None)
                    files_to_remove.append(safe_tf)
                    changed = True
            elif has_valid_sid:
                entry.pop('token_file', None)
                changed = True

    if changed:
        save_manifest(manifest)
        for old_tf in files_to_remove:
            _shred_and_remove_file(old_tf)

    return manifest

def load_manifest(migrate=True):
    """Load the manifest of saved accounts and migrate any legacy token files."""
    if migrate:
        with _account_store_transaction():
            manifest = load_manifest(migrate=False)
            if os.path.exists(MANIFEST_PATH):
                os.chmod(MANIFEST_PATH, 0o600)
            return migrate_legacy_tokens(manifest) if manifest else manifest
    manifest = {}
    if os.path.exists(MANIFEST_PATH):
        try:
            with open(MANIFEST_PATH, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                manifest = loaded
        except Exception:
            return {}
    return manifest

def _report_error(title, msg, quiet=False):
    """Report error via stderr in quiet mode or GUI alert otherwise."""
    if quiet:
        print(msg, file=sys.stderr)
    else:
        ui_alert(title, msg, is_critical=True)

def _update_usage_cache(mutator_fn):
    """Safely update usage_cache.json in place if it exists."""
    cache_path = os.path.join(ACCOUNTS_DIR, "usage_cache.json")
    if not os.path.exists(cache_path):
        return
    try:
        with open(cache_path, 'r', encoding='utf-8') as f:
            cached = json.load(f)
        if not isinstance(cached, dict):
            return
        if mutator_fn(cached):
            write_secure_file(cache_path, json.dumps(cached))
    except Exception:
        pass

def save_current_account(custom_label=None, quiet=False):
    """Save the currently active OS account securely in OS credential store."""
    token = get_current_keychain_token()
    if not token:
        _report_error("Error", "No active Antigravity account found in system credential store. Please sign in to Antigravity first.", quiet=quiet)
        return False
    
    email = extract_email_from_token(token)
    if not email:
        if quiet:
            email = (custom_label or "").strip() or "antigravity-account"
        else:
            email = ui_input("Save Account", "Enter email or name for this account:", default_val="my-account@gmail.com")
            if not email:
                return False

    key = (custom_label if custom_label else email).strip()
    if not key:
        _report_error("Error", "Account label cannot be empty.", quiet=quiet)
        return False

    ok, result = _save_token_directly(token, email, key)
    if not ok:
        _report_error("Error", result, quiet=quiet)
        return False
    if not quiet:
        play_sound("Glass")
        notify(f"Account '{key}' saved successfully!", sound=False)
    print(f"✓ Account saved: {key}")
    return True


@_serialized_account_change
def _save_token_directly(token, email, custom_label=None):
    """Save one credential, preserving an existing account with a different identity."""
    key = (custom_label or email or "antigravity-account").strip()
    if not key:
        return False, "Account label cannot be empty."
    manifest = load_manifest()
    existing = manifest.get(key) if isinstance(manifest.get(key), dict) else {}
    existing_token = get_account_token(existing) if existing else None
    if existing:
        old_email = (existing.get('email') or '').strip().casefold()
        new_email = (email or '').strip().casefold()
        _, old_refresh = _extract_token_identity(existing_token)
        _, new_refresh = _extract_token_identity(token)
        same_email = '@' in new_email and old_email == new_email
        if existing_token != token and not same_email and not (old_refresh and old_refresh == new_refresh):
            return False, f"Account label '{key}' is already in use. Choose a different label."

    used_ids = {
        v.get('secret_id')
        for k, v in manifest.items()
        if k != key and isinstance(v, dict) and validate_secret_id(v.get('secret_id'))
    }
    current_sid = existing.get('secret_id')
    secret_id = current_sid if validate_secret_id(current_sid) and current_sid not in used_ids else make_secret_id(key, used_ids)
    previous_secret = get_saved_account_token(secret_id)
    ok, error = set_saved_account_token(secret_id, token, label=f"Antigravity Switcher ({key})")
    if not ok:
        return False, error or "Keychain write failed."

    entry = {
        'label': key,
        'email': email or key,
        'secret_id': secret_id,
        'storage': get_storage_backend_name(),
        'token_sha256': compute_token_sha256(token),
        'saved_at': time.strftime('%Y-%m-%d %H:%M:%S'),
    }
    for field in ('pinned', 'plan_label'):
        if field in existing:
            entry[field] = existing[field]
    manifest[key] = entry
    try:
        if get_saved_account_token(secret_id) != token.strip():
            raise OSError("Keychain verification failed.")
        save_manifest(manifest)
    except OSError as exc:
        if previous_secret is None:
            delete_saved_account_token(secret_id)
        else:
            set_saved_account_token(secret_id, previous_secret)
        return False, f"Could not save account list: {exc}"

    prior_file = resolve_safe_account_path(existing.get('token_file'))
    if prior_file:
        _shred_and_remove_file(prior_file)
    return True, key


def _persist_refreshed_token(account_key, previous_token, new_token):
    """Update a saved credential if its account still holds the token we fetched."""
    if not account_key or not new_token or not new_token.startswith('go-keyring-base64:'):
        return
    with _account_store_transaction():
        manifest = load_manifest(migrate=False)
        entry = manifest.get(account_key)
        if not isinstance(entry, dict) or get_account_token(entry) != previous_token:
            return
        sid = entry.get('secret_id')
        if not validate_secret_id(sid):
            return
        ok, _ = set_saved_account_token(sid, new_token)
        if ok and get_saved_account_token(sid) == new_token:
            entry['token_sha256'] = compute_token_sha256(new_token)
            try:
                save_manifest(manifest)
            except OSError:
                pass

@_serialized_account_change
def pin_saved_account(account_key, pinned=True):
    """Pin or unpin a saved account so it stays prioritized."""
    manifest = load_manifest()
    if account_key not in manifest or not isinstance(manifest[account_key], dict):
        print(f"Account '{account_key}' not found.", file=sys.stderr)
        return False
    manifest[account_key]['pinned'] = bool(pinned)
    save_manifest(manifest)
    print(f"✓ Account {'pinned' if pinned else 'unpinned'}: {account_key}")
    return True

@_serialized_account_change
def set_account_plan(account_key, plan_label):
    """Set or clear a custom plan tag (e.g. 'Pro', 'Ultra', or '' for Auto) on a saved account."""
    manifest = load_manifest()
    if account_key not in manifest or not isinstance(manifest[account_key], dict):
        print(f"Account '{account_key}' not found.", file=sys.stderr)
        return False
    clean_plan = (plan_label or "").strip()
    if clean_plan:
        manifest[account_key]['plan_label'] = clean_plan
    else:
        manifest[account_key].pop('plan_label', None)
    save_manifest(manifest)

    def _update_tier_cache(c):
        if account_key in c and isinstance(c[account_key], dict):
            c[account_key]['tier'] = clean_plan
            return True
        return False
    _update_usage_cache(_update_tier_cache)
    print(f"✓ Updated plan for {account_key}: {clean_plan or 'Auto'}")
    return True

def _extract_quota_pair(usage_obj):
    """Return (min_rem, gemini_rem) tuple for ranking accounts by available quota."""
    if not isinstance(usage_obj, dict):
        return None
    pools = usage_obj.get('pools') or []
    gem = next(
        (p for p in pools if isinstance(p, dict)
         and 'gemini' in (p.get('group_name') or p.get('name') or '').lower()
         and 'argon' not in (p.get('group_name') or p.get('name') or '').lower()
         and '5h' in (p.get('window_label') or p.get('name') or '').lower()),
        None
    ) or next(
        (p for p in pools if isinstance(p, dict)
         and 'gemini' in (p.get('group_name') or p.get('name') or '').lower()
         and 'argon' not in (p.get('group_name') or p.get('name') or '').lower()),
        None
    )
    if gem is None and isinstance(usage_obj.get('daily'), dict):
        gem = usage_obj['daily']

    vals = [
        float(p['remaining_pct'])
        for p in pools
        if isinstance(p, dict) and isinstance(p.get('remaining_pct'), (int, float))
    ]
    if not vals:
        for k in ('daily', 'weekly'):
            p = usage_obj.get(k)
            if isinstance(p, dict) and isinstance(p.get('remaining_pct'), (int, float)):
                vals.append(float(p['remaining_pct']))
    if not vals:
        return None
    gem_rem = float(gem['remaining_pct']) if isinstance(gem, dict) and isinstance(gem.get('remaining_pct'), (int, float)) else vals[0]
    return (min(vals), gem_rem)

def compute_best_switch_candidate(accounts_out, active_key):
    """Recommend best alternate account when active quota is low or significantly behind."""
    active_score = None
    best_key = None
    best_score = None

    for item in accounts_out:
        if not isinstance(item, dict):
            continue
        k = item.get('key')
        score = _extract_quota_pair(item.get('usage'))
        if score is None:
            continue
        if k == active_key:
            active_score = score
        elif best_score is None or score > best_score:
            best_key = k
            best_score = score

    if not best_key or best_score is None:
        return None
    if active_score is None:
        return best_key
    if active_score[0] < 25.0 and best_score[0] > active_score[0]:
        return best_key
    if (best_score[0] - active_score[0]) >= 20.0:
        return best_key
    return None

@_serialized_account_change
def remove_saved_account(account_key, quiet=False):
    """Remove a saved account from manifest and OS credential store."""
    manifest = load_manifest()
    if account_key not in manifest:
        _report_error("Error", f"Account '{account_key}' not found in saved list.", quiet=quiet)
        return False
    entry = manifest[account_key] if isinstance(manifest[account_key], dict) else {}
    del manifest[account_key]
    try:
        save_manifest(manifest)
    except OSError as exc:
        _report_error("Error", f"Could not update account list: {exc}", quiet=quiet)
        return False
    sid = entry.get('secret_id')
    remaining = [v for v in manifest.values() if isinstance(v, dict)]
    if validate_secret_id(sid) and not any(v.get('secret_id') == sid for v in remaining):
        delete_saved_account_token(sid)
    tf = entry.get('token_file')
    safe_tf = resolve_safe_account_path(tf)
    if safe_tf and not any(resolve_safe_account_path(v.get('token_file')) == safe_tf for v in remaining):
        _shred_and_remove_file(safe_tf)
    _update_usage_cache(lambda c: c.pop(account_key, None) is not None)
    if not quiet:
        play_sound("Submarine")
        notify(f"Removed account {account_key}", sound=False)
    print(f"✓ Account removed: {account_key}")
    return True

@_serialized_account_change
def rename_saved_account(old_key, new_key):
    """Rename a saved account key and label in manifest."""
    new_clean = (new_key or "").strip()
    if not new_clean:
        print("New account label cannot be empty.", file=sys.stderr)
        return False
    manifest = load_manifest()
    if old_key not in manifest:
        print(f"Account '{old_key}' not found.", file=sys.stderr)
        return False
    if new_clean == old_key:
        return True
    if new_clean in manifest:
        print(f"Account '{new_clean}' already exists.", file=sys.stderr)
        return False
    entry = manifest.pop(old_key)
    if isinstance(entry, dict):
        entry['label'] = new_clean
    manifest[new_clean] = entry
    save_manifest(manifest)

    def _rename_cache(c):
        if old_key in c:
            c[new_clean] = c.pop(old_key)
            return True
        return False
    _update_usage_cache(_rename_cache)
    print(f"✓ Account renamed: {old_key} -> {new_clean}")
    return True

def prepare_add_account_login():
    """Sign out active Antigravity session and relaunch app for new sign-in."""
    previous = get_current_keychain_token()
    if previous and not delete_keychain_token():
        return False
    if restart_antigravity():
        return True
    _restore_active_session_if_missing(previous)
    return False


def _restore_active_session_if_missing(previous):
    with _account_store_transaction():
        if previous and not get_current_keychain_token():
            return set_keychain_token(previous)[0]
        return True

def _ensure_pool_reset_short(usage_obj):
    """Backfill reset_short on cached usage objects created by older versions."""
    if not isinstance(usage_obj, dict):
        return usage_obj
    for key in ('session', 'daily', 'weekly'):
        p = usage_obj.get(key)
        if isinstance(p, dict) and 'reset_short' not in p:
            p['reset_short'] = format_reset_short(p.get('reset_iso', ''))
    for p in usage_obj.get('pools', []) or []:
        if isinstance(p, dict) and 'reset_short' not in p:
            p['reset_short'] = format_reset_short(p.get('reset_iso', ''))
    return usage_obj

def get_status_payload(force_refresh=False, cached_only=False, include_unsaved_usage=False):
    """Return structured JSON-ready account and quota state with zero secrets."""
    manifest = load_manifest(migrate=not cached_only)
    curr_token = get_current_keychain_token()
    active_key = find_active_account_key(manifest, curr_token)
    cache_path = os.path.join(ACCOUNTS_DIR, "usage_cache.json")

    cached_data = {}
    cache_mtime = 0.0
    if os.path.exists(cache_path):
        try:
            cache_mtime = os.path.getmtime(cache_path)
            with open(cache_path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                cached_data = loaded
        except Exception:
            cached_data = {}

    age = time.time() - cache_mtime if cache_mtime else float('inf')
    cached_data = {k: u for k, u in cached_data.items() if isinstance(u, dict)}
    all_saved_cached = all(k in cached_data for k in manifest)
    used_cache = False
    usage_by_key = {}
    unsaved_usage = None

    if cached_only:
        if cached_data and age < 86400:
            used_cache = True
            for k in manifest.keys():
                if k in cached_data:
                    usage_by_key[k] = _ensure_pool_reset_short(cached_data[k])
    else:
        if not force_refresh and cached_data and age < 45 and all_saved_cached and (active_key or not curr_token):
            used_cache = True
            for k in manifest.keys():
                usage_by_key[k] = _ensure_pool_reset_short(cached_data[k])
        else:
            tasks = {}
            for k, v in manifest.items():
                if not isinstance(v, dict):
                    continue
                tok = get_account_token(v)
                if tok:
                    tasks[k] = (tok, v.get('email'), v.get('plan_label', ''))

            if curr_token and not active_key:
                tasks[None] = (curr_token, None, '')

            if tasks:
                import concurrent.futures
                def _fetch_one(item):
                    name, (tok, email, plan_lbl) = item
                    def _on_rf(new_tok):
                        _persist_refreshed_token(name, tok, new_tok)
                    return name, fetch_antigravity_usage(
                        tok,
                        known_email=email,
                        on_token_refreshed=_on_rf,
                        saved_plan_label=plan_lbl
                    )

                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    for name, u in executor.map(_fetch_one, tasks.items()):
                        if name is None:
                            unsaved_usage = _ensure_pool_reset_short(u) if u else None
                        elif u:
                            usage_by_key[name] = _ensure_pool_reset_short(u)
                        elif not force_refresh and name in cached_data:
                            usage_by_key[name] = _ensure_pool_reset_short(cached_data[name])

            if usage_by_key:
                try:
                    write_secure_file(cache_path, json.dumps(usage_by_key))
                except Exception:
                    pass

    active_email = None
    if active_key:
        u_act = usage_by_key.get(active_key)
        if isinstance(u_act, dict) and u_act.get('email') and u_act.get('email') != 'Unknown':
            active_email = u_act.get('email')
        elif isinstance(manifest.get(active_key), dict):
            active_email = manifest[active_key].get('email')
    elif curr_token:
        if isinstance(unsaved_usage, dict) and unsaved_usage.get('email') and unsaved_usage.get('email') != 'Unknown':
            active_email = unsaved_usage.get('email')
        elif not cached_only:
            active_email = extract_email_from_token(curr_token)
        matched_key = _find_account_key_by_email(manifest, active_email)
        if matched_key:
            active_key = matched_key
            if isinstance(unsaved_usage, dict) and matched_key not in usage_by_key:
                usage_by_key[matched_key] = unsaved_usage
                try:
                    write_secure_file(cache_path, json.dumps(usage_by_key))
                except Exception:
                    pass

    accounts_out = []
    for k in sorted(manifest.keys()):
        v = manifest[k] if isinstance(manifest[k], dict) else {}
        u_obj = usage_by_key.get(k)
        plan_lbl = v.get('plan_label', '') if isinstance(v.get('plan_label'), str) else ''
        if isinstance(u_obj, dict) and plan_lbl.strip():
            u_obj = dict(u_obj)
            u_obj['tier'] = plan_lbl.strip()
        resolved_email = None
        if isinstance(u_obj, dict) and u_obj.get('email') and u_obj.get('email') != 'Unknown':
            resolved_email = u_obj.get('email')
        elif v.get('email'):
            resolved_email = v.get('email')
        else:
            resolved_email = k

        accounts_out.append({
            'key': k,
            'label': v.get('label', k),
            'email': resolved_email,
            'saved_at': v.get('saved_at', ''),
            'storage': v.get('storage', get_storage_backend_name()),
            'is_active': (k == active_key),
            'pinned': bool(v.get('pinned', False)),
            'plan_label': plan_lbl,
            'usage': u_obj,
        })

    return {
        **({'unsaved_usage': unsaved_usage} if include_unsaved_usage else {}),
        'active_key': active_key,
        'has_active_session': bool(curr_token),
        'active_session_unsaved': bool(curr_token and not active_key),
        'active_email': active_email,
        'best_switch_candidate': compute_best_switch_candidate(accounts_out, active_key),
        'accounts': accounts_out,
        'fetched_at': int(time.time()),
        'from_cache': used_cache,
    }

def get_antigravity_app_path():
    """Locate Antigravity application path on macOS."""
    if IS_MACOS:
        candidates = [
            "/Applications/Antigravity.app",
            "/Applications/Antigravity IDE.app",
            os.path.expanduser("~/Applications/Antigravity.app"),
            os.path.expanduser("~/Applications/Antigravity IDE.app")
        ]
        for p in candidates:
            if os.path.exists(p):
                return p
        return "/Applications/Antigravity.app"
    return "Antigravity"

def _any_process_running(checks):
    """Return True if any pgrep check matches a running process."""
    for check in checks:
        code, _, _ = run_cmd(['pgrep'] + list(check))
        if code == 0:
            return True
    return False

def restart_antigravity(app_path=None):
    """Gracefully terminate Antigravity, its helpers, and its language server, falling back to force-kill after timeout."""
    if IS_MACOS:
        app_path = app_path or get_antigravity_app_path()
        root = "^" + re.escape(app_path)
        main_checks = [['-f', f"{root}/Contents/MacOS/"]]
        helper_checks = [['-f', f"{root}/Contents/Frameworks/"]]
        ls_patterns = [f"{root}/Contents/Resources/.*/language_server"]
        pgrep_checks = main_checks + helper_checks + [['-f', pattern] for pattern in ls_patterns]
        if _any_process_running(pgrep_checks):
            quit_script = (
                'on run argv\n'
                '    set targetPath to item 1 of argv\n'
                '    tell application "System Events"\n'
                '        repeat with p in (every application process)\n'
                '            try\n'
                '                set pPath to POSIX path of file of p\n'
                '                if pPath is targetPath or pPath is (targetPath & "/") then\n'
                '                    set appName to name of p\n'
                '                    tell application appName to quit\n'
                '                end if\n'
                '            end try\n'
                '        end repeat\n'
                '    end tell\n'
                'end run'
            )
            osascript(quit_script, [app_path])
            for ls_pat in ls_patterns:
                run_cmd(['pkill', '-TERM', '-f', ls_pat])

            deadline = time.time() + 5.0
            while time.time() < deadline:
                if not _any_process_running(pgrep_checks):
                    break
                time.sleep(0.25)

            if _any_process_running(pgrep_checks):
                for chk in pgrep_checks:
                    run_cmd(['pkill', '-9'] + list(chk))
                time.sleep(0.5)

        # Allow LaunchServices and Electron SingletonLock to finish unregistering the exiting instance.
        time.sleep(0.45)
        for options in ([], ['-n']):
            code, _, _ = run_cmd(['open', *options, '-a', app_path])
            if code == 0:
                for _ in range(10):
                    if _any_process_running(main_checks):
                        return True
                    time.sleep(0.25)
    return False

def switch_to_account(account_key, quiet=False, restart_bundle=None):
    """Switch active Antigravity account in credential store and restart app."""
    if restart_bundle:
        try:
            bundle = pathlib.Path(restart_bundle).resolve(strict=True)
            with (bundle / "Contents/Info.plist").open("rb") as plist_file:
                bundle_id = plistlib.load(plist_file).get("CFBundleIdentifier")
            if bundle.suffix != ".app" or bundle_id not in {
                "com.google.antigravity", "com.google.antigravity-ide",
                "com.antigravity.ide", "com.todesktop.antigravity",
            }:
                raise ValueError("Unrecognized Antigravity bundle")
        except (OSError, ValueError, plistlib.InvalidFileException, AttributeError):
            _report_error("Error", "Could not identify the Antigravity app to restart.", quiet=quiet)
            return False
        restart_bundle = str(bundle)

    with _account_store_transaction():
        manifest = load_manifest()
        if account_key not in manifest:
            _report_error("Error", f"Account '{account_key}' not found in saved list.", quiet=quiet)
            return False
        token = get_account_token(manifest[account_key])
        if not token:
            _report_error("Error", f"Saved credential for '{account_key}' is missing.", quiet=quiet)
            return False

        ok, err = set_keychain_token(token)
        if not ok:
            _report_error("Error", f"Failed to update credential store: {err}", quiet=quiet)
            return False

    # Restart Antigravity
    if not (restart_antigravity(restart_bundle) if restart_bundle else restart_antigravity()):
        _report_error("Antigravity could not restart",
                      "The active credential was updated. Open Antigravity to use the selected account.",
                      quiet=quiet)
        return False
    
    if not quiet:
        play_sound("Hero")
        notify(f"Switched to {account_key}!", sound=False)
    print(f"✓ Successfully switched to: {account_key}")
    return True

_AGY_STRIPPED_ENV_KEYS = {
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
    "WAYLAND_DISPLAY",
}


def find_agy_executable():
    """Locate the official Google Antigravity CLI (agy) binary."""
    import shutil
    candidates = [
        os.path.expanduser("~/.gemini/bin/agy"),
        "/opt/homebrew/bin/agy",
        "/usr/local/bin/agy",
        os.path.expanduser("~/.local/bin/agy"),
    ]
    for p in candidates:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return shutil.which("agy")


def _build_agy_login_env(base_env, profile_dir, temp_dir):
    """Build isolated T3 Code compatible environment for `agy acp --login`."""
    env = {k: v for k, v in (base_env or {}).items() if k.upper() not in _AGY_STRIPPED_ENV_KEYS}
    env["SSH_CONNECTION"] = (base_env or {}).get("SSH_CONNECTION") or "127.0.0.1 0 127.0.0.1 0"
    env["GEMINI_HOME"] = profile_dir
    env["AGY_ACP_FORCE_FILE_STORAGE"] = "1"
    env["AGY_CLI_DISABLE_AUTO_UPDATE"] = "1"
    env["PYTHONUNBUFFERED"] = "1"
    env["ELECTRON_RUN_AS_NODE"] = "1"
    env["TMPDIR"] = temp_dir
    return env


def _normalize_official_credential(raw_text, fallback_email=""):
    """Normalize acp_token.json or Keychain credential into canonical go-keyring-base64 format."""
    if not isinstance(raw_text, str):
        return None
    clean = raw_text.strip()
    if not clean:
        return None
    if clean.startswith("go-keyring-base64:"):
        return clean
    try:
        parsed = json.loads(clean)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None
    if isinstance(parsed.get("token"), dict) and parsed["token"].get("access_token"):
        root = dict(parsed)
        if not root.get("auth_method"):
            root["auth_method"] = "consumer"
        if fallback_email and not root.get("id_token_email"):
            root["id_token_email"] = fallback_email
    elif isinstance(parsed.get("access_token"), str) and parsed["access_token"]:
        tok = {
            "access_token": parsed["access_token"],
            "token_type": parsed.get("token_type") or "Bearer",
        }
        if parsed.get("refresh_token"):
            tok["refresh_token"] = parsed["refresh_token"]
        if parsed.get("expiry") is not None:
            tok["expiry"] = parsed["expiry"]
        if parsed.get("expires_in") is not None:
            tok["expires_in"] = parsed["expires_in"]
        root = {
            "token": tok,
            "auth_method": "consumer",
            "writer_id": "antigravity",
        }
        if fallback_email:
            root["id_token_email"] = fallback_email
    else:
        return None
    return "go-keyring-base64:" + base64.b64encode(
        json.dumps(root, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def _read_google_authorization_url(stream, timeout):
    deadline = time.monotonic() + timeout
    pending = b""
    with selectors.DefaultSelector() as selector:
        selector.register(stream, selectors.EVENT_READ)
        while len(pending) < 65536:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                return None
            chunk = os.read(stream.fileno(), 8192)
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop() if chunk else b""
            for line in lines:
                url = line.strip()
                if url.startswith(b"https://accounts.google.com/"):
                    return url.decode("utf-8")
            if not chunk:
                return None
    return None


def agy_cli_login(timeout_secs=300):
    """Run official agy sign-in using a temporary credential profile."""
    agy = find_agy_executable()
    if not agy:
        raise RuntimeError("Official Antigravity CLI (agy) was not found.")

    with tempfile.TemporaryDirectory(prefix="ag_agy_login_") as profile_dir:
        acp_dir = pathlib.Path(profile_dir) / "antigravity-acp"
        tmp_dir = acp_dir / "tmp"
        tmp_dir.mkdir(mode=0o700, parents=True)
        (acp_dir / "settings.json").write_text('{"auth":{"type":"oauth-personal"}}\n', encoding="utf-8")
        with subprocess.Popen(
            [agy, "acp", "--gemini-dir", profile_dir, "--app-data-dir", "antigravity-acp", "--login"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_build_agy_login_env(os.environ, profile_dir, str(tmp_dir)),
            cwd=profile_dir,
        ) as process:
            try:
                url = _read_google_authorization_url(process.stdout, min(timeout_secs, 15))
                if not url:
                    raise RuntimeError("Antigravity CLI did not output an authorization link.")
                if not open_url(url):
                    raise RuntimeError("Could not open the Google authorization link in the default browser.")
                code = ui_input(
                    "Antigravity Official Sign-In",
                    "Complete Google sign-in, then paste the code or redirect URL shown by Antigravity:",
                    default_val="",
                )
                if not code or not code.strip():
                    raise RuntimeError("Sign-in cancelled.")

                try:
                    process.communicate(input=(code.strip() + "\n").encode("utf-8"), timeout=min(timeout_secs, 30))
                except subprocess.TimeoutExpired as exc:
                    raise RuntimeError("Antigravity sign-in timed out.") from exc
                if process.returncode != 0:
                    raise RuntimeError(f"agy exited with status {process.returncode}")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()

        token_file = acp_dir / "acp_token.json"
        token = _normalize_official_credential(token_file.read_text(encoding="utf-8")) if token_file.is_file() else None
        if not token:
            raise RuntimeError("Antigravity CLI did not write a credential to the temporary profile.")
        return token, extract_email_from_token(token) or "antigravity-account"


def add_account_wizard():
    """Interactive guided wizard to log in via official Antigravity CLI (`agy`) or Antigravity app."""
    has_agy = find_agy_executable() is not None
    if has_agy:
        mode = ui_confirm(
            "Add New Account",
            "Choose how to sign in safely with official Google Antigravity:\n\n• Antigravity CLI (Recommended): Uses `agy acp --login` (T3 Code method) without closing Antigravity.\n• Antigravity App: Restarts Antigravity desktop app in login mode.",
            buttons=["Cancel", "Antigravity App", "Antigravity CLI"],
            default_idx=3,
            icon="note",
        )
        if mode == "Antigravity CLI":
            try:
                full_tok, email = agy_cli_login()
            except Exception as e:
                ui_alert("Sign-In Failed", f"Could not complete Antigravity CLI sign-in:\n{e}", is_critical=True)
                return
            label = ui_input("Save Account", f"🎉 Detected: {email}\n\nEnter a label for this account:", default_val=email)
            label = label.strip() if label else email
            ok, res_msg = _save_token_directly(full_tok, email, custom_label=label)
            if ok:
                play_sound("Hero")
                ui_alert("Success", f"✅ Account '{res_msg}' saved successfully!\n\nYou can now switch between accounts with 1 click.")
            else:
                ui_alert("Save Failed", f"Could not save account: {res_msg}", is_critical=True)
            return
        if mode != "Antigravity App":
            return

    curr = get_current_keychain_token()
    manifest = load_manifest()

    # 1. Protect unsaved active account
    if curr:
        is_saved = find_active_account_key(manifest, curr) is not None
        if not is_saved:
            ans = ui_confirm(
                "Save Active Session",
                "⚠️ Your currently active account is not saved yet.\n\nSave it first before switching to a new account?",
                buttons=["Save Active First", "Skip & Logout", "Cancel"],
                default_idx=1,
                icon="caution"
            )
            if ans == "Cancel" or not ans:
                return
            if ans == "Save Active First":
                if not save_current_account():
                    return

    # 2. Confirm logout & launch login
    step1 = ui_confirm(
        "Add New Account Wizard",
        "🧙‍♂️ Add New Account Wizard\n\nStep 1: Antigravity will restart in login mode.\nStep 2: Sign in with your new Gmail inside Antigravity.\nStep 3: This wizard will automatically capture and save your new account!",
        buttons=["Cancel", "Start Login"],
        default_idx=2,
        icon="note"
    )
    if step1 != "Start Login":
        return

    if not prepare_add_account_login():
        ui_alert("Sign-In Failed", "Could not restart Antigravity for sign-in.", is_critical=True)
        return
    play_sound("Blow")

    try:
        _wait_for_desktop_sign_in(curr, manifest)
    finally:
        if not _restore_active_session_if_missing(curr):
            ui_alert("Sign-In Failed", "Could not restore the previous Antigravity session.", is_critical=True)


def _wait_for_desktop_sign_in(curr, manifest):
    while True:
        step2 = ui_confirm(
            "Waiting for Login",
            "⏳ Waiting for Login...\n\nPlease complete sign-in with your new Gmail inside Antigravity.\n\nWhen done, click \"I Have Signed In\" below:",
            buttons=["Cancel", "I Have Signed In"],
            default_idx=2,
            icon="note"
        )
        if step2 != "I Have Signed In":
            return

        new_tok = get_current_keychain_token()
        if new_tok and new_tok != curr:
            email = extract_email_from_token(new_tok)
            def_label = email if email else f"Account {len(manifest) + 1}"
            label = ui_input("Save Account", "🎉 Login detected!\n\nEnter a friendly name/label for this account:", default_val=def_label)
            label = label.strip() if label else def_label
            if save_current_account(custom_label=label):
                play_sound("Hero")
                ui_alert("Success", f"✅ Account '{label}' saved successfully!\n\nYou can now switch between accounts with 1 click.")
            return
        elif new_tok and new_tok == curr:
            retry = ui_confirm(
                "Same Account Detected",
                "⚠️ Same account detected.\n\nPlease log in with a different Gmail account in Antigravity.",
                buttons=["Cancel", "Try Again"],
                default_idx=2,
                icon="caution"
            )
            if retry != "Try Again":
                return
        else:
            retry = ui_confirm(
                "No Login Detected",
                "⚠️ No active login detected in Antigravity yet.\n\nPlease ensure you completed Google sign-in in the Antigravity window.",
                buttons=["Cancel", "Try Again"],
                default_idx=2,
                icon="caution"
            )
            if retry != "Try Again":
                return

def logout_and_add_account():
    """Launch add account wizard."""
    add_account_wizard()

def main_menu():
    """Interactive GUI dialog picker."""
    manifest = load_manifest()
    curr_token = get_current_keychain_token()
    
    # Quick live usage fetch for active account
    active_key = find_active_account_key(manifest, curr_token)
    active_plan = manifest[active_key].get('plan_label', '') if (active_key and isinstance(manifest.get(active_key), dict)) else ''
    def _persist_active_rf(new_tok):
        _persist_refreshed_token(active_key, curr_token, new_tok)
    active_usage = fetch_antigravity_usage(curr_token, on_token_refreshed=_persist_active_rf, saved_plan_label=active_plan) if curr_token else None
    active_email = active_usage.get('email') if active_usage else (extract_email_from_token(curr_token) if curr_token else None)

    items = []
    for k in sorted(manifest.keys()):
        if k == active_key:
            items.append(f"🟢 [ACTIVE] {k}")
        else:
            items.append(f"⚡️ Switch to: {k}")
        
    items.append("─────────────────────────────")
    curr_display = active_email or (active_key if active_key else "Active Session") if curr_token else "Not Signed In"
    
    usage_info_line = ""
    sess = active_usage.get('session') if active_usage else None
    if sess:
        u_pct = sess.get('used_pct', 0.0)
        r_in = sess.get('resets_in', 'N/A')
        usage_info_line = f" • ⚡️ {u_pct}% used"
        if r_in != 'N/A':
            usage_info_line += f" (Resets: {r_in})"
            
    items.append("📊 View Usage & Limits (Claude Style)")
    items.append(f"💾 Save Current Account ({curr_display})")
    items.append("➕ Add New Account (Guided Wizard)")
    if manifest:
        items.append("🗑 Remove a Saved Account")
    items.append("─────────────────────────────")
    items.append("⭐ About & Star on GitHub (by Rick Sanchez)")
        
    arch_info = get_arch_label()
    prompt = f"🚀 GravityBar · Antigravity Account Switcher\n{arch_info} • by Rick Sanchez\n🟢 Active Account: {curr_display}{usage_info_line}\n\nChoose an action:"
    
    choice = ui_choose_from_list(prompt, items, title="GravityBar")
    if not choice or "──────" in choice:
        return

    if choice.startswith("⚡️ Switch to: "):
        acc = choice.replace("⚡️ Switch to: ", "").strip()
        switch_to_account(acc)
    elif choice.startswith("🟢 [ACTIVE] "):
        play_sound("Tink")
        ui_alert("Active Account", "This account is already active!")
    elif choice == "📊 View Usage & Limits (Claude Style)":
        open_claude_usage_window(active_key)
    elif choice.startswith("💾 Save Current Account"):
        save_current_account()
    elif choice.startswith("➕ Add New Account") or choice.startswith("➕ Add New Gmail"):
        logout_and_add_account()
    elif choice.startswith("⭐ About"):
        show_about()
    elif choice.startswith("🗑 Remove a Saved Account"):
        del_items = list(manifest.keys())
        del_choice = ui_choose_from_list("Select an account to remove from Switcher:", del_items, title="Remove Account")
        if del_choice and del_choice in manifest:
            remove_saved_account(del_choice)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=f"GravityBar — Antigravity Account Switcher by {AUTHOR_NAME}")
    parser.add_argument('-u', '--usage', action='store_true', help="Display Antigravity usage in Claude Code CLI style")
    parser.add_argument('--usage-gui', action='store_true', help="Open interactive Claude-style desktop usage dashboard")
    parser.add_argument('--status-json', action='store_true', help="Print accounts and quota status as JSON")
    parser.add_argument('--force-refresh', action='store_true', help="Bypass quota cache when fetching usage")
    parser.add_argument('--cached-only', action='store_true', help="Return cached quota status without network calls")
    parser.add_argument('--quiet', action='store_true', help="Suppress GUI alerts, banners, and sounds")
    parser.add_argument('--list', action='store_true', help="List saved accounts")
    parser.add_argument('--switch', type=str, help="Switch to specific account")
    parser.add_argument('--restart-bundle', type=str, metavar="APP", help="Restart a specific Antigravity app when switching")
    parser.add_argument('--save', nargs='?', const='', help="Save current account with optional name")
    parser.add_argument('--remove', type=str, help="Remove a specific saved account")
    parser.add_argument('--rename', nargs=2, metavar=('OLD', 'NEW'), help="Rename a saved account label")
    parser.add_argument('--pin', type=str, help="Pin an account to stay prioritized")
    parser.add_argument('--unpin', type=str, help="Unpin a saved account")
    parser.add_argument('--set-plan', nargs=2, metavar=('ACCOUNT', 'PLAN'), help="Set custom plan tag for an account")
    parser.add_argument('--prepare-add-login', action='store_true', help="Log out and relaunch Antigravity for new account login")
    parser.add_argument('--wizard', '--add', action='store_true', dest='wizard', help="Run interactive guided wizard to add a new account")
    parser.add_argument('--logout', action='store_true', help="Log out from current account")
    parser.add_argument('--github', action='store_true', help="Open GitHub project page")
    parser.add_argument('--about', action='store_true', help="Display creator & project info")
    parser.add_argument('--get-token', action='store_true', help="Print currently active token to stdout")
    parser.add_argument('--warmup-5h', action='store_true', help="Send 1-token warmup ping to start 5h Gemini quota timers across saved accounts")
    args = parser.parse_args()

    if args.warmup_5h:
        m = load_manifest()
        any_ok = False
        if m:
            for k, entry in sorted(m.items()):
                tok = get_account_token(entry) if isinstance(entry, dict) else None
                if not tok:
                    continue
                ok, mdl, err = send_gemini_warmup_ping(
                    tok,
                    on_token_refreshed=lambda nt, key=k, previous=tok: _persist_refreshed_token(key, previous, nt),
                )
                any_ok = any_ok or ok
                print(f"{'✓' if ok else '❌'} {k}: {mdl if ok else err}")
        else:
            curr = get_current_keychain_token()
            if curr:
                ok, mdl, err = send_gemini_warmup_ping(curr)
                any_ok = ok
                print(f"{'✓' if ok else '❌'} active: {mdl if ok else err}")
        sys.exit(0 if any_ok else 1)
    elif args.get_token:
        curr = get_current_keychain_token()
        if curr:
            print(curr)
            sys.exit(0)
        sys.exit(1)
    elif args.status_json:
        print(json.dumps(get_status_payload(force_refresh=args.force_refresh, cached_only=args.cached_only)))
    elif args.usage:
        curr = get_current_keychain_token()
        if not curr:
            print("\n❌ No active Antigravity session found in credential store. Please sign in first.\n")
            sys.exit(1)
        m = load_manifest()
        active_k = find_active_account_key(m, curr)
        plan_lbl = m[active_k].get('plan_label', '') if (active_k and isinstance(m.get(active_k), dict)) else ''
        usage = fetch_antigravity_usage(
            curr,
            on_token_refreshed=lambda nt: _persist_refreshed_token(active_k, curr, nt),
            saved_plan_label=plan_lbl
        )
        print_claude_cli_usage(usage)
        if not usage or not (usage.get('pools') or usage.get('daily') or usage.get('weekly')):
            sys.exit(1)
    elif args.usage_gui:
        if not open_claude_usage_window(force_refresh=args.force_refresh, quiet=args.quiet):
            sys.exit(1)
    elif args.list:
        m = load_manifest()
        curr = get_current_keychain_token()
        active_key = find_active_account_key(m, curr)
        print(f"\n🚀 GravityBar — Antigravity Accounts [{get_arch_label()}]")
        print(f"👨‍💻 Created by Rick Sanchez ({GITHUB_REPO_URL})\n")
        for k, v in m.items():
            active = " [ACTIVE]" if k == active_key else ""
            print(f" • {k}{active} (Saved: {v.get('saved_at', 'N/A') if isinstance(v, dict) else 'N/A'})")
        print()
    elif args.switch:
        if not switch_to_account(args.switch, quiet=args.quiet, restart_bundle=args.restart_bundle):
            sys.exit(1)
    elif args.save is not None:
        if not save_current_account(args.save if args.save else None, quiet=args.quiet):
            sys.exit(1)
    elif args.remove:
        if not remove_saved_account(args.remove, quiet=args.quiet):
            sys.exit(1)
    elif args.rename:
        if not rename_saved_account(args.rename[0], args.rename[1]):
            sys.exit(1)
    elif args.pin:
        if not pin_saved_account(args.pin, pinned=True):
            sys.exit(1)
    elif args.unpin:
        if not pin_saved_account(args.unpin, pinned=False):
            sys.exit(1)
    elif args.set_plan:
        if not set_account_plan(args.set_plan[0], args.set_plan[1]):
            sys.exit(1)
    elif args.prepare_add_login:
        if not prepare_add_account_login():
            sys.exit("Could not restart Antigravity for sign-in.")
    elif args.wizard:
        add_account_wizard()
    elif args.logout:
        logout_and_add_account()
    elif args.github:
        open_github()
    elif args.about:
        show_about()
    else:
        main_menu()
