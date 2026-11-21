#!/usr/bin/env python3
import base64
import datetime
import io
import json
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import switcher_core as sc
import install_extension


def make_fake_token(access_tok="ya29.initial", refresh_tok="1//refresh_abc"):
    payload = json.dumps({"token": {"access_token": access_tok, "refresh_token": refresh_tok}}).encode("utf-8")
    return "go-keyring-base64:" + base64.b64encode(payload).decode("ascii")


class FakeHTTPResponse:
    def __init__(self, body_dict):
        self._data = json.dumps(body_dict).encode("utf-8")

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class SwitcherCoreTestSuite(unittest.TestCase):
    def setUp(self):
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmpdir_obj.name
        self.acct_dir = os.path.join(self.tmpdir, "accounts")
        self.outside_dir = os.path.join(self.tmpdir, "outside")
        os.makedirs(self.acct_dir, exist_ok=True)
        os.makedirs(self.outside_dir, exist_ok=True)

        self.orig_dir = sc.ACCOUNTS_DIR
        self.orig_man = sc.MANIFEST_PATH
        self.orig_dash = sc.USAGE_DASHBOARD_PATH
        sc.ACCOUNTS_DIR = self.acct_dir
        sc.MANIFEST_PATH = os.path.join(self.acct_dir, "manifest.json")
        sc.USAGE_DASHBOARD_PATH = os.path.join(self.acct_dir, "usage_dashboard.html")

        self.store = {}
        self.orig_get = sc.get_credential_secret
        self.orig_set = sc.set_credential_secret
        self.orig_del = sc.delete_credential_secret
        self.orig_alert = sc.ui_alert
        self.orig_notify = sc.notify
        self.orig_sound = sc.play_sound
        self.orig_restart = sc.restart_antigravity

        self.alerts = []
        self.notifies = []
        self.sounds = []
        self.restarts = []

        sc.get_credential_secret = lambda svc, acct: self.store.get((svc, acct))
        sc.set_credential_secret = lambda svc, acct, sec, label=None: (self.store.__setitem__((svc, acct), sec) or (True, ""))
        sc.delete_credential_secret = lambda svc, acct: (self.store.pop((svc, acct), None) is not None)
        sc.ui_alert = lambda *a, **k: self.alerts.append(a)
        sc.notify = lambda *a, **k: self.notifies.append(a)
        sc.play_sound = lambda *a, **k: self.sounds.append(a)
        sc.restart_antigravity = lambda: self.restarts.append(True) or True

    def tearDown(self):
        sc.ACCOUNTS_DIR = self.orig_dir
        sc.MANIFEST_PATH = self.orig_man
        sc.USAGE_DASHBOARD_PATH = self.orig_dash
        sc.get_credential_secret = self.orig_get
        sc.set_credential_secret = self.orig_set
        sc.delete_credential_secret = self.orig_del
        sc.ui_alert = self.orig_alert
        sc.notify = self.orig_notify
        sc.play_sound = self.orig_sound
        sc.restart_antigravity = self.orig_restart
        self.tmpdir_obj.cleanup()

    def test_resolve_safe_account_path_and_secret_id(self):
        inside = os.path.join(self.acct_dir, "acct.token")
        outside = os.path.join(self.outside_dir, "secret.txt")
        with open(inside, "w") as f:
            f.write("t")
        with open(outside, "w") as f:
            f.write("do_not_touch")
        sym_out = os.path.join(self.acct_dir, "sym_out.token")
        sym_in = os.path.join(self.acct_dir, "sym_in.token")
        os.symlink(outside, sym_out)
        os.symlink(inside, sym_in)

        self.assertEqual(sc.resolve_safe_account_path(inside), os.path.realpath(inside))
        self.assertIsNone(sc.resolve_safe_account_path(os.path.join(self.acct_dir, "..", "outside", "secret.txt")))
        self.assertIsNone(sc.resolve_safe_account_path(outside))
        self.assertIsNone(sc.resolve_safe_account_path(self.acct_dir))
        self.assertIsNone(sc.resolve_safe_account_path(sym_out))
        self.assertIsNone(sc.resolve_safe_account_path(sym_in))
        self.assertIsNone(sc.resolve_safe_account_path(""))
        self.assertIsNone(sc.resolve_safe_account_path(None))

        sid1 = sc.make_secret_id("user@example.invalid")
        sid2 = sc.make_secret_id("user@example.invalid", existing_ids={sid1})
        self.assertTrue(sc.validate_secret_id(sid1))
        self.assertTrue(sc.validate_secret_id(sid2))
        self.assertNotEqual(sid1, sid2)
        for bad in ["", None, "../etc", "acct_123", "acct_$(id)", "acct_" + "Z" * 16]:
            self.assertFalse(sc.validate_secret_id(bad))

    def test_legacy_migration_and_permissions(self):
        os.chmod(self.acct_dir, 0o755)
        legacy_tf = os.path.join(self.acct_dir, "valid@example.invalid.token")
        legacy_tok = make_fake_token("ya29.leg", "1//rf_leg")
        with open(legacy_tf, "w") as f:
            f.write(legacy_tok)
        os.chmod(legacy_tf, 0o644)

        outside = os.path.join(self.outside_dir, "outside.token")
        with open(outside, "w") as f:
            f.write("keep_me")
        sym_out = os.path.join(self.acct_dir, "sym_out.token")
        os.symlink(outside, sym_out)

        seed = {
            "valid@example.invalid": {"label": "valid@example.invalid", "email": "valid@example.invalid", "token_file": legacy_tf, "saved_at": "2026-01-01 00:00:00"},
            "evil_traversal": {"label": "evil_traversal", "email": "e@x.com", "token_file": outside},
            "evil_symlink": {"label": "evil_symlink", "email": "s@x.com", "token_file": sym_out},
        }
        with open(sc.MANIFEST_PATH, "w") as f:
            json.dump(seed, f)
        os.chmod(sc.MANIFEST_PATH, 0o644)

        migrated = sc.load_manifest(migrate=True)
        self.assertEqual(stat.S_IMODE(os.stat(self.acct_dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(sc.MANIFEST_PATH).st_mode), 0o600)
        v = migrated["valid@example.invalid"]
        self.assertNotIn("token_file", v)
        self.assertTrue(sc.validate_secret_id(v["secret_id"]))
        self.assertEqual(self.store[(sc.KEYCHAIN_SAVED_SERVICE, v["secret_id"])], legacy_tok)
        self.assertFalse(os.path.exists(legacy_tf))
        self.assertTrue(os.path.exists(outside))
        self.assertTrue(os.path.islink(sym_out))

    def test_html_dashboard_xss_csp_light_mode(self):
        xss = '</script><script>alert(1)</script><img src=x onerror=alert(2)>'
        evil_key = 'evil"</script><script>alert(3)</script>'
        data = {
            evil_key: {
                "email": xss,
                "tier": "",
                "daily": {"used_pct": 30, "remaining_pct": 70, "resets_in": "2h", "reset_time": "Today", "reset_iso": ""},
                "weekly": {"used_pct": 20, "remaining_pct": 80, "resets_in": "3d", "reset_time": "Fri", "reset_iso": ""},
                "pools": [{"name": "<img src=x onerror=alert(9)>", "used_pct": 30, "resets_in": "2h", "reset_time": "Today"}],
            }
        }
        path = sc.generate_claude_html_dashboard(data, evil_key)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("prefers-color-scheme: light", html)
        self.assertNotIn("218, 119, 86", html)
        self.assertNotIn("innerHTML", html)
        script_body = html.split("<script>", 1)[1].rsplit("</script>", 1)[0]
        self.assertNotIn("</script>", script_body)
        self.assertIn("\\u003c/script\\u003e", script_body)

    def test_detect_tier_name(self):
        self.assertEqual(sc._detect_tier_name({}, saved_plan_label="Custom Team"), "Custom Team")
        self.assertEqual(sc._detect_tier_name({"userTier": "PRO"}), "Antigravity Pro")
        self.assertEqual(sc._detect_tier_name({"userTier": {"displayName": "Antigravity Ultra"}}), "Antigravity Ultra")
        self.assertEqual(sc._detect_tier_name({}), "")

    def test_quota_refresh_preserves_new_active_session_and_manifest_changes(self):
        tok_old = make_fake_token("ya29.expired", "1//my_refresh")
        tok_other = make_fake_token("ya29.other", "1//other")
        self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = tok_old

        with patch.object(sc, "extract_email_from_token", return_value="user1@example.invalid"):
            self.assertTrue(sc.save_current_account(custom_label="Work", quiet=True))

        calls = []

        def fake_urlopen(req, timeout=3.5):
            calls.append(req.full_url)
            if "daily-cloudcode-pa.googleapis.com" in req.full_url:
                auth = req.headers.get("Authorization") or req.headers.get("authorization")
                if auth == "Bearer ya29.expired":
                    raise RuntimeError("401 Unauthorized")
                return FakeHTTPResponse({
                    "userTier": "PRO",
                    "models": {
                        "gemini-3-pro": {"displayName": "Gemini 3 Pro", "quotaInfo": {"remainingFraction": 0.85, "resetTime": "2099-01-01T12:00:00Z"}},
                        "claude-4-6-sonnet": {"displayName": "Claude 4.6 Sonnet", "quotaInfo": {"remainingFraction": 0.60, "resetTime": "2099-01-05T12:00:00Z"}},
                    },
                })
            if "oauth2.googleapis.com/token" in req.full_url:
                self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = tok_other
                self.assertTrue(sc.pin_saved_account("Work"))
                return FakeHTTPResponse({"access_token": "ya29.fresh_token", "expires_in": 3600})
            raise AssertionError(f"Unexpected URL: {req.full_url}")

        with patch.object(sc.urllib.request, "urlopen", side_effect=fake_urlopen):
            payload = sc.get_status_payload(force_refresh=True, cached_only=False)

        self.assertEqual(payload["accounts"][0]["usage"]["tier"], "Antigravity Pro")
        m = sc.load_manifest(migrate=False)
        sid = m["Work"]["secret_id"]
        saved_tok = self.store[(sc.KEYCHAIN_SAVED_SERVICE, sid)]
        active_tok = self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)]
        self.assertNotEqual(saved_tok, tok_old)
        self.assertEqual(active_tok, tok_other)
        self.assertTrue(m["Work"]["pinned"])
        decoded = json.loads(base64.b64decode(saved_tok.split("go-keyring-base64:", 1)[1]).decode("utf-8"))
        self.assertEqual(decoded["token"]["access_token"], "ya29.fresh_token")
        self.assertEqual(m["Work"]["token_sha256"], sc.compute_token_sha256(saved_tok))

    def test_failed_remove_preserves_saved_credential(self):
        token = make_fake_token()
        self.assertTrue(sc._save_token_directly(token, "work@example.invalid", "Work")[0])
        with patch.object(sc, "save_manifest", side_effect=OSError("Mock write failure")):
            self.assertFalse(sc.remove_saved_account("Work", quiet=True))
        self.assertEqual(sc.get_account_token(sc.load_manifest(migrate=False)["Work"]), token)

    def test_corrupt_manifest_is_preserved_when_saving_account(self):
        path = Path(sc.MANIFEST_PATH)
        path.write_text('{"incomplete":', encoding='utf-8')
        self.assertFalse(sc._save_token_directly(make_fake_token(), "work@example.invalid", "Work")[0])
        self.assertEqual(path.read_text(encoding='utf-8'), '{"incomplete":')
        self.assertEqual(self.store, {})

    def test_extension_registry_preserves_peers_and_rolls_back_failed_registration(self):
        source = Path(self.tmpdir) / "extension-source"
        extensions = Path(self.tmpdir) / "extensions"
        source.mkdir()
        extensions.mkdir()
        package = {"publisher": "m4tinbeigi", "name": "gravitybar", "version": "1.2.0"}
        (source / "package.json").write_text(json.dumps(package), encoding="utf-8")
        script = source / "extension.js"
        script.write_text("new code", encoding="utf-8")
        target = extensions / "m4tinbeigi.gravitybar-1.2.0-arm64"
        target.mkdir()
        (target / "extension.js").write_text("old code", encoding="utf-8")
        registry = extensions / "extensions.json"

        registry.write_text("broken registry", encoding="utf-8")
        with self.assertRaises(ValueError):
            install_extension.register_extension(source, extensions)
        self.assertEqual(registry.read_text(encoding="utf-8"), "broken registry")
        self.assertEqual((target / "extension.js").read_text(encoding="utf-8"), "old code")

        peer = {"identifier": {"id": "other.extension"}, "version": "4.0.0"}
        registry.write_text(json.dumps([peer]), encoding="utf-8")
        with patch.object(install_extension.os, "replace", side_effect=OSError("simulated registry failure")):
            with self.assertRaises(OSError):
                install_extension.register_extension(source, extensions)
        self.assertEqual((target / "extension.js").read_text(encoding="utf-8"), "old code")
        self.assertEqual(json.loads(registry.read_text(encoding="utf-8")), [peer])

        install_extension.register_extension(source, extensions)
        install_extension.register_extension(source, extensions)
        self.assertEqual((target / "extension.js").read_text(encoding="utf-8"), "new code")
        entries = json.loads(registry.read_text(encoding="utf-8"))
        self.assertEqual(len(entries), 2)
        self.assertIn(peer, entries)
        self.assertEqual(entries[1]["version"], "1.2.0")

    def test_reused_label_preserves_other_account(self):
        original = make_fake_token()
        other = make_fake_token("ya29.other", "1//other")
        self.assertTrue(sc._save_token_directly(original, "work@example.invalid", "Work")[0])
        self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = other
        with patch.object(sc, "extract_email_from_token", return_value="other@example.invalid"):
            self.assertFalse(sc.save_current_account("Work", quiet=True))
        self.assertFalse(sc._save_token_directly(other, "other@example.invalid", "Work")[0])
        self.assertEqual(sc.get_account_token(sc.load_manifest(migrate=False)["Work"]), original)

    def test_missing_quota_windows_are_not_reported_as_full(self):
        weekly = {"groups": [{
            "displayName": "Gemini Models",
            "buckets": [{"window": "weekly", "remainingFraction": 0.42}],
        }]}
        for summary, weekly_remaining in (({"groups": []}, None), (weekly, 42)):
            with self.subTest(summary=summary):
                def post(method, *_args, **_kwargs):
                    return 200, summary if method == "retrieveUserQuotaSummary" else {}

                with patch.object(sc, "_post_cloudcode", side_effect=post):
                    usage = sc.fetch_antigravity_usage(make_fake_token(), known_email="work@example.invalid")
                self.assertIsNone(usage["daily"])
                self.assertEqual(usage["weekly"] and usage["weekly"]["remaining_pct"], weekly_remaining)
                output = io.StringIO()
                with patch("sys.stdout", output):
                    sc.print_claude_cli_usage(usage)
                self.assertIn("Quota unavailable", output.getvalue())

    def test_official_login_times_out_when_cli_never_prints_a_url(self):
        program = os.path.join(self.tmpdir, "agy")
        with open(program, "w") as handle:
            handle.write("#!/bin/sh\nexec sleep 1\n")
        os.chmod(program, 0o700)
        start = time.monotonic()
        with patch.object(sc, "find_agy_executable", return_value=program):
            with self.assertRaisesRegex(RuntimeError, "authorization link"):
                sc.agy_cli_login(timeout_secs=0.1)
        self.assertLess(time.monotonic() - start, 0.75)

    def test_official_login_times_out_when_child_inherits_stdout(self):
        program = Path(self.tmpdir) / "agy"
        program.write_text("#!/usr/bin/python3\nimport os, time\nif os.fork() == 0:\n    time.sleep(1.5)\n")
        program.chmod(0o700)
        start = time.monotonic()
        with patch.object(sc, "find_agy_executable", return_value=str(program)):
            with self.assertRaisesRegex(RuntimeError, "authorization link"):
                sc.agy_cli_login(timeout_secs=0.1)
        self.assertLess(time.monotonic() - start, 1)

    def test_official_login_reads_only_the_temporary_profile(self):
        program = Path(self.tmpdir) / "agy"
        program.write_text(
            "#!/usr/bin/python3\n"
            "import os\nfrom pathlib import Path\n"
            "print('https://accounts.google.com/fixture', flush=True)\n"
            "if input() == 'test-code':\n"
            "    p = Path(os.environ['GEMINI_HOME']) / 'antigravity-acp/acp_token.json'\n"
            "    p.write_text('{\"access_token\": \"test-access\"}')\n"
        )
        program.chmod(0o700)
        existing = make_fake_token()
        self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = existing
        with patch.object(sc, "find_agy_executable", return_value=str(program)), \
             patch.object(sc, "open_url", return_value=True), \
             patch.object(sc, "ui_input", return_value="test-code"), \
             patch.object(sc, "extract_email_from_token", return_value="new@example.invalid"):
            token, email = sc.agy_cli_login(timeout_secs=2)
        self.assertEqual(email, "new@example.invalid")
        self.assertEqual(json.loads(base64.b64decode(token.split(":", 1)[1]))["token"]["access_token"], "test-access")
        self.assertEqual(sc.get_current_keychain_token(), existing)

    def test_desktop_sign_in_cancel_restores_previous_credential(self):
        token = make_fake_token()
        self.assertTrue(sc._save_token_directly(token, "work@example.invalid", "Work")[0])
        self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = token
        with patch.object(sc, "find_agy_executable", return_value=None), \
             patch.object(sc, "ui_confirm", side_effect=["Start Login", "Cancel"]):
            sc.add_account_wizard()
        self.assertEqual(sc.get_current_keychain_token(), token)

    def test_dashboard_reports_when_no_quota_is_available(self):
        status = {"accounts": [], "active_key": None, "active_session_unsaved": False}
        with patch.object(sc, "get_status_payload", return_value=status):
            self.assertFalse(sc.open_claude_usage_window(quiet=True))

    def test_pin_plan_rename_remove_best_candidate_and_quiet(self):
        t1 = make_fake_token("ya29.a", "1//ra")
        t2 = make_fake_token("ya29.b", "1//rb")
        with patch.object(sc, "extract_email_from_token", side_effect=["a@example.invalid", "b@example.invalid"]):
            self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = t1
            self.assertTrue(sc.save_current_account(custom_label="Acct A", quiet=True))
            self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = t2
            self.assertTrue(sc.save_current_account(custom_label="Acct B", quiet=True))

        self.assertTrue(sc.pin_saved_account("Acct A", pinned=True))
        self.assertTrue(sc.set_account_plan("Acct A", "Antigravity Pro"))
        self.assertTrue(sc.rename_saved_account("Acct A", "Acct A Pinned"))
        m = sc.load_manifest(migrate=False)
        self.assertTrue(m["Acct A Pinned"]["pinned"])
        self.assertEqual(m["Acct A Pinned"]["plan_label"], "Antigravity Pro")

        # Save again on same key preserves pinned & plan_label
        self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = t1
        with patch.object(sc, "extract_email_from_token", return_value="a@example.invalid"):
            self.assertTrue(sc.save_current_account(custom_label="Acct A Pinned", quiet=True))
        m2 = sc.load_manifest(migrate=False)
        self.assertTrue(m2["Acct A Pinned"]["pinned"])
        self.assertEqual(m2["Acct A Pinned"]["plan_label"], "Antigravity Pro")

        # Best candidate logic
        accounts_out = [
            {"key": "Acct A Pinned", "usage": {"daily": {"remaining_pct": 12.0}, "weekly": {"remaining_pct": 80.0}}},
            {"key": "Acct B", "usage": {"daily": {"remaining_pct": 92.0}, "weekly": {"remaining_pct": 95.0}}},
        ]
        self.assertEqual(sc.compute_best_switch_candidate(accounts_out, "Acct A Pinned"), "Acct B")
        self.assertIsNone(sc.compute_best_switch_candidate(accounts_out, "Acct B"))

        self.assertTrue(sc.switch_to_account("Acct A Pinned", quiet=True))
        self.assertEqual(self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)], t1)
        self.assertEqual(len(self.restarts), 1)
        self.assertFalse(self.alerts or self.notifies or self.sounds)

        self.assertTrue(sc.remove_saved_account("Acct B", quiet=True))
        self.assertNotIn("Acct B", sc.load_manifest(migrate=False))

    def test_restart_antigravity_graceful_and_fallback(self):
        if not sc.IS_MACOS:
            return
        sc.restart_antigravity = self.orig_restart
        calls = []
        poll = [0]

        def any_running_once(checks):
            poll[0] += 1
            return poll[0] == 1

        with patch.object(sc, "_any_process_running", side_effect=any_running_once), \
             patch.object(sc, "osascript", side_effect=lambda s, args=None: calls.append(("osascript", args)) or ""), \
             patch.object(sc, "run_cmd", side_effect=lambda cmd, input_text=None: calls.append(("run_cmd", list(cmd))) or (0, "", "")), \
             patch("time.sleep", return_value=None):
            sc.restart_antigravity()

        self.assertTrue(any(c[0] == "osascript" for c in calls))
        self.assertFalse(any(c[0] == "run_cmd" and c[1][0] == "pkill" and "-9" in c[1] for c in calls))

        calls_hang = []
        ticks = [0.0]

        def fake_time():
            ticks[0] += 2.0
            return ticks[0]

        with patch.object(sc, "_any_process_running", return_value=True), \
             patch.object(sc, "osascript", side_effect=lambda s, args=None: calls_hang.append(("osascript", args)) or ""), \
             patch.object(sc, "run_cmd", side_effect=lambda cmd, input_text=None: calls_hang.append(("run_cmd", list(cmd))) or (0, "", "")), \
             patch("time.time", side_effect=fake_time), \
             patch("time.sleep", return_value=None):
            sc.restart_antigravity()

        pkill9 = [c[1] for c in calls_hang if c[0] == "run_cmd" and c[1][0] == "pkill" and "-9" in c[1]]
        self.assertGreaterEqual(len(pkill9), 2)
        for cmd in pkill9:
            self.assertTrue(cmd[-1].startswith("^") and "Antigravity" in cmd[-1])

    def test_switch_reports_restart_failure_after_setting_credential(self):
        token = make_fake_token()
        self.assertTrue(sc._save_token_directly(token, "work@example.invalid", "Work")[0])
        with patch.object(sc, "restart_antigravity", return_value=False), patch("sys.stderr", io.StringIO()) as errors:
            self.assertFalse(sc.switch_to_account("Work", quiet=True))
        self.assertEqual(sc.get_current_keychain_token(), token)
        self.assertIn("active credential was updated", errors.getvalue())

    def test_switch_restarts_the_requesting_ide_bundle(self):
        token = make_fake_token()
        self.assertTrue(sc._save_token_directly(token, "work@example.invalid", "Work")[0])
        bundle = Path(self.tmpdir) / "Antigravity IDE.app"
        contents = bundle / "Contents"
        contents.mkdir(parents=True)
        info = contents / "Info.plist"
        info.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.google.antigravity-ide"}))
        with patch.object(sc, "restart_antigravity", return_value=True) as restart:
            self.assertTrue(sc.switch_to_account("Work", quiet=True, restart_bundle=str(bundle)))
            restart.assert_called_once_with(str(bundle.resolve()))

        info.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.example.other"}))
        self.store.pop((sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT))
        self.assertFalse(sc.switch_to_account("Work", quiet=True, restart_bundle=str(bundle)))
        self.assertIsNone(sc.get_current_keychain_token())

    def test_macos_isolated_keychain_and_large_secret(self):
        if not sc.IS_MACOS:
            return
        kc_path = os.path.join(self.tmpdir, "isolated.keychain-db")
        subprocess.run(["/usr/bin/security", "create-keychain", "-p", "testpass", kc_path], check=True)
        subprocess.run(["/usr/bin/security", "unlock-keychain", "-p", "testpass", kc_path], check=True)

        recorded = []
        orig_rc = sc.run_cmd

        def spy(cmd, input_text=None):
            recorded.append((list(cmd), input_text))
            return orig_rc(cmd, input_text=input_text)

        sec1 = make_fake_token("ya29.k1", "1//r1")
        sec2 = make_fake_token("ya29.k2", "1//r2")
        with patch.object(sc, "run_cmd", side_effect=spy):
            ok1, err1 = sc._macos_keychain_set("ag-test", "acct_0123456789abcdef", sec1, keychain_path=kc_path)
            ok2, err2 = sc._macos_keychain_set("ag-test", "acct_0123456789abcdef", sec2, keychain_path=kc_path)
        self.assertTrue(ok1, err1)
        self.assertTrue(ok2, err2)
        for cmd, inp in recorded:
            self.assertEqual(cmd, ["/usr/bin/security", "-i"])
            self.assertNotIn(sec1, " ".join(cmd))
            self.assertNotIn(sec2, " ".join(cmd))
            self.assertIsNotNone(inp)

        rb = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-s", "ag-test", "-a", "acct_0123456789abcdef", "-w", kc_path],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(rb.stdout.strip(), sec2)

        with patch.object(sc, "_macos_keychain_set_ctypes", return_value=(True, "")) as mock_ct:
            ok_big, _ = sc._macos_keychain_set("ag-test", "acct_0123456789abcdef", "go-keyring-base64:" + ("A" * 3900))
        self.assertTrue(ok_big)
        self.assertEqual(mock_ct.call_count, 1)

    def test_retrieve_user_quota_summary_5h_weekly_and_argon(self):
        tok = make_fake_token("ya29.valid", "1//rf_tok")
        seen_headers = {}

        def fake_urlopen(req, timeout=3.5):
            ua = req.headers.get("User-agent") or req.headers.get("User-Agent") or ""
            if "retrieveUserQuotaSummary" in req.full_url:
                seen_headers["summary_ua"] = ua
                return FakeHTTPResponse({
                    "groups": [
                        {
                            "displayName": "Gemini Models",
                            "description": "Models within this group: Gemini 3.8 Flash",
                            "buckets": [
                                {"bucketId": "gemini-weekly", "displayName": "Weekly Limit Remaining", "window": "weekly", "resetTime": "2099-01-07T00:00:00Z", "remainingFraction": 0.79},
                                {"bucketId": "gemini-5h", "displayName": "Five Hour Limit Remaining", "window": "5h", "resetTime": "2099-01-01T05:00:00Z", "remainingFraction": 0.67},
                            ],
                        },
                        {
                            "displayName": "Claude and GPT models",
                            "description": "Models within this group: Claude Opus 5.5, Claude Sonnet 5.5, GPT-OSS 120B",
                            "buckets": [
                                {"bucketId": "3p-weekly", "displayName": "Weekly Limit Remaining", "window": "weekly", "resetTime": "2099-01-07T00:00:00Z", "remainingFraction": 1.0},
                                {"bucketId": "3p-5h", "displayName": "Five Hour Limit Remaining", "window": "5h", "resetTime": "2099-01-01T05:00:00Z", "remainingFraction": 1.0},
                            ],
                        },
                        {
                            "displayName": "Gemini 4 Argon",
                            "buckets": [
                                {"bucketId": "gemini-argon-wtu-weekly", "displayName": "Gemini 4 Argon Weekly Limit", "window": "weekly", "resetTime": "2099-01-07T22:00:00Z", "remainingFraction": 0.87},
                            ],
                        },
                    ]
                })
            if "fetchAvailableModels" in req.full_url:
                seen_headers["models_ua"] = ua
                return FakeHTTPResponse({"models": {}})
            if "loadCodeAssist" in req.full_url:
                seen_headers["lca_ua"] = ua
                return FakeHTTPResponse({
                    "currentTier": {"id": "free-tier", "name": "Antigravity"},
                    "paidTier": {"id": "g1-pro-tier", "name": "Google AI Pro"},
                })
            raise AssertionError(f"Unexpected URL: {req.full_url}")

        with patch.object(sc.urllib.request, "urlopen", side_effect=fake_urlopen):
            usage = sc.fetch_antigravity_usage(tok, known_email="user@example.invalid")

        self.assertIsNotNone(usage)
        self.assertTrue(seen_headers.get("summary_ua", "").startswith("antigravity/hub/"))
        self.assertTrue(seen_headers.get("models_ua", "").startswith("antigravity/hub/"))
        self.assertEqual(usage["tier"], "Google AI Pro")
        self.assertEqual(usage["daily"]["window_label"], "5h limit")
        self.assertAlmostEqual(usage["daily"]["remaining_pct"], 67.0)
        self.assertEqual(usage["weekly"]["window_label"], "Weekly limit")
        self.assertAlmostEqual(usage["weekly"]["remaining_pct"], 79.0)
        names = [p["name"] for p in usage["pools"]]
        self.assertEqual(
            names,
            [
                "Gemini Models — 5h limit",
                "Gemini Models — Weekly limit",
                "Claude and GPT models — 5h limit",
                "Claude and GPT models — Weekly limit",
                "Gemini 4 Argon — Weekly limit",
            ],
        )
        argon = next(p for p in usage["pools"] if "Argon" in p["name"])
        self.assertAlmostEqual(argon["remaining_pct"], 87.0)
        self.assertEqual(argon["window_label"], "Weekly limit")

    def test_exhausted_omitted_fraction_and_gcp_tos_routing(self):
        tok = make_fake_token("ya29.valid", "1//rf_tok")
        urls = []

        def fake_urlopen(req, timeout=3.5):
            urls.append(req.full_url)
            if "loadCodeAssist" in req.full_url:
                return FakeHTTPResponse({
                    "cloudaicompanionProject": {"id": "my-gcp-proj"},
                    "currentTier": {"id": "standard-tier", "usesGcpTos": True},
                })
            if "retrieveUserQuotaSummary" in req.full_url:
                return FakeHTTPResponse({
                    "groups": [{
                        "buckets": [
                            {"bucketId": "gemini-5h", "window": "5h"},
                            {"bucketId": "gemini-argon-wtu-weekly", "window": "weekly", "remainingFraction": 0.5},
                        ]
                    }]
                })
            if "fetchAvailableModels" in req.full_url:
                return FakeHTTPResponse({"models": {}})
            raise AssertionError(f"Unexpected URL: {req.full_url}")

        with patch.object(sc.urllib.request, "urlopen", side_effect=fake_urlopen):
            usage = sc.fetch_antigravity_usage(tok, known_email="user@example.invalid")

        self.assertIsNotNone(usage)
        self.assertTrue(any(u.startswith("https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary") for u in urls))
        self.assertAlmostEqual(usage["daily"]["remaining_pct"], 0.0)
        argon = next(p for p in usage["pools"] if "Argon" in p["name"])
        self.assertEqual(argon["group_name"], "Gemini 4 Argon")
        self.assertAlmostEqual(argon["remaining_pct"], 50.0)

    def test_agy_cli_env_and_normalize_credential(self):
        env = sc._build_agy_login_env(
            {"PATH": "/usr/bin", "GEMINI_API_KEY": "bad", "DISPLAY": ":0"},
            "/tmp/ag_prof",
            "/tmp/ag_prof/tmp",
        )
        self.assertNotIn("GEMINI_API_KEY", env)
        self.assertNotIn("DISPLAY", env)
        self.assertEqual(env["AGY_ACP_FORCE_FILE_STORAGE"], "1")
        self.assertTrue(env["SSH_CONNECTION"])
        self.assertEqual(env["GEMINI_HOME"], "/tmp/ag_prof")

        flat_norm = sc._normalize_official_credential(
            json.dumps({"access_token": "ya29.flat", "refresh_token": "1//rf"}),
            fallback_email="second@example.invalid",
        )
        self.assertIsNotNone(flat_norm)
        self.assertTrue(flat_norm.startswith("go-keyring-base64:"))

        ok, saved_key = sc._save_token_directly(flat_norm, "second@example.invalid", custom_label="Second")
        self.assertTrue(ok)
        self.assertEqual(saved_key, "Second")
        m = sc.load_manifest(migrate=False)
        self.assertIn("Second", m)
        self.assertEqual(self.store[(sc.KEYCHAIN_SAVED_SERVICE, m["Second"]["secret_id"])], flat_norm)

    def test_find_active_account_matches_rotated_token(self):
        saved_tok = "go-keyring-base64:" + base64.b64encode(json.dumps({
            "token": {"access_token": "ya29.old", "refresh_token": "1//same_rf"},
            "id_token_email": "rotated-account@example.invalid",
        }).encode("utf-8")).decode("ascii")
        rotated_tok = "go-keyring-base64:" + base64.b64encode(json.dumps({
            "token": {"access_token": "ya29.refreshed_by_ide", "refresh_token": "1//same_rf"},
            "id_token_email": "rotated-account@example.invalid",
        }).encode("utf-8")).decode("ascii")

        self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = saved_tok
        with patch.object(sc, "extract_email_from_token", return_value="rotated-account@example.invalid"):
            self.assertTrue(sc.save_current_account(custom_label="rotated-account@example.invalid", quiet=True))
        # Simulate Antigravity refreshing active access token in Keychain
        self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = rotated_tok
        manifest = sc.load_manifest(migrate=False)
        self.assertEqual(sc.find_active_account_key(manifest, rotated_tok), "rotated-account@example.invalid")
        status = sc.get_status_payload(cached_only=True)
        self.assertEqual(status["active_key"], "rotated-account@example.invalid")
        self.assertFalse(status["active_session_unsaved"])

    def test_select_warmup_gemini_model_and_ping(self):
        with_hydrogen = {
            "models": {
                "gemini-3.8-flash-low": {"displayName": "Gemini 3.8 Flash", "quotaInfo": {}},
                "gemini-4-hydrogen": {"displayName": "Gemini 4 Hydrogen", "quotaInfo": {}},
                "claude-opus-5-5": {"displayName": "Claude Opus 5.5", "quotaInfo": {}},
            }
        }
        self.assertEqual(sc.select_warmup_gemini_model(with_hydrogen), ("gemini-4-hydrogen", "Gemini 4 Hydrogen"))

        without_hydrogen = {
            "models": {
                "gemini-3.8-flash": {"displayName": "Gemini 3.8 Flash", "quotaInfo": {}},
                "gemini-4-argon": {"displayName": "Gemini 4 Argon", "quotaInfo": {}},
            }
        }
        self.assertEqual(sc.select_warmup_gemini_model(without_hydrogen), ("gemini-3.8-flash", "Gemini 3.8 Flash"))

        tok = make_fake_token("ya29.warm", "1//rf_warm")
        seen_gen = []

        def fake_urlopen(req, timeout=3.5):
            if "loadCodeAssist" in req.full_url:
                return FakeHTTPResponse({"cloudaicompanionProject": "proj-123"})
            if "fetchAvailableModels" in req.full_url:
                return FakeHTTPResponse(with_hydrogen)
            if "v1internal:generateContent" in req.full_url:
                body = json.loads(req.data.decode("utf-8"))
                seen_gen.append(body)
                return FakeHTTPResponse({"response": {"candidates": [{"content": {"parts": [{"text": "ok"}]}}]}})
            raise AssertionError(f"Unexpected URL: {req.full_url}")

        with patch.object(sc.urllib.request, "urlopen", side_effect=fake_urlopen):
            ok, model_disp, err = sc.send_gemini_warmup_ping(tok)

        self.assertTrue(ok, err)
        self.assertEqual(model_disp, "Gemini 4 Hydrogen")
        self.assertIsNone(err)
        self.assertEqual(len(seen_gen), 1)
        self.assertEqual(seen_gen[0]["model"], "gemini-4-hydrogen")
        self.assertEqual(seen_gen[0]["project"], "proj-123")
        self.assertEqual(seen_gen[0]["request"]["generationConfig"]["maxOutputTokens"], 1)

    def test_warmup_uses_advertised_flash_low_after_hydrogen_rejection(self):
        token = make_fake_token()
        attempted = []

        def post(endpoint, access_token, payload, **kwargs):
            if endpoint == "loadCodeAssist":
                return 200, {"cloudaicompanionProject": "test-project"}
            if endpoint == "fetchAvailableModels":
                return 200, {"models": {
                    "gemini-4-hydrogen": {"displayName": "Gemini 4 Hydrogen"},
                    "gemini-3.8-flash": {"displayName": "Gemini 3.8 Flash"},
                    "gemini-3.8-flash-low": {"displayName": "Gemini 3.8 Flash (Low)"},
                }}
            attempted.append(payload["model"])
            if payload["model"] == "gemini-3.8-flash-low":
                return 200, {"response": {"candidates": [{"finishReason": "MAX_TOKENS"}]}}
            return 400, {"error": {"message": "Model unavailable"}}

        with patch.object(sc, "_post_cloudcode", side_effect=post):
            ok, model, error = sc.send_gemini_warmup_ping(token)

        self.assertTrue(ok, error)
        self.assertEqual(model, "Gemini 3.8 Flash (Low)")
        self.assertEqual(attempted, ["gemini-4-hydrogen", "gemini-3.8-flash-low"])

    def test_warmup_recognizes_successful_event_stream(self):
        class EventStream(FakeHTTPResponse):
            def read(self):
                return b'data: {"response":{"candidates":[{"finishReason":"STOP"}]}}\n\n'

        def urlopen(request, timeout):
            if request.full_url.endswith(":loadCodeAssist"):
                return FakeHTTPResponse({})
            if request.full_url.endswith(":fetchAvailableModels"):
                return FakeHTTPResponse({"models": {"gemini-4-hydrogen": {}}})
            if request.full_url.endswith(":streamGenerateContent?alt=sse"):
                return EventStream({})
            raise sc.urllib.error.HTTPError(request.full_url, 405, "Mock", {}, None)

        with patch.object(sc.urllib.request, "urlopen", side_effect=urlopen):
            ok, _, error = sc.send_gemini_warmup_ping(make_fake_token())

        self.assertTrue(ok, error)

    def test_warmup_stops_on_rate_limit_or_ambiguous_response(self):
        for reply in ((429, None), (-1, None), (200, {"error": {"message": "Unknown"}})):
            with self.subTest(status=reply[0]):
                attempted = []

                def post(endpoint, access_token, payload, **kwargs):
                    if endpoint == "loadCodeAssist":
                        return 200, {}
                    if endpoint == "fetchAvailableModels":
                        return 200, {"models": {"gemini-4-hydrogen": {}, "gemini-3.8-flash-low": {}}}
                    attempted.append(payload["model"])
                    return reply

                with patch.object(sc, "_post_cloudcode", side_effect=post):
                    ok, _, _ = sc.send_gemini_warmup_ping(make_fake_token())

                self.assertFalse(ok)
                self.assertEqual(attempted, ["gemini-4-hydrogen"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
