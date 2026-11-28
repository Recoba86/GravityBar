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


AGY_QUOTA_SAMPLE = {
    "conversation_id": "", "status": "SUCCESS", "response": "",
    "command": {"name": "usage", "data": {"groups": [
        {"name": "Gemini Models", "description": "Models within this group: Gemini 4 Hydrogen, Gemini 3.8 Flash", "buckets": [
            {"id": "gemini-weekly", "name": "Weekly Limit Remaining", "window": "weekly", "remaining_fraction": 0.56, "reset_time": "2099-12-03T12:58:36Z"},
            {"id": "gemini-5h", "name": "Five Hour Limit Remaining", "window": "5h", "remaining_fraction": 0.58, "reset_time": "2099-11-28T16:24:52Z"}]},
        {"name": "Claude and GPT models", "buckets": [
            {"id": "3p-weekly", "name": "Weekly Limit Remaining", "window": "weekly", "remaining_fraction": 1, "reset_time": "1970-01-01T00:00:00Z"},
            {"id": "3p-5h", "name": "Five Hour Limit Remaining", "window": "5h", "remaining_fraction": 1, "reset_time": "1970-01-01T00:00:00Z"}]}]}},
}


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
        path = sc.generate_claude_html_dashboard(data, evil_key, {evil_key: xss})
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path, "r", encoding="utf-8") as f:
            html = f.read()
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("prefers-color-scheme: light", html)
        self.assertNotIn("218, 119, 86", html)
        self.assertNotIn("innerHTML", html)
        self.assertIn('getElementById("checkErrors").textContent', html)
        self.assertIn("Reset time passed. Check quotas again.", html)
        script_body = html.split("<script>", 1)[1].rsplit("</script>", 1)[0]
        self.assertNotIn("</script>", script_body)
        self.assertIn("\\u003c/script\\u003e", script_body)

    def test_quota_check_uses_official_cli_and_preserves_new_active_session(self):
        tok_old = make_fake_token("ya29.expired", "1//my_refresh")
        tok_other = make_fake_token("ya29.other", "1//other")
        self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = tok_old
        with patch.object(sc, "extract_email_from_token", return_value="user1@example.invalid"):
            self.assertTrue(sc.save_current_account(custom_label="Work", quiet=True))

        program = Path(self.tmpdir) / "agy"
        log = Path(self.tmpdir) / "agy.log"
        program.write_text(
            "#!/usr/bin/python3\n"
            "import json, os, sys\n"
            f"open({str(log)!r}, 'a').write(json.dumps({{'argv': sys.argv[1:], 'home': os.environ['HOME'], "
            "'browser': os.environ.get('BROWSER'), 'ssh': os.environ.get('SSH_CONNECTION'), "
            "'storage': os.environ.get('AGY_CLI_FORCE_FILE_TOKEN_STORAGE')}) + '\\n')\n"
            "p = os.path.join(os.environ['HOME'], '.gemini/antigravity-cli/antigravity-oauth-token')\n"
            "cred = json.load(open(p))\n"
            "cred['token']['access_token'] = 'ya29.fresh_token'\n"
            "json.dump(cred, open(p, 'w'))\n"
            + "print(json.dumps(" + repr(AGY_QUOTA_SAMPLE) + "))\n"
        )
        program.chmod(0o700)

        def changed_while_running(*_a):
            self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = tok_other
            self.assertTrue(sc.pin_saved_account("Work"))

        with patch.object(sc, "find_agy_executable", return_value=str(program)), \
             patch("socket.socket.connect", side_effect=AssertionError("GravityBar made a network call")):
            payload = sc.get_status_payload(force_refresh=True, on_progress=changed_while_running)

        run = json.loads(log.read_text().splitlines()[0])
        self.assertEqual(run["argv"], ["-p", "/quota", "--output-format", "json", "--print-timeout", "30s"])
        self.assertIsNone(payload["active_key"])
        self.assertTrue(run["browser"].endswith("/bin/open"))
        self.assertIsNone(run["ssh"])
        self.assertEqual(run["storage"], "1")
        self.assertFalse(os.path.exists(run["home"]))

        usage = payload["accounts"][0]["usage"]
        self.assertAlmostEqual(usage["daily"]["remaining_pct"], 58.0)
        self.assertFalse(payload["from_cache"])
        m = sc.load_manifest(migrate=False)
        saved_tok = self.store[(sc.KEYCHAIN_SAVED_SERVICE, m["Work"]["secret_id"])]
        self.assertEqual(self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)], tok_other)
        self.assertTrue(m["Work"]["pinned"])
        decoded = json.loads(base64.b64decode(saved_tok.split("go-keyring-base64:", 1)[1]).decode("utf-8"))
        self.assertEqual(decoded["token"]["access_token"], "ya29.fresh_token")
        self.assertEqual(m["Work"]["token_sha256"], sc.compute_token_sha256(saved_tok))

        cached = sc.get_status_payload(cached_only=True)
        self.assertTrue(cached["from_cache"])
        self.assertAlmostEqual(cached["accounts"][0]["usage"]["daily"]["remaining_pct"], 58.0)

    def test_quota_check_spaces_accounts_and_reports_errors(self):
        for label, rf in (("A", "1//a"), ("B", "1//b")):
            self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = make_fake_token("ya29." + label, rf)
            with patch.object(sc, "extract_email_from_token", return_value=f"{label.lower()}@example.invalid"):
                self.assertTrue(sc.save_current_account(custom_label=label, quiet=True))
        sleeps = []
        results = iter([(None, "Sign-in expired. Add this account again."), ({"pools": [], "daily": None, "weekly": None}, None)])
        with patch.object(sc, "fetch_antigravity_usage", side_effect=lambda *a, **k: next(results)), \
             patch.object(sc.time, "sleep", side_effect=sleeps.append):
            payload = sc.get_status_payload(force_refresh=True)
        self.assertEqual(sleeps, [sc.QUOTA_INTER_ACCOUNT_DELAY_SECS])
        self.assertGreaterEqual(sc.QUOTA_INTER_ACCOUNT_DELAY_SECS, 5)
        self.assertEqual(payload["errors"], {"A": "Sign-in expired. Add this account again."})

        with patch.object(sc, "fetch_antigravity_usage", side_effect=AssertionError("must not run agy")):
            sc.get_status_payload()
            sc.get_status_payload(cached_only=True)

    def test_parse_agy_quota_json(self):
        usage = sc.parse_agy_quota_json(json.dumps(AGY_QUOTA_SAMPLE), known_email="u@example.invalid", saved_plan_label="Pro")
        self.assertEqual(usage["tier"], "Pro")
        self.assertAlmostEqual(usage["daily"]["remaining_pct"], 58.0)
        self.assertAlmostEqual(usage["weekly"]["remaining_pct"], 56.0)
        claude = [p for p in usage["pools"] if p["group_name"] == "Claude and GPT models"]
        self.assertEqual([p["window_label"] for p in claude], ["5h limit", "Weekly limit"])
        self.assertTrue(all(p["remaining_pct"] == 100.0 and p["resets_in"] == "N/A" for p in claude))
        self.assertIn("Gemini 4 Hydrogen", usage["daily"]["models"])
        self.assertIsNone(sc.parse_agy_quota_json('{"status":"ERROR"}'))
        self.assertIsNone(sc.parse_agy_quota_json("Authentication required"))
        for groups in ([], [{"name": "Gemini", "buckets": []}], [{"name": 123, "buckets": 123}]):
            response = {"status": "SUCCESS", "command": {"name": "usage", "data": {"groups": groups}}}
            self.assertIsNone(sc.parse_agy_quota_json(json.dumps(response)))

    def test_quota_failure_preserves_last_successful_snapshot(self):
        token = make_fake_token()
        self.assertTrue(sc._save_token_directly(token, "work@example.invalid", "Work")[0])
        usage = sc.parse_agy_quota_json(json.dumps(AGY_QUOTA_SAMPLE))
        with patch.object(sc, "fetch_antigravity_usage", return_value=(usage, None)):
            successful = sc.get_status_payload(force_refresh=True)
        cache = Path(sc.ACCOUNTS_DIR) / "usage_cache.json"
        timestamp = cache.stat().st_mtime_ns
        with patch.object(sc, "fetch_antigravity_usage", return_value=(None, "Sign-in expired.")):
            failed = sc.get_status_payload(force_refresh=True)
        self.assertTrue(failed["from_cache"])
        self.assertEqual(failed["accounts"][0]["usage"], successful["accounts"][0]["usage"])
        self.assertEqual(cache.stat().st_mtime_ns, timestamp)
        self.assertIn("checked_at", failed["accounts"][0]["usage"])

    def test_quota_result_follows_account_renamed_during_check(self):
        self.assertTrue(sc._save_token_directly(make_fake_token(), "work@example.invalid", "Work")[0])

        def finish_after_rename(*args, **kwargs):
            self.assertTrue(sc.rename_saved_account("Work", "Renamed"))
            return sc.parse_agy_quota_json(json.dumps(AGY_QUOTA_SAMPLE)), None

        with patch.object(sc, "fetch_antigravity_usage", side_effect=finish_after_rename):
            payload = sc.get_status_payload(force_refresh=True)
        self.assertEqual([a["key"] for a in payload["accounts"]], ["Renamed"])
        cache = json.loads((Path(sc.ACCOUNTS_DIR) / "usage_cache.json").read_text())
        self.assertEqual(set(cache), {"Renamed"})

    def test_quota_cli_uses_exit_status_and_stderr(self):
        program = Path(self.tmpdir) / "agy"
        program.write_text(
            "#!/usr/bin/python3\nimport sys\n"
            "print('Authentication required', file=sys.stderr)\n"
            f"print({json.dumps(AGY_QUOTA_SAMPLE)!r})\n"
            "sys.exit(1)\n"
        )
        program.chmod(0o700)
        with patch.object(sc, "find_agy_executable", return_value=str(program)):
            self.assertEqual(sc.fetch_antigravity_usage(make_fake_token()), (None, "Sign-in expired. Add this account again."))

    def test_no_internal_google_api_or_borrowed_oauth_client(self):
        paths = [Path(sc.__file__), Path(REPO_ROOT) / "editor-extension/extension.js"]
        paths.extend((Path(REPO_ROOT) / "menubar-app").glob("*.swift"))
        for path in paths:
            with self.subTest(path=path):
                source = path.read_text(encoding="utf-8").lower()
                for banned in ("cloudcode-pa", "v1internal", "oauth2.googleapis.com", "googleapis.com/oauth2",
                               "client_secret", "antigravity/hub", "retrieveuserquotasummary", "fetchavailablemodels"):
                    self.assertNotIn(banned, source)

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
        package = {"publisher": "recoba86", "name": "gravitybar", "version": "1.2.0"}
        (source / "package.json").write_text(json.dumps(package), encoding="utf-8")
        script = source / "extension.js"
        script.write_text("new code", encoding="utf-8")
        target = extensions / "recoba86.gravitybar-1.2.0-arm64"
        target.mkdir()
        (target / "extension.js").write_text("old code", encoding="utf-8")
        registry = extensions / "extensions.json"

        registry.write_text("broken registry", encoding="utf-8")
        with self.assertRaises(ValueError):
            install_extension.register_extension(source, extensions)
        self.assertEqual(registry.read_text(encoding="utf-8"), "broken registry")
        self.assertEqual((target / "extension.js").read_text(encoding="utf-8"), "old code")

        peer = {"identifier": {"id": "other.extension"}, "version": "4.0.0"}
        previous_entries = [
            peer,
            {"identifier": {"id": "m4tinbeigi.gravitybar"}, "version": "1.1.0"},
            {"identifier": {"id": "m4tinbeigi.antigravity-account-switcher"}, "version": "1.0.0"},
        ]
        registry.write_text(json.dumps(previous_entries), encoding="utf-8")
        with patch.object(install_extension.os, "replace", side_effect=OSError("simulated registry failure")):
            with self.assertRaises(OSError):
                install_extension.register_extension(source, extensions)
        self.assertEqual((target / "extension.js").read_text(encoding="utf-8"), "old code")
        self.assertEqual(json.loads(registry.read_text(encoding="utf-8")), previous_entries)

        install_extension.register_extension(source, extensions)
        install_extension.register_extension(source, extensions)
        self.assertEqual((target / "extension.js").read_text(encoding="utf-8"), "new code")
        entries = json.loads(registry.read_text(encoding="utf-8"))
        self.assertEqual(len(entries), 2)
        self.assertIn(peer, entries)
        self.assertEqual(entries[1]["identifier"]["id"], "recoba86.gravitybar")
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
        def sample(groups):
            return json.dumps({"status": "SUCCESS", "command": {"name": "usage", "data": {"groups": groups}}})
        weekly = [{"name": "Gemini Models", "buckets": [{"window": "weekly", "remaining_fraction": 0.42}]}]
        usage = sc.parse_agy_quota_json(sample(weekly), known_email="work@example.invalid")
        self.assertIsNone(usage["daily"])
        self.assertEqual(usage["weekly"]["remaining_pct"], 42)
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
        existing = make_fake_token()
        self.store[(sc.KEYCHAIN_ACTIVE_SERVICE, sc.KEYCHAIN_ACTIVE_ACCOUNT)] = existing
        for filename in ("acp_token.json", "antigravity-oauth-token"):
            with self.subTest(filename=filename):
                program.write_text(
                    "#!/usr/bin/python3\n"
                    "import os, sys\nfrom pathlib import Path\n"
                    "print('https://accounts.google.com/fixture', flush=True)\n"
                    "if input() == 'test-code':\n"
                    f"    p = Path(sys.argv[sys.argv.index('--gemini-dir') + 1]) / 'antigravity-acp/{filename}'\n"
                    "    p.write_text('{\"token\": {\"access_token\": \"test-access\"}}')\n"
                )
                program.chmod(0o700)
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

    def test_agy_cli_env_and_normalize_credential(self):
        env = sc._build_agy_login_env(
            {"PATH": "/usr/bin", "GEMINI_API_KEY": "bad", "DISPLAY": ":0", "SSH_CONNECTION": "1 2 3 4"},
            "/tmp/ag_prof",
            "/tmp/ag_prof/tmp",
        )
        self.assertNotIn("GEMINI_API_KEY", env)
        self.assertNotIn("DISPLAY", env)
        self.assertEqual(env["AGY_CLI_FORCE_FILE_TOKEN_STORAGE"], "1")
        self.assertNotIn("SSH_CONNECTION", env)
        self.assertNotIn("GEMINI_HOME", env)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
