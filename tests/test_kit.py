"""Offline tests: a fake tenant stands in for Zscaler, so no credentials or network are needed.

Run:  uv run --with pytest --with requests --with keyring --with truststore pytest -q tests
"""
import copy
import importlib.util
import itertools
import json
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_kit(monkeypatch, tmp_path, argv):
    monkeypatch.setattr(sys, "argv", ["aiguard_kit.py", *argv])
    spec = importlib.util.spec_from_file_location("aiguard_kit_under_test", ROOT / "aiguard_kit.py")
    kit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kit)
    kit.CFG_DIR = tmp_path
    kit.CFG_FILE = tmp_path / "config.json"
    kc = {}
    kit.kc_get = kc.get
    kit.kc_set = kc.__setitem__
    kit.kc_del = lambda n: kc.pop(n, None)
    kit._kc = kc
    return kit


class FakeTenant:
    """In-memory AI Guard: enough of the OneAPI surface for the kit."""

    def __init__(self):
        self.db = {"policies": [{"id": 1, "name": "Existing policy"}], "policy_match_rules": [{"id": 2, "name": "x", "ruleOrder": 4}],
                   "llm_providers": [{"id": 10, "type": "openai", "public": True}, {"id": 11, "type": "anthropic", "public": True}],
                   "llm_provider_credentials": [], "llm_applications": [], "llm_application_credentials": []}
        self.ids = itertools.count(100)
        self.calls = []

    def list(self, r):
        objs = self.db[r]
        if r == "llm_application_credentials":   # like the real API: DETECTIONS keys are not listed
            objs = [o for o in objs if o.get("mode") != "DETECTIONS"]
        return copy.deepcopy(objs)

    def call(self, r, m, *a, **kw):
        self.calls.append((r, m, a, kw))
        if m.startswith("add"):
            if r == "llm_application_credentials" and any(o.get("name") == kw.get("name") for o in self.db[r]):
                raise sys.modules[type(self).kit_module].KitError(
                    'llm_application_credentials.add_credential failed: {"status": 409, "already_exists"}')
            o = dict(copy.deepcopy(kw), id=next(self.ids))
            if r == "llm_application_credentials":
                o["key"] = f"key-{o['id']}"
            self.db[r].append(o)
            return copy.deepcopy(o)
        if m.startswith("get"):
            return copy.deepcopy(next(o for o in self.db[r] if o["id"] == a[0]))
        if m.startswith("update"):
            objs = self.db[r]
            i = next(i for i, o in enumerate(objs) if o["id"] == a[0])
            objs[i] = dict(copy.deepcopy(kw), id=a[0])
            return copy.deepcopy(objs[i])
        if m.startswith("delete"):
            self.db[r] = [o for o in self.db[r] if o["id"] != a[0]]
        return None


@pytest.fixture
def env(monkeypatch, tmp_path):
    def make(*argv):
        import requests
        monkeypatch.setattr(requests, "get", lambda *a, **k: types.SimpleNamespace(status_code=404))
        kit = load_kit(monkeypatch, tmp_path, list(argv))
        t = FakeTenant()
        kit.Tenant = lambda cfg: t
        FakeTenant.kit_module = kit.__name__
        sys.modules[kit.__name__] = kit
        kit.import_claude_desktop = lambda: {"ZSCALER_CLIENT_ID": "cid", "ZSCALER_CLIENT_SECRET": "sec",
                                             "ZSCALER_VANITY_DOMAIN": "acme"}
        kit.das_scan = lambda key, text, direction="IN", user=None, timeout=60: (
            {"action": "ALLOW", "severity": "LOW", "policyName": "SE-Demo: Test all",
             "detectorResponses": {"pii": {"triggered": "SSN" in text}, "language": {"triggered": True}}}, 42)
        return kit, t
    return make


def names(t, r):
    return sorted(o["name"] for o in t.db[r])


def test_library_is_consistent():
    lib = json.loads((ROOT / "tests.json").read_text(encoding="utf-8"))
    ids = [t["id"] for t in lib["tests"]]
    assert len(ids) == len(set(ids))
    assert all(t["group"] in lib["groups"] for t in lib["tests"])
    assert all(t["direction"] in ("IN", "OUT") for t in lib["tests"])
    assert all(s["test"] in ids for st in lib["stories"] for s in st["steps"])
    assert all(s.get("proxy_test", s["test"]) in ids for st in lib["stories"] for s in st["steps"])
    by_id = {t["id"]: t for t in lib["tests"]}
    assert all(by_id[s["proxy_test"]]["direction"] == "IN" for st in lib["stories"] for s in st["steps"] if s.get("proxy_test"))
    for p in (ROOT / "packs").glob("*.json"):
        pack = json.loads(p.read_text(encoding="utf-8"))
        assert pack["name"] and pack["tests"]


def test_no_scannable_secrets_in_repo_files():
    import re
    text = (ROOT / "tests.json").read_text() + "".join(p.read_text() for p in (ROOT / "packs").glob("*.json"))
    for pat in (r"sk_live_[A-Za-z0-9]{20,}", r"xoxb-\d+-\d+-\w+", r"AIza[0-9A-Za-z_-]{35}", r"sq0atp-[\w-]{22}",
                r"ghp_[A-Za-z0-9]{36}"):
        assert not re.search(pat, text), f"secret-scanner pattern in repo: {pat}"


def test_setup_is_idempotent_and_teardown_cleans(env):
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    assert names(t, "policies") == ["Existing policy", "SE-Demo: Test all"]
    assert names(t, "llm_applications") == ["SE-Demo: Anthropic App", "SE-Demo: OpenAI App"]
    assert all(c["mode"] == "DETECTIONS" for c in t.db["llm_application_credentials"])
    rule = next(r for r in t.db["policy_match_rules"] if r["name"] == "SE-Demo: detection apps")
    assert rule["matchCriteria"]["type"] == "DAS_APPLICATION" and rule["ruleOrder"] == 5
    assert kit._kc["SE-Demo: OpenAI App:detections"].startswith("key-")
    before = copy.deepcopy(t.db)
    kit.cmd_setup()  # second run creates nothing new
    assert {k: len(v) for k, v in t.db.items()} == {k: len(v) for k, v in before.items()}
    kit.FORCE = True
    kit.teardown(t, kit.load_cfg())
    assert names(t, "policies") == ["Existing policy"]
    assert t.db["llm_applications"] == [] and t.db["llm_application_credentials"] == []
    assert names(t, "policy_match_rules") == ["x"]
    assert "SE-Demo: OpenAI App:detections" not in kit._kc


def test_policy_profiles_and_custom(env):
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    cfg = kit.load_cfg()
    pol = lambda: next(p for p in t.db["policies"] if p["name"] == "SE-Demo: Test all")  # noqa: E731
    det = lambda side, name: next(d for d in pol()[side] if d["detector"] == name)  # noqa: E731
    assert kit.policy_mode(t, cfg)[0] == "monitor"
    for prof in ("attacks", "data", "everything", "monitor"):
        assert kit.policy_mode(t, cfg, prof)[0] == prof          # each profile round-trips
    assert "id" not in t.calls[-1][3]                            # body sent without id/timestamps
    kit.policy_mode(t, cfg, "block")                             # alias
    assert kit.policy_mode(t, cfg)[0] == "attacks"
    assert det("inputDetectorPolicies", "secrets")["configuration"]["defaultAction"] == "DETECT"
    kit.policy_mode(t, cfg, "data")
    pii = {e["entityType"]: e["action"] for e in det("inputDetectorPolicies", "pii")["configuration"]["entities"]}
    assert pii["US_SSN"] == "BLOCK" and pii["CREDIT_CARD"] == "BLOCK" and pii["EMAIL_ADDRESS"] == "DETECT"
    assert pii["CRYPTO"] == "DISABLE"                            # disabled entities stay disabled
    assert {s["secretType"]: s["action"] for s in det("inputDetectorPolicies", "secrets")["configuration"]["secretTypes"]}["GITHUB_TOKEN"] == "BLOCK"
    assert det("inputDetectorPolicies", "secrets")["configuration"]["defaultAction"] == "DETECT"
    kit.policy_mode(t, cfg, "everything")
    assert det("inputDetectorPolicies", "competition")["configuration"]["competitors"][0]["action"] == "BLOCK"
    assert all(t_["action"] == "DETECT" for t_ in det("inputDetectorPolicies", "prompt_tags")["configuration"]["tags"])
    assert all(x["action"] == "DETECT" for x in det("inputDetectorPolicies", "language")["configuration"]["languages"])
    # the AI Guard API rejects defaultAction BLOCK: never send it
    assert all((d.get("configuration") or {}).get("defaultAction") != "BLOCK" for side in kit.SIDES for d in pol()[side])
    prof, _, _ = kit.policy_mode(t, cfg, {"prompt": ["code", "prompt_tags"], "response": ["malicious_url"]})
    assert prof == "custom"
    assert kit.blocked_map(pol()) == {"prompt": ["code"], "response": ["malicious_url"]}
    d = kit.policy_details(t, cfg)
    assert d["mode"] == "custom" and "prompt_tags" not in d["detectors"]["prompt"]
    cfg["state"]["policy_id"] = 1  # someone else's policy
    with pytest.raises(kit.KitError):
        kit.policy_mode(t, cfg, "attacks")
    with pytest.raises(kit.KitError):
        kit.policy_mode(t, kit.load_cfg(), "nonsense")


def test_proxy_run_with_tags(env):
    kit, t = env("setup", "--yes")
    kit.save_credentials(kit.load_cfg(), "acme", "cid", "sec")
    cfg = kit.load_cfg()
    ans = kit.default_answers(kit.tenant_facts(t, cfg))
    ans["providers"]["openai"]["key"] = "sk-test"
    kit.setup_apply(t, cfg, ans, lambda *a: None)
    kit.proxy_chat = lambda *a, **k: ("Here is a record: SSN 123-45-6789", 10)
    scans = []
    kit.das_scan = lambda key, text, direction="IN", user=None, timeout=60: (scans.append(direction) or {
        "action": "ALLOW", "detectorResponses": {"pii": {"triggered": True}, "secrets": {"triggered": direction == "IN"}}}, 5)
    test = {"id": "x", "text": "make a record", "direction": "IN", "expect": ["secrets"]}
    r = kit.run_one(cfg, test, "SE-Demo: OpenAI App", "a@b.c", "proxy", tags=True)
    assert r["status"] == "OK" and r["reply"].startswith("Here") and r["detectors"] == ["pii", "secrets"]
    assert r["resp_detectors"] == ["pii"] and scans == ["IN", "OUT"] and r["missed"] == []
    def blocked(*a, **k):
        raise kit.KitError('HTTP 403: {"error":"blocked by policy"}')
    kit.proxy_chat = blocked
    scans.clear()
    r = kit.run_one(cfg, test, "SE-Demo: OpenAI App", "a@b.c", "proxy", tags=True)
    assert r["action"] == "BLOCK" and scans == ["IN"] and "resp_detectors" not in r
    r = kit.run_one(cfg, test, "SE-Demo: OpenAI App", "a@b.c", "proxy")
    assert r["detectors"] == [] and r["action"] == "BLOCK"


def test_run_substitutes_placeholders(env):
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    cfg = kit.load_cfg()
    cfg["competitor"] = "Contoso"
    seen = []
    kit.das_scan = lambda key, text, *a, **k: (seen.append(text) or {"action": "ALLOW", "detectorResponses": {}}, 1)
    lib = kit.load_tests()
    for tid in ("competition-competitor-compare", "secret-stripe-key"):
        test = next(x for x in lib["tests"] if x["id"] == tid)
        r = kit.run_one(cfg, test, next(iter(cfg["state"]["apps"])), "a@b.c", "detect")
        assert r["status"] == "OK"
    assert "Contoso" in seen[0] and "{_}" not in seen[1] and "sk_live_" in seen[1]


def test_plan_handles_no_proxy_apps(env):
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    cfg = kit.load_cfg()
    assert kit.plan(cfg, kit.load_tests()["tests"], "proxy") == []
    jobs = kit.plan(cfg, kit.load_tests()["tests"][:4], "detect", rounds=2)
    assert len(jobs) == 8 and all(app in cfg["state"]["apps"] for _, app, _ in jobs)


def test_import_pack_validates_and_loads(env):
    kit, _ = env("gui")
    path, n = kit.import_pack("Acme POC", [{"prompt": "Jane, SSN 123-45-6789", "expect": "pii, bogus"},
                                           {"prompt": "  "}, {"prompt": "reply", "direction": "out"}])
    assert n == 2 and path.name == "custom-acme-poc.json"
    lib = kit.load_tests()
    imported = [t for t in lib["tests"] if t.get("pack") == "Acme POC"]
    assert [t["expect"] for t in imported] == [["pii"], []] and imported[1]["direction"] == "OUT"
    assert any(p["id"] == "pack-acme-poc" for p in lib["presets"])
    with pytest.raises(kit.KitError):
        kit.import_pack("", [{"prompt": "x"}])
    with pytest.raises(kit.KitError):
        kit.import_pack("Empty", [{"prompt": ""}])


def test_trickle_and_profiles(env, capsys):
    kit, t = env("run", "--trickle", "--count", "4", "--profile", "acme", "--yes")
    assert kit.PROFILE == "acme" and kit.KC_NS == "acme/"
    kit.cmd_setup()
    kit.cmd_run()
    out = capsys.readouterr().out
    assert "trickle profile=acme sent=4 errors=0" in out
    assert kit.schedule_cmdline(4)[-3:] == ["--profile", "acme", "--yes"]


def test_schedule_mac_plist(env, monkeypatch, tmp_path):
    import platform
    import plistlib
    import subprocess
    kit, _ = env("schedule", "install", "--every", "30", "--count", "6")
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(kit, "HOME", tmp_path)
    monkeypatch.setattr(kit.os, "getuid", lambda: 501, raising=False)
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: ran.append(cmd) or types.SimpleNamespace(returncode=0, stderr="", stdout=""))
    kit.cmd_schedule()
    plist = plistlib.loads((tmp_path / "Library/LaunchAgents/com.aiguard-se-kit.default.plist").read_bytes())
    assert plist["StartInterval"] == 1800 and plist["ProgramArguments"][1:4] == ["run", "--trickle", "--count"]
    assert ["launchctl", "bootstrap", "gui/501"] == ran[-1][:3]


def test_command_parsing_skips_option_values(env, monkeypatch):
    kit, _ = env("--profile", "setup", "status")
    called = []
    monkeypatch.setattr(kit, "cmd_status", lambda: called.append("status"))
    monkeypatch.setattr(kit, "cmd_setup", lambda: called.append("setup"))
    kit.main()
    assert called == ["status"]


def test_hints_cover_known_failures(env):
    kit, _ = env("status")
    assert "API role" in kit.hint("HTTP 401 NOT_AUTHORIZED")
    assert "credit" in kit.hint("402 Insufficient Balance")
    assert "TLS" in kit.hint("SSLError CERTIFICATE_VERIFY_FAILED")


def test_preflight_probe_leaves_nothing_and_flags_user_rules(env):
    kit, t = env("setup", "--yes")
    t.db["policy_match_rules"].append({"id": 3, "name": "VIP", "enabled": True, "ruleOrder": 1, "matchCriteria": {"type": "USER"}})
    kit.save_credentials(kit.load_cfg(), "acme", "cid", "sec")
    checks, tenant = kit.preflight(kit.load_cfg(), write_probe=True)
    by = {c["id"]: c for c in checks}
    assert tenant is t and by["write"]["status"] == "ok" and t.db["llm_applications"] == []
    assert by["rules"]["status"] == "warn" and "VIP" in by["rules"]["detail"]


def test_preflight_stops_on_bad_login(env):
    kit, _ = env("setup", "--yes")
    kit.save_credentials(kit.load_cfg(), "acme", "cid", "sec")
    def boom(cfg):
        raise kit.KitError("Couldn't connect: invalid_client")
    kit.connect = boom
    checks, tenant = kit.preflight(kit.load_cfg())
    assert tenant is None and checks[-1]["id"] == "login" and checks[-1]["status"] == "fail" and "secret" in checks[-1]["fix"]


def test_verify_catches_wrong_policy(env):
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    cfg = kit.load_cfg()
    kit.das_scan = lambda *a, **k: ({"policyId": 999, "policyName": "Someone else's", "action": "ALLOW"}, 5)
    res = kit.verify(cfg, lambda *a: None, wait=0)
    assert all(c["status"] == "fail" and "Someone else's" in c["detail"] for c in res)
    kit.das_scan = lambda *a, **k: ({"policyId": cfg["state"]["policy_id"], "policyName": "SE-Demo: Test all"}, 5)
    assert all(c["status"] == "ok" for c in kit.verify(cfg, lambda *a: None, wait=0))


def test_reused_policy_is_audited_and_untouched(env):
    kit, t = env("setup", "--yes")
    t.db["policies"][0].update(inputDetectorPolicies=[{"detector": "pii", "enabled": True}], outputDetectorPolicies=[])
    kit.save_credentials(kit.load_cfg(), "acme", "cid", "sec")
    cfg, logs = kit.load_cfg(), []
    ans = kit.default_answers(kit.tenant_facts(t, cfg))
    ans["policy"] = 1
    kit.setup_apply(t, cfg, ans, lambda lv, m: logs.append((lv, m)))
    assert cfg["state"]["policy_id"] == 1 and len(t.db["policies"]) == 1
    assert any(lv == "warn" and "Prompt Classifications" in m for lv, m in logs)
    with pytest.raises(kit.KitError):
        kit.policy_mode(t, cfg, "block")


def test_setup_apply_with_provider_key_creates_proxy_path(env):
    kit, t = env("setup", "--yes")
    kit.save_credentials(kit.load_cfg(), "acme", "cid", "sec")
    cfg = kit.load_cfg()
    ans = kit.default_answers(kit.tenant_facts(t, cfg))
    ans["providers"]["openai"]["key"] = "sk-test"
    ans["mode"] = "block"
    kit.setup_apply(t, cfg, ans, lambda *a: None)
    pc = t.db["llm_provider_credentials"][0]
    assert pc["apiCredentials"] == {"type": "BEARER", "token": "sk-test"}
    assert any(r.get("matchCriteria", {}).get("type") == "APPLICATION" for r in t.db["policy_match_rules"])
    assert kit.policy_mode(t, cfg)[0] == "attacks"
    assert "sk-test" not in kit.CFG_FILE.read_text()


def test_every_check_has_runbook_help(env):
    kit, t = env("setup", "--yes")
    t.db["policy_match_rules"].append({"id": 3, "name": "VIP", "enabled": True, "matchCriteria": {"type": "USER"}})
    kit.save_credentials(kit.load_cfg(), "acme", "cid", "sec")
    cfg = kit.load_cfg()
    cfg["state"] = {"apps": {}, "policy_id": 1}
    kit.save_cfg(cfg)
    t.db["policies"][0].update(inputDetectorPolicies=[], outputDetectorPolicies=[])
    checks, _ = kit.preflight(kit.load_cfg(), write_probe=True)
    helpmap = kit.preflight_help()
    ids = {kit.help_id(c["id"]) for c in checks} | {"verify-policy"}
    assert ids <= set(helpmap), ids - set(helpmap)
    for h in helpmap.values():
        assert h["what"] and h["why"] and h["verify"] and h["fix"] and h["retest"]


def test_preflight_json_and_exit_codes(env, capsys):
    kit, t = env("preflight", "--json")
    kit.save_credentials(kit.load_cfg(), "acme", "cid-123456", "supersecret")
    with pytest.raises(SystemExit) as e:
        kit.cmd_preflight()
    out = capsys.readouterr().out
    rep = json.loads(out)
    assert e.value.code == 0 and rep["result"] == "pass" and rep["tenant"] == "acme"
    assert "supersecret" not in out and "cid-123456" not in out
    t.db["policy_match_rules"].append({"id": 3, "name": "VIP", "enabled": True, "matchCriteria": {"type": "USER"}})
    with pytest.raises(SystemExit) as e:
        kit.cmd_preflight()
    assert e.value.code == 2
    kit.connect = lambda cfg: (_ for _ in ()).throw(kit.KitError("invalid_client"))
    with pytest.raises(SystemExit) as e:
        kit.cmd_preflight()
    assert e.value.code == 1


def test_runbook_doc_in_sync():
    import subprocess
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "gen_preflight_doc.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_reuses_existing_provider_key_and_teardown_keeps_it(env):
    kit, t = env("setup", "--yes")
    t.db["llm_provider_credentials"] += [{"id": 901, "providerId": 10, "name": "OpenAI API Key"},
                                         {"id": 902, "providerId": 99, "name": "DeepSeek API Key"}]
    kit.save_credentials(kit.load_cfg(), "acme", "cid", "sec")
    cfg = kit.load_cfg()
    facts = kit.tenant_facts(t, cfg)
    assert [c["name"] for c in facts["providers"]["openai"]["creds"]] == ["OpenAI API Key"]  # DeepSeek excluded
    assert facts["providers"]["anthropic"]["creds"] == []
    ans = kit.default_answers(facts)
    assert ans["providers"]["openai"]["cred_id"] == 901 and ans["providers"]["anthropic"]["cred_id"] is None
    logs = []
    kit.setup_apply(t, cfg, ans, lambda lv, m: logs.append(m))
    proxy = [c for c in t.db["llm_application_credentials"] if c.get("mode") == "PROXY"]
    assert len(proxy) == 1 and proxy[0]["providerCredentialsId"] == 901
    assert len(t.db["llm_provider_credentials"]) == 2  # nothing new created
    assert any("no Anthropic key is configured" in m for m in logs)
    kit.FORCE = True
    kit.teardown(t, kit.load_cfg())
    assert [c["name"] for c in t.db["llm_provider_credentials"]] == ["OpenAI API Key", "DeepSeek API Key"]


def test_reused_key_that_vanished_gives_clear_error(env):
    kit, t = env("setup", "--yes")
    kit.save_credentials(kit.load_cfg(), "acme", "cid", "sec")
    cfg = kit.load_cfg()
    ans = kit.default_answers(kit.tenant_facts(t, cfg))
    ans["providers"]["openai"]["cred_id"] = 555
    with pytest.raises(kit.KitError, match="no longer exists"):
        kit.setup_apply(t, cfg, ans, lambda *a: None)


def test_reinstall_with_hidden_detection_keys(env):
    """Keys exist in AI Guard but not on this machine (new laptop, wiped keychain): setup must replace them
    without a 409, and teardown must still find the DETECTIONS keys the list API hides."""
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    first = {c["id"] for c in t.db["llm_application_credentials"]}
    kit._kc.clear()
    kit._kc["oneapi-client-secret"] = "s"
    cfg = kit.load_cfg()
    for a in cfg["state"]["apps"].values():
        a.pop("das_cred_id", None)
    kit.save_cfg(cfg)
    logs = []
    kit.setup_apply(t, kit.load_cfg(), kit.default_answers(kit.tenant_facts(t, kit.load_cfg())),
                    lambda lv, m: logs.append(m))
    now = {c["id"]: c for c in t.db["llm_application_credentials"]}
    assert not (first & set(now)), "old keys should be retired"
    assert all(c["name"].startswith("SE-Demo: ") for c in now.values()) and len(now) == 2
    assert any("replacement" in m for m in logs) and any("Removed an old key" in m for m in logs)
    rule = next(r for r in t.db["policy_match_rules"] if r["name"] == "SE-Demo: detection apps")
    assert {i for a in rule["matchCriteria"]["llmApplications"] for i in a["applicationCredentialsIds"]} == set(now)
    kit.FORCE = True
    kit.teardown(t, kit.load_cfg(), log=lambda *a: None)
    assert t.db["llm_application_credentials"] == [] and t.db["llm_applications"] == []


def windows(kit, monkeypatch, tmp_path):
    """Make the loaded kit behave as it does on Windows, with its folder in tmp_path."""
    import platform
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(kit, "WINDOWS", True)
    monkeypatch.setattr(kit, "LAUNCHER", ".\\aiguard-kit.cmd")
    here = tmp_path / "kit folder"
    here.mkdir()
    monkeypatch.setattr(kit, "HERE", here)
    return here


def test_windows_launcher_written_when_missing(env, monkeypatch, tmp_path, capsys):
    kit, _ = env("status")
    here = windows(kit, monkeypatch, tmp_path)
    kit.ensure_windows_launcher()
    data = (here / "aiguard-kit.cmd").read_bytes()
    assert data.startswith(b"@echo off\r\n") and b"\n" not in data.replace(b"\r\n", b"")
    assert b'uv run --quiet --python 3.12 --script "%~dp0aiguard_kit.py" %*' in data
    assert ".\\aiguard-kit.cmd gui" in capsys.readouterr().out
    # the shipped launcher matches the one the kit writes, with Windows line endings
    assert (ROOT / "aiguard-kit.cmd").read_bytes() == data


def test_windows_messages_use_cmd_launcher(env, monkeypatch, tmp_path):
    kit, _ = env("status")
    windows(kit, monkeypatch, tmp_path)
    assert kit.L("Run ./aiguard-kit setup") == "Run .\\aiguard-kit.cmd setup"
    assert ".\\aiguard-kit.cmd" in kit.hint(kit.KitError("CERTIFICATE_VERIFY_FAILED"))
    assert "Keychain" in kit.hint(kit.KitError("Couldn't read 'x' from Windows Credential Manager"))  # Windows text is chosen at import
    # the console's JSON stays valid after swapping in a path with a backslash
    body = json.dumps({"fix": "Run ./aiguard-kit setup"}).replace("./aiguard-kit", json.dumps(kit.LAUNCHER)[1:-1])
    assert json.loads(body)["fix"] == "Run .\\aiguard-kit.cmd setup"


def test_schedule_windows_task_logs_through_wrapper(env, monkeypatch, tmp_path):
    import subprocess
    kit, _ = env("schedule", "install", "--every", "30", "--count", "6")
    here = windows(kit, monkeypatch, tmp_path)
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: ran.append(cmd) or types.SimpleNamespace(returncode=0, stderr="", stdout=""))
    kit.cmd_schedule()
    cmd = ran[-1]
    assert cmd[:2] == ["schtasks", "/Create"] and cmd[cmd.index("/MO") + 1] == "30"
    tr = cmd[cmd.index("/TR") + 1]
    assert tr == f'"{kit.CFG_DIR / "trickle.cmd"}"' and len(tr) < 261
    wrapper = (kit.CFG_DIR / "trickle.cmd").read_bytes().decode()
    assert "\r\n" in wrapper and "NO_COLOR=1" in wrapper and "trickle.log" in wrapper
    assert f'"{here / "aiguard-kit.cmd"}" "run" "--trickle" "--count" "6"' in wrapper
    assert (here / "aiguard-kit.cmd").exists()
    kit.ARGS[:] = ["schedule", "remove"]
    kit.cmd_schedule()
    assert not (kit.CFG_DIR / "trickle.cmd").exists()


def test_output_survives_a_cp1252_console(tmp_path):
    """Windows consoles and redirected output default to cp1252, which can't encode ✓ or ✗."""
    import subprocess
    import os
    env_ = {**os.environ, "PYTHONIOENCODING": "cp1252", "HOME": str(tmp_path), "USERPROFILE": str(tmp_path)}
    code = ("import sys; sys.argv=['k','help']; import runpy; "
            f"g = runpy.run_path({str(ROOT / 'aiguard_kit.py')!r}, run_name='kit'); g['ok']('done'); g['fail']('bad') "
            "if 'fail' in g else print('\\u2717 bad')")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, env=env_)
    assert r.returncode == 0, r.stderr.decode(errors="replace")
    assert "✓ done".encode() in r.stdout


def test_launchers_pin_a_python_with_prebuilt_libraries():
    """Python 3.15 has no prebuilt pyyaml, so uv tried to compile it and failed on Windows without Visual C++."""
    head = (ROOT / "aiguard_kit.py").read_text(encoding="utf-8")
    assert '# requires-python = ">=3.10,<3.15"' in head
    assert "--python 3.12 --script" in (ROOT / "aiguard-kit").read_text()
    assert b"--python 3.12 --script" in (ROOT / "aiguard-kit.cmd").read_bytes()
    assert "--python 3.12 --script" in (ROOT / "WINDOWS.md").read_text(encoding="utf-8")


def test_install_and_uninstall_mac_linux(env, monkeypatch, tmp_path, capsys):
    import subprocess
    kit, _ = env("install", "--yes")
    home = tmp_path / "home"
    monkeypatch.setattr(kit, "HOME", home)
    monkeypatch.setattr(kit, "BASE_DIR", home / ".aiguard-se-kit")
    monkeypatch.setattr(kit, "APP_DIR", home / ".aiguard-se-kit" / "app")
    monkeypatch.setattr(kit, "schedule_installed", lambda: False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=1, stdout="", stderr=""))
    kit.cmd_install()
    app = home / ".aiguard-se-kit" / "app"
    assert (app / "aiguard_kit.py").read_bytes() == (ROOT / "aiguard_kit.py").read_bytes()
    assert (app / "packs").is_dir() and (app / "aiguard-kit").stat().st_mode & 0o111
    assert not (app / "aiguard-kit.cmd").exists() and not (app / "tests").exists()
    shortcut = home / "Desktop" / "AI Guard Demo Console.command"
    assert f'exec "{app / "aiguard-kit"}" gui' in shortcut.read_text() and shortcut.stat().st_mode & 0o111
    assert f'exec "{app / "aiguard-kit"}" "$@"' in (home / ".local/bin/aiguard-kit").read_text()
    # reinstalling keeps the previous copy for rollback
    kit.cmd_install()
    assert (app.with_name("app.previous") / "aiguard_kit.py").exists()
    kit.cmd_uninstall()
    assert not app.exists() and not shortcut.exists() and not (home / ".local/bin/aiguard-kit").exists()
    assert not app.with_name("app.previous").exists()


def test_install_windows_shortcuts_path_and_schedule(env, monkeypatch, tmp_path):
    import subprocess
    kit, _ = env("install", "--yes")
    windows(kit, monkeypatch, tmp_path)
    for f in kit.INSTALL_FILES:  # the kit folder under test
        src = ROOT / f
        if src.is_file():
            (kit.HERE / f).write_bytes(src.read_bytes())
    (kit.HERE / "packs").mkdir()
    home = tmp_path / "home"
    monkeypatch.setattr(kit, "HOME", home)
    monkeypatch.setattr(kit, "BASE_DIR", home / ".aiguard-se-kit")
    monkeypatch.setattr(kit, "APP_DIR", home / ".aiguard-se-kit" / "app")
    monkeypatch.setenv("APPDATA", str(home / "AppData/Roaming"))
    shortcuts, path = [], []
    monkeypatch.setattr(kit, "_desktop_dir", lambda: home / "OneDrive/Desktop")
    monkeypatch.setattr(kit, "_win_shortcut", lambda p, target, args, wd, desc: shortcuts.append((p.name, target.name, args)))
    monkeypatch.setattr(kit, "_win_user_path", lambda add=None, remove=None: path.append((add, remove)))
    monkeypatch.setattr(kit, "schedule_installed", lambda: True)
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: ran.append(cmd) or types.SimpleNamespace(returncode=0, stderr="", stdout=""))
    kit.cmd_install()
    app = home / ".aiguard-se-kit" / "app"
    assert (app / "aiguard-kit.cmd").exists() and not (app / "aiguard-kit").exists()
    assert (app / "Uninstall AI Guard Kit.cmd").exists() and not (app / "Uninstall AI Guard Kit.command").exists()
    assert ("AI Guard Demo Console.lnk", "aiguard-kit.cmd", "gui") in shortcuts
    assert ("Uninstall AI Guard Demo Kit.lnk", "Uninstall AI Guard Kit.cmd", "") in shortcuts
    assert path == [(str(app), None)]
    # the existing schedule now runs the installed copy
    assert ran[-1][:2] == ["schtasks", "/Create"]
    assert f'cd /d "{app}"' in (kit.CFG_DIR / "trickle.cmd").read_text()
    assert f'"{app / "aiguard-kit.cmd"}"' in (kit.CFG_DIR / "trickle.cmd").read_text()
    assert kit.load_cfg()["schedule"] == {"every": 60, "count": 12}


def test_double_click_installers_are_well_formed():
    win = (ROOT / "Install AI Guard Kit.cmd").read_bytes()
    assert win.startswith(b"@echo off\r\n") and b"\n" not in win.replace(b"\r\n", b"")
    assert b'uv run --quiet --python 3.12 --script "%~dp0aiguard_kit.py" install' in win
    mac = ROOT / "Install AI Guard Kit.command"
    assert mac.stat().st_mode & 0o111 and b"\r" not in mac.read_bytes()
    assert "--python 3.12 --script ./aiguard_kit.py install" in mac.read_text()
    for f in ("Install AI Guard Kit.command", "Uninstall AI Guard Kit.command", "aiguard-kit"):
        assert (ROOT / f).stat().st_mode & 0o111, f


def test_installers_stop_when_run_from_inside_the_zip():
    assert b'if not exist "%~dp0aiguard_kit.py" (' in (ROOT / "Install AI Guard Kit.cmd").read_bytes()
    assert "[ ! -f aiguard_kit.py ]" in (ROOT / "Install AI Guard Kit.command").read_text()
