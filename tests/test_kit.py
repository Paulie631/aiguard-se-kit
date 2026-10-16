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
        return copy.deepcopy(self.db[r])

    def call(self, r, m, *a, **kw):
        self.calls.append((r, m, a, kw))
        if m.startswith("add"):
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
        kit = load_kit(monkeypatch, tmp_path, list(argv))
        t = FakeTenant()
        kit.Tenant = lambda cfg: t
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


def test_policy_switch_only_touches_kit_policy(env):
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    cfg = kit.load_cfg()
    assert kit.policy_mode(t, cfg)[0] == "detect"
    mode, name, sw = kit.policy_mode(t, cfg, "block")
    pol = next(p for p in t.db["policies"] if p["name"] == "SE-Demo: Test all")
    pi = next(d for d in pol["inputDetectorPolicies"] if d["detector"] == "prompt_injection")
    assert mode == "block" and sw and pi["configuration"]["action"] == "BLOCK"
    assert "id" not in t.calls[-1][3]  # body sent without id/timestamps
    assert kit.policy_mode(t, cfg, "detect")[0] == "detect"
    cfg["state"]["policy_id"] = 1  # someone else's policy
    with pytest.raises(kit.KitError):
        kit.policy_mode(t, cfg, "block")


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
