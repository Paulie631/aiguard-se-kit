"""Offline tests: a fake tenant stands in for Zscaler, so no credentials or network are needed.

Run:  uv run --with pytest --with requests --with keyring --with truststore pytest -q tests
"""
import copy
import importlib.util
import itertools
import json
import pathlib
import re
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
    kit.LOG_DIR = tmp_path / "logs"  # never write test activity into the real ~/.aiguard-se-kit
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
        KitError = sys.modules[type(self).kit_module].KitError
        if r == "policy_match_rules" and m in ("add_rule", "update_rule"):  # the real API rejects unknown keys
            have = {o["id"] for o in self.db["llm_application_credentials"]}
            for e in (kw.get("matchCriteria") or {}).get("llmApplications") or []:
                for i in e.get("applicationCredentialsIds") or []:
                    if i not in have:
                        raise KitError(f'policy_match_rules.{m} failed: {{"status": 400, "detail": '
                                       f'"applicationCredentialsId {i} not found"}}')
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
            o = next((o for o in self.db[r] if o["id"] == a[0]), None)
            if o is None:   # like the real API
                raise KitError(f'{r}.{m} failed: {{"status": 404, "title": "Not Found"}}')
            return copy.deepcopy(o)
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
        kit.das_scan = lambda key, text, direction="IN", user=None, timeout=60, trace=None: (
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
    pack_tests = [t for p in (ROOT / "packs").glob("*.json") for t in json.loads(p.read_text(encoding="utf-8"))["tests"]]
    known = set(ids) | {t["id"] for t in pack_tests}   # storylines may use the industry packs' prompts
    run_steps = [s for st in lib["stories"] for s in st["steps"] if s.get("kind") != "show"]   # show: no prompt
    assert all(s["test"] in known for s in run_steps)
    assert all(s.get("proxy_test", s["test"]) in known for s in run_steps)
    by_id = {t["id"]: t for t in lib["tests"] + pack_tests}
    assert all(by_id[s["proxy_test"]]["direction"] == "IN" for s in run_steps if s.get("proxy_test"))
    for p in (ROOT / "packs").glob("*.json"):
        pack = json.loads(p.read_text(encoding="utf-8"))
        assert pack["name"] and pack["tests"]


def test_no_scannable_secrets_in_repo_files():
    import re
    text = (ROOT / "tests.json").read_text(encoding="utf-8") + "".join(p.read_text(encoding="utf-8") for p in (ROOT / "packs").glob("*.json"))
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


def test_demo_readiness_wants_monitor_and_keys(env, capsys):
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    by = {c["id"]: c for c in kit.readiness(kit.load_cfg())}
    assert by["ready-aig-policy"]["status"] == "ok" and by["ready-aig-keys"]["status"] == "ok"
    kit.policy_mode(t, kit.load_cfg(), "attacks")
    by = {c["id"]: c for c in kit.readiness(kit.load_cfg())}
    assert by["ready-aig-policy"]["status"] == "warn" and "policy monitor" in by["ready-aig-policy"]["fix"]
    assert not any(c["id"].startswith("ready-zia") for c in by.values())   # no ZIA set up: no ZIA items
    kit.cmd_ready()
    assert "to sort out first" in capsys.readouterr().out


def test_storylines_talk_tracks_news_and_owasp_are_well_formed():
    lib = json.loads((ROOT / "tests.json").read_text(encoding="utf-8"))
    owasp = {f"LLM{n:02d}" for n in range(1, 11)}
    story_ids = [st["id"] for st in lib["stories"]]
    assert len(story_ids) == len(set(story_ids))
    assert {"core", "leakage", "blocking"} <= set(story_ids)            # the original three are still there
    for st in lib["stories"]:
        assert st["steps"] and st.get("requires") in (None, "zia", "eai")
        for s_ in st["steps"]:   # Endpoint AI steps: show steps that may switch its policy and embed the live feed
            assert s_.get("eai_mode") in (None, "monitor", "secrets", "destructive", "block") and (not s_.get("eai_mode") or s_.get("kind") == "show")
        changes = [s["policy"] for s in st["steps"] if s.get("policy")]
        if any(p != "monitor" for p in changes):
            assert changes[-1] == "monitor", f"{st['id']} must end back in Monitor"
        for s in st["steps"]:
            assert s["title"] and (s.get("say") or s.get("talk")), s["title"]
            assert set(s.get("owasp", [])) <= owasp, s["title"]
            for o in s.get("objections", []):
                assert o["q"].endswith("?") and o["a"]
            for n in s.get("news", []):
                assert n["url"].startswith("https://") and n["headline"] and n["source"] and n["year"].isdigit()
            if s.get("kind") == "show":
                assert s.get("where") and not s.get("policy")
            if s.get("filler"):
                assert s.get("policy"), f"'{s['title']}': a filler line only shows while a policy change applies"
    core = next(st for st in lib["stories"] if st["id"] == "core")
    assert [s["title"] for s in core["steps"]][0] == "Everyday work flows through" and len(core["steps"]) == 8


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
    kit.das_scan = lambda key, text, direction="IN", user=None, timeout=60, trace=None: (scans.append(direction) or {
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
    """Keys exist in AI Guard but this computer has no record of them (another computer's keys, or a wiped
    state): setup adds its own key without a 409, keeps the others working, and teardown still finds the
    DETECTIONS keys the list API hides."""
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    first = {c["id"] for c in t.db["llm_application_credentials"]}
    kit._kc.clear()
    kit._kc["oneapi-client-secret"] = "s"
    cfg = kit.load_cfg()
    for a in cfg["state"]["apps"].values():
        a.pop("das_cred_id", None)
    kit.save_cfg(cfg)
    kit.setup_apply(t, kit.load_cfg(), kit.default_answers(kit.tenant_facts(t, kit.load_cfg())), lambda *a: None)
    now = {c["id"]: c for c in t.db["llm_application_credentials"]}
    assert first < set(now) and len(now) == 4, "unknown keys are kept, a new key is added per app"
    assert all(c["name"].startswith("SE-Demo: ") for c in now.values())
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
    fix = kit.hint(kit.KitError("Couldn't read 'x' from Windows Credential Manager"))  # wording is chosen at import
    assert ("Credential Manager" if sys.platform == "win32" else "Keychain") in fix
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


@pytest.mark.skipif(sys.platform == "win32", reason="Mac/Linux install path")
def test_install_and_uninstall_mac_linux(env, monkeypatch, tmp_path, capsys):
    import subprocess
    kit, _ = env("install", "--yes")
    home = tmp_path / "home"
    monkeypatch.setattr(kit, "HOME", home)
    monkeypatch.setattr(kit, "BASE_DIR", home / ".aiguard-se-kit")
    monkeypatch.setattr(kit, "APP_DIR", home / ".aiguard-se-kit" / "app")
    monkeypatch.setattr(kit, "schedule_installed", lambda: False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=1, stdout="", stderr=""))
    legacy = home / "Desktop" / "AI Guard Demo Console.command"     # what earlier versions put on the desktop
    legacy.parent.mkdir(parents=True)
    legacy.write_text("old")
    kit.cmd_install()
    app = home / ".aiguard-se-kit" / "app"
    assert (app / "aiguard_kit.py").read_bytes() == (ROOT / "aiguard_kit.py").read_bytes()
    assert (app / "packs").is_dir() and (app / "aiguard-kit").stat().st_mode & 0o111
    assert not (app / "aiguard-kit.cmd").exists() and not (app / "tests").exists()
    shortcut = home / "Desktop" / "AI Guard Demo Console.app"           # an app: the kit's icon, no extension shown
    import plistlib
    info = plistlib.loads((shortcut / "Contents/Info.plist").read_bytes())
    assert info["CFBundleName"] == "AI Guard Demo Console" and info["CFBundleIconFile"] == "icon"
    assert (shortcut / "Contents/Resources/icon.icns").read_bytes() == (ROOT / "assets/aiguard-icon.icns").read_bytes()
    launch = shortcut / "Contents/MacOS/launch"   # starts the console in the background: no Terminal window
    text = launch.read_text()
    assert f'nohup "{app / "aiguard-kit"}" gui --background' in text and text.rstrip().endswith("&")
    assert "open -a Terminal" not in text and launch.stat().st_mode & 0o111
    assert not legacy.exists()
    assert f'exec "{app / "aiguard-kit"}" "$@"' in (home / ".local/bin/aiguard-kit").read_text()
    # reinstalling keeps the previous copy for rollback
    kit.cmd_install()
    assert (app.with_name("app.previous") / "aiguard_kit.py").exists()
    kit.cmd_uninstall()
    assert not app.exists() and not shortcut.exists() and not (home / ".local/bin/aiguard-kit").exists()
    assert not app.with_name("app.previous").exists()


def test_installing_an_older_release_over_a_newer_one(env, monkeypatch, tmp_path):
    """Going back a version is just running the older release's installer: no version check blocks it, the newer
    copy is kept for rollback, and settings written by the newer kit still load."""
    import subprocess
    kit, _ = env("install", "--yes")
    home = tmp_path / "home"
    app = home / ".aiguard-se-kit" / "app"
    monkeypatch.setattr(kit, "HOME", home)
    monkeypatch.setattr(kit, "BASE_DIR", home / ".aiguard-se-kit")
    monkeypatch.setattr(kit, "APP_DIR", app)
    monkeypatch.setattr(kit, "schedule_installed", lambda: False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=1, stdout="", stderr=""))
    app.mkdir(parents=True)
    (app / "aiguard_kit.py").write_text('VERSION = "99.0.0"\n', encoding="utf-8")   # a newer kit is installed
    cfg = kit.load_cfg()
    cfg["future_setting"] = {"from": "a newer kit"}
    kit.save_cfg(cfg)
    kit.cmd_install()   # this (older) kit's installer
    assert (app / "aiguard_kit.py").read_bytes() == (ROOT / "aiguard_kit.py").read_bytes()
    assert 'VERSION = "99.0.0"' in (app.with_name("app.previous") / "aiguard_kit.py").read_text(encoding="utf-8")
    assert kit.load_cfg()["future_setting"] == {"from": "a newer kit"}   # unknown settings are kept, not lost


def test_install_windows_shortcuts_path_and_schedule(env, monkeypatch, tmp_path):
    import subprocess
    kit, _ = env("install", "--yes")
    windows(kit, monkeypatch, tmp_path)
    for f in kit.INSTALL_FILES:  # the kit folder under test
        src = ROOT / f
        if src.is_file():
            (kit.HERE / f).write_bytes(src.read_bytes())
    (kit.HERE / "packs").mkdir()
    import shutil
    shutil.copytree(ROOT / "assets", kit.HERE / "assets")
    home = tmp_path / "home"
    monkeypatch.setattr(kit, "HOME", home)
    monkeypatch.setattr(kit, "BASE_DIR", home / ".aiguard-se-kit")
    monkeypatch.setattr(kit, "APP_DIR", home / ".aiguard-se-kit" / "app")
    monkeypatch.setenv("APPDATA", str(home / "AppData/Roaming"))
    shortcuts, path = [], []
    monkeypatch.setattr(kit, "_desktop_dir", lambda: home / "OneDrive/Desktop")
    monkeypatch.setattr(kit, "_win_shortcut", lambda p, target, args, wd, desc, icon=None: shortcuts.append((p.name, target.name, args, icon and icon.name)))
    monkeypatch.setattr(kit, "_win_user_path", lambda add=None, remove=None: path.append((add, remove)))
    monkeypatch.setattr(kit, "schedule_installed", lambda: True)
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: ran.append(cmd) or types.SimpleNamespace(returncode=0, stderr="", stdout=""))
    kit.cmd_install()
    app = home / ".aiguard-se-kit" / "app"
    assert (app / "aiguard-kit.cmd").exists() and not (app / "aiguard-kit").exists()
    assert (app / "Uninstall AI Guard Kit.cmd").exists() and not (app / "Uninstall AI Guard Kit.command").exists()
    assert ("AI Guard Demo Console.lnk", "conhost.exe", f'--headless "{app / "aiguard-kit.cmd"}" gui --background',
            "aiguard-icon.ico") in shortcuts   # no terminal window
    assert ("Uninstall AI Guard Demo Kit.lnk", "Uninstall AI Guard Kit.cmd", "", None) in shortcuts
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
    assert b"\r" not in mac.read_bytes()
    assert "--python 3.12 --script ./aiguard_kit.py install" in mac.read_text(encoding="utf-8")
    if sys.platform != "win32":  # Windows has no execute bit
        for f in ("Install AI Guard Kit.command", "Uninstall AI Guard Kit.command", "aiguard-kit"):
            assert (ROOT / f).stat().st_mode & 0o111, f


def test_installers_stop_when_run_from_inside_the_zip():
    assert b'if not exist "%~dp0aiguard_kit.py" (' in (ROOT / "Install AI Guard Kit.cmd").read_bytes()
    assert "[ ! -f aiguard_kit.py ]" in (ROOT / "Install AI Guard Kit.command").read_text()


@pytest.mark.skipif(sys.platform != "win32", reason="needs real Windows")
def test_real_windows_shortcut_and_user_path(env, tmp_path):
    """Runs on the Windows CI runner: creates a real .lnk and adds/removes a PATH entry, restoring PATH after."""
    kit, _ = env("status")
    lnk = tmp_path / "AI Guard Demo Console.lnk"
    kit._win_shortcut(lnk, ROOT / "aiguard-kit.cmd", "gui", ROOT, "test")
    assert lnk.exists() and lnk.stat().st_size > 0
    probe = str(tmp_path / "aiguard-path-probe")
    try:
        assert probe in kit._win_user_path(add=probe)
        assert kit._win_user_path(add=probe).count(probe) == 1  # adding twice doesn't duplicate
    finally:
        assert probe not in kit._win_user_path(remove=probe)


class FakeResp:
    def __init__(self, status=200, body=b"", ctype="application/json"):
        self.status_code, self._body, self.headers = status, body, {"Content-Type": ctype}

    def json(self):
        return json.loads(self._body)

    def iter_content(self, n):
        for i in range(0, len(self._body), n):
            yield self._body[i:i + n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def release_zip(tmp_path, version):
    import hashlib
    import zipfile
    z = tmp_path / "kit.zip"
    with zipfile.ZipFile(z, "w") as out:
        src = (ROOT / "aiguard_kit.py").read_text(encoding="utf-8")
        out.writestr("aiguard-se-kit/aiguard_kit.py", re.sub(r'^VERSION = "[^"]+"', f'VERSION = "{version}"', src, flags=re.M))
        out.writestr("aiguard-se-kit/aiguard-kit", (ROOT / "aiguard-kit").read_text())
    data = z.read_bytes()
    return data, hashlib.sha256(data).hexdigest()


def test_update_check_download_verify_and_rollback(env, monkeypatch, tmp_path):
    import requests
    kit, _ = env("update")
    monkeypatch.setattr(kit, "BASE_DIR", tmp_path / "base")
    monkeypatch.setattr(kit, "APP_DIR", tmp_path / "base" / "app")
    data, sha = release_zip(tmp_path, "9.9.9")
    info = {"version": "9.9.9", "notes": "- new", "zip_url": "https://example.test/kit.zip", "sha256": sha}
    routes = {"latest": FakeResp(body=json.dumps(info).encode()), "zip": FakeResp(body=data, ctype="application/zip")}
    monkeypatch.setattr(requests, "get", lambda url, **k: routes["zip" if url.endswith(".zip") else "latest"])
    st = kit.update_status(force=True)
    assert st["available"] and st["latest"] == "9.9.9" and not st["error"]
    assert kit.vtuple("1.10.0") > kit.vtuple("1.9.9")
    kit_dir = kit.download_release(info)
    assert re.search(r'^VERSION = "9.9.9"', (kit_dir / "aiguard_kit.py").read_text(encoding="utf-8"), re.M)
    # a tampered or swapped download is refused
    routes["zip"] = FakeResp(body=b"<html>blocked by policy</html>", ctype="application/zip")
    with pytest.raises(kit.KitError, match="checksum.*web page"):
        kit.download_release(info)
    # a web-policy block page instead of release info is explained
    routes["latest"] = FakeResp(body=b"<html>blocked</html>", ctype="text/html")
    st = kit.update_status(force=True)
    assert "blocked" in st["error"] and "github.com" in kit.hint(kit.KitError(st["error"]))
    # rollback swaps app and app.previous
    app, prev = kit.APP_DIR, kit.APP_DIR.with_name("app.previous")
    for d, v in ((app, "2.0.0"), (prev, "1.0.0")):
        d.mkdir(parents=True)
        (d / "aiguard_kit.py").write_text(f'VERSION = "{v}"\n')
    assert kit.rollback() == "1.0.0"
    assert 'VERSION = "1.0.0"' in (app / "aiguard_kit.py").read_text() and 'VERSION = "2.0.0"' in (prev / "aiguard_kit.py").read_text()


def test_update_refuses_unsafe_zips_and_links(env, monkeypatch, tmp_path):
    import hashlib
    import requests
    import zipfile
    kit, _ = env("update")
    monkeypatch.setattr(kit, "BASE_DIR", tmp_path / "base")
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as out:
        out.writestr("aiguard-se-kit/../../evil.py", "x")
    data = z.read_bytes()
    info = {"version": "9.9.9", "zip_url": "https://example.test/kit.zip", "sha256": hashlib.sha256(data).hexdigest()}
    monkeypatch.setattr(requests, "get", lambda url, **k: FakeResp(body=data, ctype="application/zip"))
    with pytest.raises(kit.KitError, match="Unexpected file"):
        kit.download_release(info)
    with pytest.raises(kit.KitError, match="insecure"):
        kit.download_release({**info, "zip_url": "http://example.test/kit.zip"})


def test_release_package_has_update_manifest(tmp_path):
    import subprocess
    if not (ROOT / ".git").exists():
        pytest.skip("needs the git checkout")
    subprocess.run([sys.executable, str(ROOT / "tools/package.py")], check=True, capture_output=True)
    v = re.search(r'^VERSION = "([^"]+)"', (ROOT / "aiguard_kit.py").read_text(encoding="utf-8"), re.M).group(1)
    info = json.loads((ROOT / "dist/latest.json").read_text())
    import hashlib
    assert info["version"] == v and info["zip_url"].endswith(f"/v{v}/aiguard-se-kit-{v}.zip")
    assert info["sha256"] == hashlib.sha256((ROOT / f"dist/aiguard-se-kit-{v}.zip").read_bytes()).hexdigest()
    assert info["notes"]



def test_two_computers_share_a_tenant(env):
    """Setup on computer B must not break computer A, and A's rerun must recover if its key was deleted."""
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    a_cfg, a_kc = kit.load_cfg(), dict(kit._kc)
    a_keys = {a["das_cred_id"] for a in a_cfg["state"]["apps"].values()}
    # computer B: same tenant, its own settings and keychain
    kit._kc.clear()
    kit._kc["oneapi-client-secret"] = "s"
    b_cfg = {k: v for k, v in a_cfg.items() if k != "state"}
    kit.save_cfg(b_cfg)
    kit.setup_apply(t, kit.load_cfg(), kit.default_answers(kit.tenant_facts(t, kit.load_cfg())), lambda *a: None)
    rule = next(r for r in t.db["policy_match_rules"] if r["name"] == "SE-Demo: detection apps")
    in_rule = {i for e in rule["matchCriteria"]["llmApplications"] for i in e["applicationCredentialsIds"]}
    assert a_keys <= in_rule, "B's setup must keep A's keys in the rule"
    assert a_keys <= {c["id"] for c in t.db["llm_application_credentials"]}, "B must not delete A's keys"
    # now A's key gets deleted (e.g. by an older kit version or a manual cleanup) and A reruns setup
    gone = sorted(a_keys)[0]
    t.db["llm_application_credentials"] = [c for c in t.db["llm_application_credentials"] if c["id"] != gone]
    for r in t.db["policy_match_rules"]:
        for e in (r.get("matchCriteria") or {}).get("llmApplications") or []:
            e["applicationCredentialsIds"] = [i for i in e["applicationCredentialsIds"] if i != gone]
    kit._kc.clear()
    kit._kc.update(a_kc)
    kit.save_cfg(a_cfg)
    logs = []
    kit.setup_apply(t, kit.load_cfg(), kit.default_answers(kit.tenant_facts(t, kit.load_cfg())),
                    lambda lv, m: logs.append(m))
    assert any("no longer exists in AI Guard" in m for m in logs)
    ids = {a["das_cred_id"] for a in kit.load_cfg()["state"]["apps"].values()}
    assert gone not in ids and ids <= {c["id"] for c in t.db["llm_application_credentials"]}


def test_lost_secret_retires_only_this_computers_own_key(env):
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    cfg = kit.load_cfg()
    app = next(iter(cfg["state"]["apps"]))
    own = cfg["state"]["apps"][app]["das_cred_id"]
    del kit._kc[f"{app}:detections"]
    kit.setup_apply(t, kit.load_cfg(), kit.default_answers(kit.tenant_facts(t, kit.load_cfg())), lambda *a: None)
    assert own not in {c["id"] for c in t.db["llm_application_credentials"]}
    assert kit.load_cfg()["state"]["apps"][app]["das_cred_id"] != own


def test_detection_api_403_points_to_setup(env):
    kit, _ = env("run")
    assert "Repair setup" in kit.hint(kit.KitError("Detection API HTTP 403: forbidden"))
    assert "ZIdentity" in kit.hint(kit.KitError("policies.list failed: 403 Forbidden"))


def test_activity_log_masks_secrets_everywhere(env, tmp_path):
    kit, _ = env("status")
    kit.LOG_DIR = tmp_path / "logs"
    kit.remember_secret("sk-REALSECRETVALUE1234")
    e = kit.activity("api", "add_credential", "ok",
                     request={"body": {"name": "x", "apiCredentials": {"type": "API_KEY", "key": "sk-REALSECRETVALUE1234"}}},
                     response={"id": 5, "key": "zz-newappkey-9999", "note": "uses sk-REALSECRETVALUE1234 inside"})
    text = json.dumps(e) + (tmp_path / "logs").joinpath(next((tmp_path / "logs").iterdir()).name).read_text()
    assert "REALSECRETVALUE" not in text and "newappkey" not in text
    assert e["detail"]["request"]["body"]["apiCredentials"]["type"] == "API_KEY"
    assert e["detail"]["response"]["id"] == 5
    # diagnostics bundle carries the logs, still masked
    import io
    import zipfile
    z = zipfile.ZipFile(io.BytesIO(kit.diagnostics_zip()))
    assert "about.json" in z.namelist() and any(n.startswith("logs/") for n in z.namelist())
    assert all("REALSECRETVALUE" not in z.read(n).decode() for n in z.namelist())


def test_health_and_repair_after_key_deleted_elsewhere(env):
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    cfg = kit.load_cfg()
    assert kit.health(t, cfg)["ok"]
    assert cfg["answers"]["mode"] == "monitor" and "key" not in json.dumps(cfg["answers"]).replace('"keep"', "")
    # the SE switched to a blocking profile, then another computer deleted this one's key
    kit.policy_mode(t, cfg, "everything")
    app = next(iter(cfg["state"]["apps"]))
    gone = cfg["state"]["apps"][app]["das_cred_id"]
    t.db["llm_application_credentials"] = [c for c in t.db["llm_application_credentials"] if c["id"] != gone]
    for r in t.db["policy_match_rules"]:
        for e in (r.get("matchCriteria") or {}).get("llmApplications") or []:
            e["applicationCredentialsIds"] = [i for i in e["applicationCredentialsIds"] if i != gone]
    h = kit.health(t, kit.load_cfg())
    assert not h["ok"] and any("removed from AI Guard" in p for p in h["problems"])
    kit.repair(t, kit.load_cfg(), lambda *a: None)
    cfg = kit.load_cfg()
    assert kit.health(t, cfg)["ok"]
    assert kit.policy_mode(t, cfg)[0] == "everything", "repair must keep the SE's policy profile"


def test_health_flags_key_missing_from_rule(env):
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    rule = next(r for r in t.db["policy_match_rules"] if r["name"] == "SE-Demo: detection apps")
    rule["matchCriteria"]["llmApplications"] = rule["matchCriteria"]["llmApplications"][:1]
    h = kit.health(t, kit.load_cfg())
    assert not h["ok"] and any("isn't in the rule" in p for p in h["problems"])


def test_scan_result_carries_request_and_response(env):
    kit, t = env("setup", "--yes")
    kit.cmd_setup()
    cfg = kit.load_cfg()

    def fake_scan(key, text, direction="IN", user=None, timeout=60, trace=None):
        d = {"action": "ALLOW", "severity": "LOW", "detectorResponses": {}}
        if trace is not None:
            trace.update(request={"method": "POST", "body": {"content": text, "direction": direction, "user": user}},
                         status=200, response=d)
        return d, 3
    kit.das_scan = fake_scan
    r = kit.run_one(cfg, {"text": "hello", "direction": "IN"}, next(iter(cfg["state"]["apps"])), "a@b.c", "detect")
    assert r["exchange"]["request"]["body"]["content"] == "hello" and r["exchange"]["response"]["action"] == "ALLOW"


def test_guided_demo_switches_policy_per_step_without_a_fixed_countdown():
    """Each step has Monitor / Block, the policy switches when the step opens, and Run only waits for what's left."""
    html = (ROOT / "gui.html").read_text(encoding="utf-8")
    assert "for(let i=30;i>0;i--)" not in html            # the old fixed 30-second countdown is gone
    assert 'id="smode"' in html and "S.choice[S.step]=b.dataset.v" in html
    assert "function preApply(" in html and "demoOpen()" in html   # pre-switch only while the Guided demo tab is open
    assert "n=applyLeft()" in html                         # Run waits for the remaining time only


def test_guided_demo_block_levels_match_the_policy_profiles(monkeypatch, tmp_path):
    """The Block button's level comes from the same detector sets the profiles use; nothing-to-block steps get no switch."""
    kit = load_kit(monkeypatch, tmp_path, ["help"])
    lv = kit.block_levels()
    assert set(lv["attacks"]) == set().union(*kit.ATTACKS.values())
    assert set(lv["data"]) == {"secrets", "pii"} and "prompt_tags" in lv["never"]
    html = (ROOT / "gui.html").read_text(encoding="utf-8")
    assert '>Block</button>' in html and "if(!canSwitch()||!bl)return" in html


def test_guided_demo_ends_the_policy_wait_when_the_step_prompt_gets_the_new_verdict():
    """The wait is a 30 s ceiling; probe scans (as kit-policy-check) end it as soon as the policy is enforced."""
    html = (ROOT / "gui.html").read_text(encoding="utf-8")
    assert "async function probe(m)" in html and 'user:"kit-policy-check"' in html
    assert "const APPLY_MS=30000" in html                  # still the upper limit
    assert html.count("probe(") >= 4                       # defined, and started after every switch


def test_a_rejected_oneapi_login_is_one_clear_message_not_a_wall_of_sdk_errors(monkeypatch, tmp_path):
    import logging
    kit = load_kit(monkeypatch, tmp_path, ["help"])
    t = kit.Tenant.__new__(kit.Tenant)
    failing = types.SimpleNamespace(list_policies=lambda: (None, None, Exception(
        "401 Unauthorized - token refresh attempts exhausted or OAuth not available.")))
    t.ag = types.SimpleNamespace(policies=failing)
    with pytest.raises(kit.KitError) as e:
        t.call("policies", "list_policies")
    assert "Use different credentials" in str(e.value) and "token refresh" not in str(e.value)
    kit.quiet_sdk()
    assert logging.getLogger("zscaler-sdk-python").level == logging.CRITICAL


def test_diagnostics_keep_the_newest_log_entries(monkeypatch, tmp_path):
    """The zip used to keep only the first 20,000 characters of a day's log, i.e. the oldest entries."""
    import io
    import zipfile
    kit = load_kit(monkeypatch, tmp_path, ["help"])
    for i in range(400):
        kit.activity("setup", f"entry {i} " + "x" * 200)
    data = zipfile.ZipFile(io.BytesIO(kit.diagnostics_zip()))
    log = data.read(next(n for n in data.namelist() if n.startswith("logs/"))).decode()
    assert "entry 399 " in log and "entry 0 " in log and len(log) > 20000
    kit.activity("api", "big", response={"items": ["y" * 30000]})
    data = zipfile.ZipFile(io.BytesIO(kit.diagnostics_zip()))
    lines = data.read(next(n for n in data.namelist() if n.startswith("logs/"))).decode().splitlines()
    assert all(json.loads(line) for line in lines)    # long entries stay valid JSON


def test_deployment_guide_ships_and_is_stamped_with_the_version(tmp_path, monkeypatch):
    """The guide is versioned with the kit: it's in the zip, and the release copy names the versions it describes."""
    import importlib.util
    root = pathlib.Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("build_guide", root / "tools" / "build_guide.py")
    bg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bg)
    kit, zia = bg.versions()
    text = bg.stamped((root / "docs" / "DEPLOYMENT-GUIDE.md").read_text(encoding="utf-8"), kit, zia)
    assert text.startswith("# AI Guard + ZIA SE Demo Kit: Deployment Guide\n\n")
    assert f"AI Guard SE Demo Kit {kit} · ZIA SE Demo Kit {zia}" in text.splitlines()[2]
    pkg = (root / "tools" / "package.py").read_text(encoding="utf-8")
    assert '"docs"]' in pkg
    assert "zslogin.net" in text and "SE-Demo Z-Tunnel 2.0" in text


def test_keychain_entry_owned_by_an_older_python_is_replaced(monkeypatch, tmp_path):
    """macOS -25244: the entry was saved by a previous Python (uv moved it), so it can't be updated in place. The kit
    deletes its own stale entry and saves the new value instead of failing setup's repair."""
    monkeypatch.setattr(sys, "argv", ["aiguard_kit.py", "setup"])
    spec = importlib.util.spec_from_file_location("aiguard_kit_kc_test", ROOT / "aiguard_kit.py")
    kit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kit)   # the real kc_set (load_kit swaps in a dict)
    monkeypatch.setattr(kit, "WINDOWS", False)   # the Mac case (Windows shows Credential Manager advice instead)
    import keyring
    store = {("aiguard-se-kit", "SE-Demo: Anthropic App:proxy"): "old"}
    locked = {"on": True}

    def set_pw(svc, user, pw):
        if (svc, user) in store and locked["on"]:
            raise Exception("Can't store password on keychain: (-25244, 'Unknown Error')")
        store[(svc, user)] = pw

    def del_pw(svc, user):
        store.pop((svc, user), None)
    monkeypatch.setattr(keyring, "set_password", set_pw)
    monkeypatch.setattr(keyring, "delete_password", del_pw)
    monkeypatch.setattr(keyring, "get_password", lambda s, u: store.get((s, u)))
    kit.kc_set("SE-Demo: Anthropic App:proxy", "new-key-123")
    assert store[("aiguard-se-kit", "SE-Demo: Anthropic App:proxy")] == "new-key-123"
    # if even a fresh entry can't be saved, the error says exactly which entry to delete
    monkeypatch.setattr(keyring, "set_password", lambda *a: (_ for _ in ()).throw(Exception("(-25244, 'Unknown Error')")))
    with pytest.raises(kit.KitError, match="delete-generic-password -s aiguard-se-kit"):
        kit.kc_set("SE-Demo: Anthropic App:proxy", "x")


def test_background_console_reuses_a_running_one_and_quits_from_the_button(monkeypatch, tmp_path):
    """The shortcut starts the console with no terminal window. Clicking it again opens the running console instead
    of starting a second one, and the Quit button stops it (there is no window to close)."""
    import socket
    import threading
    import time
    import urllib.request
    kit = load_kit(monkeypatch, tmp_path, ["gui", "--background", "--no-browser"])
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        port = sk.getsockname()[1]
    monkeypatch.setattr(kit, "ARGS", ["gui", "--background", "--no-browser", "--port", str(port)])
    monkeypatch.setattr(kit, "update_check", lambda: None)
    t = threading.Thread(target=kit.cmd_gui, daemon=True)
    t.start()
    for _ in range(300):   # CI machines can be slow to start the server
        if kit.console_file().exists() or not t.is_alive():
            break
        time.sleep(0.1)
    assert t.is_alive(), "the console stopped on its own"
    assert json.loads(kit.console_file().read_text())["port"] == port
    assert kit.running_console() == f"http://127.0.0.1:{port}/"
    opened = []
    import webbrowser
    monkeypatch.setattr(webbrowser, "open", lambda u: opened.append(u))
    kit.cmd_gui()                       # second click: no new server, just the browser
    assert opened == [f"http://127.0.0.1:{port}/"]
    html = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode()
    token = re.search(r'TOKEN\s*=\s*"([^"]+)"', html) or re.search(r'TOKEN="([^"]+)"', html)
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/quit", data=b"{}", method="POST",
                                 headers={"X-Kit-Token": token.group(1), "Content-Type": "application/json"})
    assert json.loads(urllib.request.urlopen(req).read())["ok"]
    t.join(5)
    assert not t.is_alive() and not kit.console_file().exists() and kit.running_console() is None


def test_restart_and_installers_bring_the_console_up_without_a_terminal(monkeypatch, tmp_path):
    """After an update the console comes back in the background even if it had been started in a terminal (by the
    installer or an older shortcut); the installers start it in the background too."""
    import subprocess
    kit = load_kit(monkeypatch, tmp_path, ["gui"])
    calls = []
    monkeypatch.setattr(subprocess, "Popen", lambda cmd, **kw: calls.append((cmd, kw)))
    monkeypatch.setattr(kit.os, "_exit", lambda code: calls.append(("exit", code)))
    srv = types.SimpleNamespace(socket=types.SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(kit, "WINDOWS", False)
    kit.restart_console(srv, 8765)
    cmd, kw = calls[0]
    assert cmd[:2] == ["nohup", "bash"] and "--background" in cmd and "--restarted" in cmd and kw["start_new_session"]
    assert calls[-1] == ("exit", 0)
    calls.clear()
    monkeypatch.setattr(kit, "WINDOWS", True)
    kit.restart_console(srv, 8765)
    assert calls[0][0][0].endswith("conhost.exe") and calls[0][0][1] == "--headless" and "--background" in calls[0][0]
    mac = (ROOT / "Install AI Guard Kit.command").read_text(encoding="utf-8")
    win = (ROOT / "Install AI Guard Kit.cmd").read_text(encoding="utf-8")
    assert 'nohup "$HOME/.aiguard-se-kit/app/aiguard-kit" gui --background' in mac and "Keep this window open" not in mac
    assert 'conhost.exe" --headless' in win and "gui --background" in win and "Keep this window open" not in win


def test_feed_raw_route_serves_one_event_and_needs_the_token(monkeypatch, tmp_path):
    import socket
    import threading
    import time
    import urllib.error
    import urllib.request
    kit = load_kit(monkeypatch, tmp_path, ["gui", "--background", "--no-browser"])
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        port = sk.getsockname()[1]
    monkeypatch.setattr(kit, "ARGS", ["gui", "--background", "--no-browser", "--port", str(port)])
    monkeypatch.setattr(kit, "update_check", lambda: None)
    t = threading.Thread(target=kit.cmd_gui, daemon=True)
    t.start()
    for _ in range(300):
        if kit.console_file().exists() or not t.is_alive():
            break
        time.sleep(0.1)
    base = f"http://127.0.0.1:{port}"
    html = urllib.request.urlopen(base + "/").read().decode()
    tok = (re.search(r'TOKEN\s*=\s*"([^"]+)"', html) or re.search(r'TOKEN="([^"]+)"', html)).group(1)
    get = lambda u, h=None: urllib.request.urlopen(urllib.request.Request(base + u, headers=h or {}))  # noqa: E731
    kit.FEED_RAW["eai-ev 1"] = '{"id": "ev 1"}'
    assert json.loads(get("/api/feed/raw?id=eai-ev%201", {"X-Kit-Token": tok}).read())["raw"] == '{"id": "ev 1"}'
    with pytest.raises(urllib.error.HTTPError) as gone:
        get("/api/feed/raw?id=eai-nope", {"X-Kit-Token": tok})
    assert gone.value.code == 404
    with pytest.raises(urllib.error.HTTPError):   # no token, no data
        get("/api/feed/raw?id=eai-ev%201")
    req = urllib.request.Request(base + "/api/quit", data=b"{}", method="POST",
                                 headers={"X-Kit-Token": tok, "Content-Type": "application/json"})
    urllib.request.urlopen(req).read()
    t.join(5)
