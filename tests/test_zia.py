"""Offline tests for the ZIA module and traffic generator: a fake ZIA tenant and a fake web stand in for Zscaler."""
import copy
import hashlib
import importlib.util
import io
import itertools
import json
import pathlib
import re
import sys
import types
import zipfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from test_kit import load_kit, windows  # noqa: E402


def camel(d):
    if isinstance(d, list):
        return [camel(x) for x in d]
    if not isinstance(d, dict):
        return d
    return {re.sub(r"_([a-z])", lambda m: m.group(1).upper(), k): camel(v) for k, v in d.items()}


class FakeZia:
    """In-memory ZIA: the parts of the OneAPI SDK the kit calls. Returns camelCase like the real API."""

    def __init__(self, cbi=True, actions=None, file_types=None):
        self.ids = itertools.count(1000)
        self.db = {
            "url_filtering": [{"id": 1, "name": "URL Filtering Rule-1", "order": 1, "state": "DISABLED"},
                              {"id": 2, "name": "Isolate of Misc and Unknown Cat", "order": 2}],
            "file_type_control_rule": [], "dlp_web_rules": [{"id": 3, "name": "DLP PCI Rule-1", "order": 1}],
            "cloud_firewall_rules": [{"id": 4, "name": "Zscaler Proxy Traffic", "order": 1},
                                     {"id": 5, "name": "Recommended Firewall Rule", "order": 2}],
            "cloud_firewall_dns": [{"id": 6, "name": "Default Firewall DNS Rule", "order": 1}],
            "cac": {"AI_ML": [{"id": 7, "name": "AI_ML_App_Rule_1", "order": 1}]},
            "rule_labels": [], "url_categories": [{"id": "CUSTOM_00", "configuredName": "Home allow list"}],
            "network_services": [{"id": 8, "name": "HTTPS"}],
            "users": [{"id": 501, "name": "ztest", "email": "ztest@pyite.buzz"},
                      {"id": 502, "name": "SE Traffic", "email": "se-demo-traffic@pyite.buzz"}],
            "ssl": [{"id": 9, "name": "Decrypt All Traffic", "state": "ENABLED", "action": {"type": "DECRYPT"}}],
        }
        self.engines = [{"id": 61, "predefinedEngineName": "PCI"}, {"id": 17, "name": "PII (US) - Low Volume"},
                        {"id": 2, "name": "5 or more Credit Card Numbers"}, {"id": 19, "name": "Credentials and Secrets"},
                        {"id": 1, "name": "5 or more PII Identifiers"}]
        self.cbi = [{"id": "cbi-1", "name": "Default isolation", "url": "https://isolation.example", "defaultProfile": True}] if cbi else []
        self.actions = actions
        self.file_types = file_types
        self.calls = []
        self.activations = 0
        self.zins = {}

    def _rules(self, resource, rule_type=None):
        if resource == "cloudappcontrol":
            return self.db["cac"].setdefault(rule_type, [])
        return self.db[resource]

    def _add(self, objs, kw):
        o = dict(camel(copy.deepcopy(kw)), id=next(self.ids))
        if "order" in o:   # inserting shifts the others down, like ZIA
            for x in objs:
                if int(x.get("order") or 0) >= o["order"]:
                    x["order"] = int(x["order"]) + 1
        objs.append(o)
        return copy.deepcopy(o)

    def call(self, resource, method, *a, **kw):
        self.calls.append((resource, method, a, kw))
        if resource.startswith("zins."):
            return copy.deepcopy(self.zins.get(method + str(sorted(kw.items())), self.zins.get(method, [])))
        if resource == "activate":
            self.activations += method == "activate"
            return {"status": "ACTIVE"}
        if resource == "user_management":
            return copy.deepcopy(self.db["users"])
        if resource == "dlp_engine":
            return copy.deepcopy(self.engines)
        if resource == "cloud_browser_isolation":
            return copy.deepcopy(self.cbi)
        if resource == "ssl_inspection_rules":
            return copy.deepcopy(self.db["ssl"])
        if resource == "file_type_control_rule" and method == "list_file_type_categories":
            if self.file_types is None:
                raise sys.modules[type(self).kit_module].KitError("file_type_control_rule.list failed: 404")
            return [{"name": n} for n in self.file_types]
        if resource == "cloudappcontrol" and method == "list_available_actions":
            return list(self.actions.get(a[0], [])) if self.actions else []
        if resource == "rule_labels":
            objs = self.db["rule_labels"]
            if method == "list_labels":
                return copy.deepcopy(objs)
            if method == "add_label":
                return self._add(objs, kw)
            self.db["rule_labels"] = [o for o in objs if o["id"] != a[0]]
            return None
        if resource == "url_categories":
            objs = self.db["url_categories"]
            if method == "list_categories":
                return copy.deepcopy(objs)
            if method == "add_url_category":
                o = dict(camel(copy.deepcopy(kw)), id=f"CUSTOM_{next(self.ids)}")
                objs.append(o)
                return copy.deepcopy(o)
            if method == "update_url_category":
                i = next(i for i, o in enumerate(objs) if o["id"] == a[0])
                objs[i] = dict(camel(copy.deepcopy(kw)), id=a[0])
                return copy.deepcopy(objs[i])
            self.db["url_categories"] = [o for o in objs if o["id"] != a[0]]
            return None
        if resource == "cloud_firewall":
            objs = self.db["network_services"]
            if method == "list_network_services":
                q = (kw.get("query_params") or {}).get("search", "")
                return copy.deepcopy([o for o in objs if q.lower() in o["name"].lower()])
            if method == "add_network_service":
                return self._add(objs, kw)
            if method == "update_network_service":
                i = next(i for i, o in enumerate(objs) if o["id"] == a[0])
                objs[i] = dict(camel(copy.deepcopy(kw)), id=a[0])
                return copy.deepcopy(objs[i])
            self.db["network_services"] = [o for o in objs if o["id"] != a[0]]
            return None
        # rules
        rule_type = a[0] if resource == "cloudappcontrol" else None
        args = a[1:] if resource == "cloudappcontrol" else a
        objs = self._rules(resource, rule_type)
        if method == "list_rules":
            return copy.deepcopy(objs)
        if method == "add_rule":
            return self._add(objs, kw)
        if method == "update_rule":
            i = next(i for i, o in enumerate(objs) if o["id"] == args[0])
            objs[i] = dict(camel(copy.deepcopy(kw)), id=args[0])
            return copy.deepcopy(objs[i])
        if method == "delete_rule":
            objs[:] = [o for o in objs if o["id"] != args[0]]
            return None
        raise AssertionError(f"unexpected call {resource}.{method}")

    def all_rules(self):
        out = [r for k in ("url_filtering", "file_type_control_rule", "dlp_web_rules", "cloud_firewall_rules",
                           "cloud_firewall_dns") for r in self.db[k]]
        return out + [r for v in self.db["cac"].values() for r in v]


@pytest.fixture
def zenv(monkeypatch, tmp_path):
    def make(*argv, **fake_kw):
        kit = load_kit(monkeypatch, tmp_path, list(argv))
        z = kit.product("zia")
        fake = FakeZia(**fake_kw)
        FakeZia.kit_module = "aiguard_kit_zia_kit"
        sys.modules["aiguard_kit_zia_kit"] = kit
        monkeypatch.setattr(z, "ZiaTenant", lambda cfg: fake)
        kit.save_cfg({"vanity_domain": "paulaiuto", "client_id": "abcd1234"})
        kit._kc["oneapi-client-secret"] = "s3cret"
        return kit, z, fake
    return make


def mine(fake):
    return sorted(r["name"] for r in fake.all_rules() if r["name"].startswith("SE-Demo:"))


def test_product_registry_loads_zia_and_aiguard_is_builtin(zenv):
    kit, z, _ = zenv("zia", "status")
    assert kit.product("aiguard") is None
    assert kit.product("zia") is z and z.K.PREFIX == "SE-Demo"
    kit.PREFIX = "Acme"   # the module reads the kit's settings live
    assert z.zname("x") == "Acme: x"


def test_missing_product_module_gives_clear_error(zenv, monkeypatch):
    kit, _, _ = zenv("zia")
    monkeypatch.setitem(kit.PRODUCTS, "zpa", {"label": "Private Access (ZPA)", "module": "zpa_module.py"})
    with pytest.raises(kit.KitError, match="isn't in this copy"):
        kit.product("zpa")


def test_template_names_fit_zia_limits_and_are_unique():
    tpl = json.loads((ROOT / "zia_policy_template.json").read_text(encoding="utf-8"))
    names = [f"SE-Demo: {r['name']}" for k in ("url_filtering", "isolation", "cloud_app_control", "file_type_control",
                                               "dlp", "firewall", "dns") for r in tpl[k]]
    names += [f"SE-Demo: {tpl['tenant_check']['name']}", f"SE-Demo: {tpl['network_service']['name']}"]
    assert all(len(n) <= 31 for n in names), [n for n in names if len(n) > 31]
    assert len(names) == len(set(names))
    # DNS blocks must not hide the URL-filtering blocks the web sweep is meant to show
    cat = json.loads((ROOT / "zia_traffic.json").read_text(encoding="utf-8"))
    web_cats = {w["category"] for w in cat["web"]}
    assert not {c for r in tpl["dns"] for c in r["res_categories"]} & web_cats


def test_setup_creates_scoped_rules_activates_and_is_idempotent(zenv):
    kit, z, fake = zenv("zia", "setup", "--user", "se-demo-traffic@pyite.buzz", "--yes")
    kit.cmd_zia()
    made = mine(fake)
    assert "SE-Demo: Block gambling" in made and "SE-Demo: Block card numbers" in made
    assert "SE-Demo: Isolate games" in made and "SE-Demo: Block demo ports" in made
    assert all(len(n) <= 31 for n in made)
    label = next(l for l in fake.db["rule_labels"] if l["name"] == "SE-Demo: SE-Demo")
    for r in fake.all_rules():
        if r["name"].startswith("SE-Demo:"):
            assert r["users"] == [502], r["name"]           # only the test user
            assert r["labels"] == [label["id"]] and r["state"] == "ENABLED"
    tc = next(c for c in fake.db["url_categories"] if c["configuredName"] == "SE-Demo: tenant check")
    tenant_rule = next(r for r in fake.db["url_filtering"] if r["name"] == "SE-Demo: Block tenant check")
    assert tenant_rule["urlCategories"] == [tc["id"]] and "www.example.com" in tc["urls"]
    ns = next(s for s in fake.db["network_services"] if s["name"] == "SE-Demo: demo ports")
    assert next(r for r in fake.db["cloud_firewall_rules"] if r["name"] == "SE-Demo: Block demo ports")["nwServices"] == [ns["id"]]
    dlp = next(r for r in fake.db["dlp_web_rules"] if r["name"] == "SE-Demo: Block card numbers")
    assert dlp["dlpEngines"] == [2] and dlp["action"] == "BLOCK"
    # demo rules go above the tenant's own, so they win for the test user
    assert min(r["order"] for r in fake.db["url_filtering"] if r["name"].startswith("SE-Demo:")) == 1
    assert fake.activations == 1
    assert kit.load_cfg()["zia"]["users"] == [{"id": 502, "name": "SE Traffic", "email": "se-demo-traffic@pyite.buzz"}]
    before = (len(fake.all_rules()), len(fake.db["url_categories"]), len(fake.db["network_services"]), len(fake.db["rule_labels"]))
    kit.cmd_zia()   # again: updates in place
    assert (len(fake.all_rules()), len(fake.db["url_categories"]), len(fake.db["network_services"]),
            len(fake.db["rule_labels"])) == before
    assert fake.activations == 2
    # the tenant's own rules are untouched
    assert {"URL Filtering Rule-1", "DLP PCI Rule-1", "AI_ML_App_Rule_1"} <= {r["name"] for r in fake.all_rules()}


def test_setup_without_user_in_yes_mode_stops_before_changes(zenv, capsys):
    kit, _, fake = zenv("zia", "setup", "--yes")
    with pytest.raises(SystemExit):
        kit.cmd_zia()
    assert "--user" in capsys.readouterr().out
    assert not mine(fake) and fake.activations == 0


def test_unknown_test_user_is_rejected(zenv, capsys):
    kit, _, fake = zenv("zia", "setup", "--user", "nobody@pyite.buzz", "--yes")
    with pytest.raises(SystemExit):
        kit.cmd_zia()
    assert "No ZIA user nobody@pyite.buzz" in capsys.readouterr().out and not mine(fake)


def test_tenant_differences_skip_or_trim_rules(zenv):
    kit, z, fake = zenv("zia", cbi=False, actions={"FILE_SHARE": ["ALLOW_FILE_SHARE_VIEW"], "AI_ML": ["ALLOW_AI_ML_WEB_USE", "BLOCK_AI_ML_WEB_USE"]},
                        file_types=["FTCATEGORY_WINDOWS_EXECUTABLES", "FTCATEGORY_PDF_DOCUMENT"])
    cfg = kit.load_cfg()
    cfg["zia"] = {"users": [{"id": 502, "name": "SE Traffic"}]}
    rules, notes = z.plan(fake, cfg)
    names = {n for _, _, n, _ in rules}
    assert "SE-Demo: Isolate games" not in names and any("Isolation" in n for n in notes)
    assert "SE-Demo: Block file uploads" not in names and any("FILE_SHARE" in n for n in notes)
    genai = next(b for k, rt, n, b in rules if n == "SE-Demo: Block risky GenAI")
    assert genai["actions"] == ["BLOCK_AI_ML_WEB_USE"]
    ftc = next(b for k, _, n, b in rules if n == "SE-Demo: Block EXE downloads")
    assert ftc["file_types"] == ["FTCATEGORY_WINDOWS_EXECUTABLES"] and any("FTCATEGORY_MSI" in n for n in notes)
    fake.engines = [e for e in fake.engines if e.get("name") != "5 or more Credit Card Numbers"]
    rules, notes = z.plan(fake, cfg)
    assert "SE-Demo: Block card numbers" not in {n for _, _, n, _ in rules}


def test_a_rejected_rule_is_reported_and_the_rest_continue(zenv, monkeypatch):
    kit, z, fake = zenv("zia")
    cfg = kit.load_cfg()
    cfg["zia"] = {"users": [{"id": 502, "name": "SE Traffic"}]}
    real = fake.call

    def picky(resource, method, *a, **kw):
        if resource == "cloud_firewall_dns" and method == "add_rule":
            raise kit.KitError('cloud_firewall_dns.add_rule failed: {"code": "INVALID_INPUT_ARGUMENT"}')
        return real(resource, method, *a, **kw)
    fake.call = picky
    logs = []
    res = z.setup_apply(fake, cfg, lambda lv, m: logs.append((lv, m)))
    assert res["failed"] == ["SE-Demo: Block marijuana DNS"] and res["rules"] > 10
    assert any(lv == "warn" and "INVALID_INPUT" in m and "zia_policy_template.json" in m for lv, m in logs)
    assert fake.activations == 1


def test_predefined_rules_pinned_at_top_push_demo_rules_down(zenv):
    kit, z, fake = zenv("zia")
    real = fake.call

    def pinned(resource, method, *a, **kw):
        if resource == "cloud_firewall_rules" and method == "add_rule" and kw.get("order") == 1:
            raise kit.KitError("cloud_firewall_rules.add_rule failed: rule order 1 is reserved for predefined rules")
        return real(resource, method, *a, **kw)
    fake.call = pinned
    cfg = kit.load_cfg()
    cfg["zia"] = {"users": [{"id": 502, "name": "SE Traffic"}]}
    z.setup_apply(fake, cfg, lambda *a: None)
    assert next(r for r in fake.db["cloud_firewall_rules"] if r["name"] == "SE-Demo: Block demo ports")["order"] == 2


def test_teardown_removes_only_kit_objects_and_activates(zenv):
    kit, z, fake = zenv("zia", "setup", "--user", "se-demo-traffic@pyite.buzz", "--yes")
    kit.cmd_zia()
    assert mine(fake)
    kit.ARGS[:] = ["zia", "teardown", "--force"]
    kit.FORCE = True
    kit.cmd_zia()
    assert not mine(fake)
    assert not [c for c in fake.db["url_categories"] if c["configuredName"].startswith("SE-Demo:")]
    assert not [s for s in fake.db["network_services"] if s["name"].startswith("SE-Demo:")]
    assert not fake.db["rule_labels"]
    assert {"Home allow list"} == {c["configuredName"] for c in fake.db["url_categories"]}
    assert {"URL Filtering Rule-1", "Zscaler Proxy Traffic", "AI_ML_App_Rule_1"} <= {r["name"] for r in fake.all_rules()}
    assert fake.activations == 2
    assert "state" not in kit.load_cfg()["zia"]


def test_aiguard_teardown_leaves_zia_settings(zenv):
    kit, _, _ = zenv("zia")
    cfg = kit.load_cfg()
    cfg["zia"] = {"users": [{"id": 502, "name": "SE Traffic"}], "schedule": {"every": 30, "count": 4}}
    cfg["state"] = {"apps": {}}
    kit.save_cfg(cfg)
    t = types.SimpleNamespace(list=lambda r: [], call=lambda *a, **k: None)
    kit.teardown(t, kit.load_cfg(), confirm=False, log=lambda *a: None)
    assert kit.load_cfg()["zia"]["users"][0]["id"] == 502


def test_preflight_checks(zenv):
    kit, z, fake = zenv("zia")
    checks, t = z.preflight(kit.load_cfg(), write_probe=True)
    by = {c["id"]: c for c in checks}
    assert by["zia-login"]["status"] == "ok" and by["zia-read"]["status"] == "ok"
    assert by["zia-dlp"]["status"] == "ok" and by["zia-ssl"]["status"] == "ok"
    assert by["zia-write"]["status"] == "ok" and not fake.db["rule_labels"]   # probe cleaned up
    assert by["zia-tunnel"]["status"] == "info" and "Z-Tunnel 2.0" in by["zia-tunnel"]["fix"]
    fake.db["ssl"] = [{"id": 9, "name": "Default", "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}}]
    cfg = kit.load_cfg()
    cfg["zia"] = {"users": [{"id": 9, "name": "gone", "email": "gone@pyite.buzz"}]}
    by = {c["id"]: c for c in z.preflight(cfg)[0]}
    assert by["zia-ssl"]["status"] == "warn" and by["zia-user"]["status"] == "fail"


def test_preflight_without_credentials(zenv):
    kit, z, _ = zenv("zia")
    kit._kc.clear()
    checks, t = z.preflight(kit.load_cfg())
    assert t is None and checks[0]["status"] == "fail" and "./aiguard-kit setup" in checks[0]["fix"]


def test_dashboards_report_empty_and_partial_panels(zenv):
    kit, z, fake = zenv("zia")
    fake.zins = {"get_no_grouping": [{"name": "TOTAL", "total": 232105}],
                 "get_no_grouping[('action_filter', 'BLOCK')]": [{"name": "TOTAL", "total": 0}],
                 "get_traffic_by_action": [{"name": "ALLOW", "total": 95946}],
                 "get_apps": [], "get_threat_class": [{"name": "ADVANCED", "total": 14}]}
    rep = z.dashboards(fake)
    by = {p["id"]: p["status"] for p in rep["panels"]}
    assert by["web"] == "ok" and by["web-blocked"] == "empty" and by["firewall"] == "partial"
    assert by["shadow-it"] == "empty" and by["threats"] == "ok"
    assert rep["end"] - rep["start"] == 7 * 86400 * 1000


def test_zia_schedule_is_separate_from_aiguard(zenv, monkeypatch, tmp_path):
    import subprocess
    kit, z, _ = zenv("zia", "schedule", "install", "--every", "30")
    windows(kit, monkeypatch, tmp_path)
    ran = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: ran.append(cmd) or types.SimpleNamespace(returncode=0, stderr="", stdout=""))
    kit.cmd_zia()
    cmd = ran[-1]
    assert cmd[cmd.index("/TN") + 1] == "AIGuardSEKit-ZIA-default" and cmd[cmd.index("/MO") + 1] == "30"
    wrapper = (kit.CFG_DIR / "zia-traffic.cmd").read_text()
    assert '"zia" "traffic" "--count" "4"' in wrapper and "zia-traffic.log" in wrapper
    cfg = kit.load_cfg()
    assert cfg["zia"]["schedule"] == {"every": 30, "count": 4} and "schedule" not in cfg
    assert kit.schedule_cmdline(12)[1:3] == ["run", "--trickle"]   # AI Guard's job unchanged


def test_install_ships_zia_files():
    spec = importlib.util.spec_from_file_location("pkg", ROOT / "tools/package.py")
    pkg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pkg)
    for f in ("zia_module.py", "zia_traffic.py", "zia_policy_template.json", "zia_traffic.json", "ZIA.md"):
        assert f in pkg.SHIP and (ROOT / f).exists()
    text = (ROOT / "aiguard_kit.py").read_text(encoding="utf-8")
    assert '"zia_module.py", "zia_traffic.py", "zia_policy_template.json", "zia_traffic.json", "ZIA.md"' in text


def test_console_state_endpoint(zenv):
    kit, z, fake = zenv("zia")
    cfg = kit.load_cfg()
    st = z.api_get("/api/zia/state", cfg, lambda: fake)
    assert st["creds"] is True and st["users"] == [] and st["prefix"] == "SE-Demo"
    assert z.api_get("/api/zia/nope", cfg, lambda: fake) is None


# ---------------------------------------------------------------- traffic generator
@pytest.fixture
def tm():
    spec = importlib.util.spec_from_file_location("zia_traffic_under_test", ROOT / "zia_traffic.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_eicar_is_the_standard_test_string_but_never_stored_whole(tm):
    assert hashlib.md5(tm.eicar().encode()).hexdigest() == "44d88612fea8a8f36de82e1278abb02f"
    needle = tm.eicar()[10:40].encode()
    for p in list(ROOT.glob("*.py")) + list(ROOT.glob("*.json")) + list(ROOT.glob("*.md")) + list((ROOT / "tests").glob("*.py")):
        assert needle not in p.read_bytes(), f"{p.name} contains the EICAR string; antivirus would quarantine it"


def test_fake_data_is_well_formed_and_from_test_ranges(tm):
    import random
    rnd = random.Random(7)
    for _ in range(200):
        c = tm.fake_card(rnd)
        assert tm.luhn_ok(c) and c[:6] in tm.TEST_BINS and len(c) in (15, 16)
        s = tm.fake_ssn(rnd)
        area = int(s[:3])
        assert re.fullmatch(r"\d{3}-\d{2}-\d{4}", s) and 100 <= area < 900 and area != 666 and s[4:6] != "00"
    kid, sec = tm.fake_aws_key(rnd)
    assert re.fullmatch(r"AKIA[A-Z2-7]{16}", kid) and len(sec) == 40
    assert tm.luhn_ok("4111111111111111") and not tm.luhn_ok("4111111111111112")


def test_upload_files_are_real_files(tm):
    files = {n: d for n, d, _ in tm.upload_files(tm.fake_records(4))}
    assert files["statement.pdf"].startswith(b"%PDF-1.4") and b"%%EOF" in files["statement.pdf"]
    assert zipfile.ZipFile(io.BytesIO(files["archive.zip"])).read("customers.csv").startswith(b"name,ssn")
    assert json.loads(files["export.json"])[0]["card"]


class Resp:
    def __init__(self, status=200, text="", ctype="text/html", url="https://x/", history=(), headers=None):
        self.status_code, self.text, self.url, self.history = status, text, url, list(history)
        self.headers = dict({"Content-Type": ctype}, **(headers or {}))
        self.content = text.encode()
        self._content = None

    def iter_content(self, n):
        yield self.content

    def close(self):
        pass


ZS_BLOCK = "<html><title>Website blocked</title>Internet Security by Zscaler. Access to this site is blocked by policy.</html>"
ZS_VIRUS = "<html>Zscaler: virus detected. This download is blocked.</html>"
ZS_CAUTION = "<html>Zscaler Caution: this site may not be appropriate. Continue to the site?</html>"


def test_classify_reads_zscaler_pages(tm):
    assert tm.classify(Resp(200, ZS_BLOCK)) == "block"
    assert tm.classify(Resp(403, ZS_VIRUS)) == "block"
    assert tm.classify(Resp(200, ZS_CAUTION)) == "caution"
    iso = Resp(200, "<html>loading</html>", url="https://abc.isolation.zscaler.com/profile/x")
    assert tm.classify(iso) == "isolate"
    assert tm.classify(Resp(200, "<html>Welcome to Dropbox</html>")) == "allow"
    assert tm.classify(Resp(404, "not found")) == "allow:404"
    assert tm.classify(error=ConnectionResetError("[Errno 104] Connection reset by peer")) == "block"
    assert tm.classify(error=TimeoutError("timed out")) == "error:TimeoutError"


class FakeWeb:
    """Answers like the demo tenant would for the test user."""

    def __init__(self, tm, tenant=True, ssl=True):
        self.tm, self.tenant, self.ssl, self.seen = tm, tenant, ssl, []
        self.headers = {}

    def request(self, method, url, **kw):
        self.seen.append((method, url))
        host = re.sub(r"^https?://([^/]+).*", r"\1", url)
        if "ip.zscaler.com" in url:
            return Resp(200, "You are accessing the Internet via Zscaler's proxy on zscalertwo.net")
        if host in ("www.example.com",) and self.tenant:
            return Resp(200, ZS_BLOCK)
        if any(h in host for h in ("bet365", "torproject", "hide.me", "guns.com")):
            return Resp(200, ZS_BLOCK)
        if "httpbin.org/base64" in url and (url.startswith("http:") or self.ssl):
            return Resp(200, ZS_VIRUS)
        if method == "POST" and "SSN" in str(kw.get("data")) and self.ssl:
            return Resp(403, "<html>Zscaler data loss prevention: sensitive data blocked</html>")
        if url.endswith(".exe"):
            return Resp(200, ZS_BLOCK)
        return Resp(200, "<html>ok</html>")

    get = lambda self, url, **kw: self.request("GET", url, **kw)  # noqa: E731


def test_traffic_round_covers_every_type_and_writes_summary(tm, monkeypatch, tmp_path):
    monkeypatch.setattr(tm.time, "sleep", lambda s: None)
    monkeypatch.setattr(tm, "tcp_probe", lambda host, port, timeout=6: "block" if port in (23, 2222, 4444, 8888) else "open")
    monkeypatch.setattr(tm, "dns_query", lambda server, name, qtype=1, timeout=4: ("NOERROR", 1))
    monkeypatch.setattr(tm.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("192.0.2.10", 443))])
    web = FakeWeb(tm)
    res = tm.run(count=2, sess=web, quiet=True, seed=1, log_dir=tmp_path)
    assert set(res["by_type"]) == set(tm.TYPES)
    assert res["errors"] == 0 and res["by_type"]["threats"]["block"] >= 2
    assert ("GET", "https://www.example.com/") in web.seen          # the tenant check is in every round
    assert any(m == "POST" and "dlptest.com" in u for m, u in web.seen)
    assert json.loads((tmp_path / "zia-traffic-last.json").read_text())["summary"] == res["summary"]
    only = tm.run(types=["saas"], count=1, sess=FakeWeb(tm), quiet=True, seed=2)
    assert set(only["by_type"]) == {"saas"} and only["total"] == 4


def test_catalog_is_safe_and_big_enough(tm):
    cat = tm.catalog()
    saas = cat["saas"]
    assert 40 <= len(set(saas)) <= 70 and len(saas) == len(set(saas))
    urls = [w["url"] for w in cat["web"]] + saas + cat["genai"] + cat["files"]["downloads"][0:0]
    assert all(re.match(r"https?://", u) for u in urls)
    blob = json.dumps(cat).lower()
    assert "wicar" not in blob   # real exploit samples: never
    assert {"chatgpt.com", "gemini.google.com", "copilot.microsoft.com"} <= {re.sub(r"https://([^/]+)/.*", r"\1", u) for u in cat["genai"]}
    assert sum(w["expect"] == "block" for w in cat["web"]) >= 5


def test_generator_check_passes_in_the_demo_tenant(tm, monkeypatch):
    monkeypatch.setattr(tm, "zcc_running", lambda: True)
    monkeypatch.setattr(tm, "tls_issuer", lambda host="x": "Zscaler Inc.")
    monkeypatch.setattr(tm, "tcp_probe", lambda host, port, timeout=6: "block")
    by = {c["id"]: c for c in tm.check(cloud="zscalertwo", sess=FakeWeb(tm))}
    assert all(c["status"] == "ok" for c in by.values()), {k: (v["status"], v["detail"]) for k, v in by.items()}


def test_generator_check_explains_wrong_tenant_and_tunnel_1(tm, monkeypatch):
    monkeypatch.setattr(tm, "zcc_running", lambda: True)
    monkeypatch.setattr(tm, "tls_issuer", lambda host="x": "DigiCert Inc")
    monkeypatch.setattr(tm, "tcp_probe", lambda host, port, timeout=6: "open")
    by = {c["id"]: c for c in tm.check(cloud="zscalerthree", sess=FakeWeb(tm, tenant=False, ssl=False))}
    assert by["gen-tenant"]["status"] == "fail" and "signed in as the user chosen" in by["gen-tenant"]["fix"]
    assert by["gen-via"]["status"] == "warn" and "different tenant" in by["gen-via"]["fix"]
    assert by["gen-ssl"]["status"] == "warn" and by["gen-eicar-https"]["status"] == "warn"
    assert by["gen-eicar-http"]["status"] == "ok"
    assert by["gen-tunnel2"]["status"] == "warn" and "Z-Tunnel 2.0" in by["gen-tunnel2"]["fix"]


def test_dns_query_packet_is_well_formed(tm, monkeypatch):
    sent = {}

    class Sock:
        def __init__(self, *a):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def settimeout(self, t):
            pass

        def sendto(self, data, addr):
            sent["data"], sent["addr"] = data, addr

        def recvfrom(self, n):
            d = sent["data"]
            return d[:2] + b"\x81\x80" + d[4:6] + b"\x00\x01" + d[8:], None
    monkeypatch.setattr(tm.socket, "socket", Sock)
    assert tm.dns_query("8.8.8.8", "www.wikipedia.org") == ("NOERROR", 1)
    assert sent["addr"] == ("8.8.8.8", 53) and b"\x09wikipedia\x03org\x00" in sent["data"]
