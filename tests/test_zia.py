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

    def __init__(self, cbi=True, actions=None, file_types=None, strict=("rule_labels", "url_categories")):
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
                      {"id": 502, "name": "SE Traffic", "email": "traffic.tester@pyite.buzz"}],
            "ssl": [{"id": 9, "name": "Decrypt All Traffic", "order": 1, "state": "ENABLED", "action": {"type": "DECRYPT"}}],
        }
        self.engines = [{"id": 61, "predefinedEngineName": "PCI"}, {"id": 17, "name": "PII (US) - Low Volume"},
                        {"id": 2, "name": "5 or more Credit Card Numbers"}, {"id": 19, "name": "Credentials and Secrets"},
                        {"id": 1, "name": "5 or more PII Identifiers"}]
        self.cbi = [{"id": "cbi-1", "name": "Default isolation", "url": "https://isolation.example", "defaultProfile": True}] if cbi else []
        self.actions = actions
        self.file_types = file_types
        self.strict = set(strict)   # resources that reject ':' in names, like the real rule-label API
        self.calls = []
        self.activations = 0
        self.zins = {}
        self.zid_users = [{"id": "zu-1", "loginName": "ztest@pyite.buzz", "primaryEmail": "ztest@pyite.buzz"},
                          {"id": "zu-2", "loginName": "admin@paulaiuto.zslogin.net", "primaryEmail": "paiuto@zscaler.com"}]
        self.zid_groups = []
        self.members = []
        self.sync = True          # ZIdentity users show up in ZIA right away
        self.passwords = {}
        self.auth = {"orgAuthType": "SAFECHANNEL_DIR", "samlEnabled": False, "passwordStrength": "NONE"}  # as in the demo tenant
        self.zid_allowed = True
        self.zcc_allowed = True
        self.fwd = [{"id": 71, "name": "Default", "forwardingProfileActions": [
            {"networkType": 1, "actionType": 1, "enablePacketTunnel": 0, "primaryTransport": 1},
            {"networkType": 2, "actionType": 1, "enablePacketTunnel": 0}]}]
        self.web = [{"id": 81, "name": "Default", "ruleOrder": 1, "groupAll": 1, "active": 1,
                     "deviceType": "DEVICE_TYPE_WINDOWS", "forwardingProfileId": 71, "pacUrl": "https://pac.example",
                     "windowsPolicy": {"installSslCerts": 0, "cacheSystemProxy": 0}, "groups": []}]

    def _rules(self, resource, rule_type=None):
        if resource == "ssl_inspection_rules":
            return self.db["ssl"]
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
        name = kw.get("name") or kw.get("configured_name") or ""
        if method.startswith(("add", "update")) and ":" in str(name) and (resource in self.strict or "*" in self.strict):
            msg = ('"code": "INVALID_NAME", "message": "Category name can only have alphanumeric, underscore, hyphen, '
                   'dot, parenthesis and space."' if resource == "url_categories" else '"message": "Name should be valid"')
            raise sys.modules[type(self).kit_module].KitError(f'{resource}.{method} failed: {{"status": 400, {msg}}}')
        if resource.startswith("zid."):
            return self._zid(resource, method, a, kw)
        if resource.startswith("zins."):
            return copy.deepcopy(self.zins.get(method + str(sorted(kw.items())), self.zins.get(method, [])))
        if resource == "activate":
            self.activations += method == "activate"
            return {"status": "ACTIVE"}
        if resource == "user_management":
            return self._users(method, a, kw)
        if resource == "authentication_settings":
            if self.auth is None:
                raise sys.modules[type(self).kit_module].KitError("authentication_settings.get failed: 403")
            return copy.deepcopy(self.auth)
        if resource == "dlp_engine":
            return copy.deepcopy(self.engines)
        if resource == "cloud_browser_isolation":
            return copy.deepcopy(self.cbi)
        if resource.startswith("zcc."):
            return self._zcc(resource, method, a, kw)
        if resource == "file_type_control_rule" and method == "list_file_type_categories":
            if self.file_types is None:
                raise sys.modules[type(self).kit_module].KitError("file_type_control_rule.list failed: 404")
            return [{"name": n} for n in self.file_types]
        if resource == "cloudappcontrol" and method == "list_available_actions":
            if self.actions is None:
                return []
            per = self.actions.get(a[0], [])
            if isinstance(per, dict):   # per app, like the real tenant (some apps list nothing)
                return list(per.get(a[1][0] if a[1] else "*", []))
            return list(per)
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

    def _zcc(self, resource, method, a, kw):
        err = sys.modules[type(self).kit_module].KitError
        if not self.zcc_allowed:
            raise err(f"{resource}.{method} failed: 401 Unauthorized")
        objs = self.fwd if resource == "zcc.forwarding_profile" else self.web
        if method == "list_by_company":
            return copy.deepcopy(objs)
        if method in ("update_forwarding_profile", "web_policy_edit"):
            assert "groups" not in kw and "users" not in kw, "read-only arrays echoed back"
            if method == "update_forwarding_profile" and getattr(self, "fwd_rejects", None) and self.fwd_rejects(kw):
                raise err(f'{resource}.{method} failed: {{ "status": 400, "code": null, "message": null }}')
            o = copy.deepcopy(kw)
            if o.get("id"):
                i = next(i for i, x in enumerate(objs) if x["id"] == o["id"])
                objs[i] = o
            else:
                o["id"] = next(self.ids)
                objs.append(o)
            return {"success": "true"} if resource == "zcc.web_policy" else copy.deepcopy(o)
        if method in ("delete_forwarding_profile", "delete_web_policy"):
            objs[:] = [x for x in objs if x["id"] != a[0]]
            return None
        raise AssertionError(f"unexpected call {resource}.{method}")

    def _zid(self, resource, method, a, kw):
        KitError = sys.modules[type(self).kit_module].KitError
        if not self.zid_allowed:
            raise KitError(f"{resource}.{method} failed: 403 Forbidden")
        if resource == "zid.users":
            if method == "list_users":
                want = (kw.get("query_params") or {}).get("login_name")
                return {"records": copy.deepcopy([u for u in self.zid_users if not want or u["loginName"] == want])}
            if method == "add_user":
                u = dict(camel(copy.deepcopy(kw)), id=f"zu-{next(self.ids)}")
                self.zid_users.append(u)
                if self.sync:
                    self.push(u)
                return copy.deepcopy(u)
            if method == "delete_user":
                self.zid_users = [u for u in self.zid_users if u["id"] != a[0]]
                self.db["users"] = [u for u in self.db["users"] if u.get("zid") != a[0]]
                return None
        if resource == "zid.groups":
            if method == "list_groups":
                return {"records": copy.deepcopy(self.zid_groups)}
            if method == "add_group":
                grp = dict(camel(copy.deepcopy(kw)), id=f"zg-{next(self.ids)}")
                self.zid_groups.append(grp)
                return copy.deepcopy(grp)
            if method == "add_user_to_group":
                if (a[0], a[1]) in self.members:
                    raise KitError("zid.groups.add_user_to_group failed: 409 already a member")
                self.members.append((a[0], a[1]))
                if any(u.get("zid") == a[1] for u in self.db["users"]):   # already synced: its groups follow
                    self.push_groups(a[1])
                return None
            if method == "delete_group":
                self.zid_groups = [x for x in self.zid_groups if x["id"] != a[0]]
                return None
        raise AssertionError(f"unexpected call {resource}.{method}")

    def _users(self, method, a, kw):
        if method == "list_users":
            return copy.deepcopy(self.db["users"])
        kind = {"group": "zia_groups", "department": "zia_depts", "user": "users"}[method.split("_", 1)[1].rstrip("s")]
        objs = self.db.setdefault(kind, [])
        if method.startswith("list"):
            q = (kw.get("query_params") or {}).get("search", "")
            return copy.deepcopy([o for o in objs if q.lower() in o["name"].lower()])
        if method.startswith("add"):
            if kind == "users":
                assert kw["groups"] and kw["department"] and kw["password"]
                self.passwords[kw["email"]] = kw["password"]
            o = {k: copy.deepcopy(v) for k, v in kw.items() if k != "password"}
            o["id"] = next(self.ids)
            objs.append(o)
            return copy.deepcopy(o)
        if method.startswith("delete"):
            self.db[kind] = [o for o in objs if o["id"] != a[0]]
            return None
        raise AssertionError(method)

    def push(self, u):
        """ZIdentity -> ZIA user sync."""
        self.db["users"].append({"id": next(self.ids), "name": u["displayName"], "email": u["loginName"], "zid": u["id"]})
        self.push_groups(u["id"])

    def push_groups(self, zid_user):
        """ZIdentity -> ZIA group sync for one user's groups."""
        for gid, uid in self.members:
            grp = next((x for x in self.zid_groups if x["id"] == gid), None)
            if uid == zid_user and grp and not any(z["name"] == grp["name"] for z in self.db.setdefault("zia_groups", [])):
                self.db["zia_groups"].append({"id": next(self.ids), "name": grp["name"]})

    def all_rules(self):
        out = [r for k in ("url_filtering", "file_type_control_rule", "dlp_web_rules", "cloud_firewall_rules",
                           "cloud_firewall_dns", "ssl") for r in self.db[k]]
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
    kit, z, fake = zenv("zia", "setup", "--user", "traffic.tester@pyite.buzz", "--yes")
    kit.cmd_zia()
    made = mine(fake)
    assert "SE-Demo: Block gambling" in made and "SE-Demo: Block card numbers" in made
    assert "SE-Demo: Isolate games" in made and "SE-Demo: Block demo ports" in made
    assert all(len(n) <= 31 for n in made)
    label = next(l for l in fake.db["rule_labels"] if l["name"] == "SE-Demo demo kit")
    for r in fake.all_rules():
        if r["name"].startswith("SE-Demo:"):
            assert r["users"] == [502], r["name"]           # only the test user
            assert r["labels"] == [label["id"]] and r["state"] == "ENABLED"
    tc = next(c for c in fake.db["url_categories"] if c["configuredName"] == "SE-Demo - tenant check")
    tenant_rule = next(r for r in fake.db["url_filtering"] if r["name"] == "SE-Demo: Block tenant check")
    assert tenant_rule["urlCategories"] == [tc["id"]] and "www.example.com" in tc["urls"]
    ns = next(s for s in fake.db["network_services"] if s["name"] == "SE-Demo: demo ports")
    assert next(r for r in fake.db["cloud_firewall_rules"] if r["name"] == "SE-Demo: Block demo ports")["nwServices"] == [ns["id"]]
    dlp = next(r for r in fake.db["dlp_web_rules"] if r["name"] == "SE-Demo: Block card numbers")
    assert dlp["dlpEngines"] == [2] and dlp["action"] == "BLOCK"
    # demo rules go above the tenant's own, so they win for the test user
    assert min(r["order"] for r in fake.db["url_filtering"] if r["name"].startswith("SE-Demo:")) == 1
    assert fake.activations == 1
    assert kit.load_cfg()["zia"]["users"] == [{"id": 502, "name": "SE Traffic", "email": "traffic.tester@pyite.buzz"}]
    before = (len(fake.all_rules()), len(fake.db["url_categories"]), len(fake.db["network_services"]), len(fake.db["rule_labels"]))
    kit.cmd_zia()   # again: updates in place
    assert (len(fake.all_rules()), len(fake.db["url_categories"]), len(fake.db["network_services"]),
            len(fake.db["rule_labels"])) == before
    assert fake.activations == 2
    # the tenant's own rules are untouched
    assert {"URL Filtering Rule-1", "DLP PCI Rule-1", "AI_ML_App_Rule_1"} <= {r["name"] for r in fake.all_rules()}


def test_setup_adds_ssl_inspection_with_an_aws_bypass_above_it(zenv):
    kit, z, fake = zenv("zia", "setup", "--yes")
    kit.cmd_zia()
    ssl = sorted(fake.db["ssl"], key=lambda r: r["order"])
    names = [r["name"] for r in ssl]
    assert names.index("SE-Demo: AWS SSM bypass") < names.index("SE-Demo: Inspect test user") < names.index("Decrypt All Traffic")
    inspect = next(r for r in ssl if r["name"] == "SE-Demo: Inspect test user")
    bypass = next(r for r in ssl if r["name"] == "SE-Demo: AWS SSM bypass")
    user = next(u for u in fake.db["users"] if u["email"] == "se-demo-traffic@pyite.buzz")
    assert inspect["users"] == [user["id"]] and bypass["users"] == [user["id"]]
    assert inspect["action"]["type"] == "DECRYPT" and bypass["action"]["type"] == "DO_NOT_DECRYPT"
    aws = next(c for c in fake.db["url_categories"] if c["configuredName"] == "SE-Demo - AWS management")
    assert bypass["urlCategories"] == [aws["id"]] and ".ssmmessages.us-west-2.amazonaws.com" in aws["urls"]
    kit.cmd_zia()   # again: same rules, same order
    assert [r["name"] for r in sorted(fake.db["ssl"], key=lambda r: r["order"])] == names


def test_demo_rules_keep_template_order_so_blocks_win(zenv):
    kit, z, fake = zenv("zia", "setup", "--yes")
    kit.cmd_zia()

    def order(name):
        return next(r["order"] for r in fake.db["dlp_web_rules"] if r["name"] == name)
    assert order("SE-Demo: Block card numbers") < order("SE-Demo: Monitor PII and PCI")   # first match wins in ZIA
    # a tenant set up by an older kit has them reversed: setup puts them back
    blk = next(r for r in fake.db["dlp_web_rules"] if r["name"] == "SE-Demo: Block card numbers")
    mon = next(r for r in fake.db["dlp_web_rules"] if r["name"] == "SE-Demo: Monitor PII and PCI")
    blk["order"], mon["order"] = mon["order"], blk["order"]
    kit.cmd_zia()
    assert order("SE-Demo: Block card numbers") < order("SE-Demo: Monitor PII and PCI")
    assert order("DLP PCI Rule-1") > order("SE-Demo: Monitor PII and PCI")   # the tenant's own rule stays below


def test_setup_gives_the_test_group_a_client_connector_profile(zenv, capsys):
    kit, z, fake = zenv("zia", "setup", "--yes")
    kit.cmd_zia()
    grp = next(x for x in fake.db["zia_groups"] if x["name"] == "SE-Demo: traffic generator")
    fwd = next(f for f in fake.fwd if f["name"] == "SE-Demo Z-Tunnel 2.0")
    assert all(a["enablePacketTunnel"] == 1 for a in fwd["forwardingProfileActions"])
    app = next(p for p in fake.web if p["name"] == "SE-Demo traffic generator")
    assert app["groupIds"] == [grp["id"]] and app["groupAll"] == 0 and app["forwardingProfileId"] == fwd["id"]
    assert app["windowsPolicy"]["installSslCerts"] == 1 and app["pacUrl"] == "https://pac.example"   # copied
    default = next(p for p in fake.web if p["name"] == "Default")   # yours: untouched
    assert default["forwardingProfileId"] == 71 and default["windowsPolicy"]["installSslCerts"] == 0
    assert fake.fwd[0]["forwardingProfileActions"][0]["enablePacketTunnel"] == 0
    kit.cmd_zia()   # again: updated in place
    assert len(fake.fwd) == 2 and len(fake.web) == 2
    kit.ARGS[:] = ["zia", "teardown", "--force"]
    kit.FORCE = True
    kit.cmd_zia()
    assert [f["name"] for f in fake.fwd] == ["Default"] and [p["name"] for p in fake.web] == ["Default"]


def test_z_tunnel_2_switches_tunnel_with_local_proxy_to_tunnel(zenv, capsys):
    kit, z, fake = zenv("zia", "setup", "--yes")
    for a in fake.fwd[0]["forwardingProfileActions"]:
        a.update(actionType=3, enablePacketTunnel=0, systemProxy=1)    # the default: Tunnel with Local Proxy
    kit.cmd_zia()
    fwd = next(f for f in fake.fwd if f["name"] == "SE-Demo Z-Tunnel 2.0")
    assert all(a["actionType"] == 1 and a["enablePacketTunnel"] == 1 for a in fwd["forwardingProfileActions"])
    assert fake.fwd[0]["forwardingProfileActions"][0]["actionType"] == 3      # yours: untouched
    assert "Z-Tunnel 2.0 on 2 of 2" in capsys.readouterr().out


def test_z_tunnel_2_copies_a_profile_you_already_made(zenv, capsys):
    kit, z, fake = zenv("zia", "setup", "--yes")
    fake.fwd.append({"id": 72, "name": "ztest", "forwardingProfileActions": [
        {"networkType": 0, "actionType": 1, "enablePacketTunnel": 1, "primaryTransport": 0, "allowTLSFallback": 1},
        {"networkType": 1, "actionType": 1, "enablePacketTunnel": 1, "primaryTransport": 0, "allowTLSFallback": 1}]})
    kit.cmd_zia()
    fwd = next(f for f in fake.fwd if f["name"] == "SE-Demo Z-Tunnel 2.0")
    assert fwd["forwardingProfileActions"] == fake.fwd[1]["forwardingProfileActions"]
    assert "your Z-Tunnel 2.0 profile 'ztest'" in capsys.readouterr().out


def test_drift_is_clean_right_after_setup(zenv):
    kit, z, fake = zenv("zia", "setup", "--yes")
    kit.cmd_zia()
    by = {c["id"]: c for c in z.drift(fake, kit.load_cfg())}
    assert by["drift-missing"]["status"] == "ok" and by["drift-order"]["status"] == "ok"
    assert by["drift-zcc-fwd"]["status"] == "ok" and by["drift-zcc-app"]["status"] == "ok"
    assert not [c for c in by.values() if c.get("fixable")]


def test_drift_finds_problems_and_fix_repairs_only_kit_objects(zenv, capsys):
    kit, z, fake = zenv("zia", "setup", "--yes")
    kit.cmd_zia()
    # break things the way they broke in a real tenant
    blk = next(r for r in fake.db["dlp_web_rules"] if r["name"] == "SE-Demo: Block card numbers")
    mon = next(r for r in fake.db["dlp_web_rules"] if r["name"] == "SE-Demo: Monitor PII and PCI")
    blk["order"], mon["order"] = mon["order"], blk["order"]
    fake.db["url_filtering"] = [r for r in fake.db["url_filtering"] if r["name"] != "SE-Demo: Block gambling"]
    next(r for r in fake.db["cloud_firewall_rules"] if r["name"] == "SE-Demo: Block demo ports")["state"] = "DISABLED"
    fake.db["ssl"].append({"id": 990, "name": "SE-Demo", "order": 9, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}})
    fwd = next(f for f in fake.fwd if f["name"] == "SE-Demo Z-Tunnel 2.0")
    for a in fwd["forwardingProfileActions"]:
        a["actionType"] = 3
    fake.web.append({"id": 85, "name": "Everyone first", "ruleOrder": 0, "groupAll": 1, "active": 1})
    by = {c["id"]: c for c in z.drift(fake, kit.load_cfg())}
    assert "Block gambling" in by["drift-missing"]["detail"] and by["drift-missing"]["fixable"]
    assert "Block demo ports" in by["drift-disabled"]["detail"]
    assert "Monitor PII and PCI > SE-Demo: Block card numbers" in by["drift-order"]["detail"]
    assert "'SE-Demo' (SSL inspection)" in by["drift-lookalike"]["detail"] and not by["drift-lookalike"].get("fixable")
    assert by["drift-zcc-fwd"]["status"] == "warn"
    assert "Everyone first" in by["drift-zcc-app"]["detail"]
    kit.ARGS[:] = ["zia", "status", "--fix"]
    kit.cmd_zia()
    after = {c["id"]: c for c in z.drift(fake, kit.load_cfg())}
    assert after["drift-missing"]["status"] == "ok" and after["drift-order"]["status"] == "ok"
    assert "drift-disabled" not in after and after["drift-zcc-fwd"]["status"] == "ok"
    assert any(r["name"] == "SE-Demo" for r in fake.db["ssl"])                    # yours: reported, never touched
    assert any(p["name"] == "Everyone first" for p in fake.web)
    assert "Everyone first" in after["drift-zcc-app"]["detail"]                    # can't fix someone else's profile


def test_readiness_on_the_admin_machine(zenv, monkeypatch):
    kit, z, fake = zenv("zia", "setup", "--yes")
    kit.cmd_zia()
    by = {c["id"]: c for c in kit.readiness(kit.load_cfg())}
    assert by["ready-zia-policy"]["status"] == "ok"
    assert by["ready-insights"]["status"] == "warn" and "3 days" in by["ready-insights"]["fix"]   # no data yet
    assert by["ready-lead"]["status"] == "info" and "ready-gen" not in by and "ready-aws" not in by
    fake.db["url_filtering"] = [r for r in fake.db["url_filtering"] if r["name"] != "SE-Demo: Block gambling"]
    by = {c["id"]: c for c in kit.readiness(kit.load_cfg())}
    assert by["ready-zia-policy"]["status"] == "warn" and by["ready-zia-policy"]["fixable"]
    # after writing an AWS template, the schedule is part of the check
    import datetime
    cfg = kit.load_cfg()
    cfg["zia"]["aws"] = {"written": "2026-10-17T20:00:00-0400"}
    kit.save_cfg(cfg)
    monkeypatch.setattr(z, "_new_york_now", lambda: datetime.datetime(2026, 10, 17, 22, 0))   # a Saturday night
    by = {c["id"]: c for c in kit.readiness(kit.load_cfg())}
    assert by["ready-aws"]["status"] == "warn" and "Instance state > Start" in by["ready-aws"]["fix"]
    monkeypatch.setattr(z, "_new_york_now", lambda: datetime.datetime(2026, 10, 19, 10, 0))   # Monday morning
    assert {c["id"]: c for c in kit.readiness(kit.load_cfg())}["ready-aws"]["status"] == "info"


def test_readiness_on_the_generator(zenv):
    kit, z, fake = zenv("zia", "ready")
    p = kit.CFG_DIR / "zia-traffic-last.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    import time as _t
    now = _t.strftime("%Y-%m-%dT%H:%M:%S%z")
    p.write_text(json.dumps({"time": now, "total": 196, "by_type": {"web": {"n": 57, "block": 18}}}), encoding="utf-8")
    kit._kc.pop("oneapi-client-secret", None)                    # a generator has no API keys
    by = {c["id"]: c for c in kit.readiness(kit.load_cfg())}
    assert by["ready-gen"]["status"] == "ok" and "Zscaler acted on 18" in by["ready-gen"]["detail"]
    p.write_text(json.dumps({"time": "2026-01-01T00:00:00+0000", "total": 5, "by_type": {}}), encoding="utf-8")
    assert {c["id"]: c for c in kit.readiness(kit.load_cfg())}["ready-gen"]["status"] == "warn"
    p.write_text(json.dumps({"time": now, "skipped": True, "summary": "not through Zscaler"}), encoding="utf-8")
    assert {c["id"]: c for c in kit.readiness(kit.load_cfg())}["ready-gen"]["status"] == "fail"


def test_client_connector_api_refused_still_applies_the_zia_policy(zenv, capsys):
    kit, z, fake = zenv("zia", "setup", "--yes")
    fake.zcc_allowed = False
    kit.cmd_zia()
    out = capsys.readouterr().out
    assert "Client Connector profiles skipped" in out and "Z-Tunnel 2.0" in out
    assert "SE-Demo: Block gambling" in mine(fake) and fake.activations == 1


def test_setup_creates_a_zia_test_user_with_a_password(zenv, capsys):
    kit, z, fake = zenv("zia", "setup", "--yes")
    kit.cmd_zia()
    out = capsys.readouterr().out
    user = next(u for u in fake.db["users"] if u["email"] == "se-demo-traffic@pyite.buzz")   # the tenant's domain
    grp = next(x for x in fake.db["zia_groups"] if x["name"] == "SE-Demo: traffic generator")
    dept = next(x for x in fake.db["zia_depts"] if x["name"] == "SE-Demo: traffic generator")
    assert user["groups"] == [{"id": grp["id"]}] and user["department"] == {"id": dept["id"]}
    pw = fake.passwords["se-demo-traffic@pyite.buzz"]
    assert kit._kc["zia-test-user-password"] == pw and len(pw) == 20
    assert pw not in out                                     # never printed by setup
    assert all(r["users"] == [user["id"]] for r in fake.all_rules() if r["name"].startswith("SE-Demo:"))
    assert "zia password" in out
    assert not fake.zid_users[2:]                             # nothing created in ZIdentity
    kit.cmd_zia()   # again: reuses the user, no duplicates, same password
    assert sum(u["email"] == "se-demo-traffic@pyite.buzz" for u in fake.db["users"]) == 1
    assert len(fake.db["zia_groups"]) == 1 and kit._kc["zia-test-user-password"] == pw
    kit.ARGS[:] = ["zia", "password"]
    kit.cmd_zia()
    assert pw in capsys.readouterr().out
    assert z.api_password(kit.load_cfg()) == {"email": "se-demo-traffic@pyite.buzz", "password": pw}


def test_generated_passwords_meet_zia_rules(zenv):
    kit, z, _ = zenv("zia")
    for _ in range(200):
        pw = z.gen_password()
        assert len(pw) == 20 and any(c.isupper() for c in pw) and any(c.islower() for c in pw)
        assert any(c.isdigit() for c in pw) and any(c in "!@#$%^&*-_=+" for c in pw)


def test_teardown_removes_the_user_it_created_but_never_yours(zenv):
    kit, z, fake = zenv("zia", "setup", "--yes")
    kit.cmd_zia()
    kit.ARGS[:] = ["zia", "teardown", "--force"]
    kit.FORCE = True
    kit.cmd_zia()
    assert not [u for u in fake.db["users"] if u["email"] == "se-demo-traffic@pyite.buzz"]
    assert not fake.db["zia_groups"] and not fake.db["zia_depts"]
    assert "zia-test-user-password" not in kit._kc and "created_user" not in kit.load_cfg()["zia"]
    # a user you chose yourself stays
    kit.ARGS[:] = ["zia", "setup", "--user", "ztest@pyite.buzz", "--yes"]
    kit.cmd_zia()
    kit.ARGS[:] = ["zia", "teardown", "--force"]
    kit.cmd_zia()
    assert any(u["email"] == "ztest@pyite.buzz" for u in fake.db["users"])


def test_an_existing_user_is_reused_and_its_password_left_alone(zenv, capsys):
    kit, z, fake = zenv("zia", "setup", "--yes")
    fake.db["users"].append({"id": 777, "name": "Old", "email": "se-demo-traffic@pyite.buzz"})
    kit.cmd_zia()
    out = capsys.readouterr().out
    assert "already exists" in out and "Change Password" in out and not fake.passwords
    assert all(r["users"] == [777] for r in fake.all_rules() if r["name"].startswith("SE-Demo:"))


def test_no_user_management_access_explains_both_ways_out(zenv, capsys):
    kit, z, fake = zenv("zia", "setup", "--yes")
    real = fake.call

    def denied(resource, method, *a, **kw):
        if resource == "user_management" and method.startswith("add"):
            raise kit.KitError("user_management.add_group failed: 403 Forbidden")
        return real(resource, method, *a, **kw)
    fake.call = denied
    with pytest.raises(SystemExit):
        kit.cmd_zia()
    out = capsys.readouterr().out
    assert "can't manage users" in out and "--user" in out and not mine(fake)


def test_preflight_catches_a_role_without_user_management(zenv, capsys):
    kit, z, fake = zenv("zia", "setup", "--yes")
    real = fake.call
    rba = ('user_management.add_group failed: {\n  "status": 403,\n  "code": "RBA_LIMITED",\n'
           '  "message": "Functional scope restriction",\n  "url": "https://api.zsapi.net/zia/api/v1/groups"\n}')

    def limited(resource, method, *a, **kw):
        if resource == "user_management" and method.startswith("add"):
            raise kit.KitError(rba)
        return real(resource, method, *a, **kw)
    fake.call = limited
    by = {c["id"]: c for c in z.preflight(kit.load_cfg(), write_probe=True)[0]}
    assert by["zia-mkuser"]["status"] == "warn" and by["zia-mkuser"]["detail"] == "RBA_LIMITED: Functional scope restriction"
    assert "Role Management" in by["zia-mkuser"]["fix"] and "--user se-demo-traffic@pyite.buzz" in by["zia-mkuser"]["fix"]
    with pytest.raises(SystemExit):
        kit.cmd_zia()
    out = capsys.readouterr().out
    assert "RBA_LIMITED: Functional scope restriction" in out and "User Management to Full" in out
    assert " x," not in out and "Give the role full access to URL Filtering" not in out


def test_zidentity_option_creates_the_user_there(zenv, capsys):
    kit, z, fake = zenv("zia", "setup", "--via", "zidentity", "--yes")
    kit.cmd_zia()
    out = capsys.readouterr().out
    new = next(u for u in fake.zid_users if u["loginName"] == "se-demo-traffic@pyite.buzz")
    grp = next(x for x in fake.zid_groups if x["name"] == "SE-Demo: traffic generator")
    assert (grp["id"], new["id"]) in fake.members and "Directory > Users" in out
    assert kit.load_cfg()["zia"]["created_user"]["via"] == "zidentity"
    kit.ARGS[:] = ["zia", "teardown", "--force"]
    kit.FORCE = True
    kit.cmd_zia()
    assert not [u for u in fake.zid_users if u["loginName"].startswith("se-demo-traffic@")] and not fake.zid_groups


def test_slow_zidentity_sync_stops_cleanly_and_resumes(zenv):
    kit, z, fake = zenv("zia")
    fake.sync = False
    cfg = kit.load_cfg()
    with pytest.raises(kit.KitError, match="hasn't received it yet"):
        z.create_test_user(fake, cfg, lambda *a: None, via="zidentity", wait=0)
    assert not mine(fake) and kit.load_cfg()["zia"]["created_user"]["email"] == "se-demo-traffic@pyite.buzz"
    fake.push(fake.zid_users[-1])   # ZIA catches up
    kit.ARGS[:] = ["zia", "setup", "--yes"]
    kit.YES = True
    kit.cmd_zia()
    assert sum(u["loginName"].startswith("se-demo-traffic@") for u in fake.zid_users) == 1
    assert mine(fake)


def test_where_the_user_is_created_follows_the_tenants_sign_in(zenv):
    kit, z, fake = zenv("zia")
    assert z.auth_mode(fake) == ("hosted", "Hosted DB, form-based sign-in")
    by = {c["id"]: c for c in z.preflight(kit.load_cfg())[0]}
    assert by["zia-auth"]["status"] == "ok" and "Hosted DB" in by["zia-auth"]["detail"]
    fake.auth = {"orgAuthType": "SAFECHANNEL_DIR", "samlEnabled": True}      # SAML: the user goes in ZIdentity
    z.create_test_user(fake, kit.load_cfg(), lambda *a: None)
    assert any(u["loginName"] == "se-demo-traffic@pyite.buzz" for u in fake.zid_users) and not fake.passwords
    fake.auth = {"orgAuthType": "MICROSOFT_ACTIVE_DIRECTORY", "samlEnabled": False}
    cfg = kit.load_cfg()
    cfg["zia"] = {}
    with pytest.raises(kit.KitError, match="directory"):
        z.create_test_user(fake, cfg, lambda *a: None)
    fake.auth = None                                                     # unreadable: Hosted DB is assumed
    z.create_test_user(fake, cfg, lambda *a: None, email="other@pyite.buzz")
    assert "other@pyite.buzz" in fake.passwords


def test_tenant_domain_ignores_zscaler_admin_domains(zenv):
    kit, z, fake = zenv("zia")
    assert z.tenant_domain(fake) == "pyite.buzz"
    fake.zid_users, fake.db["users"] = [{"id": "x", "loginName": "admin@acme.zslogin.net"}], []
    assert z.tenant_domain(fake) is None


def test_names_zia_rejects_are_retried_without_the_colon(zenv):
    kit, z, fake = zenv("zia", "setup", "--user", "traffic.tester@pyite.buzz", "--yes", strict=("*",))
    checks, _ = z.preflight(kit.load_cfg(), write_probe=True)
    assert next(c for c in checks if c["id"] == "zia-write")["status"] == "ok" and not fake.db["rule_labels"]
    kit.cmd_zia()
    names = mine(fake) + [r["name"] for r in fake.all_rules() if r["name"].startswith("SE-Demo - ")]
    assert "SE-Demo - Block gambling" in names and not any(":" in n for n in names)
    assert any(c["configuredName"] == "SE-Demo - tenant check" for c in fake.db["url_categories"])
    before = len(fake.all_rules())
    kit.cmd_zia()   # finds them again under the safe names
    assert len(fake.all_rules()) == before
    kit.ARGS[:] = ["zia", "teardown", "--force"]
    kit.FORCE = True
    kit.cmd_zia()
    assert not [r for r in fake.all_rules() if r["name"].startswith("SE-Demo")]
    assert not [s for s in fake.db["network_services"] if s["name"].startswith("SE-Demo")]
    assert not fake.db["rule_labels"]


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


def test_cloud_app_actions_come_only_from_what_the_tenant_lists(zenv):
    kit, z, fake = zenv("zia", actions={
        "FILE_SHARE": {"WETRANSFER": [], "MEGA": ["ALLOW_FILE_SHARE_VIEW", "DENY_FILE_SHARE_UPLOAD"],
                       "SENDSPACE": ["DENY_FILE_SHARE_UPLOAD"], "FILE_IO": [], "FILEBIN": []},
        "AI_ML": {"DEEPSEEK": [], "CHARACTER_AI": [], "POE_AI": [],
                  "CHATGPT_AI": ["ALLOW_AI_ML_WEB_USE", "BLOCK_AI_ML_WEB_USE"], "GOOGLE_GEMINI": ["ALLOW_AI_ML_WEB_USE"],
                  "MICROSOFT_COPILOT": ["ALLOW_AI_ML_WEB_USE"], "CLAUDE_AI": ["ALLOW_AI_ML_WEB_USE"], "PERPLEXITY": []},
        "ENTERPRISE_COLLABORATION": {"ANYDESK": ["ALLOW_ENTERPRISE_COLLABORATION_CHAT"], "TEAMVIEWER": []}})
    fake.actions["FILE_SHARE"]["*"] = []
    cfg = kit.load_cfg()
    cfg["zia"] = {"users": [{"id": 502, "name": "SE Traffic"}]}
    rules, notes = z.plan(fake, cfg)
    by = {n: b for k, rt, n, b in rules if k == "cloud_app_control"}
    up = by["SE-Demo: Block file uploads"]   # same verb and last word: DENY_..._UPLOAD
    assert up["actions"] == ["DENY_FILE_SHARE_UPLOAD"] and up["applications"] == ["MEGA", "SENDSPACE"]
    # PERPLEXITY lists nothing of its own, so it takes the same basic web-use action as the others
    assert by["SE-Demo: Allow GenAI"]["applications"] == ["CHATGPT_AI", "GOOGLE_GEMINI", "MICROSOFT_COPILOT",
                                                          "CLAUDE_AI", "PERPLEXITY"]
    # none list actions: the deny web-use action learned from ChatGPT (a name the tenant gave, never a guess)
    risky = by["SE-Demo: Block risky GenAI"]
    assert risky["applications"] == ["DEEPSEEK", "CHARACTER_AI", "POE_AI"] and risky["actions"] == ["BLOCK_AI_ML_WEB_USE"]
    assert "SE-Demo: Block remote access" not in by
    text = " ".join(notes)
    assert "tenant offers: ALLOW_ENTERPRISE_COLLABORATION_CHAT" in text and "left out WETRANSFER" in text


def test_type_level_actions_are_used_when_apps_list_none(zenv):
    kit, z, fake = zenv("zia", actions={"FILE_SHARE": {"*": ["ALLOW_FILE_SHARE_VIEW", "BLOCK_FILE_SHARE_UPLOAD"]}})
    apps, actions, why = z.pick_actions(fake, "FILE_SHARE", ["WETRANSFER", "MEGA"], [["BLOCK_FILE_SHARE_UPLOAD"]])
    assert apps == ["WETRANSFER", "MEGA"] and actions == ["BLOCK_FILE_SHARE_UPLOAD"] and "rule type" in why


def test_a_name_rejected_on_update_is_renamed_safely(zenv):
    kit, z, fake = zenv("zia", "setup", "--user", "traffic.tester@pyite.buzz", "--yes", strict=("rule_labels",))
    kit.cmd_zia()
    assert any(s["name"] == "SE-Demo: demo ports" for s in fake.db["network_services"])
    fake.strict.add("cloud_firewall")   # now ZIA rejects the ':' it accepted on create
    kit.cmd_zia()
    names = [s["name"] for s in fake.db["network_services"] if s["name"].startswith("SE-Demo")]
    assert names == ["SE-Demo - demo ports"]
    kit.cmd_zia()   # and finds it again under the new name
    assert [s["name"] for s in fake.db["network_services"] if s["name"].startswith("SE-Demo")] == names


def test_caution_and_isolate_rules_use_what_zia_allows(zenv):
    kit, z, fake = zenv("zia")
    cfg = kit.load_cfg()
    cfg["zia"] = {"users": [{"id": 502, "name": "SE Traffic"}]}
    by = {n: b for k, rt, n, b in z.plan(fake, cfg)[0] if k == "url_filtering"}
    assert by["SE-Demo: Caution social"]["request_methods"] == ["CONNECT", "GET", "HEAD"]
    assert by["SE-Demo: Isolate games"]["protocols"] == ["HTTPS_RULE", "HTTP_RULE"]
    assert "OTHER" not in by["SE-Demo: Isolate games"]["user_agent_types"]   # ZIA isolates known browsers only
    assert "POST" in by["SE-Demo: Block gambling"]["request_methods"]


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
    kit, z, fake = zenv("zia", "setup", "--user", "traffic.tester@pyite.buzz", "--yes")
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
    for f in ("zia_module.py", "zia_traffic.py", "zia_aws.py", "zia_policy_template.json", "zia_traffic.json", "ZIA.md"):
        assert f in pkg.SHIP and (ROOT / f).exists()
    text = (ROOT / "aiguard_kit.py").read_text(encoding="utf-8")
    assert '"zia_module.py", "zia_traffic.py", "zia_aws.py", "zia_policy_template.json", "zia_traffic.json", "ZIA.md"' in text


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


def test_classify_tls_error_from_zscaler_counts_as_block(tm, monkeypatch):
    class SSLError(Exception):
        pass
    err = SSLError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate")
    seen = []
    monkeypatch.setattr(tm, "peer_issuer", lambda host, port=443: seen.append(host) or "Zscaler")
    assert tm.classify(error=err, url="https://www.bet365.com/") == "block"
    assert seen == ["www.bet365.com"]
    monkeypatch.setattr(tm, "peer_issuer", lambda host, port=443: "other")
    assert tm.classify(error=err, url="https://expired.example/") == "error:SSLError"
    assert tm.classify(error=err) == "error:SSLError"


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


# ---------------------------------------------------------------- AWS template
@pytest.fixture
def aws():
    spec = importlib.util.spec_from_file_location("zia_aws_under_test", ROOT / "zia_aws.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PSEUDO = {"AWS::Region", "AWS::AccountId", "AWS::Partition", "AWS::NoValue", "AWS::StackName", "AWS::URLSuffix"}


def walk(node, refs, subs, conds):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "Ref":
                refs.add(v)
            elif k == "Fn::GetAtt":
                refs.add(v[0])
            elif k == "Fn::Sub":
                text = v if isinstance(v, str) else v[0]
                subs.update(x.split(".")[0] for x in re.findall(r"\$\{(?!!)([^}]+)\}", text))
            elif k == "Fn::If":
                conds.add(v[0])
            elif k == "Condition" and isinstance(v, str):
                conds.add(v)
            walk(v, refs, subs, conds)
    elif isinstance(node, list):
        for v in node:
            walk(v, refs, subs, conds)


def test_aws_template_is_consistent_and_has_no_secrets(aws):
    t = aws.build(cloud="zscalertwo", domain="pyite.buzz", test_user="se-demo-traffic@pyite.buzz")
    json.dumps(t)
    names = set(t["Parameters"]) | set(t["Resources"]) | PSEUDO
    refs, subs, conds = set(), set(), set()
    walk(t, refs, subs, conds)
    assert refs <= names, refs - names
    assert subs <= names, subs - names          # the boot script substitutes only real parameters
    assert conds <= set(t["Conditions"]), conds - set(t["Conditions"])
    for r in t["Resources"].values():
        assert r["Type"].startswith("AWS::") and "Properties" in r
    sg = t["Resources"]["NoInbound"]["Properties"]
    assert "SecurityGroupIngress" not in sg      # nothing exposed: connect with Fleet Manager
    assert t["Resources"]["Generator"]["Properties"]["MetadataOptions"] == {"HttpTokens": "required"}
    p = t["Parameters"]
    assert p["TestUser"]["Default"] == "se-demo-traffic@pyite.buzz" and p["ZccCloudName"]["Default"] == "zscalertwo"
    assert p["KitZipUrl"]["Default"].endswith("/zia-latest/zscaler-zia-kit.zip") and p["ZccInstallerUrl"]["Default"] == aws.ZCC_DEFAULT["url"]
    assert not [k for k, v in p.items() if v.get("NoEcho") or "password" in k.lower()]   # no secret parameters
    assert not re.search(r"(?i)(password|secret)\s*[=:]\s*\S", aws.USER_DATA)          # none in the boot script
    ud = aws.USER_DATA
    assert "zia %* --yes" in ud and "-User \"SYSTEM\"" in ud and "${TrafficEveryMinutes}" in ud
    assert "\r\n" not in ud   # CloudFormation JSON carries plain newlines; the script writes CRLF itself


def test_aws_template_can_read_the_installer_from_your_own_s3_bucket(aws):
    tpl = aws.build(cloud="zscalertwo", domain="pyite.buzz", test_user="t@pyite.buzz", zcc_s3="my-bucket/zcc/ZCC-x64.msi")
    assert tpl["Parameters"]["ZccS3Object"]["Default"] == "my-bucket/zcc/ZCC-x64.msi"
    pol = tpl["Resources"]["ZccInstallerRead"]
    assert pol["Condition"] == "ReadZccFromS3"
    stmt = pol["Properties"]["PolicyDocument"]["Statement"][0]
    assert stmt["Action"] == "s3:GetObject" and stmt["Resource"]["Fn::Sub"].endswith(":s3:::${ZccS3Object}")
    ud = tpl["Resources"]["Generator"]["Properties"]["UserData"]["Fn::Base64"]["Fn::Sub"]
    assert "Read-S3Object" in ud and "${ZccS3Object}" in ud
    import re as _re
    pat = tpl["Parameters"]["ZccS3Object"]["AllowedPattern"]
    assert _re.match(pat, "") and _re.match(pat, "my-bucket/zcc/ZCC-x64.msi") and not _re.match(pat, "my-bucket/readme.txt")


def test_zia_aws_command_writes_a_template_for_this_tenant(zenv, tmp_path):
    out = tmp_path / "gen.json"
    kit, z, fake = zenv("zia", "aws", "--out", str(out), "--zcc-url", "https://bucket.s3.amazonaws.com/zcc.msi")
    fake.db["users"].append({"id": 1, "name": "DEFAULT ADMIN", "email": "admin@164554707.zscalertwo.net"})
    with pytest.raises(SystemExit):
        kit.cmd_zia()    # no test user yet
    cfg = kit.load_cfg()
    cfg["zia"] = {"users": [{"id": 502, "name": "SE Traffic", "email": "traffic.tester@pyite.buzz"}]}
    kit.save_cfg(cfg)
    kit.cmd_zia()
    t = json.loads(out.read_text())
    assert t["Parameters"]["ZccCloudName"]["Default"] == "zscalertwo"
    assert t["Parameters"]["ZccUserDomain"]["Default"] == "pyite.buzz"
    assert t["Parameters"]["ZccInstallerUrl"]["Default"].endswith("zcc.msi")
    assert z.api_aws(kit.load_cfg(), {}, lambda: fake)["filename"].endswith(".cfn.json")


def test_traffic_is_skipped_unless_it_goes_through_zscaler(tm, monkeypatch):
    class Direct(FakeWeb):
        def request(self, method, url, **kw):
            if "ip.zscaler.com" in url:
                return Resp(200, "The request received from you did not have an XFF header, so you are not going "
                                 "through Zscaler.")
            return super().request(method, url, **kw)
    web = Direct(tm)
    res = tm.run(count=1, sess=web, quiet=True)
    assert res["skipped"] and res["total"] == 0 and web.seen == []   # only the ip.zscaler.com check, nothing else
    assert "isn't going through Zscaler" in res["summary"]
    monkeypatch.setattr(tm.time, "sleep", lambda s: None)
    assert tm.run(types=["saas"], count=1, sess=Direct(tm), quiet=True, require_zscaler=False)["total"] == 4


# ---------------------------------------------------------------- the ZIA kit edition
def test_zia_kit_package_is_its_own_edition(tmp_path):
    import subprocess
    if not (ROOT / ".git").exists():
        pytest.skip("needs the git checkout")
    subprocess.run([sys.executable, str(ROOT / "tools/package.py"), "--edition", "zia"], check=True, capture_output=True)
    v = re.search(r'^ZIA_VERSION = "([^"]+)"', (ROOT / "zia_module.py").read_text(encoding="utf-8"), re.M).group(1)
    info = json.loads((ROOT / "dist/zia/latest.json").read_text())
    zpath = ROOT / f"dist/zscaler-zia-kit-{v}.zip"
    assert info["version"] == v and info["edition"] == "zia" and info["notes"]
    assert info["zip_url"].endswith(f"/zia-v{v}/zscaler-zia-kit-{v}.zip")
    assert info["sha256"] == hashlib.sha256(zpath.read_bytes()).hexdigest()
    z = zipfile.ZipFile(zpath)
    names = z.namelist()
    assert all(n.startswith("zscaler-zia-kit/") for n in names)       # it unpacks to a ZIA-named folder
    ed = json.loads(z.read("zscaler-zia-kit/edition.json"))
    assert ed["product"] == "zia" and ed["app_dir"] == "app-zia" and ed["command"] == "zia-kit" and ed["version"] == v
    assert ed["update_url"].endswith("/releases/download/zia-latest/latest.json")
    for f in ("Install ZIA Kit.cmd", "Install ZIA Kit.command", "zia-kit", "zia-kit.cmd", "zia_module.py", "ZIA.md",
              "CHANGELOG-ZIA.md", "aiguard_kit.py"):
        assert f"zscaler-zia-kit/{f}" in names, f
    assert not any("plugin" in n for n in names)
    for f in ("Install ZIA Kit.cmd", "Install ZIA Kit.command"):
        text = z.read(f"zscaler-zia-kit/{f}").decode()
        assert "Zscaler ZIA SE Demo Kit" in text and "zscaler-zia-kit folder" in text
        assert "app-zia" in text and not re.search(r"aiguard-se-kit[\\/]app[\\/\s]", text)   # opens the ZIA console
        assert "AI Guard" not in text
    assert (ROOT / "dist/zscaler-zia-kit.zip").read_bytes() == zpath.read_bytes()
    # the AI Guard release is unchanged: no edition file, its own installer names
    subprocess.run([sys.executable, str(ROOT / "tools/package.py")], check=True, capture_output=True)
    kv = re.search(r'^VERSION = "([^"]+)"', (ROOT / "aiguard_kit.py").read_text(encoding="utf-8"), re.M).group(1)
    ag = zipfile.ZipFile(ROOT / f"dist/aiguard-se-kit-{kv}.zip").namelist()
    assert "aiguard-se-kit/edition.json" not in ag and "aiguard-se-kit/Install AI Guard Kit.cmd" in ag


def test_edition_file_gives_the_zia_kit_its_own_install_and_updates(zenv, tmp_path):
    kit, z, fake = zenv("check")
    default_update = kit.UPDATE_URL
    assert kit.EDITION is None and kit.APP_DIR.name == "app" and kit.CLI_NAME == "aiguard-kit"
    assert default_update.endswith("/releases/latest/download/latest.json")
    ed = tmp_path / "edition.json"
    ed.write_text(json.dumps({"product": "zia", "name": "Zscaler ZIA SE Demo Kit", "app_name": "Zscaler ZIA Demo Console",
                              "app_dir": "app-zia", "command": "zia-kit", "uninstall_link": "Uninstall Zscaler ZIA Demo Kit.lnk",
                              "version": "0.1.0", "update_url": "https://github.com/x/y/releases/download/zia-latest/latest.json"}))
    kit.apply_edition(ed)
    assert kit.VERSION == "0.1.0" and kit.APP_DIR.name == "app-zia" and kit.APP_NAME == "Zscaler ZIA Demo Console"
    assert kit.UPDATE_URL.endswith("/zia-latest/latest.json") and kit.kit_name() == "Zscaler ZIA SE Demo Kit"
    sp = kit.shortcut_paths()
    if kit.WINDOWS:
        assert sp["start_uninstall"].name == "Uninstall Zscaler ZIA Demo Kit.lnk"
        assert sp["desktop"].name == "Zscaler ZIA Demo Console.lnk"
    else:
        assert sp["wrapper"].name == "zia-kit" and sp["desktop"].name == "Zscaler ZIA Demo Console.app"
    called = []
    kit.cmd_zia = lambda: called.append(list(kit.ARGS))
    kit.cmds_seen = None
    kit.main()
    assert called == [["zia", "check"]]          # `zia-kit check` runs the ZIA check
    assert "zia_kit_status" not in kit.ARGS


def test_each_edition_refuses_the_others_release_zip(zenv, monkeypatch, tmp_path):
    import requests
    kit, z, fake = zenv("update")
    stage = tmp_path / "zip"
    (stage / "zscaler-zia-kit").mkdir(parents=True)
    (stage / "zscaler-zia-kit" / "aiguard_kit.py").write_text('VERSION = "1.7.2"\n')
    (stage / "zscaler-zia-kit" / "edition.json").write_text(json.dumps({"product": "zia", "version": "0.2.0"}))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for f in (stage / "zscaler-zia-kit").iterdir():
            zf.write(f, f"zscaler-zia-kit/{f.name}")
    data = buf.getvalue()
    sha = hashlib.sha256(data).hexdigest()

    class R:
        status_code, headers = 200, {"Content-Type": "application/zip"}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def iter_content(self, n):
            yield data

        def raise_for_status(self):
            pass
    monkeypatch.setattr(requests, "get", lambda url, **k: R())
    monkeypatch.setattr(kit, "BASE_DIR", tmp_path / "base")
    info = {"version": "0.2.0", "zip_url": "https://example.test/z.zip", "sha256": sha}
    with pytest.raises(kit.KitError, match="doesn't match"):
        kit.download_release(info)                 # the AI Guard kit won't install a ZIA zip
    ed = tmp_path / "edition.json"
    ed.write_text(json.dumps({"product": "zia", "version": "0.1.0"}))
    kit.apply_edition(ed)
    assert kit.download_release(info).name == "zscaler-zia-kit"   # the ZIA kit takes a newer ZIA zip


def test_zia_kit_console_keeps_the_ai_guard_policy_menu_once_ai_guard_is_set_up():
    """The ZIA kit carries the full console; SEs who also demo AI Guard need the Policy menu (and Custom…)."""
    html = (ROOT / "gui.html").read_text(encoding="utf-8")
    line = next(l for l in html.splitlines() if "querySelector('.pol').style.display='none'" in l)
    assert "if(!st.policy_id)" in line


def test_another_prefix_gets_its_own_test_user_and_client_connector_profiles(zenv):
    kit, z, fake = zenv("zia", "setup", "--yes")
    kit.PREFIX = "SE-CI"
    assert z.test_user_names()["login"] == "se-ci-traffic"
    assert z.zcc_names() == ("SE-CI traffic generator", "SE-CI Z-Tunnel 2.0")
    kit.PREFIX = "SE-Demo"
    assert z.test_user_names()["login"] == "se-demo-traffic"
    assert z.zcc_names() == ("SE-Demo traffic generator", "SE-Demo Z-Tunnel 2.0")



def test_aws_template_uses_the_kits_installer_copy_pinned_by_hash_and_signature(aws, monkeypatch):
    """With a default copy set, the template points at it with its SHA-256; 'none' or your own source overrides it."""
    sha = "ab" * 32
    monkeypatch.setattr(aws, "ZCC_DEFAULT", {"version": "4.7", "url": "https://example.test/zcc.msi", "sha256": sha})
    p = aws.build(domain="pyite.buzz", test_user="t@pyite.buzz")["Parameters"]
    assert p["ZccInstallerUrl"]["Default"] == "https://example.test/zcc.msi" and p["ZccInstallerSha256"]["Default"] == sha
    p = aws.build(domain="pyite.buzz", test_user="t@pyite.buzz", zcc_url="none")["Parameters"]
    assert p["ZccInstallerUrl"]["Default"] == "" and p["ZccInstallerSha256"]["Default"] == ""
    p = aws.build(domain="pyite.buzz", test_user="t@pyite.buzz", zcc_s3="b-1/zcc.msi")["Parameters"]
    assert p["ZccInstallerUrl"]["Default"] == "" and p["ZccS3Object"]["Default"] == "b-1/zcc.msi"
    ud = aws.USER_DATA
    assert "Get-FileHash $f -Algorithm SHA256" in ud and "Get-AuthenticodeSignature $f" in ud
    assert ud.index("Get-AuthenticodeSignature") < ud.index("msiexec.exe")   # checked before anything runs
    import re as _re
    pat = p["ZccInstallerSha256"]["AllowedPattern"]
    assert _re.match(pat, "") and _re.match(pat, sha) and not _re.match(pat, "abc")


def test_tenant_with_zidentity_managed_users_creates_the_test_user_in_zidentity(zenv, capsys):
    """'OneIdentityUserLogin enabled users will have read only access': not a role problem, so don't say it is."""
    kit, z, fake = zenv("zia", "setup", "--yes")
    real = fake.call
    ro = ('user_management.add_group failed: {\n  "status": 400,\n  "code": "UNMODIFIABLE",\n'
          '  "message": "Group can\'t be added.OneIdentityUserLogin enabled users will have read only access."\n}')

    def read_only(resource, method, *a, **kw):
        if resource == "user_management" and method.startswith("add"):
            raise kit.KitError(ro)
        return real(resource, method, *a, **kw)
    fake.call = read_only
    by = {c["id"]: c for c in z.preflight(kit.load_cfg(), write_probe=True)[0]}
    assert by["zia-mkuser"]["status"] == "info" and "ZIdentity" in by["zia-mkuser"]["detail"]
    assert "Users Admin" in by["zia-mkuser"]["fix"] and "User Management to Full" not in by["zia-mkuser"]["fix"]
    kit.cmd_zia()
    out = capsys.readouterr().out
    assert any(u["loginName"] == "se-demo-traffic@pyite.buzz" for u in fake.zid_users) and not fake.passwords
    assert kit.load_cfg()["zia"]["created_user"]["via"] == "zidentity" and "Directory > Users" in out
    assert mine(fake)


def test_zidentity_test_user_still_gets_the_client_connector_profiles(zenv, capsys):
    """The ZIdentity path has no ZIA group id of its own; the profiles use ZIA's synced copy of the group."""
    kit, z, fake = zenv("zia", "setup", "--via", "zidentity", "--yes")
    kit.cmd_zia()
    out = capsys.readouterr().out
    zia_grp = next(x for x in fake.db["zia_groups"] if x["name"] == "SE-Demo: traffic generator")
    app = next(p for p in fake.web if p["name"] == "SE-Demo traffic generator")
    assert app["groupIds"] == [int(zia_grp["id"])] and "Created Windows app profile" in out
    assert "wasn't created by the kit" not in out
    cfg = kit.load_cfg()
    assert cfg["zia"]["created_user"]["zia_group_id"] == zia_grp["id"]
    found = {k for k, _, _ in z.kit_objects(fake, cfg)} if hasattr(z, "kit_objects") else set()
    assert "zia_group" not in found     # ZIA's synced copy is never deleted by teardown


def test_zidentity_group_not_synced_yet_says_to_sign_in_first(zenv, capsys):
    kit, z, fake = zenv("zia")
    cfg = kit.load_cfg()
    cfg["zia"] = {"created_user": {"via": "zidentity", "email": "se-demo-traffic@pyite.buzz",
                                   "group": "SE-Demo: traffic generator", "group_id": "zg-1", "zid_id": "z-1"}}
    kit.save_cfg(cfg)
    lines = []
    assert z.setup_zcc(fake, cfg, lambda lvl, msg: lines.append(msg)) is None
    assert "hasn't received the ZIdentity group" in lines[-1] and "sign" in lines[-1].lower()


def test_apps_that_list_no_actions_get_the_basic_web_use_action(zenv):
    """Like a real tenant: only big apps (ChatGPT, Dropbox, Slack) list actions; DeepSeek, Claude, WeTransfer and
    TeamViewer list none, yet the console lets you allow or deny their web use. The kit now does the same."""
    ai = ["ALLOW_AI_ML_WEB_USE", "DENY_AI_ML_WEB_USE", "ALLOW_AI_ML_UPLOAD"]
    fs = ["ALLOW_FILE_SHARE_VIEW", "DENY_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_WEB_USE", "DENY_FILE_SHARE_WEB_USE"]
    ec = ["ALLOW_ENTERPRISE_COLLABORATION_WEB_USE", "DENY_ENTERPRISE_COLLABORATION_WEB_USE"]
    kit, z, fake = zenv("zia", actions={"AI_ML": {"CHATGPT_AI": ai, "GOOGLE_GEMINI": ai, "MICROSOFT_COPILOT": ai,
                                                   "PERPLEXITY": ai},
                                         "FILE_SHARE": {"DROPBOX": fs}, "ENTERPRISE_COLLABORATION": {"SLACK": ec}})
    cfg = kit.load_cfg()
    cfg["zia"] = {"users": [{"id": 502, "name": "SE Traffic"}]}
    rules, notes = z.plan(fake, cfg)
    by = {n: b for k, rt, n, b in rules if k == "cloud_app_control"}
    assert "CLAUDE_AI" in by["SE-Demo: Allow GenAI"]["applications"]
    assert by["SE-Demo: Allow GenAI"]["actions"] == ["ALLOW_AI_ML_WEB_USE"]
    assert by["SE-Demo: Block risky GenAI"]["actions"] == ["DENY_AI_ML_WEB_USE"]
    assert by["SE-Demo: Block risky GenAI"]["applications"] == ["DEEPSEEK", "CHARACTER_AI", "POE_AI"]
    assert by["SE-Demo: Block file uploads"]["actions"] == ["DENY_FILE_SHARE_WEB_USE"]
    assert by["SE-Demo: Block remote access"]["applications"] == ["ANYDESK", "TEAMVIEWER"]
    assert any("blocks the whole site" in n for n in notes)


def test_forwarding_profile_retries_a_plainer_copy_when_zcc_refuses(zenv, capsys):
    """Greg's tenant: ZCC answered a bare 400 to the copied profile. The kit retries without trusted-network
    conditions and copied ids, and the app profile still gets created."""
    kit, z, fake = zenv("zia", "setup", "--yes")
    for f in fake.fwd:   # the tenant's own profile has trusted-network settings and ids in its actions
        f["trustedNetworkIds"] = [77]
        f["evaluateTrustedNetwork"] = 1
        for a in f.get("forwardingProfileActions") or []:
            a["id"] = 991
    fake.fwd_rejects = lambda body: bool(body.get("trustedNetworkIds")) or any(
        "id" in a for a in body.get("forwardingProfileActions") or [])
    kit.cmd_zia()
    out = capsys.readouterr().out
    mine_fwd = next(f for f in fake.fwd if f["name"] == "SE-Demo Z-Tunnel 2.0")
    assert not mine_fwd.get("trustedNetworkIds") and mine_fwd["evaluateTrustedNetwork"] == 0
    assert all(z.is_z2(a) for a in mine_fwd["forwardingProfileActions"])
    assert "without trusted-network conditions" in out and "Created Windows app profile" in out
    assert any(p["name"] == "SE-Demo traffic generator" for p in fake.web)


def test_zia_and_client_connector_writes_and_failures_reach_the_activity_log(monkeypatch, tmp_path):
    """So a diagnostics zip shows what Client Connector refused, with passwords masked."""
    kit = load_kit(monkeypatch, tmp_path, ["zia"])
    z = kit.product("zia")
    t = z.ZiaTenant.__new__(z.ZiaTenant)
    bad = types.SimpleNamespace(update_forwarding_profile=lambda **kw: (None, None, '{"status": 400, "message": null}'))
    users = types.SimpleNamespace(add_user=lambda **kw: ({"id": 1}, None, None))
    t.c = types.SimpleNamespace(zcc=types.SimpleNamespace(forwarding_profile=bad),
                                zia=types.SimpleNamespace(user_management=users))
    with pytest.raises(kit.KitError):
        t.call("zcc.forwarding_profile", "update_forwarding_profile", name="SE-Demo Z-Tunnel 2.0", trustedNetworkIds=[7])
    t.call("user_management", "add_user", email="u@x.test", password="Sup3r-Secret-Value!")
    logged = kit.ACTIVITY[-2:]
    assert logged[0]["level"] == "error" and logged[0]["detail"]["request"]["body"]["trustedNetworkIds"] == [7]
    assert '"status": 400' in logged[0]["detail"]["error"]
    assert logged[1]["detail"]["request"]["body"]["password"].startswith("Sup3") and "Secret" not in json.dumps(logged[1])
