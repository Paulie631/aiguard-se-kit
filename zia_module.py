"""Internet Access (ZIA) for the SE demo kit.

Admin side (your laptop, OneAPI client from the kit's setup):
  setup / preflight / status / teardown / dashboards  -> the SE-Demo ZIA policy and Insights checks
Generator side (the Windows VM or cloud machine running Client Connector as the test user; no API keys):
  check / traffic / schedule                         -> zia_traffic.py

Everything the kit creates is named "<prefix>: ...", carries the SE-Demo rule label and is scoped to the
test user(s) chosen in setup, so the rest of the tenant (other users, locations, your home network) is untouched.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ZIA_VERSION = "0.2.27"   # the ZIA kit's own version (its releases are tagged zia-v<version>; see CHANGELOG-ZIA.md)
K = None  # the kit (aiguard_kit), set by bind()
NAME_MAX = 31  # ZIA rule-name limit
RULE_KINDS = ("url_filtering", "cloud_app_control", "file_type_control", "dlp", "firewall", "dns", "ssl")
CONSOLE = "https://console.zscaler.com"


def bind(kit):
    global K
    K = kit


def template():
    return json.loads((HERE / "zia_policy_template.json").read_text(encoding="utf-8"))


def zname(suffix):
    """'SE-Demo: Block gambling', cut to ZIA's 31-character limit."""
    return f"{K.PREFIX}: {suffix}"[:NAME_MAX].rstrip()


def g(o, key, default=None):
    """Read a field whether the record is camelCase (raw API) or snake_case (SDK models)."""
    if not isinstance(o, dict):
        return default
    if key in o:
        return o[key]
    camel = re.sub(r"_([a-z])", lambda m: m.group(1).upper(), key)
    return o.get(camel, default)


def safe_name(name):
    """Some ZIA objects (rule labels, at least) reject ':' and other punctuation: 'SE-Demo: x' -> 'SE-Demo - x'."""
    n = name.replace(f"{K.PREFIX}:", f"{K.PREFIX} -", 1)
    return re.sub(r"[^A-Za-z0-9 _.()-]", "", n)[:NAME_MAX].rstrip()


def label_name():
    return safe_name(f"{K.PREFIX} demo kit")


def names_for(name):
    return {name, safe_name(name)}


def mine(o):
    n = str(g(o, "name") or g(o, "configured_name") or "")
    return n.startswith(K.PREFIX + ":") or n.startswith(K.PREFIX + " - ") or n == label_name()


BAD_NAME = re.compile(r"name should be valid|invalid[ _](character|name)|can only have|name.{0,20}not valid", re.I)


def with_valid_name(create, name, field="name"):
    """create(**{field: name}); if ZIA rejects the name's characters, try once more with safe_name()."""
    try:
        return create(**{field: name})
    except K.KitError as e:
        if not BAD_NAME.search(str(e)) or safe_name(name) == name:
            raise
        return create(**{field: safe_name(name)})


def zcfg(cfg):
    return cfg.setdefault("zia", {})


# ---------------------------------------------------------------- OneAPI
def _failed(resource, method, err):
    """Summary and level for a failed call. ZIA refusing user changes on a tenant whose users ZIdentity manages is
    expected (setup then uses ZIdentity), so it's logged as info, not as an error."""
    if resource.startswith("user_management") and zid_managed(err):
        return f"ZIA API {resource}.{method}: read-only here (users are managed in ZIdentity; the kit uses ZIdentity)", "info"
    return f"ZIA API {resource}.{method} failed", "error"


def cli_log(level, msg):
    """The terminal's log for ZIA commands: prints, and records the line in the activity log (Logs tab,
    diagnostics), as the console's ZIA jobs do."""
    record(level, msg)
    K.cli_log(level, msg)


def record(level, msg):
    if level != "head":
        K.activity("setup", f"ZIA: {msg}", {"fail": "error", "warn": "warn", "ok": "ok"}.get(level, "info"))


class ZiaTenant:
    def __init__(self, cfg):
        from zscaler import ZscalerClient
        secret = K.kc_get("oneapi-client-secret")
        if not (cfg.get("client_id") and cfg.get("vanity_domain") and secret):
            raise K.KitError("No OneAPI credentials saved yet. Run `./aiguard-kit setup` (or the console's Setup tab) "
                             "to enter them, then run `./aiguard-kit zia setup`.")
        conf = {"clientId": cfg["client_id"], "clientSecret": secret, "vanityDomain": cfg["vanity_domain"]}
        if cfg.get("cloud"):
            conf["cloud"] = cfg["cloud"]
        K.quiet_sdk()
        self.c = ZscalerClient(conf)

    def call(self, resource, method, *a, **kw):
        """resource is a ZIA SDK area ('url_filtering'), Insights ('zins.web_traffic'), ZIdentity ('zid.users') or
        Client Connector ('zcc.web_policy')."""
        insights = resource.startswith("zins.")
        svc = (self.c.zins if insights else self.c.zid if resource.startswith("zid.")
               else self.c.zcc if resource.startswith("zcc.") else self.c.zia)
        api = getattr(svc, resource.split(".", 1)[-1])
        K.vlog(f"zia {resource}.{method} {a} {json.dumps(kw, default=str)[:300] if kw else ''}")
        write = not re.match(r"(list|get|search)", method)
        req = json.loads(json.dumps({"args": list(a), "body": kw}, default=str)) if (a or kw) else {}
        t0 = time.time()
        try:
            out = getattr(api, method)(*a, **kw)
        except Exception as e:
            K.activity("api", *_failed(resource, method, e), request=req, error=str(e)[:2000],
                       ms=int((time.time() - t0) * 1000))
            raise
        if not (isinstance(out, tuple) and len(out) == 3):
            return out
        result, resp, err = out
        if err or write:   # failures and changes go to the activity log (Logs tab, diagnostics); reads stay quiet
            K.activity("api", *(_failed(resource, method, err) if err else (f"ZIA API {resource}.{method}", "ok")),
                       request=req, **({"error": str(err)[:2000]} if err else {}), ms=int((time.time() - t0) * 1000))
        if err:
            K.vlog(f"error: {err}")
            if K.oauth_failed(err):
                raise K.KitError(K.OAUTH_FAILED)
            raise K.KitError(f"{resource}.{method} failed: {err}")
        if insights:
            return result
        body = resp.get_body() if resp is not None and hasattr(resp, "get_body") else None
        return body if body is not None else _plain(result)


def _plain(x):
    if isinstance(x, list):
        return [_plain(i) for i in x]
    return x.as_dict() if hasattr(x, "as_dict") else x


def items(body):
    if isinstance(body, list):
        return body
    return next((v for v in (body or {}).values() if isinstance(v, list)), [])


LISTS = {"url_filtering": ("url_filtering", "list_rules"), "file_type_control": ("file_type_control_rule", "list_rules"),
         "dlp": ("dlp_web_rules", "list_rules"), "firewall": ("cloud_firewall_rules", "list_rules"),
         "dns": ("cloud_firewall_dns", "list_rules"), "ssl": ("ssl_inspection_rules", "list_rules")}
API = {"url_filtering": "url_filtering", "file_type_control": "file_type_control_rule", "dlp": "dlp_web_rules",
       "firewall": "cloud_firewall_rules", "dns": "cloud_firewall_dns", "ssl": "ssl_inspection_rules"}


def list_rules(t, kind, rule_type=None):
    if kind == "cloud_app_control":
        return items(t.call("cloudappcontrol", "list_rules", rule_type))
    return items(t.call(*LISTS[kind]))


def connect(cfg):
    try:
        t = ZiaTenant(cfg)
        list_rules(t, "url_filtering")
        return t
    except K.KitError:
        raise
    except Exception as e:
        raise K.KitError(f"Couldn't connect to ZIA: {e}") from e


ZIA_HINTS = [
    (r"Internet & SaaS \(ZIA\) service entitlement",
     "In ZIdentity, give the group 'SE-Demo: traffic generator' the Internet & SaaS (ZIA) service entitlement (Zscaler "
     "Help: 'Assigning entitlements to users'), set the test user's password there, then run setup again. It reuses "
     "the user it created."),
    (r"can't manage users",
     "See above: give the API role User Management access, or create the test user yourself and pass --user."),
    (r"RBA_LIMITED|scope restriction",
     "The client's ZIA API role doesn't cover this area. In Administration > Role Management, open the API role the "
     "kit's OneAPI client uses and give it full access to the area named in the error, then rerun."),
    (r"\b401\b|NOT_AUTHORIZED|Unauthorized",
     "The OneAPI client works but has no ZIA access. X"),
    (r"\b403\b|Forbidden|not permitted|insufficient",
     "The client's ZIA API role is read-only or missing a policy area. Give the role full access to URL Filtering, "
     "Cloud App Control, File Type Control, DLP, Firewall and Activation."),
    (r"EDIT_LOCK|edit lock|locked",
     "Another admin session is editing ZIA. Wait a minute, or activate pending changes in the console, then retry."),
    (r"DUPLICATE|already exists",
     "An object with that name already exists but isn't visible to the kit's API role. Rename or delete it in the console."),
    (r"name should be valid",
     "ZIA rejected characters in a name. Update the kit (this was fixed), or run with --prefix using only letters, "
     "digits and hyphens."),
    (r"Request body is invalid",
     "ZIA didn't accept the rule's apps or actions. Run setup with --verbose and send the lines for this rule to the "
     "kit owner (they show the apps and actions sent and what the tenant lists)."),
    (r"INVALID_NAME|can only have",
     "ZIA rejected characters in a name. Update the kit (git pull), then rerun setup: it picks up where it stopped."),
    (r"INVALID_INPUT_ARGUMENT|invalid",
     "Your tenant rejected a value (often a category, app or action it doesn't have). Run with --verbose to see which, "
     "then edit zia_policy_template.json or tell the kit owner."),
]


def zhint(err):
    text = str(err)
    for pat, fix in ZIA_HINTS:
        if re.search(pat, text, re.I):
            return fix
    return K.hint(err)


# ---------------------------------------------------------------- what the tenant has
def find_users(t, wanted):
    """wanted: emails or names. Returns (found [{id,name,email}], missing [str]). Demo tenants are small, so this
    reads the user list once and matches locally (the API's own filter only matches the start of the name)."""
    wanted = [x.strip() for x in wanted if x and x.strip()]
    if not wanted:
        return [], []
    users = items(t.call("user_management", "list_users", query_params={"page_size": 10000}))
    found, missing = [], []
    for w in wanted:
        hit = next((u for u in users if w.lower() in (str(g(u, "email", "")).lower(), str(g(u, "name", "")).lower())), None)
        if hit:
            found.append({"id": g(hit, "id"), "name": g(hit, "name"), "email": g(hit, "email")})
        else:
            missing.append(w)
    return found, missing


# ---------------------------------------------------------------- the test user
TEST_USER = {"login": "se-demo-traffic", "display": "SE-Demo Traffic", "first": "SE-Demo", "last": "Traffic"}


def test_user_names():
    """The test user's login and names follow the prefix, so another prefix (the nightly test's SE-CI) gets its own
    user and never touches the demo's."""
    if K.PREFIX == "SE-Demo":
        return TEST_USER
    return {"login": f"{K.slug(K.PREFIX)}-traffic", "display": f"{K.PREFIX} Traffic", "first": K.PREFIX, "last": "Traffic"}
NOT_TENANT_DOMAINS = re.compile(r"zscaler|zslogin|zscloud", re.I)
PW_KEY = "zia-test-user-password"   # keychain entry for the password of a test user the kit created
CONSOLE_USERS = "Administration > Internet & SaaS Authentication > Internet & SaaS Users"
MANUAL_TAB = " Step by step: Manual steps on the console's Setup tab, or aiguard-kit todo."
ZID_NOTE = ("ZIdentity's API can't set passwords, so set one yourself, once: Administration > Authentication > "
            "Directory > Users, click {email}, and set a password. Then sign in to Client Connector on the traffic "
            "generator as {email}. Never paste the password into chat or email." + MANUAL_TAB)
MANUAL_PW = ("Set or reset its password in the console: " + CONSOLE_USERS + ", click the pencil (Edit) on {email}, "
             "fill Change Password > Password and Confirm Password, then Save.")


def auth_mode(t):
    """How Client Connector users sign in to ZIA: 'hosted' (Hosted DB with form sign-in: the kit can create the user
    and its password), 'saml' or 'directory' (an IdP or AD/LDAP owns users and passwords), or None if unreadable.
    Console: Administration > Internet & SaaS Authentication > Internet Authentication Settings."""
    try:
        a = t.call("authentication_settings", "get_authentication_settings") or {}
    except Exception as e:
        K.vlog(f"auth settings: {e}")
        return None, ""
    repo = str(g(a, "org_auth_type") or "").upper()
    saml = bool(g(a, "saml_enabled"))
    detail = f"{'Hosted DB' if repo == 'SAFECHANNEL_DIR' else repo or 'unknown'}, {'SAML' if saml else 'form-based'} sign-in"
    if saml:
        return "saml", detail
    if repo == "SAFECHANNEL_DIR":
        return "hosted", detail
    return ("directory" if repo else None), detail


def gen_password(n=20):
    """Random, and meets ZIA's hosted-database password rules (upper, lower, digit, special, 8+ characters)."""
    import secrets
    import string
    special = "!@#$%^&*-_=+"
    pool = string.ascii_letters + string.digits + special
    while True:
        pw = "".join(secrets.choice(pool) for _ in range(n))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                and any(c in special for c in pw)):
            return pw


def test_user_password():
    return K.kc_get(PW_KEY)


def tenant_domain(t):
    """The email domain this tenant's users use (not Zscaler's own admin domains)."""
    from collections import Counter
    seen = Counter()
    for res, method, kw in (("zid.users", "list_users", {"query_params": {"limit": 1000}}),
                            ("user_management", "list_users", {"query_params": {"page_size": 10000}})):
        try:
            rows = items(t.call(res, method, **kw))
        except Exception as e:
            K.vlog(f"{res}: {e}")
            continue
        for u in rows:
            for key in ("primary_email", "login_name", "email"):
                v = str(g(u, key) or "")
                if "@" in v and not NOT_TENANT_DOMAINS.search(v.split("@", 1)[1]):
                    seen[v.split("@", 1)[1].lower()] += 1
    return seen.most_common(1)[0][0] if seen else None


def zid_find(t, email):
    rows = items(t.call("zid.users", "list_users", query_params={"login_name": email}))
    return next((u for u in rows if str(g(u, "login_name", "")).lower() == email.lower()), None)


ZIA_SERVICE = re.compile(r"\bZIA\b|internet\s*(&|and)\s*saas|internet access", re.I)
ENTITLE_FIX = ("ZIdentity created {email}, but hasn't given it the Internet & SaaS (ZIA) service entitlement, so ZIA "
               "never receives it (your tenant grants entitlements to chosen users or groups, not to everyone). In "
               "ZIdentity, assign the Internet & SaaS entitlement to the group '{group}' (or to the user), then run "
               "setup again; it picks up where it left off. Zscaler Help: 'Assigning entitlements to users'." + MANUAL_TAB)


def zid_services(t, user_id):
    """The service names a ZIdentity user is entitled to, or None if they can't be read. ZIdentity only syncs a user
    to ZIA when it has the Internet & SaaS entitlement, and its API can read entitlements but not grant them."""
    try:
        body = t.call("zid.user_entitlement", "get_service_entitlement", user_id)
    except Exception as e:
        K.vlog(f"entitlements {user_id}: {e}")
        return None
    names = []

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k in ("serviceName", "service_name", "name", "displayName", "display_name") and isinstance(v, str):
                    names.append(v)
                else:
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(body)
    return names


def zia_entitled(names):
    return names is None or any(ZIA_SERVICE.search(n) for n in names)


def zid_group(t, log):
    """ZIdentity group for the test user. Assign the Client Connector Z-Tunnel 2.0 app profile to it."""
    name = zname("traffic generator")
    rows = items(t.call("zid.groups", "list_groups", query_params={"limit": 1000}))
    hit = next((x for x in rows if g(x, "name") == name), None)
    if hit:
        return hit
    grp = t.call("zid.groups", "add_group", name=name, is_dynamic_group=False,
                 description="Test user(s) for the SE demo kit's ZIA traffic generator")
    log("ok", f"Created ZIdentity group '{name}'")
    return grp


def zid_domain(cfg):
    """ZIdentity's own domain for this tenant (<vanity>.zslogin.net). A test user there signs in with a ZIdentity
    password even when the company's domain is routed to an identity provider, which would refuse the password."""
    v = str(cfg.get("vanity_domain") or "").strip().lower()
    v = re.sub(r"\.zslogin\.net$", "", v)
    return f"{v}.zslogin.net" if v else None


def test_email(t, email=None, domain=None):
    if email:
        return email
    domain = domain or tenant_domain(t)
    if not domain:
        raise K.KitError("Couldn't tell which email domain this tenant's users use. Pass it: "
                         "./aiguard-kit zia setup --domain yourdomain.com")
    return f"{test_user_names()['login']}@{domain}"


def create_test_user(t, cfg, log, email=None, domain=None, via=None, wait=180, poll=10):
    """Creates the dedicated test user and scopes the demo to it. via="zia" (default): a ZIA Internet & SaaS user with
    a generated password kept in this computer's keychain. via="zidentity": a ZIdentity user (set its password by
    hand). Safe to run again: an existing user is reused."""
    z = zcfg(cfg)
    via = via or (z.get("created_user") or {}).get("via") or ("zidentity" if z.get("users_in_zidentity") else None)
    if not via:
        mode, detail = auth_mode(t)
        if mode == "directory":
            raise K.KitError(f"This tenant signs users in from a directory ({detail}), so the test user has to be "
                             f"created there. Create it, then rerun with --user <its email>.")
        via = "zidentity" if mode == "saml" else "zia"
        if mode == "saml":
            log("info", f"Users sign in with SAML ({detail}), so the test user is created in ZIdentity")
    if via == "zidentity":
        return create_zid_user(t, cfg, log, email, domain, wait, poll)
    try:
        return create_zia_user(t, cfg, log, email, domain)
    except K.KitError as e:
        if not zid_managed(e):
            raise
        log("info", "This tenant manages users in ZIdentity (ZIA's copies are read-only), so the test user is "
                    "created in ZIdentity instead")
        z["users_in_zidentity"] = True   # kept after teardown: next time setup goes straight to ZIdentity
        K.save_cfg(cfg)
        return create_zid_user(t, cfg, log, email, domain, wait, poll)


USER_MGMT_FIX = ("Either give the role User Management access (Administration > Role Management, open the API role "
                 "the kit's OneAPI client uses, set User Management to Full, save) and rerun setup, or create "
                 "{email} yourself (" + "Administration > Internet & SaaS Authentication > Internet & SaaS Users"
                 " > Add User) and rerun with --user {email}.")


ZID_MANAGED_FIX = ("This tenant manages users in ZIdentity, so ZIA's API can't create users or groups. Setup creates "
                   "the test user in ZIdentity instead: give the kit's API client ZIAM = Role: Users Admin "
                   "(Administration > API > OneAPI > API Clients > Resources), run setup, then set the user's password "
                   "once in ZIdentity. If your tenant grants the Internet & SaaS entitlement only to chosen users or "
                   "groups, assign it to the group 'SE-Demo: traffic generator' too, or ZIA never receives the user. "
                   "Or create {email} yourself and rerun with --user {email}.")


def zid_managed(e):
    """ZIA refuses user and group changes when ZIdentity owns the users ('UNMODIFIABLE ... OneIdentityUserLogin
    enabled users will have read only access'), whatever the API role allows."""
    return bool(re.search(r"UNMODIFIABLE|OneIdentity", str(e), re.I))


def rba_reason(e):
    """'RBA_LIMITED: Functional scope restriction' out of the SDK's multi-line error."""
    text = str(e)
    code = re.search(r'"code":\s*"([^"]+)"', text)
    msg = re.search(r'"message":\s*"([^"]+)"', text)
    return ": ".join(x.group(1) for x in (code, msg) if x) or text[:120]


def ensure_zia_ref(t, kind, name, log):
    """A ZIA group or department for the test user."""
    lister, adder = {"group": ("list_groups", "add_group"), "department": ("list_departments", "add_department")}[kind]
    rows = items(t.call("user_management", lister, query_params={"search": K.PREFIX}))
    hit = next((x for x in rows if g(x, "name") in names_for(name)), None)
    if hit:
        return hit
    made = with_valid_name(lambda **n: t.call("user_management", adder, comments="Created by the SE demo kit", **n), name)
    log("ok", f"Created ZIA {kind} '{g(made, 'name') or name}'")
    return made


def create_zia_user(t, cfg, log, email=None, domain=None):
    z = zcfg(cfg)
    email = test_email(t, email, domain)
    found, _ = find_users(t, [email])
    made = z.get("created_user") or {}
    if found:
        z["users"] = found
        K.save_cfg(cfg)
        if made.get("email") == email and test_user_password():
            log("ok", f"Test user {email} is ready (password in this computer's keychain: ./aiguard-kit zia password)")
        else:
            log("ok", f"{email} already exists in ZIA; the demo will use it")
            log("info", "The kit didn't create it, so it doesn't know its password. " + MANUAL_PW.format(email=email))
        return found[0]
    name = zname("traffic generator")
    try:
        grp = ensure_zia_ref(t, "group", name, log)
        dept = ensure_zia_ref(t, "department", name, log)
        pw = gen_password()
        user = t.call("user_management", "add_user", name=test_user_names()["display"], email=email, password=pw,
                      groups=[{"id": g(grp, "id")}], department={"id": g(dept, "id")},
                      comments="Test user for the SE demo kit's ZIA traffic generator")
    except K.KitError as e:
        if re.search(r"\b40[13]\b|unauthori|forbidden|not authorized", str(e), re.I):
            raise K.KitError(f"The OneAPI client's ZIA API role can't manage users ({rba_reason(e)}). "
                             f"{USER_MGMT_FIX.format(email=email)}") from e
        if re.search(r"password", str(e), re.I):
            raise K.KitError(f"ZIA rejected the generated password ({str(e)[:160]}). Check Password Strength in "
                             f"Administration > Internet & SaaS Authentication > Internet Authentication Settings, or create {email} yourself and rerun "
                             f"with --user {email}.") from e
        raise
    K.kc_set(PW_KEY, pw)
    z["created_user"] = {"via": "zia", "email": email, "zia_id": g(user, "id"), "group": name,
                         "zia_group_id": g(grp, "id"), "zia_dept_id": g(dept, "id")}
    z["users"] = [{"id": g(user, "id"), "name": g(user, "name") or test_user_names()["display"], "email": email}]
    K.save_cfg(cfg)
    log("ok", f"Created ZIA user {email} in group and department '{name}'")
    log("ok", "Its password is saved in this computer's keychain. Show it with ./aiguard-kit zia password "
              "(or Show password in the console's ZIA tab) when you sign in to Client Connector on the generator.")
    return z["users"][0]


def create_zid_user(t, cfg, log, email=None, domain=None, wait=180, poll=10):
    """The user goes on <vanity>.zslogin.net unless --user or --domain says otherwise: on a domain routed to an
    identity provider ZIdentity can't give it a password."""
    z = zcfg(cfg)
    made = z.get("created_user") or {}
    old = made.get("email") or ""
    if (made.get("via") == "zidentity" and old and email in (None, old) and not domain
            and not old.lower().endswith(".zslogin.net") and zid_domain(cfg)):
        # an earlier kit version put the user on the company domain; replace it, and keep the old one for teardown
        log("info", f"Replacing the earlier test user {old} with one on {zid_domain(cfg)}: on your company domain "
                    f"your identity provider handles sign-in, so ZIdentity can't give it a password. Teardown "
                    f"removes the old one too.")
        if made.get("zid_id"):
            z.setdefault("retired_users", []).append({"zid_id": made["zid_id"], "email": old})
        z.pop("created_user", None)
        z.pop("users", None)
        email = None
    email = test_email(t, email, domain or zid_domain(cfg))
    found, _ = find_users(t, [email])
    if found and not (z.get("created_user") or {}).get("email") == email:
        z["users"] = found
        K.save_cfg(cfg)
        log("ok", f"{email} already exists in ZIA; the demo will use it")
        return found[0]
    try:
        user = zid_find(t, email)
        if user:
            log("ok", f"{email} already exists in ZIdentity")
        else:
            user = t.call("zid.users", "add_user", login_name=email, primary_email=email, display_name=test_user_names()["display"],
                          first_name=test_user_names()["first"], last_name=test_user_names()["last"], status=True, source="API")
            log("ok", f"Created ZIdentity user {email}")
        grp = zid_group(t, log)
        try:
            t.call("zid.groups", "add_user_to_group", g(grp, "id"), g(user, "id"))
        except K.KitError as e:
            if not re.search(r"already|exist|409|duplicate", str(e), re.I):
                log("warn", f"Couldn't add the user to '{g(grp, 'name')}': {str(e)[:120]}")
    except K.KitError as e:
        if re.search(r"\b40[13]\b|unauthori|forbidden|not authorized", str(e), re.I):
            raise K.KitError(f"The OneAPI client can't manage ZIdentity users ({str(e)[:120]}). In Administration > "
                             f"API > OneAPI > API Clients, give the kit's client the ZIdentity user-management scope, or "
                             f"create {email} yourself and rerun with --user {email}.") from e
        raise
    z["created_user"] = {"via": "zidentity", "email": email, "zid_id": g(user, "id"), "group": g(grp, "name"),
                         "group_id": g(grp, "id")}
    K.save_cfg(cfg)
    if not found:
        log("info", "Waiting for ZIdentity to sync the user to ZIA (usually under a minute)…")
        deadline = time.time() + wait
        checked = False
        while True:
            found, _ = find_users(t, [email])
            if found or time.time() >= deadline:
                break
            if not checked:   # a user without the ZIA entitlement never syncs: say so now instead of waiting
                checked = True
                if not zia_entitled(zid_services(t, g(user, "id"))):
                    raise K.KitError(ENTITLE_FIX.format(email=email, group=g(grp, "name")))
            time.sleep(poll)
        if not found:
            services = zid_services(t, g(user, "id"))
            if not zia_entitled(services):
                raise K.KitError(ENTITLE_FIX.format(email=email, group=g(grp, "name")))
            raise K.KitError(f"Created {email} in ZIdentity, but ZIA hasn't received it yet. Check that it has the "
                             f"Internet & SaaS entitlement in ZIdentity (it needs it to reach ZIA), wait a few "
                             f"minutes, then rerun ./aiguard-kit zia setup (it picks up where it left off).")
    z["users"] = found
    K.save_cfg(cfg)
    log("ok", f"ZIA has the test user; the demo rules will apply only to {email}")
    log("warn", ZID_NOTE.format(email=email))
    return found[0]


def resolve(t, tpl):
    """Look up what the template names (engines, file types, isolation profile, actions). Missing items are reported,
    not fatal: the matching rule is skipped or trimmed."""
    facts = {"engines": {}, "file_types": None, "cbi": None, "notes": []}
    for e in items(t.call("dlp_engine", "list_dlp_engines_lite")):
        for key in ("name", "predefined_engine_name"):
            if g(e, key):
                facts["engines"][str(g(e, key))] = g(e, "id")
    try:
        cats = t.call("file_type_control_rule", "list_file_type_categories", query_params={"enums": "FILETYPECATEGORYFORFILETYPECONTROL"})
        names = {g(c, "name") if isinstance(c, dict) else c for c in items(cats)}
        facts["file_types"] = {n for n in names if n} or None
    except Exception as e:  # older tenants: no listing, so the template's names are sent as they are
        K.vlog(f"file type categories: {e}")
    try:
        profiles = items(t.call("cloud_browser_isolation", "list_isolation_profiles"))
        facts["cbi"] = next((p for p in profiles if g(p, "default_profile")), None) or (profiles[0] if profiles else None)
    except Exception as e:
        K.vlog(f"isolation profiles: {e}")
    return facts


def available_actions(t, rule_type, app):
    try:
        return [str(a) for a in items(t.call("cloudappcontrol", "list_available_actions", rule_type,
                                             [app] if app else []))
                if isinstance(a, str) and a]
    except Exception as e:
        K.vlog(f"actions {rule_type} {app}: {e}")
        return []


def _match(choice, avail):
    """The template's preferred action, else the tenant's action with the same verb and the same last word
    (BLOCK_FILE_SHARE_UPLOAD -> a BLOCK_/DENY_ action ending in UPLOAD)."""
    for a in choice:
        if a in avail:
            return a
    verb = ("BLOCK", "DENY") if choice[0].startswith(("BLOCK", "DENY")) else (choice[0].split("_", 1)[0],)
    tail = choice[0].rsplit("_", 2)[-2:] if choice[0].endswith("WEB_USE") else choice[0].rsplit("_", 1)[-1:]
    want = "_".join(tail)
    return next((a for a in avail if a.startswith(verb) and a.endswith(want)), None)


# Apps that list their full action set in each category. Many apps (DeepSeek, Claude, WeTransfer, TeamViewer…) list
# none: they only take the category's basic allow/deny web-use action, which the console offers for every app. The
# kit learns those action names from one of these apps rather than guessing them.
ACTION_REFERENCE = {"AI_ML": ["CHATGPT_AI", "GOOGLE_GEMINI"], "FILE_SHARE": ["DROPBOX", "GOOGLE_DRIVE", "BOX"],
                    "ENTERPRISE_COLLABORATION": ["SLACK", "WEBEX"]}


def _web_use(choice, avail):
    """The basic web-use action with the choice's verb (ALLOW_… or DENY_/BLOCK_…), from a list the tenant gave."""
    verb = ("BLOCK", "DENY") if choice[0].startswith(("BLOCK", "DENY")) else (choice[0].split("_", 1)[0],)
    return next((a for a in avail if a.startswith(verb) and a.endswith("_WEB_USE")), None)


def basic_actions(t, rule_type):
    for app in ACTION_REFERENCE.get(rule_type, []):
        avail = available_actions(t, rule_type, app)
        if avail:
            return avail
    return []


def pick_actions(t, rule_type, apps, choices):
    """Asks the tenant which actions each app supports. Returns (apps, actions, why): the largest set of apps that
    share actions matching the template's choices, or ([], None, why) when none do. Apps that list no actions of
    their own get the category's basic web-use action. Never guesses action names: a guessed name makes ZIA reject
    the whole rule ("Request body is invalid")."""
    groups, seen = {}, {}
    for app in apps:
        avail = available_actions(t, rule_type, app)
        seen[app] = avail
        picked = [_match(c, avail) for c in choices]
        if avail and None not in picked:
            groups.setdefault(tuple(picked), []).append(app)
    basic = [a for a in apps if not seen[a]]
    if groups:
        actions, kept = max(groups.items(), key=lambda kv: len(kv[1]))
        if basic and all(str(x).endswith("_WEB_USE") for x in actions):
            kept = [a for a in apps if a in kept or a in basic]      # basic apps take the same web-use action
        dropped = [a for a in apps if a not in kept]
        return kept, list(actions), (f"left out {', '.join(dropped)} (no matching actions)" if dropped else "")
    if basic == list(apps):
        ref = basic_actions(t, rule_type)
        web = list(dict.fromkeys(_web_use(c, ref) for c in choices))
        if ref and None not in web:
            finer = not all(str(c[0]).endswith(("_WEB_USE", "_ACCESS")) for c in choices)
            return list(apps), web, ("these apps only offer basic web-use control" +
                                     (", so the rule blocks the whole site, not just that activity" if finer else ""))
    general = available_actions(t, rule_type, None)   # some app types only list actions without an app
    if general:
        picked = [_match(c, general) for c in choices]
        if None not in picked:
            return list(apps), picked, "actions from the rule type (the apps list none of their own)"
    sample = sorted({a for v in seen.values() for a in v} | set(general))[:10]
    return [], None, ("your tenant lists no actions for " + ", ".join(apps) if not sample else
                      f"no action like {choices[0][0]} for {', '.join(apps)} (tenant offers: {', '.join(sample)})")


# ---------------------------------------------------------------- the plan
def plan(t, cfg, facts=None):
    """The objects setup will create or update, as (kind, rule_type, name, body) plus notes about skips."""
    tpl = template()
    facts = facts or resolve(t, tpl)
    z = zcfg(cfg)
    users = [u["id"] for u in z.get("users", [])]
    notes = list(facts["notes"])
    out = []
    scope = {"users": users, "state": "ENABLED", "rank": 7}

    all_methods = ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "OTHER", "POST", "PUT", "TRACE"]
    for r in tpl["url_filtering"]:
        out.append(("url_filtering", None, zname(r["name"]),
                    dict(scope, action=r["action"], url_categories=r["url_categories"], protocols=["ANY_RULE"],
                         # ZIA: Caution works only for CONNECT/GET/HEAD
                         request_methods=["CONNECT", "GET", "HEAD"] if r["action"] == "CAUTION" else all_methods,
                         description="SE demo kit: demo rule for the test user only")))
    for r in tpl.get("isolation", []):
        if not facts.get("cbi"):
            notes.append(f"'{zname(r['name'])}' skipped: no Cloud Browser Isolation profile in this tenant")
            continue
        cbi = facts["cbi"]
        out.append(("url_filtering", None, zname(r["name"]),
                    dict(scope, action="ISOLATE", url_categories=r["url_categories"], protocols=["HTTPS_RULE", "HTTP_RULE"],
                         request_methods=["CONNECT", "GET", "HEAD"],
                         user_agent_types=["CHROME", "FIREFOX", "MSEDGE", "MSCHREDGE", "SAFARI", "OPERA"],   # ZIA: known browsers only,
                         cbi_profile={"id": g(cbi, "id"), "name": g(cbi, "name"), "url": g(cbi, "url")},
                         description="SE demo kit: isolates this category for the test user")))
    for r in tpl["cloud_app_control"]:
        apps, actions, why = pick_actions(t, r["rule_type"], r["applications"], r["actions"])
        if not actions:
            notes.append(f"'{zname(r['name'])}' skipped: {why}")
            continue
        if why:
            notes.append(f"'{zname(r['name'])}': {why}")
        out.append(("cloud_app_control", r["rule_type"], zname(r["name"]),
                    dict(scope, applications=apps, actions=actions,
                         description="SE demo kit: Shadow IT and GenAI demo")))
    for r in tpl["file_type_control"]:
        types_ = r["file_types"]
        if facts.get("file_types"):
            skipped = [x for x in types_ if x not in facts["file_types"]]
            types_ = [x for x in types_ if x in facts["file_types"]]
            if skipped:
                notes.append(f"'{zname(r['name'])}': file types not in this tenant, left out: {', '.join(skipped)}")
        if not types_:
            continue
        out.append(("file_type_control", None, zname(r["name"]),
                    dict(scope, filtering_action=r["filtering_action"], operation=r["operation"], file_types=types_,
                         protocols=["FOHTTP_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE"],
                         description="SE demo kit: file type demo")))
    for r in tpl["dlp"]:
        ids = [facts["engines"][e] for e in r["engines"] if e in facts["engines"]]
        missing = [e for e in r["engines"] if e not in facts["engines"]]
        if missing:
            notes.append(f"'{zname(r['name'])}': DLP engines not found, left out: {', '.join(missing)}")
        if not ids:
            continue
        out.append(("dlp", None, zname(r["name"]),
                    dict(scope, action=r["action"], dlp_engines=ids, protocols=["FTP_RULE", "HTTPS_RULE", "HTTP_RULE"],
                         severity="RULE_SEVERITY_HIGH" if r["action"] == "BLOCK" else "RULE_SEVERITY_MEDIUM",
                         description="SE demo kit: fake card numbers and SSNs from the traffic generator")))
    for r in tpl["firewall"]:
        out.append(("firewall", None, zname(r["name"]),
                    dict(scope, action=r["action"], nw_services=r["nw_services"], enable_full_logging=True,
                         description="SE demo kit: unusual ports (needs Z-Tunnel 2.0)")))
    for r in tpl["dns"]:
        out.append(("dns", None, zname(r["name"]),
                    dict(scope, action=r["action"], res_categories=r["res_categories"],
                         description="SE demo kit: DNS control demo (needs Z-Tunnel 2.0)")))
    for r in tpl.get("ssl_inspection", []):   # template order = rule order (setup keeps it)
        body = dict(scope, action=SSL_ACTIONS[r["action"]],
                    description="SE demo kit: " + ("decrypts the test user's HTTPS" if r["action"] == "DECRYPT"
                                                   else "never decrypt AWS management traffic (remote desktop)"))
        if r.get("url_categories"):
            body["url_categories"] = r["url_categories"]
        out.append(("ssl", None, zname(r["name"]), body))
    return out, notes


SSL_ACTIONS = {
    "DECRYPT": {"type": "DECRYPT",
                "decrypt_sub_actions": {"server_certificates": "ALLOW", "ocsp_check": True,
                                        "block_ssl_traffic_with_no_sni_enabled": False,
                                        "min_client_tls_version": "CLIENT_TLS_1_0",
                                        "min_server_tls_version": "SERVER_TLS_1_0",
                                        "block_undecrypt": False}},
    "DO_NOT_DECRYPT": {"type": "DO_NOT_DECRYPT",
                       "do_not_decrypt_sub_actions": {"bypass_other_policies": False, "server_certificates": "ALLOW",
                                                      "ocsp_check": True,
                                                      "block_ssl_traffic_with_no_sni_enabled": False,
                                                      "min_tls_version": "SERVER_TLS_1_0"}},
}


def _resolve_refs(body, refs):
    """'@tenant_check' -> the custom category id; '@demo_ports' -> the network service id."""
    b = dict(body)
    if "url_categories" in b:
        b["url_categories"] = [refs.get(c, c) for c in b["url_categories"]]
    if "nw_services" in b:
        b["nw_services"] = [refs.get(c, c) for c in b["nw_services"]]
    return b


def ensure_label(t, log):
    name = label_name()   # rule labels reject ':'
    hit = next((x for x in items(t.call("rule_labels", "list_labels")) if g(x, "name") == name), None)
    if hit:
        return g(hit, "id")
    lab = t.call("rule_labels", "add_label", name=name, description="Objects created by the SE demo kit")
    log("ok", f"Created rule label '{name}'")
    return g(lab, "id")


def ensure_tenant_category(t, log, key="tenant_check"):
    tc = template()[key]
    name = zname(tc["name"])
    cats = items(t.call("url_categories", "list_categories", query_params={"custom_only": True}))
    hit = next((c for c in cats if g(c, "configured_name") in names_for(name)), None)
    body = dict(super_category="USER_DEFINED", urls=tc["urls"], custom_category=True, description=tc["description"])
    if hit:
        with_valid_name(lambda **n: t.call("url_categories", "update_url_category", g(hit, "id"), **n, **body),
                        g(hit, "configured_name"), "configured_name")
        return g(hit, "id")
    c = t.call("url_categories", "add_url_category", configured_name=safe_name(name), **body)   # no ':' allowed
    shown = ", ".join(tc["urls"][:3]) + (f" and {len(tc['urls']) - 3} more" if len(tc["urls"]) > 3 else "")
    log("ok", f"Created URL category '{g(c, 'configured_name') or name}' ({shown})")
    return g(c, "id")


def ensure_network_service(t, log):
    ns = template()["network_service"]
    name = zname(ns["name"])
    hit = next((s for s in items(t.call("cloud_firewall", "list_network_services", query_params={"search": K.PREFIX}))
                if g(s, "name") in names_for(name)), None)
    ports = [("dest", "tcp", str(p)) for p in ns["dest_tcp"]]
    if hit:   # ZIA has accepted ':' on create but rejected it on update, so a rejected name is renamed safely
        with_valid_name(lambda **n: t.call("cloud_firewall", "update_network_service", g(hit, "id"), ports=ports,
                                           description=ns["description"], **n), g(hit, "name"))
        return g(hit, "id")
    s = with_valid_name(lambda **n: t.call("cloud_firewall", "add_network_service", ports=ports,
                                           description=ns["description"], **n), name)
    log("ok", f"Created network service '{g(s, 'name') or name}' (TCP {', '.join(map(str, ns['dest_tcp']))})")
    return g(s, "id")


def _add_at_top(t, kind, rule_type, body, existing):
    """Rules go above the tenant's own, so the user-scoped demo rules win for the test user. Some tenants pin
    predefined rules at the top; then the next slot down is tried."""
    taken = sorted(int(g(r, "order") or 0) for r in existing if int(g(r, "order") or 0) > 0)
    last_err = None
    for order in range(1, (taken[-1] if taken else 0) + 2):
        try:
            b = dict(body, order=order)
            b.pop("name")
            if kind == "cloud_app_control":
                return with_valid_name(lambda **n: t.call("cloudappcontrol", "add_rule", rule_type, **n, **b), body["name"])
            return with_valid_name(lambda **n: t.call(API[kind], "add_rule", **n, **b), body["name"])
        except K.KitError as e:
            if not re.search(r"order|rank|predefined", str(e), re.I):
                raise
            last_err = e
    raise last_err


def setup_apply(t, cfg, log, facts=None):
    """Creates or updates every SE-Demo ZIA object, then activates. Safe to run again."""
    z = zcfg(cfg)
    if not z.get("users"):
        raise K.KitError("No test user chosen. Run `./aiguard-kit zia setup --user test.user@yourdomain` "
                         "(the user signed in to Client Connector on the traffic generator).")
    log("head", "Shared objects")
    refs = {"@tenant_check": ensure_tenant_category(t, log), "@demo_ports": ensure_network_service(t, log)}
    if template().get("aws_mgmt"):
        refs["@aws_mgmt"] = ensure_tenant_category(t, log, "aws_mgmt")
    label = ensure_label(t, log)
    rules, notes = plan(t, cfg, facts)
    for n in notes:
        log("warn", n)
    log("head", "Demo rules (scoped to " + ", ".join(u.get("email") or u["name"] for u in z["users"]) + ")")
    made, failed = 0, []
    cache, placed = {}, {}
    for kind, rule_type, name, body in rules:
        key = (kind, rule_type)
        if key not in cache:
            cache[key] = list_rules(t, kind, rule_type)
        existing = cache[key]
        b = _resolve_refs(dict(body, name=name, labels=[label]), refs)
        hit = next((r for r in existing if g(r, "name") in names_for(name)), None)
        try:
            if hit:
                b["order"] = g(hit, "order")
                b["name"] = g(hit, "name")   # keep the name ZIA accepted
                nm = b.pop("name")
                if kind == "cloud_app_control":
                    with_valid_name(lambda **n: t.call("cloudappcontrol", "update_rule", rule_type, g(hit, "id"), **n, **b), nm)
                else:
                    with_valid_name(lambda **n: t.call(API[kind], "update_rule", g(hit, "id"), **n, **b), nm)
                b["name"] = nm
                placed.setdefault(key, []).append((g(hit, "id"), b))
                log("ok", f"Updated '{name}'")
            else:
                r = _add_at_top(t, kind, rule_type, b, existing)
                existing.append(r if isinstance(r, dict) else {"name": name})
                if isinstance(r, dict) and g(r, "id"):
                    placed.setdefault(key, []).append((g(r, "id"), dict(b, name=g(r, "name") or b["name"])))
                log("ok", f"Created '{name}'")
            made += 1
        except Exception as e:
            failed.append(name)
            log("warn", f"'{name}' not created: {str(e)[:200]}. Fix: {zhint(e)}")
    for (kind, rule_type), group in placed.items():
        try:
            keep_template_order(t, kind, rule_type, group, log)
        except Exception as e:
            log("warn", f"Couldn't put the {kind.replace('_', ' ')} demo rules in order: {str(e)[:160]}")
    log("head", "Client Connector (test user's group only)")
    zcc = setup_zcc(t, cfg, log)
    log("head", "Activate")
    activate(t, log)
    z["state"] = {"set_up": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "rules": made, "failed": failed,
                  "tenant_check_category": refs["@tenant_check"], "client_connector": zcc}
    K.save_cfg(cfg)
    return {"rules": made, "failed": failed, "notes": notes, "client_connector": zcc}


# ---------------------------------------------------------------- Client Connector
ZCC_MANUAL = ("In the Client Connector portal: copy your Windows forwarding profile, set its ZIA action to Tunnel with "
              "Z-Tunnel 2.0, then add a Windows app profile for the test user's group with 'Install Zscaler SSL "
              "Certificate' on and that forwarding profile (ZIA.md, step 2).")
ZCC_BY_HAND = ("Create them by hand in the Client Connector portal, then run Fix drift (`./aiguard-kit zia status --fix`), "
               "which finds them by name and uses them as they are: "
               "1) Forwarding profile named exactly '{fwd}': ZIA action Tunnel with Z-Tunnel 2.0 on every network type "
               "(on corporate network, off corporate network, VPN, split VPN). "
               "2) Windows app profile named exactly '{app}': group '{group}', Install Zscaler SSL Certificate on, "
               "forwarding profile '{fwd}', and no broader profile above it in the order." + MANUAL_TAB)


def zcc_by_hand(cfg):
    app, fwd = zcc_names()
    made = zcfg(cfg).get("created_user") or {}
    return ZCC_BY_HAND.format(app=app, fwd=fwd, group=made.get("group") or zname("traffic generator"))


def _bare_400(e):
    return bool(re.search(r"\b400\b|invalid|bad request", str(e), re.I))


def app_ok(a, fwd_id, gid):
    """The app profile already does what the kit needs (as Fix drift checks it), so no write is needed."""
    groups = [int(g(x, "id")) for x in (a.get("groups") or []) if g(x, "id")] or \
        [int(x) for x in (a.get("groupIds") or []) if x]
    return (int(gid) in groups and str(g(a, "forwardingProfileId")) == str(fwd_id)
            and int((a.get("windowsPolicy") or {}).get("installSslCerts") or 0) == 1 and int(g(a, "active") or 0) == 1)


ZCC_DROP = {"id", "groups", "users", "deviceGroups", "groupNames", "userNames", "deviceGroupNames", "policyToken",
            "createdBy", "editedBy", "lastModification", "lastModifiedBy", "lastModifiedTime"}


# Trusted-network conditions point at objects of the profile they came from; on a new profile ZCC can reject them
# with a bare 400. The kit's profile is for one demo machine, so it doesn't need them.
ZCC_TRUSTED = {"trustedNetworkIds", "trustedNetworks", "trustedSubnets", "trustedGateways", "trustedDhcpServers",
               "trustedEgressIps", "dnsServers", "dnsSearchDomains", "hostname", "resolvedIpsForHostname",
               "conditionType", "predefinedTrustedNetworks", "predefinedTnAll", "skipTrustedCriteriaMatch"}


def _clean_fwd(fwd):
    """A forwarding-profile body with nothing tied to another profile: no ids inside the per-network actions and
    no trusted-network conditions."""
    out = {k: v for k, v in fwd.items() if k not in ZCC_TRUSTED}
    out["evaluateTrustedNetwork"] = 0
    for key in ("forwardingProfileActions", "forwardingProfileZpaActions"):
        if isinstance(out.get(key), list):
            out[key] = [{k: v for k, v in dict(a).items() if k not in ("id", "forwardingProfileId")}
                        for a in out[key] if isinstance(a, dict)]
    return out


ZCC_CORE_ACTION = ("networkType", "actionType", "enablePacketTunnel", "primaryTransport", "allowTLSFallback",
                   "tunnel2FallbackType", "DTLSTimeout", "UDPTimeout", "TLSTimeout", "mtuForZadapter", "systemProxy",
                   "systemProxyData")


def _minimal_fwd(fwd_name, actions):
    """Only what a Z-Tunnel 2.0 profile needs: a name and, per network type, Tunnel + Z-Tunnel 2.0."""
    nets = sorted({int(a.get("networkType") or 0) for a in actions if isinstance(a, dict)}) or [0, 1, 2, 3]
    by = {int(a.get("networkType") or 0): a for a in actions if isinstance(a, dict)}
    acts = []
    for n in nets:
        a = {k: v for k, v in dict(by.get(n) or {}).items() if k in ZCC_CORE_ACTION}
        a.update(networkType=n, actionType=ZCC_TUNNEL, enablePacketTunnel=1)
        a.setdefault("primaryTransport", 1)
        acts.append(a)
    return {"name": fwd_name, "active": 1, "evaluateTrustedNetwork": 0, "forwardingProfileActions": acts}


def _save_fwd(t, log, fwd, src_fwd, fwd_name):
    """Creates or updates the kit's forwarding profile. ZCC can answer a bare 400 to a body copied from another
    profile, so this tries progressively plainer copies and says which one it kept."""
    plain = dict(_clean_fwd(fwd))
    base_acts = [dict(a) for a in (src_fwd or {}).get("forwardingProfileActions") or []]
    for a in base_acts:
        a.update(actionType=ZCC_TUNNEL, enablePacketTunnel=1)
    from_base = dict(_clean_fwd(dict(plain, forwardingProfileActions=base_acts))) if base_acts else None
    no_ut = {k: v for k, v in plain.items() if k not in ("unifiedTunnel", "enableUnifiedTunnel")}
    no_zpa = {k: v for k, v in no_ut.items() if k not in ("forwardingProfileZpaActions", "enableLWFDriver")}
    tries = [("as copied", fwd), ("without trusted-network conditions and copied ids", plain)]
    if from_base:
        tries.append(("from your default profile's actions, switched to Z-Tunnel 2.0", from_base))
    tries += [("without the Unified Tunnel settings", no_ut),
              ("without the Unified Tunnel and ZPA tunnel settings", no_zpa),
              ("as a minimal Z-Tunnel 2.0 profile", _minimal_fwd(fwd_name, plain.get("forwardingProfileActions") or []))]
    last = None
    for i, (how, body) in enumerate(tries):
        try:
            res = t.call("zcc.forwarding_profile", "update_forwarding_profile", **body)
            if i:
                log("info", f"Forwarding profile '{fwd_name}': saved {how} (Client Connector refused the fuller copy)")
            return res
        except Exception as e:
            last = e
            if not re.search(r"\b400\b|invalid|bad request", str(e), re.I):
                raise
            K.vlog(f"forwarding profile ({how}) refused: {e}")
    raise last


def _zcc_list(t, resource, **q):
    return items(t.call(resource, "list_by_company", query_params=q or None))


def zcc_names():
    """Client Connector profile names follow the prefix too ('SE-Demo traffic generator' -> 'SE-CI traffic generator')."""
    c = template().get("client_connector") or {}
    fix = lambda n: n.replace("SE-Demo", K.PREFIX, 1) if n else n   # noqa: E731
    return fix(c.get("app_profile")), fix(c.get("forwarding_profile"))


def zcc_group_id(cfg, t=None):
    """The ZIA group the Client Connector profiles are scoped to. A ZIA-created test user has it from setup; a
    ZIdentity-created one gets ZIA's synced copy of its ZIdentity group, looked up by name and remembered."""
    made = zcfg(cfg).get("created_user") or {}
    if made.get("zia_group_id") or t is None or made.get("via") != "zidentity":
        return made.get("zia_group_id")
    try:
        rows = items(t.call("user_management", "list_groups", query_params={"search": K.PREFIX}))
    except Exception as e:
        K.vlog(f"ZIA groups: {e}")
        return None
    hit = next((x for x in rows if g(x, "name") in names_for(made.get("group") or zname("traffic generator"))), None)
    if hit:
        made["zia_group_id"] = g(hit, "id")   # ZIA's copy: teardown removes the ZIdentity group, never this id
        K.save_cfg(cfg)
    return made.get("zia_group_id")


def setup_zcc(t, cfg, log):
    """A Windows app profile for the kit's test-user group: a copy of the default Windows profile that installs the
    Zscaler root certificate and uses a Z-Tunnel 2.0 copy of its forwarding profile. Other users are untouched.
    Best effort: anything ZCC's API refuses is reported with the manual steps, and the ZIA policy still applies."""
    app_name, fwd_name = zcc_names()
    if not app_name:
        return None
    gid = zcc_group_id(cfg, t)
    if not gid:
        made = zcfg(cfg).get("created_user") or {}
        if made.get("via") == "zidentity":
            log("warn", f"Client Connector profiles not created yet: ZIA hasn't received the ZIdentity group "
                        f"'{made.get('group')}'. ZIdentity syncs it once the test user has signed in. Sign in to "
                        f"Client Connector on the generator as {made.get('email')}, then run setup again (or Fix "
                        f"drift) to add the profiles.")
        else:
            log("warn", "Client Connector profiles skipped: the test user wasn't created by the kit, so there's no "
                        "kit group to scope them to. " + ZCC_MANUAL)
        return None
    try:
        policies = _zcc_list(t, "zcc.web_policy", device_type="windows")
        fwds = _zcc_list(t, "zcc.forwarding_profile")
    except Exception as e:
        log("warn", f"Client Connector profiles skipped: couldn't read them ({str(e)[:140]}). Give the API client "
                    "Client Connector access, or do it by hand. " + ZCC_MANUAL)
        return None
    mine_app = next((p for p in policies if g(p, "name") == app_name), None)
    base = next((p for p in sorted(policies, key=lambda p: -int(g(p, "ruleOrder") or 0))
                 if g(p, "name") != app_name and int(g(p, "groupAll") or 0) == 1), None) or \
        next((p for p in policies if g(p, "name") != app_name), None)
    if not base and not mine_app:
        log("warn", "Client Connector profiles skipped: no Windows app profile to copy. " + ZCC_MANUAL)
        return None
    z = zcfg(cfg)
    hit_fwd = next((f for f in fwds if g(f, "name") == fwd_name), None)
    hit_acts = (hit_fwd or {}).get("forwardingProfileActions") or []
    if hit_fwd and hit_acts and all(is_z2(a) for a in hit_acts):
        fwd_id = g(hit_fwd, "id")   # already Tunnel + Z-Tunnel 2.0 (made by the kit or by hand): use it as it is
        log("ok", f"Forwarding profile '{fwd_name}' is already Z-Tunnel 2.0; using it as it is")
    elif z.get("zcc_api_refused"):
        log("warn", "Client Connector profiles not created: an earlier run found that this tenant's Client Connector "
                    "API refuses new forwarding profiles. " + zcc_by_hand(cfg))
        return None
    else:
        try:
            src_fwd_id = g(base or mine_app, "forwardingProfileId")
            src_fwd = next((f for f in fwds if str(g(f, "id")) == str(src_fwd_id)), None) or \
                next((f for f in fwds if g(f, "name") != fwd_name), None)
            fwd = {k: v for k, v in dict(hit_fwd or src_fwd or {}).items() if k not in ZCC_DROP}
            acts, how = z2_actions(fwds, fwd_name, fwd.get("forwardingProfileActions") or [])
            fwd.update(name=fwd_name, forwardingProfileActions=acts)
            log("info", f"Forwarding profile '{fwd_name}': {how}")
            if hit_fwd:
                fwd["id"] = g(hit_fwd, "id")
            res = _save_fwd(t, log, fwd, src_fwd, fwd_name)
            fwd_id = g(res, "id") if isinstance(res, dict) and g(res, "id") else g(hit_fwd, "id")
            if not fwd_id:
                fwd_id = next((g(f, "id") for f in _zcc_list(t, "zcc.forwarding_profile") if g(f, "name") == fwd_name), None)
            log("ok", f"{'Updated' if hit_fwd else 'Created'} forwarding profile '{fwd_name}' (Z-Tunnel 2.0)")
        except Exception as e:
            if _bare_400(e):   # even the minimal profile was refused: retrying on later runs won't help
                z["zcc_api_refused"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
                K.save_cfg(cfg)
                log("warn", "Client Connector profiles not created: this tenant's Client Connector API refused every "
                            "version of the forwarding profile, down to a minimal Z-Tunnel 2.0 one (HTTP 400, no "
                            "reason given). The ZIA policy still applies. " + zcc_by_hand(cfg))
            else:
                log("warn", f"Forwarding profile '{fwd_name}' not created: {str(e)[:180]}. " + ZCC_MANUAL)
            return None
    if mine_app and app_ok(mine_app, fwd_id, gid):
        log("ok", f"Windows app profile '{app_name}' already uses '{fwd_name}' for the test group; using it as it is")
        zcc_verify(t, log, app_name, fwd_name, gid)
        return {"app_profile": app_name, "forwarding_profile": fwd_name}
    try:
        app = {k: v for k, v in dict(mine_app or base).items() if k not in ZCC_DROP}
        win = dict(app.get("windowsPolicy") or {})
        win["installSslCerts"] = 1
        app.update(name=app_name, description="SE demo kit: the traffic generator's test user only", active=1,
                   groupAll=0, groupIds=[int(gid)], userIds=[], forwardingProfileId=fwd_id, windowsPolicy=win,
                   deviceType=app.get("deviceType") or "DEVICE_TYPE_WINDOWS")
        if mine_app:
            app["id"] = g(mine_app, "id")
        else:
            app["ruleOrder"] = 1
        t.call("zcc.web_policy", "web_policy_edit", **app)
        log("ok", f"{'Updated' if mine_app else 'Created'} Windows app profile '{app_name}' (installs the Zscaler "
                  "root certificate, uses Z-Tunnel 2.0). On the traffic generator, open Client Connector, turn "
                  "Internet Security off and on (or log out and back in) so the new tunnel is used.")
        zcc_verify(t, log, app_name, fwd_name, gid)
        return {"app_profile": app_name, "forwarding_profile": fwd_name}
    except Exception as e:
        log("warn", f"App profile '{app_name}' not created: {str(e)[:180]}. " + (zcc_by_hand(cfg) if _bare_400(e) else ZCC_MANUAL))
        return {"forwarding_profile": fwd_name}


ZCC_TUNNEL = 1   # forwardingProfileActions.actionType for "Tunnel" (the console's other choices: Tunnel with Local
                 # Proxy, Enforce Proxy, None). Z-Tunnel 2.0 is "Tunnel" plus enablePacketTunnel = 1.


def is_z2(action):
    return int(action.get("actionType") or 0) == ZCC_TUNNEL and int(action.get("enablePacketTunnel") or 0) == 1


def z2_actions(fwds, fwd_name, base_actions):
    """The ZIA actions for the kit's Z-Tunnel 2.0 profile, and how they were chosen. Best: copy a forwarding profile
    you already set to Tunnel + Z-Tunnel 2.0 in the console (its settings are known to work in this tenant).
    Otherwise switch a copy of the default profile's actions to Tunnel + Z-Tunnel 2.0."""
    ref = next((f for f in fwds if g(f, "name") != fwd_name and (f.get("forwardingProfileActions") or [])
                and all(int(a.get("enablePacketTunnel") or 0) == 1 for a in f["forwardingProfileActions"])), None)
    if ref:
        return ([dict(a) for a in ref["forwardingProfileActions"]],
                f"copied the ZIA tunnel settings of your Z-Tunnel 2.0 profile '{g(ref, 'name')}'")
    acts = [dict(a) for a in base_actions]
    for a in acts:
        a.update(actionType=ZCC_TUNNEL, enablePacketTunnel=1)
    return acts, "set every network type to Tunnel with Z-Tunnel 2.0"


def zcc_verify(t, log, app_name, fwd_name, gid):
    """Reads both profiles back, so what ZCC actually stored is visible (its API can accept fields it ignores)."""
    try:
        f = next((x for x in _zcc_list(t, "zcc.forwarding_profile") if g(x, "name") == fwd_name), None)
        pols = _zcc_list(t, "zcc.web_policy", device_type="windows")
        a = next((x for x in pols if g(x, "name") == app_name), None)
    except Exception as e:
        log("warn", f"Couldn't read the Client Connector profiles back: {str(e)[:140]}")
        return
    acts = (f or {}).get("forwardingProfileActions") or []
    z2 = [x for x in acts if is_z2(x)]
    log("ok" if f and z2 else "warn",
        f"Forwarding profile '{fwd_name}': " + ("not found" if not f else
        f"Z-Tunnel 2.0 on {len(z2)} of {len(acts)} network types "
        f"({', '.join(str(x.get('networkType')) + ':' + str(x.get('actionType')) + '/' + str(x.get('enablePacketTunnel')) for x in acts)})"))
    if not a:
        log("warn", f"App profile '{app_name}': not found after saving")
        return
    groups = [g(x, "id") for x in (a.get("groups") or [])] or a.get("groupIds") or []
    ahead = [g(x, "name") for x in pols if int(g(x, "ruleOrder") or 0) < int(g(a, "ruleOrder") or 0)
             and int(g(x, "active") or 0) == 1]
    ok_ = str(g(a, "forwardingProfileId")) == str(g(f or {}, "id")) and int(gid) in [int(x) for x in groups if x]
    log("ok" if ok_ and not ahead else "warn",
        f"App profile '{app_name}': order {g(a, 'ruleOrder')}, active {g(a, 'active')}, groups {groups}, forwarding "
        f"profile {g(a, 'forwardingProfileId')}, install certificate "
        f"{(a.get('windowsPolicy') or {}).get('installSslCerts')}"
        + (f"; profiles ahead of it: {', '.join(map(str, ahead))}" if ahead else ""))


def zcc_objects(t):
    app_name, fwd_name = zcc_names()
    found = []
    if not app_name:
        return found
    try:
        found += [("zcc_app_profile", None, p) for p in _zcc_list(t, "zcc.web_policy", device_type="windows")
                  if g(p, "name") == app_name]
        found += [("zcc_forwarding_profile", None, f) for f in _zcc_list(t, "zcc.forwarding_profile")
                  if g(f, "name") == fwd_name]
    except Exception as e:
        K.vlog(f"list zcc: {e}")
    return found


def keep_template_order(t, kind, rule_type, group, log):
    """ZIA applies the first matching rule, so the kit's rules of one kind must keep the template's order (for
    example 'Block card numbers' above 'Monitor PII and PCI'). New rules each go on top, which reverses them, and
    older kit versions left them reversed; this reassigns the slots the kit's rules already hold, in template order."""
    if len(group) < 2:
        return
    current = {g(r, "id"): int(g(r, "order") or 0) for r in list_rules(t, kind, rule_type)}
    ids = [rid for rid, _ in group if rid in current]
    slots = sorted(current[rid] for rid in ids)
    if [current[rid] for rid in ids] == slots:
        return
    for (rid, body), order in zip([x for x in group if x[0] in current], slots):
        b = dict(body, order=order)
        nm = b.pop("name")
        if kind == "cloud_app_control":
            t.call("cloudappcontrol", "update_rule", rule_type, rid, name=nm, **b)
        else:
            t.call(API[kind], "update_rule", rid, name=nm, **b)
    log("ok", f"Put the {kind.replace('_', ' ')} demo rules in order: " + " > ".join(b["name"] for _, b in group))


def activate(t, log):
    try:
        t.call("activate", "activate")
        log("ok", "Changes activated")
    except Exception as e:
        log("warn", f"Activation failed: {str(e)[:160]}. Activate pending changes in the ZIA console. {zhint(e)}")


# ---------------------------------------------------------------- drift (is the tenant still what setup made?)
KIND_LABEL = {"url_filtering": "URL filtering", "cloud_app_control": "Cloud App Control", "file_type_control":
              "File Type Control", "dlp": "DLP", "firewall": "firewall", "dns": "DNS control", "ssl": "SSL inspection"}


def _chk(cid, label, status, detail="", fix="", fixable=False):
    return {"id": cid, "label": label, "status": status, "detail": detail, "fix": fix, "fixable": fixable}


def drift(t, cfg):
    """Compares the tenant with what setup would make. Returns kit-style checks; 'fixable' ones are repaired by
    running setup again (`zia status --fix`). Objects you made yourself are reported, never changed."""
    z = zcfg(cfg)
    out = []
    if not z.get("users"):
        return [_chk("drift-user", "Demo policy set up", "fail", "no test user chosen yet",
                     "Run `zia setup` (or Create or update policy in the console).")]
    uid = {u["id"] for u in z["users"]}
    rules, notes = plan(t, cfg)
    cache, groups = {}, {}
    for kind, rule_type, name, body in rules:
        groups.setdefault((kind, rule_type), []).append(name)
    missing, disabled, unscoped, order_bad, lookalike = [], [], [], [], []
    for (kind, rule_type), names in groups.items():
        try:
            existing = cache.setdefault((kind, rule_type), list_rules(t, kind, rule_type))
        except Exception as e:
            out.append(_chk(f"drift-{kind}", f"{KIND_LABEL[kind]} rules", "warn", f"couldn't read them: {str(e)[:120]}"))
            continue
        found = []
        for name in names:
            hit = next((r for r in existing if g(r, "name") in names_for(name)), None)
            if not hit:
                missing.append(name)
                continue
            found.append((name, int(g(hit, "order") or 0)))
            if g(hit, "state") not in (None, "ENABLED"):
                disabled.append(name)
            users = {g(u, "id") if isinstance(u, dict) else u for u in (g(hit, "users") or [])}
            if users and not users & uid:
                unscoped.append(name)
        orders = [o for _, o in found]
        if orders != sorted(orders):
            order_bad.append(f"{KIND_LABEL[kind]}: " + " > ".join(n for n, _ in sorted(found, key=lambda x: x[1])))
        planned = {x for n in names for x in names_for(n)}
        lookalike += [f"'{g(r, 'name')}' ({KIND_LABEL[kind]})" for r in existing
                      if str(g(r, "name") or "").startswith(K.PREFIX) and g(r, "name") not in planned and not mine(r)]
    total = len(rules)
    if missing:
        out.append(_chk("drift-missing", "Demo rules present", "warn", f"{len(missing)} of {total} missing: " +
                        ", ".join(missing[:6]) + ("…" if len(missing) > 6 else ""), "Run `zia status --fix`.", True))
    else:
        out.append(_chk("drift-missing", "Demo rules present", "ok", f"all {total}"))
    if disabled:
        out.append(_chk("drift-disabled", "Demo rules enabled", "warn", ", ".join(disabled), "Run `zia status --fix`.", True))
    if unscoped:
        out.append(_chk("drift-scope", "Demo rules apply to the test user", "warn", ", ".join(unscoped),
                        "Run `zia status --fix`.", True))
    out.append(_chk("drift-order", "Demo rules in the intended order", "warn" if order_bad else "ok",
                    "; ".join(order_bad) if order_bad else "first match wins, so blocks sit above monitors",
                    "Run `zia status --fix`." if order_bad else "", bool(order_bad)))
    if lookalike:
        out.append(_chk("drift-lookalike", "Objects named like the kit's, but not the kit's", "info", ", ".join(lookalike),
                        "Setup and teardown leave these alone. Delete them in the console if you made them for testing."))
    for n in notes:
        out.append(_chk("drift-note", "Skipped by design", "info", n))
    out += zcc_drift(t, cfg)
    try:
        st = t.call("activate", "status")
        state = g(st, "status") if isinstance(st, dict) else st
        if state and str(state).upper() != "ACTIVE":
            out.append(_chk("drift-activate", "ZIA changes activated", "warn", f"status {state}",
                            "Activate pending changes in the ZIA console, or run `zia status --fix`.", True))
    except Exception as e:
        K.vlog(f"activation status: {e}")
    return out


def zcc_drift(t, cfg):
    app_name, fwd_name = zcc_names()
    gid = zcc_group_id(cfg, t)
    if not app_name or not gid:
        return []
    try:
        fwds = _zcc_list(t, "zcc.forwarding_profile")
        pols = _zcc_list(t, "zcc.web_policy", device_type="windows")
    except Exception as e:
        return [_chk("drift-zcc", "Client Connector profiles", "info", f"couldn't read them ({str(e)[:100]})",
                     "Give the API client Client Connector access to check these.")]
    out = []
    refused = bool(zcfg(cfg).get("zcc_api_refused"))
    f = next((x for x in fwds if g(x, "name") == fwd_name), None)
    acts = (f or {}).get("forwardingProfileActions") or []
    if not f:
        out.append(_chk("drift-zcc-fwd", "Z-Tunnel 2.0 forwarding profile", "warn", f"'{fwd_name}' not found",
                        zcc_by_hand(cfg) if refused else "Run `zia status --fix`.", not refused))
    elif not acts or not all(is_z2(a) for a in acts):
        out.append(_chk("drift-zcc-fwd", "Z-Tunnel 2.0 forwarding profile", "warn",
                        f"'{fwd_name}' isn't Tunnel + Z-Tunnel 2.0 on every network type",
                        "Run `zia status --fix`, then turn Client Connector off and on on the generator.", True))
    else:
        out.append(_chk("drift-zcc-fwd", "Z-Tunnel 2.0 forwarding profile", "ok", f"'{fwd_name}'"))
    a = next((x for x in pols if g(x, "name") == app_name), None)
    if not a:
        out.append(_chk("drift-zcc-app", "Client Connector app profile for the test group", "warn",
                        f"'{app_name}' not found", zcc_by_hand(cfg) if refused else "Run `zia status --fix`.", True))
        return out
    groups = [int(g(x, "id")) for x in (a.get("groups") or []) if g(x, "id")] or \
        [int(x) for x in (a.get("groupIds") or []) if x]
    problems = []
    if int(gid) not in groups:
        problems.append("not assigned to the test group")
    if f and str(g(a, "forwardingProfileId")) != str(g(f, "id")):
        problems.append(f"uses another forwarding profile ({g(a, 'forwardingProfileId')})")
    if int((a.get("windowsPolicy") or {}).get("installSslCerts") or 0) != 1:
        problems.append("doesn't install the Zscaler root certificate")
    if int(g(a, "active") or 0) != 1:
        problems.append("inactive")
    ahead = [g(x, "name") for x in pols if x is not a and int(g(x, "active") or 0) == 1
             and int(g(x, "ruleOrder") or 0) < int(g(a, "ruleOrder") or 0)
             and (int(g(x, "groupAll") or 0) == 1 or int(gid) in [int(g(y, "id")) for y in (x.get("groups") or []) if g(y, "id")])]
    if ahead:
        problems.append("profiles that also match the test user come first: " + ", ".join(map(str, ahead)))
    out.append(_chk("drift-zcc-app", "Client Connector app profile for the test group", "warn" if problems else "ok",
                    "; ".join(problems) if problems else f"'{app_name}'",
                    "Run `zia status --fix`." if problems else "", bool(problems)))
    return out


def fix_drift(t, cfg, log):
    """Repairs what the kit owns by running setup again (it creates, updates and re-orders in place)."""
    res = setup_apply(t, cfg, log)
    return {"setup": res, "checks": drift(t, cfg)}


# ---------------------------------------------------------------- demo readiness
LEAD_DAYS = 3   # Insights answers for windows ending about 2 days ago, so traffic must start this long before a demo


def _age_hours(stamp):
    try:
        from datetime import datetime, timezone
        dt = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S%z")
        return (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    except Exception:
        return None


def _new_york_now():
    try:
        from datetime import datetime
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo("America/New_York"))
    except Exception:   # Windows without the tzdata package
        return None


def ready_checks(cfg, tenant=None):
    """The ZIA half of the demo readiness check. tenant: a callable returning the ZIA tenant (admin machine only)."""
    z = zcfg(cfg)
    out = []
    last = _last_traffic()
    if last:   # this machine is a traffic generator
        age = _age_hours(last.get("time", ""))
        acted = sum(int(v.get("block") or 0) for v in (last.get("by_type") or {}).values())
        if last.get("skipped"):
            out.append(_chk("ready-gen", "Traffic generator", "fail", last.get("summary", "last round skipped"),
                            "Sign in to Client Connector as the test user, then Check this machine."))
        elif age is not None and age > 2:
            out.append(_chk("ready-gen", "Traffic generator", "warn", f"last round {age:.0f} hours ago",
                            "Start the instance or the scheduled task (zia schedule install), then Send one round."))
        else:
            out.append(_chk("ready-gen", "Traffic generator", "ok",
                            f"last round {('%.0f min' % (age * 60)) if age is not None else 'recently'} ago: "
                            f"{last.get('total', 0)} requests, Zscaler acted on {acted}"))
    if z.get("users") and tenant:
        try:
            t = tenant()
            d = drift(t, cfg)
            bad = [c for c in d if c["status"] in ("warn", "fail")]
            out.append(_chk("ready-zia-policy", "ZIA demo policy", "warn" if bad else "ok",
                            "; ".join(c["label"] + (": " + c["detail"] if c["detail"] else "") for c in bad)[:300]
                            if bad else "all demo rules and profiles in place",
                            "Run `zia status --fix` (or Check for drift > Fix drift in the console)." if bad else "",
                            any(c.get("fixable") for c in bad)))
            dash = dashboards(t)
            panels = dash.get("panels", [])
            full = [p for p in panels if p["status"] == "ok"]
            empty = [p["label"] for p in panels if p["status"] in ("empty", "partial")]
            out.append(_chk("ready-insights", "ZIA dashboards have data", "ok" if full and not empty else
                            "warn", f"{len(full)} of {len(panels)} panels" + (f"; empty: {', '.join(empty)}" if empty else ""),
                            "" if full and not empty else f"Insights trails by about 2 days: keep the generator running "
                            f"and check again. Start it at least {LEAD_DAYS} days before a demo."))
        except K.KitError as e:
            out.append(_chk("ready-zia-policy", "ZIA demo policy", "warn", str(e)[:200], zhint(e)))
    elif not last:
        out.append(_chk("ready-zia-policy", "ZIA demo policy", "info", "not set up on this machine",
                        "Run `zia setup` on your admin machine."))
    if z.get("aws"):
        now = _new_york_now()
        line = "The AWS generator stops at 9 PM New York time and starts itself at 7 AM on weekdays only"
        off = now is not None and (now.hour >= 21 or now.hour < 7 or (now.weekday() >= 5))
        out.append(_chk("ready-aws", "AWS generator schedule", "warn" if off else "info",
                        line + (" — it's probably stopped right now." if off else "."),
                        "EC2 > Instances > select it > Instance state > Start, about 5 minutes before you need it."
                        if off else "If you turned the schedule off, ignore this."))
    out.append(_chk("ready-lead", "Lead time", "info", f"Start traffic at least {LEAD_DAYS} days before a demo",
                    "ZIA logs show traffic within minutes; Insights dashboards trail by about 2 days."))
    return out


# ---------------------------------------------------------------- teardown
def kit_objects(t, cfg=None):
    tpl = template()
    found = zcc_objects(t)
    for kind in RULE_KINDS:
        types_ = sorted({r["rule_type"] for r in tpl["cloud_app_control"]}) if kind == "cloud_app_control" else [None]
        for rt in types_:
            try:
                found += [(kind, rt, r) for r in list_rules(t, kind, rt) if mine(r)]
            except Exception as e:
                K.vlog(f"list {kind} {rt}: {e}")
    for c in items(t.call("url_categories", "list_categories", query_params={"custom_only": True})):
        if mine(c):
            found.append(("url_category", None, c))
    for s in items(t.call("cloud_firewall", "list_network_services", query_params={"search": K.PREFIX})):
        if mine(s):
            found.append(("network_service", None, s))
    for lab in items(t.call("rule_labels", "list_labels")):
        if mine(lab):
            found.append(("label", None, lab))
    made = (zcfg(cfg).get("created_user") if cfg else None) or {}
    # only a user, group and department this kit created; never ones you made yourself
    if made.get("zia_id"):
        found.append(("zia_user", None, {"id": made["zia_id"], "name": made["email"]}))
        for kind, key in (("zia_group", "zia_group_id"), ("zia_department", "zia_dept_id")):
            if made.get(key):
                found.append((kind, None, {"id": made[key], "name": made.get("group")}))
    for old in (zcfg(cfg).get("retired_users") if cfg else None) or []:   # earlier test users the kit replaced
        found.append(("zidentity_user", None, {"id": old["zid_id"], "name": old["email"]}))
    if made.get("zid_id"):
        found.append(("zidentity_user", None, {"id": made["zid_id"], "name": made["email"]}))
        if made.get("group_id"):
            found.append(("zidentity_group", None, {"id": made["group_id"], "name": made.get("group")}))
    return found


def teardown(t, cfg, log, confirm=True):
    objs = kit_objects(t, cfg)
    if not objs:
        log("ok", f"Nothing named '{K.PREFIX}: …' in ZIA.")
    else:
        if confirm:
            for kind, _, o in objs:
                K.info(f"{kind:18} {g(o, 'name') or g(o, 'configured_name')}")
            if not K.FORCE and not K.yesno(f"Delete these {len(objs)} ZIA objects and activate?", False):
                print("  Cancelled.")
                return False
        deleters = {"url_category": ("url_categories", "delete_category"),
                    "network_service": ("cloud_firewall", "delete_network_service"),
                    "label": ("rule_labels", "delete_label"),
                    "zidentity_user": ("zid.users", "delete_user"), "zidentity_group": ("zid.groups", "delete_group"),
                    "zia_user": ("user_management", "delete_user"), "zia_group": ("user_management", "delete_group"),
                    "zia_department": ("user_management", "delete_department"),
                    "zcc_app_profile": ("zcc.web_policy", "delete_web_policy"),
                    "zcc_forwarding_profile": ("zcc.forwarding_profile", "delete_forwarding_profile")}
        for kind, rt, o in objs:   # rules first, then the objects they reference
            label = g(o, "name") or g(o, "configured_name")
            try:
                if kind == "cloud_app_control":
                    t.call("cloudappcontrol", "delete_rule", rt, g(o, "id"))
                elif kind in API:
                    t.call(API[kind], "delete_rule", g(o, "id"))
                else:
                    t.call(*deleters[kind], g(o, "id"))
                log("ok", f"Deleted {label}")
            except Exception as e:
                log("warn", f"Couldn't delete {label}: {str(e)[:160]}")
        activate(t, log)
    z = zcfg(cfg)
    z.pop("state", None)
    z.pop("retired_users", None)
    z.pop("zcc_api_refused", None)
    if z.pop("created_user", None):
        z.pop("users", None)
        K.kc_del(PW_KEY)
    K.save_cfg(cfg)
    return True


# ---------------------------------------------------------------- preflight (admin side)
PROGRESS = {"on": False}


def step(msg):
    """A progress line while preflight runs, so a slow API never looks like a hang (terminal only)."""
    if PROGRESS["on"]:
        print(f"    {K.C['d']}… {msg}{K.C['x']}", flush=True)


def preflight(cfg, write_probe=False):
    checks = []

    def add(cid, label, status, detail="", fix=""):
        checks.append({"id": cid, "label": label, "status": status, "detail": detail, "fix": fix})

    if not (cfg.get("client_id") and cfg.get("vanity_domain") and K.kc_get("oneapi-client-secret")):
        add("zia-creds", "OneAPI credentials saved", "fail",
            fix="Run `./aiguard-kit setup` (or the console's Setup tab) once to save the vanity domain, client ID and secret.")
        return checks, None
    add("zia-creds", "OneAPI credentials saved", "ok", f"client {K.mask(cfg['client_id'])} on '{cfg['vanity_domain']}'")
    step(f"signing in to '{cfg['vanity_domain']}' with OneAPI")
    try:
        t = connect(cfg)
        add("zia-login", "ZIA API access", "ok")
    except Exception as e:
        add("zia-login", "ZIA API access", "fail", str(e)[:200], zhint(e))
        return checks, None

    tpl = template()
    step("reading URL filtering, Cloud App Control, File Type Control, DLP, firewall and DNS rules")
    try:
        for kind in ("url_filtering", "file_type_control", "dlp", "firewall", "dns"):
            list_rules(t, kind)
        list_rules(t, "cloud_app_control", "AI_ML")
        add("zia-read", "Read ZIA policy", "ok", "URL filtering, Cloud App Control, File Type Control, DLP, firewall, DNS")
    except Exception as e:
        add("zia-read", "Read ZIA policy", "fail", str(e)[:200], zhint(e))
        return checks, None

    z = zcfg(cfg)
    step("reading users and sign-in settings")
    if z.get("users"):
        found, missing = find_users(t, [u.get("email") or u["name"] for u in z["users"]])
        add("zia-user", "Test user exists", "fail" if missing else "ok",
            ", ".join(u.get("email") or u["name"] for u in found) + (f"; missing: {', '.join(missing)}" if missing else ""),
            f"Rerun setup without --user to create a new one, or add the user in {CONSOLE_USERS}." if missing else "")
    else:
        add("zia-user", "Test user chosen", "info", "not yet - setup creates one",
            "Setup creates a dedicated ZIA test user with a generated password, or pass --user to use one you have.")
        mode, detail = auth_mode(t)
        add("zia-auth", "How Client Connector users sign in", "ok" if mode in ("hosted", "saml") else
            ("warn" if mode else "info"), detail or "couldn't read Internet Authentication Settings",
            {"hosted": "", "saml": "Setup will create the test user in ZIdentity; set its password there once.",
             "directory": "Create the test user in your directory (AD/LDAP) and pass --user."}.get(mode,
             "Setup assumes Hosted DB. Check Administration > Internet & SaaS Authentication > Internet Authentication Settings."))
        dom = zid_domain(cfg) if mode == "saml" else tenant_domain(t)
        email = f"{test_user_names()['login']}@{dom}" if dom else "the test user"
        try:
            items(t.call("user_management", "list_groups", query_params={"search": K.PREFIX}))
            detail = f"would create {email}" if dom else "couldn't tell the tenant's email domain"
            if write_probe and mode in ("hosted", None):
                step("testing user-management permission (temporary group)")
                grp = with_valid_name(lambda **n: t.call("user_management", "add_group", comments="temporary", **n),
                                      zname("preflight probe"))
                t.call("user_management", "delete_group", g(grp, "id"))
                detail += "; created and removed a temporary group"
            add("zia-mkuser", "Can create the test user", "ok" if dom else "warn", detail,
                "" if dom else "Pass --domain yourdomain.com to setup.")
        except Exception as e:
            if zid_managed(e):
                add("zia-mkuser", "Can create the test user", "info",
                    f"users are managed in ZIdentity: setup creates {test_user_names()['login']}@{zid_domain(cfg)} there",
                    ZID_MANAGED_FIX.format(email=f"{test_user_names()['login']}@{zid_domain(cfg)}"))
            else:
                add("zia-mkuser", "Can create the test user", "warn", rba_reason(e),
                    "The kit can't create users with this API role. " + USER_MGMT_FIX.format(email=email))

    step("reading DLP engines, file types and isolation profiles")
    facts = resolve(t, tpl)
    want = sorted({e for r in tpl["dlp"] for e in r["engines"]})
    have = [e for e in want if e in facts["engines"]]
    add("zia-dlp", "DLP engines for the demo", "ok" if len(have) == len(want) else ("warn" if have else "fail"),
        f"{len(have)} of {len(want)} found" + (f"; missing {', '.join(e for e in want if e not in have)}" if len(have) < len(want) else ""),
        "" if len(have) == len(want) else "DLP rules will use the engines that exist. Check the DLP subscription.")
    try:
        step("reading SSL inspection rules")
        ssl = list_rules_ssl(t)
        dec = [r for r in ssl if g(r, "state") == "ENABLED" and str((g(r, "action") or {}).get("type", "")).upper() == "DECRYPT"]
        add("zia-ssl", "SSL inspection decrypts traffic", "ok" if dec else "warn",
            ", ".join(g(r, "name") for r in dec[:3]) or "no enabled DECRYPT rule",
            "" if dec else "EICAR over HTTPS, DLP and Cloud App Control need SSL inspection. Add a DECRYPT rule for the test user.")
    except Exception as e:
        add("zia-ssl", "SSL inspection decrypts traffic", "warn", str(e)[:160], "Couldn't read SSL inspection rules.")
    add("zia-cbi", "Browser Isolation profile", "ok" if facts.get("cbi") else "info",
        g(facts.get("cbi") or {}, "name") or "none - the isolation demo rule is skipped")
    step("looking for earlier SE-Demo objects")
    mine_ = kit_objects(t, cfg)
    add("zia-existing", "Earlier kit objects in ZIA", "info", f"{len(mine_)} found" if mine_ else "none - fresh setup")
    if write_probe:
        step("testing create permission (temporary rule label)")
        try:
            lab = t.call("rule_labels", "add_label", name=safe_name(zname("preflight probe")), description="temporary")
            t.call("rule_labels", "delete_label", g(lab, "id"))
            add("zia-write", "Create and delete permission", "ok", "Created and removed a temporary rule label")
        except Exception as e:
            add("zia-write", "Create and delete permission", "fail", str(e)[:200], zhint(e))
    add("zia-tunnel", "Client Connector uses Z-Tunnel 2.0 on the generator", "info", "Can't be read through the API",
        "Firewall, DNS and unusual-port traffic only reach ZIA with Z-Tunnel 2.0. In the Client Connector portal, give "
        "the test user a forwarding profile with Tunnel version Z-Tunnel 2.0 (see ZIA.md). `zia check` on the "
        "generator tests it.")
    t._facts = facts
    return checks, t


def list_rules_ssl(t):
    return items(t.call("ssl_inspection_rules", "list_rules"))


# ---------------------------------------------------------------- dashboards (Insights)
PANELS = [
    ("web", "Web traffic", "zins.web_traffic", "get_no_grouping", {}),
    ("web-blocked", "Blocked web traffic", "zins.web_traffic", "get_no_grouping", {"action_filter": "BLOCK"}),
    ("protocols", "Web protocols", "zins.web_traffic", "get_protocols", {}),
    ("threats", "Threat classes", "zins.web_traffic", "get_threat_class", {}),
    ("threat-cats", "Threat categories", "zins.web_traffic", "get_threat_super_categories", {}),
    ("incidents", "Cyber incidents", "zins.cyber_security", "get_incidents", {}),
    ("firewall", "Firewall by action", "zins.firewall", "get_traffic_by_action", {}),
    ("fw-services", "Firewall network services", "zins.firewall", "get_network_services", {}),
    ("shadow-it", "Shadow IT apps", "zins.shadow_it", "get_apps", {}),
    ("casb", "SaaS (CASB) apps", "zins.saas_security", "get_casb_app_report", {}),
]


def dashboards(t, days=7, end_days_ago=2):
    """Insights only answers for whole 7- or 14-day windows that end at least a day or two ago."""
    end = int((time.time() - end_days_ago * 86400) * 1000)
    start = end - days * 86400 * 1000
    out = []
    for pid, label, res, method, kw in PANELS:
        try:
            rows = t.call(res, method, start, end, **kw) or []
            rows = rows if isinstance(rows, list) else items(rows)
            total = sum(int(g(r, "total") or 0) for r in rows if isinstance(r, dict))
            names = [g(r, "name") or g(r, "application") for r in rows if isinstance(r, dict)][:6]
            apps = pid in ("shadow-it", "casb")   # app lists carry bytes and users, not a total
            status = "ok" if rows and (total or apps) else "empty"
            if status == "ok" and pid == "firewall" and not any(str(g(r, "name", "")).upper().startswith("BLOCK")
                                                                for r in rows if isinstance(r, dict)):
                status = "partial"   # traffic but nothing blocked: the demo firewall rule hasn't fired yet
            out.append({"id": pid, "label": label, "status": status, "rows": len(rows), "total": total,
                        "top": [n for n in names if n]})
        except Exception as e:
            out.append({"id": pid, "label": label, "status": "error", "error": str(e)[:160]})
    return {"start": start, "end": end, "panels": out}


# ---------------------------------------------------------------- terminal
def choose_users(t, cfg):
    z = zcfg(cfg)
    wanted = K.opt("user")
    if wanted:
        found, missing = find_users(t, wanted.split(","))
        if missing:
            raise K.KitError(f"No ZIA user {', '.join(missing)}. Leave out --user and setup creates a test user for you, "
                             f"or create it in {CONSOLE_USERS} and rerun.")
        z["users"] = found
        return
    if z.get("users") and K.yesno("Scope the demo rules to " + ", ".join(u.get("email") or u["name"] for u in z["users"]) + "?", True):
        return
    pending = (z.get("created_user") or {}).get("email")
    if K.YES or pending or "--create-user" in K.ARGS:
        create_test_user(t, cfg, cli_log, email=pending, domain=K.opt("domain"), via=K.opt("via"))
        return
    K.info("The demo rules apply only to one test user: the one signed in to Client Connector on the traffic generator.")
    domain = K.opt("domain") or tenant_domain(t) or "yourdomain"
    if not K.opt("domain") and auth_mode(t)[0] == "saml" and zid_domain(cfg):
        domain = zid_domain(cfg)
    i = K.menu("Which test user?", [f"Create one for me: {test_user_names()['login']}@{domain} (recommended)",
                                    "Use a user I already have (never your own account)"])
    if i == 0:
        create_test_user(t, cfg, cli_log, domain=K.opt("domain"), via=K.opt("via"))
        return
    while True:
        w = K.ask("Test user email (comma-separate several)")
        found, missing = find_users(t, w.split(","))
        if found and not missing:
            z["users"] = found
            return
        K.warn(f"Not found in ZIA: {', '.join(missing) or w}")


def cmd_setup():
    cfg = K.load_cfg()
    K.head(f"ZIA demo policy - setup (kit {K.VERSION})")
    print("  Creates SE-Demo URL filtering, Cloud App Control, File Type Control, DLP, firewall, DNS and SSL inspection")
    print("  rules for one test user, plus a Client Connector profile for its group, then activates. Demo/eval tenants only. Teardown: ./aiguard-kit zia teardown")
    K.head("Step 1 of 4 · Preflight (no changes yet)")
    probe = K.yesno("Also test create permission with a temporary rule label?", True)
    PROGRESS["on"] = True
    checks, t = preflight(cfg, write_probe=probe)
    PROGRESS["on"] = False
    K.print_checks(checks)
    if not t or any(c["status"] == "fail" and c["id"] in ("zia-login", "zia-read", "zia-write") for c in checks):
        print("  Stopped. Nothing was changed.")
        return
    if not K.yesno(f"'{cfg['vanity_domain']}' is a demo/eval tenant and the kit may create ZIA policy in it?", True):
        print("  Stopped. Nothing was changed.")
        return
    K.head("Step 2 of 4 · Test user")
    choose_users(t, cfg)
    K.save_cfg(cfg)
    K.head("Step 3 of 4 · Review")
    rules, notes = plan(t, cfg, getattr(t, "_facts", None))
    for kind, rt, name, body in rules:
        what = body.get("action") or body.get("filtering_action") or ",".join(body.get("actions", []))
        print(f"  • {kind.replace('_', ' '):18} {name}  ({what})")
    for n in notes:
        K.warn(n)
    print(f"  • plus: URL categories '{safe_name(zname(template()['tenant_check']['name']))}' and "
          f"'{safe_name(zname(template()['aws_mgmt']['name']))}', network service "
          f"'{zname(template()['network_service']['name'])}', rule label '{label_name()}'")
    app_name, fwd_name = zcc_names()
    if app_name:
        print(f"  • Client Connector: Windows app profile '{app_name}' and forwarding profile '{fwd_name}' "
              "(test user's group only)")
    if not K.yesno("Create or update these and activate?", True):
        print("  Cancelled. Nothing was changed.")
        return
    K.head("Step 4 of 4 · Create and activate")
    res = setup_apply(t, cfg, cli_log, getattr(t, "_facts", None))
    K.head("Done" if not res["failed"] else f"Done, {len(res['failed'])} rule(s) need attention (see above)")
    print("  Next, on the traffic generator (Client Connector signed in as the test user):")
    print("    ./aiguard-kit zia check      confirms traffic reaches this tenant")
    print("    ./aiguard-kit zia traffic    one round of demo traffic;  zia schedule install  keeps it going")


def cmd_preflight():
    cfg = K.load_cfg()
    as_json = "--json" in K.ARGS
    if not as_json:
        K.head("ZIA preflight (no changes)")
    PROGRESS["on"] = not as_json
    checks, _ = preflight(cfg, write_probe="--write-probe" in K.ARGS)
    rep = K.preflight_report(cfg, checks)
    if as_json:
        print(json.dumps(rep, indent=2))
    else:
        K.print_checks(checks)
        print(f"\n  Result: {rep['result'].upper()}.  Runbook: {HERE / 'ZIA.md'}")
    raise SystemExit({"pass": 0, "warn": 2, "fail": 1}[rep["result"]])


def cmd_status():
    cfg = K.load_cfg()
    K.head("ZIA status")
    z = zcfg(cfg)
    t = connect(cfg)
    K.ok(f"Tenant '{cfg['vanity_domain']}': ZIA API works")
    if z.get("users"):
        K.ok("Test user: " + ", ".join(u.get("email") or u["name"] for u in z["users"]))
    objs = kit_objects(t, cfg)
    (K.ok if objs else K.warn)(f"{len(objs)} SE-Demo objects" + ("" if objs else " - run ./aiguard-kit zia setup"))
    for kind, _, o in objs:
        state = g(o, "state")
        K.info(f"{kind:18} {g(o, 'name') or g(o, 'configured_name')}" + (f"  ({state})" if state else ""))
    try:
        st = t.call("activate", "status")
        K.info(f"Activation: {g(st, 'status') if isinstance(st, dict) else st}")
    except Exception as e:
        K.vlog(str(e))
    last = K.CFG_DIR / "zia-traffic-last.json"
    if last.exists():
        K.info(f"Last traffic round on this machine: {json.loads(last.read_text(encoding='utf-8')).get('summary')}")
    if not z.get("users"):
        return
    K.head("Drift: is the tenant still what setup made?")
    checks = drift(t, cfg)
    K.print_checks(checks)
    if any(c.get("fixable") for c in checks):
        if "--fix" in K.ARGS or K.yesno("Fix these now? (runs setup again; only kit objects change)", False):
            K.head("Fixing")
            res = fix_drift(t, cfg, cli_log)
            K.head("After the fix")
            K.print_checks(res["checks"])
        else:
            print("  Fix later with: ./aiguard-kit zia status --fix")


def aws_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("aiguard_kit_zia_aws", HERE / "zia_aws.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def cloud_name(t):
    """'zscalertwo' from the tenant's own admin addresses (admin@<org>.zscalertwo.net)."""
    for u in items(t.call("user_management", "list_users", query_params={"page_size": 10000})):
        m = re.search(r"\.(zscaler[a-z]*)\.net$", str(g(u, "email", "")).lower())
        if m:
            return m.group(1)
    return None


def aws_settings(t, cfg, zcc_url=""):
    z = zcfg(cfg)
    user = ((z.get("users") or [{}])[0].get("email")) or (z.get("created_user") or {}).get("email")
    if not user:
        raise K.KitError("Run ./aiguard-kit zia setup first: the template needs the test user.")
    zcc_url, zcc_s3 = (zcc_url or "").strip(), ""
    if zcc_url.lower() in ("none", "no", "manual"):
        zcc_url = "none"
    elif zcc_url.lower().startswith("s3://"):   # your own bucket: s3://bucket/key
        zcc_url, zcc_s3 = "", zcc_url[5:]
    return {"cloud": cloud_name(t) or cfg.get("cloud") or "zscalertwo", "domain": user.split("@", 1)[1],
            "test_user": user, "zcc_url": zcc_url, "zcc_s3": zcc_s3, "policy_token": zcc_policy_token(t)}


def zcc_policy_token(t):
    """The policy token of the kit's Windows app profile (made by the kit or by hand under its name), or "". With it,
    Client Connector downloads that profile at install, before anyone signs in."""
    app_name, _ = zcc_names()
    if not app_name:
        return ""
    try:
        hit = next((p for p in _zcc_list(t, "zcc.web_policy", device_type="windows") if g(p, "name") == app_name), None)
    except Exception as e:
        K.vlog(f"policy token: {e}")
        return ""
    tok = str(g(hit or {}, "policyToken") or g(hit or {}, "policy_token") or "").strip()
    return tok if re.match(r"^[A-Za-z0-9._:+=/-]{4,200}$", tok) else ""


def zcc_source(st):
    """Where the generator gets Client Connector, in words."""
    dflt = aws_module().ZCC_DEFAULT
    if st["zcc_s3"]:
        return f"Client Connector from s3://{st['zcc_s3']}"
    if st["zcc_url"] == "none" or not (st["zcc_url"] or dflt["url"]):
        return "no Client Connector installer: install it by hand on the instance"
    if st["zcc_url"]:
        return "Client Connector from your URL"
    return f"Client Connector {dflt['version'] or ''} from the kit's release (checked by SHA-256 and Zscaler signature)".replace("  ", " ")


def cmd_aws():
    cfg = K.load_cfg()
    K.head("ZIA traffic generator on AWS: CloudFormation template")
    st = aws_settings(connect(cfg), cfg, K.opt("zcc-url", ""))
    downloads = K.HOME / "Downloads"
    out = Path(K.opt("out") or (downloads if downloads.is_dir() else K.CFG_DIR) / "se-demo-zia-generator.cfn.json")
    aws_module().write(out, **st)
    zcfg(cfg)["aws"] = {"written": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    K.save_cfg(cfg)
    K.ok(f"Wrote {out}")
    K.info(f"Test user {st['test_user']} · cloud {st['cloud']} · domain {st['domain']}"
           + " · " + zcc_source(st) + " · " + token_note(st))
    print("  Next: AWS console > CloudFormation > Create stack > With new resources > Upload a template file,")
    print("        choose that file, review the parameters, tick the IAM acknowledgement, Submit. See ZIA.md (AWS).")


def api_aws(cfg, body, tenant):
    st = aws_settings(tenant(), cfg, (body.get("zcc_url") or "").strip())
    zcfg(cfg)["aws"] = {"written": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    K.save_cfg(cfg)
    tpl = aws_module().build(**st)
    st = {k: v for k, v in st.items() if k != "policy_token"} | {"has_policy_token": bool(st.get("policy_token"))}
    return {"filename": "se-demo-zia-generator.cfn.json", "template": tpl, "settings": st}


def token_note(st):
    return ("Client Connector gets the kit's app profile at install (policy token)" if st.get("policy_token") else
            "no app profile token yet (create the Client Connector profiles first): the profile arrives at sign-in")


SCRIPT_NAME = "se-demo-zia-generator-setup.ps1"


def cmd_script():
    """`zia script`: the generator setup as a PowerShell script for CloudShare or any Windows VM."""
    cfg = K.load_cfg()
    K.head("ZIA traffic generator on any Windows VM (CloudShare, a lab VM): setup script")
    st = aws_settings(connect(cfg), cfg, K.opt("zcc-url", ""))
    downloads = K.HOME / "Downloads"
    out = Path(K.opt("out") or (downloads if downloads.is_dir() else K.CFG_DIR) / SCRIPT_NAME)
    try:
        aws_module().write_script(out, **st)
    except ValueError as e:
        raise K.KitError(str(e)) from e
    K.ok(f"Wrote {out}")
    K.info(f"Test user {st['test_user']} · cloud {st['cloud']} · " + zcc_source(st) + " · " + token_note(st))
    print("  Next: copy it to the Windows VM, open PowerShell as Administrator there and run")
    print(f"        powershell -ExecutionPolicy Bypass -File .\\{SCRIPT_NAME}")
    print("        (or paste the file into that window). Then sign in to Client Connector as the test user. See ZIA.md.")


def api_script(cfg, body, tenant):
    st = aws_settings(tenant(), cfg, (body.get("zcc_url") or "").strip())
    try:
        text = aws_module().setup_script(**st)
    except ValueError as e:
        raise K.KitError(str(e)) from e
    st = {k: v for k, v in st.items() if k != "policy_token"} | {"has_policy_token": bool(st.get("policy_token"))}
    return {"filename": SCRIPT_NAME, "script": text, "settings": st}


def cmd_password():
    """Shows the kit-created test user's password, on this computer only."""
    cfg = K.load_cfg()
    made = zcfg(cfg).get("created_user") or {}
    pw = test_user_password()
    K.head("ZIA test user")
    if not (made.get("email") and pw):
        K.warn("The kit hasn't created a test user with a password on this computer.")
        K.info("Run ./aiguard-kit zia setup to create one. For a user you made yourself: " +
               MANUAL_PW.format(email="the user"))
        return
    print(f"  Sign in to Client Connector on the traffic generator as:\n    {made['email']}\n    {pw}")
    K.info("Shown here only. Don't paste it into chat, email or tickets. It's kept in this computer's keychain.")


def api_password(cfg):
    made = zcfg(cfg).get("created_user") or {}
    pw = test_user_password()
    if not (made.get("email") and pw):
        return {"error": "The kit hasn't created a test user with a password on this computer.",
                "fix": MANUAL_PW.format(email="your test user")}
    return {"email": made["email"], "password": pw}


def cmd_teardown():
    cfg = K.load_cfg()
    K.head("ZIA teardown")
    teardown(connect(cfg), cfg, cli_log)


def cmd_dashboards():
    cfg = K.load_cfg()
    K.head("ZIA dashboards (Insights, 7 days ending 2 days ago)")
    rep = dashboards(connect(cfg), days=int(K.opt("days", "7")))
    icon = {"ok": "✓", "partial": "!", "empty": "✗", "error": "?"}
    for p in rep["panels"]:
        extra = f"{p.get('total', 0):,} · {', '.join(map(str, p['top']))}" if p["status"] in ("ok", "partial") else \
            p.get("error", "no data in the window")
        print(f"  {icon[p['status']]} {p['label']:28} {extra}")
    print("  Empty panels fill once the generator has run for a few days. Firewall and DNS need Z-Tunnel 2.0.")


def traffic_module():
    import importlib.util
    s = importlib.util.spec_from_file_location("aiguard_kit_zia_traffic", HERE / "zia_traffic.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def cmd_check():
    cfg = K.load_cfg()
    tm = traffic_module()
    K.head("ZIA traffic generator check (this machine)")
    checks = tm.check(cloud=zcfg(cfg).get("cloud_name"))
    K.print_checks(checks)
    worst = "fail" if any(c["status"] == "fail" for c in checks) else "warn" if any(c["status"] == "warn" for c in checks) else "pass"
    print(f"\n  Result: {worst.upper()}.  Runbook: {HERE / 'ZIA.md'}")
    raise SystemExit({"pass": 0, "warn": 2, "fail": 1}[worst])


def cmd_traffic():
    tm = traffic_module()
    types_ = (K.opt("types") or "").split(",") if K.opt("types") else None
    res = tm.run(types=types_, count=int(K.opt("count", "4")), quiet=K.YES, log_dir=K.CFG_DIR,
                 require_zscaler="--anyway" not in K.ARGS)
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} zia-traffic profile={K.PROFILE} {res['summary']}")
    if res["total"] and res["errors"] == res["total"]:
        raise SystemExit(1)


def cli(args):
    sub = next((a for a in args if not a.startswith("-") and a not in _values(args)), "help")
    cmds = {"setup": cmd_setup, "preflight": cmd_preflight, "status": cmd_status, "teardown": cmd_teardown,
            "dashboards": cmd_dashboards, "check": cmd_check, "traffic": cmd_traffic,
            "schedule": lambda: K.cmd_schedule("zia"), "password": cmd_password, "aws": cmd_aws, "script": cmd_script,
            "ready": lambda: K.cmd_ready()}
    if sub not in cmds:
        print("Usage: ./aiguard-kit zia setup|preflight|status|teardown|dashboards|password|aws|check|traffic|schedule|ready  (see ZIA.md)")
        return
    try:
        cmds[sub]()
    except K.KitError as e:
        print(f"\n  ✗ {e}\n    Fix: {zhint(e)}")
        raise SystemExit(1)


def _values(args):
    return {args[i + 1] for i, a in enumerate(args[:-1]) if a in K.VALUE_OPTS}


# ---------------------------------------------------------------- console (gui.html ZIA tab)
def api_get(path, cfg, tenant):
    z = zcfg(cfg)
    if path == "/api/zia/state":
        return {"users": z.get("users", []), "state": z.get("state"), "prefix": K.PREFIX,
                "created_user": z.get("created_user"),
                "creds": bool(cfg.get("client_id")) and K.kc_has("oneapi-client-secret"),
                "schedule": z.get("schedule"), "last_traffic": _last_traffic()}
    if path == "/api/zia/objects":
        return {"objects": [{"kind": k, "name": g(o, "name") or g(o, "configured_name"), "state": g(o, "state")}
                            for k, _, o in kit_objects(tenant(), cfg)]}
    if path == "/api/zia/dashboards":
        return dashboards(tenant())
    if path == "/api/zia/drift":
        return {"checks": drift(tenant(), cfg)}
    return None


def _last_traffic():
    p = K.CFG_DIR / "zia-traffic-last.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except Exception:
        return None


def api_job(path, body, cfg, tenant, log, job):
    """Long-running console actions. Returns True if the path was handled."""
    if path == "/api/zia/preflight":
        checks, t = preflight(cfg, write_probe=bool(body.get("write_probe")))
        job["verify"] = checks
        if t:
            rules, notes = plan(t, cfg, getattr(t, "_facts", None))
            job["plan"] = [{"kind": k, "name": n, "action": b.get("action") or b.get("filtering_action")
                            or ",".join(b.get("actions", []))} for k, _, n, b in rules]
            job["notes"] = notes
        return True
    if path == "/api/zia/user":
        job["verify"] = create_test_user(tenant(), cfg, log, email=(body.get("email") or "").strip() or None,
                                         domain=(body.get("domain") or "").strip() or None, via=body.get("via"))
        return True
    if path == "/api/zia/apply":
        t = tenant()
        if not body.get("users") and not zcfg(cfg).get("users"):
            create_test_user(t, cfg, log)
        if body.get("users"):
            found, missing = find_users(t, body["users"])
            if missing:
                raise K.KitError(f"No ZIA user {', '.join(missing)}.")
            zcfg(cfg)["users"] = found
            K.save_cfg(cfg)
        job["verify"] = setup_apply(t, cfg, log)
        return True
    if path == "/api/zia/fix":
        res = fix_drift(tenant(), cfg, log)
        job["verify"] = res["checks"]
        return True
    if path == "/api/zia/teardown":
        teardown(tenant(), cfg, log, confirm=False)
        return True
    if path in ("/api/zia/check", "/api/zia/traffic"):
        tm = traffic_module()
        if path.endswith("check"):
            job["verify"] = tm.check(cloud=zcfg(cfg).get("cloud_name"), log=log)
        else:
            job["verify"] = tm.run(types=body.get("types") or None, count=int(body.get("count") or 4), log=log,
                                   log_dir=K.CFG_DIR, stop=lambda: job.get("stop"))
        return True
    return False
