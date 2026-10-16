# /// script
# requires-python = ">=3.10"
# dependencies = ["zscaler-sdk-python>=1.11", "requests>=2.31", "keyring>=24", "truststore>=0.9"]
# ///
"""Zscaler AI Guard SE demo kit.

  ./aiguard-kit setup      create the demo policy, apps, keys and rules in YOUR tenant (interactive)
  ./aiguard-kit gui        open the test console in your browser (localhost only)
  ./aiguard-kit run        run tests from the terminal   (--preset everything|leakage|attacks|rai|output|topics,
                           --mode detect|proxy, --rounds N, --tests id1,id2)
  ./aiguard-kit run --trickle [--count 12]   a small random batch (used by the scheduler)
  ./aiguard-kit policy [detect|block]        show or switch the demo policy between monitor and enforce
  ./aiguard-kit schedule install|remove|status [--every 60] [--count 12]
                           keep dashboards fresh with a small batch every N minutes
  ./aiguard-kit status     check credentials, tenant objects, the detection API and kit updates
  ./aiguard-kit teardown   delete everything this kit created (objects named with the prefix)

Options: --yes (accept defaults), --force (teardown without asking), --verbose (API details, keys masked),
         --prefix NAME, --profile NAME (keep several tenants apart).
Secrets live in your OS keychain, never in files or on screen. Demo/eval tenants only.
"""
from __future__ import annotations

import getpass
import json
import os
import re
import secrets
import sys
import threading
import time
import uuid
from pathlib import Path

VERSION = "1.1.0"
HERE = Path(__file__).resolve().parent
HOME = Path.home()
BASE_DIR = HOME / ".aiguard-se-kit"
KC = "aiguard-se-kit"
ARGS = sys.argv[1:]
YES = "--yes" in ARGS or "-y" in ARGS
FORCE = "--force" in ARGS
VERBOSE = "--verbose" in ARGS or "-v" in ARGS
VALUE_OPTS = ("--prefix", "--preset", "--mode", "--rounds", "--tests", "--port", "--profile", "--count", "--every")


def opt(name, default=None):
    for i, a in enumerate(ARGS):  # --name=value or --name value
        if a.startswith(f"--{name}="):
            return a.split("=", 1)[1]
        if a == f"--{name}" and i + 1 < len(ARGS) and not ARGS[i + 1].startswith("-"):
            return ARGS[i + 1]
    return default


PREFIX = opt("prefix", "SE-Demo")
PROFILE = re.sub(r"[^A-Za-z0-9_-]", "-", opt("profile", os.getenv("AIGUARD_KIT_PROFILE", "default")))
CFG_DIR = BASE_DIR if PROFILE == "default" else BASE_DIR / "profiles" / PROFILE
CFG_FILE = CFG_DIR / "config.json"
KC_NS = "" if PROFILE == "default" else f"{PROFILE}/"

# Detectors the policy switch flips between DETECT (monitor) and BLOCK (enforce).
BLOCKABLE = {"inputDetectorPolicies": ("prompt_injection", "invisible_text", "toxicity"),
             "outputDetectorPolicies": ("malicious_url", "toxicity")}
PROXY_HOST = os.getenv("AIGUARD_PROXY", "https://proxy.zseclipse.net").rstrip("/")
DAS_HOST = os.getenv("AIGUARD_DAS_HOST", "https://api.us1.zseclipse.net").rstrip("/")
DAS_PATH = "/v1/detection/resolve-and-execute-policy"
CONSOLE = "https://ai-console.zscaler.com/ai-guard/insights"

# Providers the kit knows how to drive through the proxy: type -> (credential type, field, default model)
PROVIDERS = {
    "openai": ("BEARER", "token", "gpt-4o-mini"),
    "anthropic": ("API_KEY", "key", "claude-haiku-5-5"),
}

# Which console panel each detector feeds (for the GUI coverage view).
PANELS = {
    "pii": "Sensitive data (PII)", "pii_deepscan": "Sensitive data (PII)", "personal_data": "Sensitive data (PII)",
    "secrets": "Secrets", "prompt_injection": "Prompt injection", "toxicity": "Toxicity",
    "code": "Code", "language": "Languages", "prompt_tags": "Prompt Classifications",
    "response_tags": "Response Classifications", "competition": "Competition", "brand_and_reputation_risk": "Brand risk",
    "finance_advice": "Finance advice", "legal_advice": "Legal advice", "gibberish": "Gibberish",
    "invisible_text": "Invisible text", "malicious_url": "Malicious URL", "url_reachability": "URL reachability",
    "refusal": "Refusal",
}

# ---------------------------------------------------------------- output helpers
C = {"g": "\033[32m", "y": "\033[33m", "r": "\033[31m", "b": "\033[1m", "d": "\033[2m", "x": "\033[0m"}
if not sys.stdout.isatty() or os.getenv("NO_COLOR"):
    C = {k: "" for k in C}


def ok(msg):
    print(f"  {C['g']}✓{C['x']} {msg}")


def warn(msg):
    print(f"  {C['y']}!{C['x']} {msg}")


def info(msg):
    print(f"    {C['d']}{msg}{C['x']}")


def head(msg):
    print(f"\n{C['b']}{msg}{C['x']}")


def vlog(msg):
    if VERBOSE:
        print(f"    {C['d']}[api] {msg}{C['x']}")


class KitError(Exception):
    pass


# Known failures -> what to do. Matched against the error text.
HINTS = [
    (r"invalid_client|unauthorized_client|client authentication failed|invalid client",
     "The OneAPI client ID or secret is wrong, or the client was deleted. Check ZIdentity > Integration > API Clients, "
     "then run `./aiguard-kit setup` again to re-enter them."),
    (r"Failed to resolve|Name or service not known|nodename nor servname|getaddrinfo",
     "Couldn't reach Zscaler. Check the vanity domain (just the subdomain, e.g. `acme` for acme.zslogin.net) and your network."),
    (r"CERTIFICATE_VERIFY_FAILED|UnknownIssuer|self.signed certificate|SSLError",
     "TLS inspection is breaking certificate checks. Launch through ./aiguard-kit (it sets UV_SYSTEM_CERTS), and make sure "
     "your Zscaler root CA is in the system keychain. As a last resort set SSL_CERT_FILE to a bundle that includes it."),
    (r"\b401\b|NOT_AUTHORIZED|Unauthorized",
     "Authenticated but not allowed. In ZIdentity, the API client needs the AI Guard scope (and for ZIA, an API role - "
     "not an admin role - created in ZIA > Role Management)."),
    (r"\b403\b|Forbidden",
     "The API client lacks permission for this object. Give it full AI Guard access in ZIdentity."),
    (r"Insufficient Balance|insufficient_quota|\b402\b|credit balance",
     "The LLM provider account has no credit. Top it up, or use detection mode (free) instead of proxy mode."),
    (r"\b429\b|rate.?limit",
     "Rate limited. Wait a minute, or lower --rounds."),
    (r"not one of the values accepted",
     "The API rejected an enum value - your tenant may run a newer AI Guard API. Run with --verbose and send the log to the kit owner."),
]


def hint(err) -> str:
    text = str(err)
    for pat, fix in HINTS:
        if re.search(pat, text, re.I):
            return fix
    return "Run again with --verbose and send the output to the kit owner."


# ---------------------------------------------------------------- TLS + secrets
def tls_setup():
    if os.getenv("AIGUARD_KIT_NO_TRUSTSTORE"):
        return
    try:  # use the OS trust store, which already holds the Zscaler root CA on SSL-inspected laptops
        import truststore
        truststore.inject_into_ssl()
    except Exception as e:  # pragma: no cover
        vlog(f"truststore not used: {e}")


def kc_get(name):
    import keyring
    try:
        return keyring.get_password(KC, KC_NS + name)
    except Exception:
        return None


def kc_set(name, value):
    import keyring
    keyring.set_password(KC, KC_NS + name, value)


def kc_del(name):
    import keyring
    try:
        keyring.delete_password(KC, KC_NS + name)
    except Exception:
        pass


def mask(s):
    return (s[:4] + "…") if s else s


# ---------------------------------------------------------------- config
def load_cfg():
    if CFG_FILE.exists():
        return json.loads(CFG_FILE.read_text())
    return {}


def save_cfg(cfg):
    CFG_DIR.mkdir(exist_ok=True)
    CFG_FILE.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CFG_FILE, 0o600)
    except Exception:
        pass


def ask(prompt, default=None, secret=False):
    if YES and default is not None:
        return default
    suffix = f" [{default}]" if default not in (None, "") else ""
    try:
        val = (getpass.getpass if secret else input)(f"  {prompt}{suffix}: ").strip()
    except EOFError:
        val = ""
    return val or (default if default is not None else "")


def menu(prompt, options, default=1):
    """options: list of labels. Returns 0-based index."""
    print(f"  {prompt}")
    for i, o in enumerate(options, 1):
        print(f"    {i}) {o}{'  (default)' if i == default else ''}")
    if YES:
        return default - 1
    while True:
        a = ask("Choose", str(default))
        if a.isdigit() and 1 <= int(a) <= len(options):
            return int(a) - 1
        print("    Enter a number from the list.")


def yesno(prompt, default=True):
    if YES:
        return default
    a = ask(f"{prompt} ({'Y/n' if default else 'y/N'})", "")
    return default if not a else a.lower().startswith("y")


# ---------------------------------------------------------------- Zscaler OneAPI
class Tenant:
    def __init__(self, cfg):
        from zscaler import ZscalerClient
        secret = kc_get("oneapi-client-secret")
        if not (cfg.get("client_id") and cfg.get("vanity_domain") and secret):
            raise KitError("No OneAPI credentials saved yet. Run `./aiguard-kit setup` first.")
        conf = {"clientId": cfg["client_id"], "clientSecret": secret, "vanityDomain": cfg["vanity_domain"]}
        if cfg.get("cloud"):
            conf["cloud"] = cfg["cloud"]
        self.c = ZscalerClient(conf)
        self.ag = self.c.aiguard

    def call(self, resource, method, *a, **kw):
        fn = getattr(getattr(self.ag, resource), method)
        vlog(f"{resource}.{method} {a} {json.dumps(kw)[:300] if kw else ''}")
        _, resp, err = fn(*a, **kw)
        if err:
            vlog(f"error: {err}")
            raise KitError(f"{resource}.{method} failed: {err}")
        body = resp.get_body() if resp is not None else None
        return body

    @staticmethod
    def items(body):
        if isinstance(body, list):
            return body
        return next((v for v in (body or {}).values() if isinstance(v, list)), [])

    def list(self, resource):
        method = {"policies": "list_policies", "policy_match_rules": "list_rules", "llm_providers": "list_providers",
                  "llm_provider_credentials": "list_credentials", "llm_applications": "list_applications",
                  "llm_application_credentials": "list_credentials"}[resource]
        return self.items(self.call(resource, method))


def connect(cfg) -> Tenant:
    try:
        t = Tenant(cfg)
        t.list("policies")
        return t
    except KitError:
        raise
    except Exception as e:
        raise KitError(f"Couldn't connect: {e}") from e


def das_scan(key, text, direction="IN", user=None, timeout=60):
    import requests
    body = {"content": text, "direction": direction, "transactionId": str(uuid.uuid4())}
    if user:
        body["user"] = user
    t0 = time.time()
    r = requests.post(DAS_HOST + DAS_PATH, json=body, timeout=timeout,
                      headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    ms = int((time.time() - t0) * 1000)
    if r.status_code >= 400:
        raise KitError(f"HTTP {r.status_code}: {r.text[:300]}".replace(key, "<key>"))
    return r.json(), ms


def proxy_chat(ptype, key, model, prompt, user=None, max_tokens=300, timeout=90):
    import requests
    t0 = time.time()
    if ptype == "anthropic":
        r = requests.post(f"{PROXY_HOST}/v1/messages", timeout=timeout, json={
            "model": model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": prompt}],
            **({"metadata": {"user_id": re.sub(r"[^A-Za-z0-9_-]", "-", user)}} if user else {})},
            headers={"X-ApiKey": key, "x-api-key": "unused", "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
    else:
        r = requests.post(f"{PROXY_HOST}/v1/chat/completions", timeout=timeout, json={
            "model": model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": prompt}],
            **({"user": user} if user else {})},
            headers={"X-ApiKey": key, "Authorization": "Bearer unused", "content-type": "application/json"})
    ms = int((time.time() - t0) * 1000)
    if r.status_code >= 400:
        raise KitError(f"HTTP {r.status_code}: {r.text[:300]}".replace(key, "<key>"))
    d = r.json()
    if ptype == "anthropic":
        text = " ".join(b.get("text", "") for b in d.get("content", []) if b.get("type") == "text")
    else:
        text = ((d.get("choices") or [{}])[0].get("message") or {}).get("content", "")
    return text.strip(), ms


# ---------------------------------------------------------------- tests
def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")[:40] or "x"


def pack_dirs():
    return [(HERE / "packs", False), (CFG_DIR / "packs", True)]


def load_tests():
    """Core library plus industry packs (packs/*.json) and the SE's own imported packs."""
    lib = json.loads((HERE / "tests.json").read_text(encoding="utf-8"))
    lib.setdefault("stories", [])
    lib["packs"] = []
    for d, custom in pack_dirs():
        for f in sorted(d.glob("*.json")) if d.exists() else []:
            try:
                p = json.loads(f.read_text(encoding="utf-8"))
            except Exception as e:
                warn(f"Skipping pack {f.name}: {e}")
                continue
            group = p.get("name") or f.stem
            for t in p.get("tests", []):
                t.setdefault("group", group)
                t.setdefault("category", group)
                t.setdefault("direction", "IN")
                t.setdefault("expect", [])
                t["pack"] = group
                lib["tests"].append(t)
            if group not in lib["groups"]:
                lib["groups"].append(group)
            lib["presets"].append({"id": "pack-" + slug(group), "name": group, "groups": [group], "pack": True})
            lib["packs"].append({"name": group, "file": f.name, "custom": custom, "count": len(p.get("tests", [])),
                                 "description": p.get("description", "")})
    return lib


def import_pack(name, rows):
    """Save rows [{prompt, direction?, name?, expect?}] as a custom pack. Returns the pack file path."""
    name = (name or "").strip()[:60]
    if not name:
        raise KitError("Give the pack a name.")
    if not rows or len(rows) > 500:
        raise KitError("A pack needs between 1 and 500 prompts.")
    tests, sid = [], slug(name)
    for i, r in enumerate(rows, 1):
        text = str(r.get("prompt") or r.get("text") or "").strip()
        if not text:
            continue
        if len(text) > 8000:
            raise KitError(f"Row {i}: prompt is longer than 8,000 characters.")
        direction = str(r.get("direction") or "IN").strip().upper()
        direction = "OUT" if direction in ("OUT", "RESPONSE", "REPLY") else "IN"
        expect = r.get("expect") or []
        if isinstance(expect, str):
            expect = [e.strip() for e in re.split(r"[ ,;|]+", expect) if e.strip()]
        tests.append({"id": f"{sid}-{i}", "name": str(r.get("name") or f"Prompt {i}")[:60], "direction": direction,
                      "text": text, "expect": [e for e in expect if e in PANELS]})
    if not tests:
        raise KitError("No rows had a prompt.")
    d = CFG_DIR / "packs"
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"custom-{sid}.json"
    path.write_text(json.dumps({"name": name, "description": "Imported from CSV", "tests": tests}, indent=1,
                               ensure_ascii=False), encoding="utf-8")
    return path, len(tests)


def pick_tests(lib, preset=None, ids=None):
    tests = lib["tests"]
    if ids:
        want = set(ids)
        return [t for t in tests if t["id"] in want]
    if preset:
        p = next((p for p in lib["presets"] if p["id"] == preset), None)
        if not p:
            raise KitError(f"Unknown preset '{preset}'. Choose: {', '.join(x['id'] for x in lib['presets'])}")
        return [t for t in tests if t["group"] in p["groups"]]
    return tests


def run_one(cfg, test, app_name, user, mode):
    """Runs a single test. Returns a result dict (never raises)."""
    app = cfg["state"]["apps"].get(app_name) or {}
    text = test["text"].replace("{COMPETITOR}", cfg.get("competitor", "Palo Alto")).replace("{_}", "")
    res = {"ts": time.strftime("%H:%M:%S"), "id": test.get("id", "custom"), "name": test.get("name", "Custom prompt"),
           "category": test.get("category", "Custom"), "group": test.get("group", "Custom"),
           "direction": test.get("direction", "IN"), "user": user, "app": app_name, "mode": mode,
           "expect": test.get("expect", []), "text": text}
    try:
        if mode == "proxy":
            key = kc_get(f"{app_name}:proxy")
            if not key:
                raise KitError("This app has no proxy key (no LLM provider key was added in setup).")
            if res["direction"] == "OUT":
                raise KitError("Model-reply tests only run in detection mode.")
            try:
                reply, ms = proxy_chat(app["provider_type"], key, app["model"], text, user=user)
                res.update(status="OK", action="ALLOW", severity="", detectors=[], latency_ms=ms, reply=reply[:600],
                           missed=[])
            except KitError as e:  # AI Guard answers a blocked prompt with an HTTP error instead of a reply
                if re.search(r"HTTP 4\d\d", str(e)) and re.search(r"block|policy|guard|violat", str(e), re.I):
                    res.update(status="OK", action="BLOCK", severity="", detectors=[], missed=[], reply=str(e)[:600])
                else:
                    raise
        else:
            key = kc_get(f"{app_name}:detections")
            if not key:
                raise KitError("This app has no detection key. Run `./aiguard-kit setup`.")
            d, ms = das_scan(key, text, res["direction"], user)
            dets = d.get("detectorResponses") or {}
            hits = [k for k, v in dets.items() if isinstance(v, dict) and v.get("triggered")]
            res.update(status="OK", action=d.get("action", ""), severity=d.get("severity", ""), detectors=hits,
                       latency_ms=ms, transaction_id=d.get("transactionId"),
                       detector_errors=d.get("detectorErrorCount") or 0,
                       missed=[e for e in res["expect"] if e not in hits],
                       raw={k: {kk: v.get(kk) for kk in ("triggered", "action", "latency")} for k, v in dets.items()
                            if isinstance(v, dict)})
    except Exception as e:
        res.update(status="ERROR", action="", severity="", detectors=[], missed=[], error=str(e), fix=hint(e))
    try:  # local run log for support: no keys, prompts are synthetic or typed by the SE
        CFG_DIR.mkdir(exist_ok=True)
        with open(CFG_DIR / "runs.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({k: v for k, v in res.items() if k != "raw"}) + "\n")
    except Exception:
        pass
    return res


def plan(cfg, tests, mode, apps=None, users=None, rounds=1):
    apps = apps or list(cfg["state"]["apps"])
    if mode == "proxy":
        apps = [a for a in apps if cfg["state"]["apps"][a].get("proxy_cred_id")]
        tests = [t for t in tests if t["direction"] == "IN"]
    apps = [a for a in apps if a in cfg["state"]["apps"]]
    if not apps or not tests:
        return []
    users = users or load_tests()["users"]
    jobs = []
    for r in range(rounds):
        for i, t in enumerate(tests):
            jobs.append((t, apps[(i + r) % len(apps)], users[(i + r) % len(users)]))
    return jobs


# ---------------------------------------------------------------- policy switch
def apply_mode(body, mode):
    for side, names in BLOCKABLE.items():
        for d in body.get(side, []):
            if d.get("detector") in names and isinstance(d.get("configuration"), dict):
                d["configuration"]["action"] = "BLOCK" if mode == "block" else "DETECT"
                d["severity"] = "HIGH" if mode == "block" else "LOW"
    return body


def current_mode(body):
    return "block" if any(d.get("detector") in names and (d.get("configuration") or {}).get("action") == "BLOCK"
                          for side, names in BLOCKABLE.items() for d in body.get(side, [])) else "detect"


def policy_mode(t, cfg, target=None):
    """Returns (mode, policy name, switchable). Switches the kit's own policy when target is given."""
    pid = cfg.get("state", {}).get("policy_id")
    if not pid:
        raise KitError("No demo policy yet. Run ./aiguard-kit setup")
    body = t.call("policies", "get_policy", pid)
    name = body.get("name", "")
    switchable = name.startswith(PREFIX + ":")
    mode = current_mode(body)
    if target and target != mode:
        if not switchable:
            raise KitError(f"'{name}' isn't a kit policy, so the kit won't change it. Switch it in the console.")
        for k in ("id", "createTimeMillis", "updateTimeMillis"):
            body.pop(k, None)
        t.call("policies", "update_policy", pid, **apply_mode(body, target))
        cfg["state"]["policy_mode"] = mode = target
        save_cfg(cfg)
    return mode, name, switchable


def cmd_policy():
    cfg = load_cfg()
    target = next((a for a in ARGS if a in ("detect", "block")), None)
    t = connect(cfg)
    mode, name, switchable = policy_mode(t, cfg, target)
    (ok if switchable else warn)(f"'{name}' is in {'BLOCK (enforce)' if mode == 'block' else 'DETECT (monitor)'} mode")
    if target:
        info("Allow about 30 seconds before the change shows in scans.")
    elif switchable:
        info("Switch with: ./aiguard-kit policy block   or   ./aiguard-kit policy detect")


# ---------------------------------------------------------------- updates
_UPDATE = {"checked": False, "behind": 0}


def update_check(fetch=True):
    """Number of commits the local kit is behind its git upstream (0 when not a git checkout)."""
    import subprocess
    if _UPDATE["checked"] or not (HERE / ".git").exists():
        return _UPDATE["behind"]
    try:
        if fetch:
            subprocess.run(["git", "-C", str(HERE), "fetch", "--quiet"], timeout=8, capture_output=True)
        r = subprocess.run(["git", "-C", str(HERE), "rev-list", "--count", "HEAD..@{u}"], timeout=5,
                           capture_output=True, text=True)
        _UPDATE["behind"] = int(r.stdout.strip() or 0) if r.returncode == 0 else 0
    except Exception:
        pass
    _UPDATE["checked"] = True
    return _UPDATE["behind"]


# ---------------------------------------------------------------- scheduler
def schedule_cmdline(count):
    exe = HERE / ("aiguard-kit.cmd" if os.name == "nt" else "aiguard-kit")
    return [str(exe), "run", "--trickle", "--count", str(count), "--profile", PROFILE, "--yes"]


def cmd_schedule():
    import platform
    import subprocess
    action = next((a for a in ARGS if a in ("install", "remove", "status")), "status")
    every, count = max(15, int(opt("every", "60"))), int(opt("count", "12"))
    label = f"com.aiguard-se-kit.{PROFILE}"
    system = platform.system()
    head(f"Scheduled traffic ({system})")
    if system == "Darwin":
        import plistlib
        plist = HOME / "Library/LaunchAgents" / f"{label}.plist"
        dom = f"gui/{os.getuid()}"
        if action == "install":
            CFG_DIR.mkdir(parents=True, exist_ok=True)
            plist.parent.mkdir(parents=True, exist_ok=True)
            plist.write_bytes(plistlib.dumps({
                "Label": label, "ProgramArguments": schedule_cmdline(count), "StartInterval": every * 60,
                "RunAtLoad": False, "StandardOutPath": str(CFG_DIR / "trickle.log"),
                "StandardErrorPath": str(CFG_DIR / "trickle.log"),
                "EnvironmentVariables": {"PATH": f"{HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
                                         "NO_COLOR": "1"}}))
            subprocess.run(["launchctl", "bootout", dom, str(plist)], capture_output=True)
            r = subprocess.run(["launchctl", "bootstrap", dom, str(plist)], capture_output=True, text=True)
            if r.returncode:
                raise KitError(f"launchctl couldn't load the job: {r.stderr.strip()}")
            ok(f"Installed: {count} tests every {every} minutes. Log: {CFG_DIR / 'trickle.log'}")
            info("The first run may ask for keychain access. Choose 'Always Allow' so later runs work unattended.")
        elif action == "remove":
            subprocess.run(["launchctl", "bootout", dom, str(plist)], capture_output=True)
            plist.unlink(missing_ok=True)
            ok("Removed")
        else:
            r = subprocess.run(["launchctl", "print", f"{dom}/{label}"], capture_output=True, text=True)
            (ok if r.returncode == 0 else info)("Installed and loaded" if r.returncode == 0 else "Not installed")
    elif system == "Windows":
        name = f"AIGuardSEKit-{PROFILE}"
        if action == "install":
            tr = " ".join(f'"{x}"' if " " in x else x for x in schedule_cmdline(count))
            r = subprocess.run(["schtasks", "/Create", "/F", "/SC", "MINUTE", "/MO", str(every), "/TN", name, "/TR", tr],
                               capture_output=True, text=True)
            if r.returncode:
                raise KitError(f"schtasks failed: {r.stderr.strip() or r.stdout.strip()}")
            ok(f"Installed task '{name}': {count} tests every {every} minutes")
        elif action == "remove":
            subprocess.run(["schtasks", "/Delete", "/F", "/TN", name], capture_output=True)
            ok("Removed")
        else:
            r = subprocess.run(["schtasks", "/Query", "/TN", name], capture_output=True, text=True)
            (ok if r.returncode == 0 else info)("Installed" if r.returncode == 0 else "Not installed")
    else:
        marker = f"# aiguard-se-kit:{PROFILE}"
        cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
        lines = [x for x in cur.splitlines() if marker not in x]
        if action == "install":
            spec = f"*/{every} * * * *" if every < 60 else f"0 */{max(1, every // 60)} * * *"
            cmd = " ".join(schedule_cmdline(count))
            lines.append(f"{spec} {cmd} >> {CFG_DIR / 'trickle.log'} 2>&1 {marker}")
        if action in ("install", "remove"):
            subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, check=True)
            ok("Installed" if action == "install" else "Removed")
        else:
            (ok if marker in cur else info)("Installed" if marker in cur else "Not installed")


# ---------------------------------------------------------------- setup
def import_claude_desktop():
    p = HOME / "Library/Application Support/Claude/claude_desktop_config.json"
    try:
        servers = json.loads(p.read_text())["mcpServers"]
        for s in servers.values():
            env = s.get("env", {})
            if env.get("ZSCALER_CLIENT_ID") and env.get("ZSCALER_CLIENT_SECRET"):
                return env
    except Exception:
        pass
    return None


def cmd_setup():
    cfg = load_cfg()
    cfg.setdefault("state", {"apps": {}})
    head(f"AI Guard SE demo kit {VERSION} - setup")
    print("  Creates a detect-only policy, demo apps, keys and rules in YOUR tenant. Demo/eval tenants only.")

    # 1. credentials
    head("1. OneAPI credentials")
    existing = kc_get("oneapi-client-secret")
    if cfg.get("client_id") and existing:
        ok(f"Saved: client {mask(cfg['client_id'])} on vanity domain '{cfg['vanity_domain']}'")
        if not yesno("Use these?", True):
            existing = None
    if not (cfg.get("client_id") and existing):
        env = import_claude_desktop()
        if env and yesno("Found Zscaler OneAPI credentials in Claude Desktop's config. Use them?", True):
            cfg["client_id"], cfg["vanity_domain"] = env["ZSCALER_CLIENT_ID"], env.get("ZSCALER_VANITY_DOMAIN", "")
            kc_set("oneapi-client-secret", env["ZSCALER_CLIENT_SECRET"])
            if env.get("ZSCALER_CLOUD") and env["ZSCALER_CLOUD"].upper() != "PRODUCTION":
                cfg["cloud"] = env["ZSCALER_CLOUD"]
        else:
            info("ZIdentity > Integration > API Clients. The client needs AI Guard access.")
            cfg["vanity_domain"] = ask("Vanity domain (the part before .zslogin.net)", cfg.get("vanity_domain"))
            cfg["client_id"] = ask("Client ID", cfg.get("client_id"))
            sec = ask("Client secret (hidden)", secret=True)
            if sec:
                kc_set("oneapi-client-secret", sec)
        if not cfg.get("vanity_domain") or not cfg.get("client_id") or not kc_get("oneapi-client-secret"):
            raise KitError("Vanity domain, client ID and secret are all required.")
        cfg["vanity_domain"] = cfg["vanity_domain"].replace(".zslogin.net", "").replace("https://", "").strip("/")
        save_cfg(cfg)

    t = connect(cfg)
    pols, rules = t.list("policies"), t.list("policy_match_rules")
    apps, providers = t.list("llm_applications"), t.list("llm_providers")
    head("2. Tenant")
    ok(f"Connected to '{cfg['vanity_domain']}': {len(pols)} policies, {len(rules)} rules, {len(apps)} apps, "
       f"{len(providers)} LLM providers")
    if not yesno("This is a demo/eval tenant and I want the kit to create objects in it?", True):
        print("  Stopped. Nothing was changed.")
        return

    mine = [o for o in pols + rules + apps if str(o.get("name", "")).startswith(PREFIX + ":")]
    if mine:
        i = menu(f"Found {len(mine)} objects from an earlier '{PREFIX}' setup.",
                 ["Keep them and fill in anything missing", "Delete them and start fresh", "Cancel"])
        if i == 2:
            return
        if i == 1:
            teardown(t, cfg, confirm=False)
            cfg = load_cfg()
            cfg.setdefault("state", {"apps": {}})
            pols, rules, apps = t.list("policies"), t.list("policy_match_rules"), t.list("llm_applications")

    st = cfg["state"]

    # 3. policy
    head("3. Detection policy")
    pname = f"{PREFIX}: Test all"
    mypol = next((p for p in pols if p.get("name") == pname), None)
    others = [p for p in pols if p is not mypol]
    choices = [f"{'Use' if mypol else 'Create'} '{pname}' - every detector on"] + \
              [f"Use existing '{p['name']}' (unchanged)" for p in others]
    i = menu("Which policy should the demo apps use?", choices)
    if i == 0:
        if mypol:
            st["policy_id"] = mypol["id"]
            ok(f"Using '{pname}' (id {mypol['id']})")
        else:
            style = menu("Detector actions:", ["Detect only - allow and monitor everything",
                                               "Enforce - block prompt injection, invisible text, toxicity and "
                                               "malicious URLs (switch any time with `./aiguard-kit policy`)"])
            comp = ask("Competitor name for the competition detector", cfg.get("competitor", "Palo Alto"))
            cfg["competitor"] = comp
            body = json.loads((HERE / "policy_template.json").read_text().replace("{COMPETITOR}", comp))
            apply_mode(body, "block" if style == 1 else "detect")
            body["name"] = pname
            p = t.call("policies", "add_policy", **body)
            st["policy_id"] = p["id"]
            st["policy_mode"] = ["detect", "block"][style]
            ok(f"Created '{pname}' (id {p['id']}), {len(body['inputDetectorPolicies'])} input and "
               f"{len(body['outputDetectorPolicies'])} output detectors")
    else:
        st["policy_id"] = others[i - 1]["id"]
        ok(f"Using '{others[i - 1]['name']}'")
        warn("Prompt Classifications only fills if that policy has the prompt_tags detector enabled.")
    save_cfg(cfg)

    # 4. apps + provider keys
    head("4. Demo apps")
    info("Detection mode needs no LLM keys and fills every dashboard, including Users.")
    info("Add a provider key only if you also want real LLM calls through the AI Guard proxy (token usage).")
    pcreds = t.list("llm_provider_credentials")
    for ptype, (ctype, field, model) in PROVIDERS.items():
        prov = next((p for p in providers if p.get("type") == ptype and p.get("public")), None) or \
               next((p for p in providers if p.get("type") == ptype), None)
        label = "OpenAI" if ptype == "openai" else "Anthropic"
        app_name = f"{PREFIX}: {label} App"
        a = st["apps"].get(app_name) or {}
        found = next((x for x in apps if x.get("name") == app_name), None)
        if found:
            a["id"] = found["id"]
        else:
            created = t.call("llm_applications", "add_application", name=app_name,
                             applicationSettings={"includeEventContents": True, "encryptEventContents": False})
            a = {"id": created["id"]}
            ok(f"Created app '{app_name}'")
        a.update(provider_type=ptype, model=a.get("model", model), provider_id=prov["id"] if prov else None)
        st["apps"][app_name] = a
        save_cfg(cfg)

        # detection key
        if not (a.get("das_cred_id") and kc_get(f"{app_name}:detections")):
            cred = t.call("llm_application_credentials", "add_credential", name=f"{PREFIX}: {label} detection key",
                          applicationId=a["id"], mode="DETECTIONS")
            kc_set(f"{app_name}:detections", cred["key"])
            a["das_cred_id"] = cred["id"]
            ok(f"{label}: detection key created and saved to your keychain")
        else:
            ok(f"{label}: detection key already in your keychain")
        save_cfg(cfg)

        # proxy key (optional)
        if a.get("proxy_cred_id") and kc_get(f"{app_name}:proxy"):
            ok(f"{label}: proxy key already in your keychain")
            continue
        if not prov:
            warn(f"No {label} provider in this tenant; proxy mode skipped for this app.")
            continue
        mine_pc = next((c for c in pcreds if c.get("name") == f"{PREFIX}: {label} API key"), None)
        pc_id = mine_pc["id"] if mine_pc else None
        if not pc_id:
            k = "" if YES else ask(f"{label} API key for proxy mode (hidden, Enter to skip)", "", secret=True)
            if not k:
                info(f"{label}: skipped proxy mode")
                continue
            pc = t.call("llm_provider_credentials", "add_credential", name=f"{PREFIX}: {label} API key",
                        providerId=prov["id"], apiCredentials={"type": ctype, field: k})
            pc_id = pc["id"]
            ok(f"{label}: provider key stored in AI Guard")
        a["model"] = ask(f"{label} model for proxy tests", a["model"])
        cred = t.call("llm_application_credentials", "add_credential", name=f"{PREFIX}: {label} proxy key",
                      applicationId=a["id"], providerId=prov["id"], providerCredentialsId=pc_id, mode="PROXY")
        kc_set(f"{app_name}:proxy", cred["key"])
        a["proxy_cred_id"], a["provider_cred_id"] = cred["id"], pc_id
        ok(f"{label}: proxy key created and saved to your keychain")
        save_cfg(cfg)

    # 5. rules
    head("5. Policy rules")
    rules = t.list("policy_match_rules")
    order = max([r.get("ruleOrder", 0) for r in rules if not str(r.get("name", "")).startswith(PREFIX + ":")] + [0])
    for kind, rtype, credkey in (("detection", "DAS_APPLICATION", "das_cred_id"), ("proxy", "APPLICATION", "proxy_cred_id")):
        entries = [{"applicationId": a["id"], "applicationCredentialsIds": [a[credkey]]}
                   for a in st["apps"].values() if a.get(credkey)]
        rname = f"{PREFIX}: {kind} apps"
        existing = next((r for r in rules if r.get("name") == rname), None)
        if not entries:
            info(f"No {kind} keys, so no {kind} rule needed")
            continue
        order += 1
        body = dict(policyId=st["policy_id"], name=rname, enabled=True,
                    ruleOrder=existing.get("ruleOrder", order) if existing else order,
                    matchCriteria={"type": rtype, "llmApplications": entries})
        if existing:
            t.call("policy_match_rules", "update_rule", existing["id"], **body)
            st[f"{kind}_rule_id"] = existing["id"]
            ok(f"Updated rule '{rname}'")
        else:
            r = t.call("policy_match_rules", "add_rule", **body)
            st[f"{kind}_rule_id"] = r["id"]
            ok(f"Created rule '{rname}' (order {order})")
    save_cfg(cfg)

    # 6. verify
    head("6. Check")
    first = next(iter(st["apps"]))
    try:
        d, ms = das_scan(kc_get(f"{first}:detections"), "hello", user="setup-check@acme-demo.com")
        ok(f"Detection API answered in {ms} ms (policy '{d.get('policyName', '?')}')")
    except Exception as e:
        warn(f"Detection API check failed: {e}")
        info(hint(e))
        info("New keys can take a minute to become active. Try `./aiguard-kit status` shortly.")
    head("Done")
    print("  Next:  ./aiguard-kit gui        (test console in your browser)")
    print("         ./aiguard-kit run        (populate every dashboard from the terminal)")
    print(f"  Dashboards: {CONSOLE}  - allow 10-15 minutes for events to appear.")


# ---------------------------------------------------------------- teardown
def teardown(t, cfg, confirm=True):
    pre = PREFIX + ":"
    found = {r: [o for o in t.list(r) if str(o.get("name", "")).startswith(pre)] for r in
             ("policy_match_rules", "llm_application_credentials", "llm_applications", "llm_provider_credentials",
              "policies")}
    total = sum(len(v) for v in found.values())
    if not total:
        ok(f"Nothing named '{pre} …' in this tenant.")
    else:
        for r, objs in found.items():
            for o in objs:
                info(f"{r:28} {o['name']}")
        if confirm and not FORCE and not yesno(f"Delete these {total} objects?", False):
            print("  Cancelled.")
            return
        method = {"policy_match_rules": "delete_rule", "llm_application_credentials": "delete_credential",
                  "llm_applications": "delete_application", "llm_provider_credentials": "delete_credential",
                  "policies": "delete_policy"}
        for r, objs in found.items():
            for o in objs:
                try:
                    t.call(r, method[r], o["id"])
                    ok(f"Deleted {o['name']}")
                except Exception as e:
                    warn(f"Couldn't delete {o['name']}: {e}")
    for app in (cfg.get("state") or {}).get("apps", {}):
        kc_del(f"{app}:detections")
        kc_del(f"{app}:proxy")
    cfg["state"] = {"apps": {}}
    save_cfg(cfg)


def cmd_teardown():
    cfg = load_cfg()
    head("Teardown")
    t = connect(cfg)
    teardown(t, cfg)
    if yesno("Also forget the saved OneAPI credentials on this machine?", False):
        kc_del("oneapi-client-secret")
        CFG_FILE.unlink(missing_ok=True)
        ok("Local credentials removed")


# ---------------------------------------------------------------- status
def cmd_status():
    cfg = load_cfg()
    head("Status")
    if not cfg.get("client_id"):
        warn("Not set up. Run ./aiguard-kit setup")
        return
    ok(f"Tenant '{cfg['vanity_domain']}', client {mask(cfg['client_id'])}")
    t = connect(cfg)
    ok("OneAPI login works")
    st = cfg.get("state", {})
    pol = next((p for p in t.list("policies") if p["id"] == st.get("policy_id")), None)
    (ok if pol else warn)(f"Policy: {pol['name'] if pol else 'missing - run setup'}")
    if pol:
        try:
            mode, _, _ = policy_mode(t, cfg)
            info(f"Policy mode: {'BLOCK (enforce)' if mode == 'block' else 'DETECT (monitor)'}")
        except Exception as e:
            vlog(str(e))
    behind = update_check()
    if behind:
        warn(f"A newer kit is available ({behind} change{'s' if behind > 1 else ''}). Update with: git -C {HERE} pull")
    for name, a in st.get("apps", {}).items():
        dk, pk = kc_get(f"{name}:detections"), kc_get(f"{name}:proxy")
        line = f"{name}: detection key {'✓' if dk else '✗'}, proxy key {'✓' if pk else '-'}"
        if dk:
            try:
                d, ms = das_scan(dk, "status check", user="status-check@acme-demo.com")
                line += f", detection API OK ({ms} ms)"
            except Exception as e:
                line += f", detection API FAILED: {e}"
        ok(line) if "FAILED" not in line else (warn(line), info(hint(line)))


# ---------------------------------------------------------------- CLI run
def cmd_run():
    cfg = load_cfg()
    if not cfg.get("state", {}).get("apps"):
        raise KitError("Not set up. Run ./aiguard-kit setup")
    lib = load_tests()
    if "--trickle" in ARGS:
        return trickle(cfg, lib, int(opt("count", "12")))
    mode = opt("mode", "detect")
    ids = opt("tests")
    tests = pick_tests(lib, opt("preset", "everything") if not ids else None, ids.split(",") if ids else None)
    jobs = plan(cfg, tests, mode, rounds=int(opt("rounds", "1")))
    head(f"Running {len(jobs)} tests in {mode} mode")
    totals, seen = {}, set()
    for n, (t, app, user) in enumerate(jobs, 1):
        r = run_one(cfg, t, app, user, mode)
        totals[r["status"]] = totals.get(r["status"], 0) + 1
        seen.update(r["detectors"])
        tag = f"{C['g']}OK{C['x']}  " if r["status"] == "OK" else f"{C['r']}ERR{C['x']} "
        detail = ", ".join(r["detectors"]) if mode == "detect" else (r.get("reply", "")[:60])
        if r["status"] == "ERROR":
            detail = r["error"][:120]
        print(f"  {tag}{r['direction']:3} {t['category'][:16]:16} {t['name'][:22]:22} {user.split('@')[0]:6} "
              f"{app.split(': ')[-1].split()[0]:9} {r['action'][:5]:5} {detail}")
        if r["status"] == "ERROR" and n == 1:
            info(r["fix"])
            print("  Stopping: the first test failed, so the rest would too.")
            return
        time.sleep(0.15)
    head("Summary")
    print(f"  {totals}")
    if mode == "detect":
        print(f"  Detectors that fired: {', '.join(sorted(seen)) or 'none'}")
    print(f"  Dashboards ({CONSOLE}) update in 10-15 minutes.")


def trickle(cfg, lib, count):
    """Small random batch in detection mode, one log line. Used by the scheduler."""
    import random
    pool = [t for t in lib["tests"] if not t.get("pack")]
    apps, users = list(cfg["state"]["apps"]), lib["users"]
    picked = random.sample(pool, min(count, len(pool)))
    res = [run_one(cfg, t, random.choice(apps), random.choice(users), "detect") for t in picked]
    errs = [r for r in res if r["status"] == "ERROR"]
    dets = sorted({d for r in res for d in r["detectors"]})
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} trickle profile={PROFILE} sent={len(res)} errors={len(errs)} "
          f"detectors={','.join(dets)}" + (f" first_error={errs[0]['error'][:160]!r}" if errs else ""))
    if errs and len(errs) == len(res):
        sys.exit(1)


# ---------------------------------------------------------------- GUI server
JOBS: dict = {}


def cmd_gui():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import webbrowser

    cfg = load_cfg()
    token = secrets.token_urlsafe(24)
    tenant_cache = {}
    threading.Thread(target=update_check, daemon=True).start()

    def tenant(c):
        key = (c.get("client_id"), c.get("vanity_domain"))
        if key not in tenant_cache:
            tenant_cache.clear()
            tenant_cache[key] = connect(c)
        return tenant_cache[key]
    port = int(opt("port", "8765"))

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            if VERBOSE:
                super().log_message(*a)

        def _send(self, code, obj=None, ctype="application/json", raw=None):
            data = raw if raw is not None else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _guard(self):
            host = (self.headers.get("Host") or "").split(":")[0]
            if host not in ("127.0.0.1", "localhost"):
                self._send(403, {"error": "bad host"})
                return False
            if self.path.startswith("/api/") and self.headers.get("X-Kit-Token") != token:
                self._send(403, {"error": "bad token"})
                return False
            return True

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n) or b"{}")

        def do_GET(self):
            if not self._guard():
                return
            path = self.path.split("?")[0]
            if path in ("/", "/index.html"):
                html = (HERE / "gui.html").read_text(encoding="utf-8").replace("__KIT_TOKEN__", token)
                return self._send(200, raw=html.encode(), ctype="text/html; charset=utf-8")
            if path == "/api/policy":
                c = load_cfg()
                try:
                    mode, name, sw = policy_mode(tenant(c), c)
                    return self._send(200, {"mode": mode, "name": name, "switchable": sw})
                except Exception as e:
                    return self._send(200, {"mode": None, "error": str(e), "fix": hint(e)})
            if path == "/api/state":
                c = load_cfg()
                lib = load_tests()
                apps = [{"name": n, "label": n.split(": ", 1)[-1], "provider": a.get("provider_type"),
                         "model": a.get("model"), "detect": bool(kc_get(f"{n}:detections")),
                         "proxy": bool(a.get("proxy_cred_id") and kc_get(f"{n}:proxy"))}
                        for n, a in c.get("state", {}).get("apps", {}).items()]
                return self._send(200, {"tenant": c.get("vanity_domain"), "version": VERSION, "apps": apps,
                                        "policy_id": c.get("state", {}).get("policy_id"), "console": CONSOLE,
                                        "lib": lib, "panels": PANELS, "prefix": PREFIX,
                                        "competitor": c.get("competitor", "Palo Alto"), "profile": PROFILE,
                                        "update_behind": _UPDATE["behind"], "kit_dir": str(HERE)})
            if path == "/api/job":
                q = dict(x.split("=", 1) for x in (self.path.split("?", 1)[1:] or [""])[0].split("&") if "=" in x)
                j = JOBS.get(q.get("id"))
                if not j:
                    return self._send(404, {"error": "no such job"})
                since = int(q.get("since", 0))
                return self._send(200, {"done": j["done"], "total": j["total"], "results": j["results"][since:]})
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._guard():
                return
            path = self.path.split("?")[0]
            body = self._body()
            c = load_cfg()
            lib = load_tests()
            if path == "/api/import":
                try:
                    p, n = import_pack(body.get("name"), body.get("rows") or [])
                    return self._send(200, {"ok": True, "count": n, "file": p.name})
                except KitError as e:
                    return self._send(400, {"error": str(e)})
            if path == "/api/pack/delete":
                f = CFG_DIR / "packs" / Path(str(body.get("file", ""))).name
                if f.name.startswith("custom-") and f.exists():
                    f.unlink()
                    return self._send(200, {"ok": True})
                return self._send(400, {"error": "Only imported packs can be removed here."})
            if not c.get("state", {}).get("apps"):
                return self._send(400, {"error": "Not set up. Run ./aiguard-kit setup in a terminal first."})
            if path == "/api/run":
                tests = pick_tests(lib, ids=body.get("tests"))
                jobs = plan(c, tests, body.get("mode", "detect"), body.get("apps") or None, body.get("users") or None,
                            int(body.get("rounds", 1)))
                if not jobs:
                    return self._send(400, {"error": "Nothing to run for that selection (proxy mode needs an app with a proxy key)."})
                jid = uuid.uuid4().hex[:8]
                JOBS[jid] = {"done": False, "stop": False, "total": len(jobs), "results": []}

                def work():
                    for t, app, user in jobs:
                        if JOBS[jid]["stop"]:
                            break
                        JOBS[jid]["results"].append(run_one(c, t, app, user, body.get("mode", "detect")))
                        time.sleep(0.15)
                    JOBS[jid]["done"] = True

                threading.Thread(target=work, daemon=True).start()
                return self._send(200, {"id": jid, "total": len(jobs)})
            if path == "/api/policy":
                try:
                    mode, name, sw = policy_mode(tenant(c), c, body.get("mode"))
                    return self._send(200, {"mode": mode, "name": name, "switchable": sw})
                except Exception as e:
                    return self._send(400, {"error": str(e), "fix": hint(e)})
            if path == "/api/stop":
                if body.get("id") in JOBS:
                    JOBS[body["id"]]["stop"] = True
                return self._send(200, {"ok": True})
            if path == "/api/scan":
                text = (body.get("text") or "").strip()
                if not text:
                    return self._send(400, {"error": "Type a prompt first."})
                app = body.get("app") or next(iter(c["state"]["apps"]))
                t = {"text": text, "direction": body.get("direction", "IN"), "id": "custom", "name": "Live prompt",
                     "category": "Live", "group": "Live", "expect": []}
                return self._send(200, run_one(c, t, app, body.get("user") or lib["users"][0],
                                               body.get("mode", "detect")))
            self._send(404, {"error": "not found"})

    srv = None
    for p in range(port, port + 20):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), H)
            port = p
            break
        except OSError:
            continue
    if not srv:
        raise KitError("No free local port between 8765 and 8784.")
    url = f"http://127.0.0.1:{port}/"
    head("AI Guard test console")
    print(f"  {url}   (this machine only - press Ctrl+C to stop)")
    if not cfg.get("state", {}).get("apps"):
        warn("Not set up yet: run ./aiguard-kit setup first, then reload the page.")
    if "--no-browser" not in ARGS:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")


# ---------------------------------------------------------------- main
def main():
    tls_setup()
    vals = {ARGS[i + 1] for i, a in enumerate(ARGS[:-1]) if a in VALUE_OPTS}
    cmd = next((a for a in ARGS if not a.startswith("-") and a not in vals), "help")
    cmds = {"setup": cmd_setup, "gui": cmd_gui, "run": cmd_run, "status": cmd_status, "teardown": cmd_teardown,
            "policy": cmd_policy, "schedule": cmd_schedule}
    if cmd not in cmds:
        print(__doc__)
        return
    try:
        cmds[cmd]()
    except KitError as e:
        print(f"\n  {C['r']}✗{C['x']} {e}")
        print(f"    {C['y']}Fix:{C['x']} {hint(e)}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n  Cancelled.")
        sys.exit(130)


if __name__ == "__main__":
    main()
