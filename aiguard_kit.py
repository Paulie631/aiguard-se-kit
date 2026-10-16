# /// script
# requires-python = ">=3.10"
# dependencies = ["zscaler-sdk-python>=1.11", "requests>=2.31", "keyring>=24", "truststore>=0.9"]
# ///
"""Zscaler AI Guard SE demo kit.

  ./aiguard-kit setup      guided setup in the terminal: preflight checks, choices, review, create, verify
                           (or use the Setup tab in ./aiguard-kit gui)
  ./aiguard-kit preflight  run the read-only checks on their own (--write-probe, --json; see PREFLIGHT.md)
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

VERSION = "1.4.0"
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


TEMPLATE_DETECTORS = None


def template_detectors():
    global TEMPLATE_DETECTORS
    if TEMPLATE_DETECTORS is None:
        body = json.loads((HERE / "policy_template.json").read_text())
        TEMPLATE_DETECTORS = {side: [d["detector"] for d in body[side]] for side in ("inputDetectorPolicies",
                                                                                    "outputDetectorPolicies")}
    return TEMPLATE_DETECTORS


def audit_policy(body):
    """Detectors the kit's tests rely on that this policy lacks, with the console panels that stay empty."""
    missing = []
    for side, want in template_detectors().items():
        have = {d.get("detector") for d in body.get(side, []) if d.get("enabled")}
        missing += [(side.startswith("input") and "prompt" or "response", d) for d in want if d not in have]
    panels = sorted({PANELS.get(d, d) for _, d in missing})
    return missing, panels


def is_mine(o):
    return str(o.get("name", "")).startswith(PREFIX + ":")


# ---------------------------------------------------------------- preflight
def preflight(cfg, write_probe=False):
    """Read-only checks (plus an optional create/delete probe). Returns (checks, tenant or None)."""
    import requests
    checks = []

    def add(cid, label, status, detail="", fix=""):
        checks.append({"id": cid, "label": label, "status": status, "detail": detail, "fix": fix})

    # this computer
    try:
        kc_set("preflight-test", "ok")
        good = kc_get("preflight-test") == "ok"
        kc_del("preflight-test")
        add("keychain", "Keychain available", "ok" if good else "fail",
            fix="" if good else "The OS keychain didn't return a test value. On a Mac, unlock the login keychain.")
    except Exception as e:
        add("keychain", "Keychain available", "fail", str(e)[:160],
            "The kit stores keys in the OS keychain. On Linux install a keyring service (e.g. gnome-keyring).")
    for cid, label, url in (("das", "Detection API reachable", DAS_HOST), ("proxy", "AI Guard proxy reachable", PROXY_HOST)):
        try:
            requests.get(url, timeout=8)
            add(cid, label, "ok", url)
        except Exception as e:
            add(cid, label, "fail" if cid == "das" else "warn", f"{url}: {str(e)[:120]}", hint(e))

    # credentials + login
    if not (cfg.get("client_id") and cfg.get("vanity_domain") and kc_get("oneapi-client-secret")):
        add("creds", "OneAPI credentials saved", "fail", fix="Enter the vanity domain, client ID and secret first.")
        return checks, None
    add("creds", "OneAPI credentials saved", "ok", f"client {mask(cfg['client_id'])} on '{cfg['vanity_domain']}'")
    try:
        t = connect(cfg)
        add("login", "OneAPI login", "ok")
    except Exception as e:
        add("login", "OneAPI login", "fail", str(e)[:200], hint(e))
        return checks, None

    snap = {}
    for r in ("policies", "policy_match_rules", "llm_providers", "llm_provider_credentials", "llm_applications",
              "llm_application_credentials"):
        try:
            snap[r] = t.list(r)
        except Exception as e:
            add("read-" + r, f"Read {r.replace('_', ' ')}", "fail", str(e)[:200],
                "Give the API client full AI Guard access in ZIdentity.")
            return checks, None
    add("read", "Read access to AI Guard", "ok", f"{len(snap['policies'])} policies, {len(snap['policy_match_rules'])} "
        f"rules, {len(snap['llm_applications'])} apps")

    if write_probe:
        try:
            app = t.call("llm_applications", "add_application", name=f"{PREFIX}: preflight probe",
                         applicationSettings={"includeEventContents": True, "encryptEventContents": False})
            t.call("llm_applications", "delete_application", app["id"])
            add("write", "Create and delete permission", "ok", "Created and removed a temporary app")
        except Exception as e:
            add("write", "Create and delete permission", "fail", str(e)[:200],
                "The API client can read but not change AI Guard. Give it full AI Guard access in ZIdentity.")

    types = {p.get("type") for p in snap["llm_providers"]}
    for ptype, label in (("openai", "OpenAI"), ("anthropic", "Anthropic")):
        add("prov-" + ptype, f"{label} provider available", "ok" if ptype in types else "warn",
            "" if ptype in types else "Proxy mode won't be available for this app; detection mode still works.")

    mine = [o for r in ("policies", "policy_match_rules", "llm_applications") for o in snap[r] if is_mine(o)]
    add("existing", "Earlier kit objects", "info", f"{len(mine)} found" if mine else "none - fresh setup")

    risky = [r for r in snap["policy_match_rules"] if r.get("enabled") and not is_mine(r)
             and (r.get("matchCriteria") or {}).get("type") not in ("APPLICATION", "DAS_APPLICATION")]
    add("rules", "No broad rules ahead of the kit's", "warn" if risky else "ok",
        ", ".join(f"'{r['name']}' ({(r.get('matchCriteria') or {}).get('type')}, order {r.get('ruleOrder')})"
                  for r in risky[:4]),
        "These rules match by user, not app, and may apply their own policy to demo traffic. The check after "
        "setup confirms which policy actually handled it." if risky else "")

    pid = cfg.get("state", {}).get("policy_id")
    pol = next((p for p in snap["policies"] if p["id"] == pid), None) if pid else None
    if pol and not is_mine(pol):
        try:
            body = t.call("policies", "get_policy", pid)
            missing, panels = audit_policy(body)
            add("policy", f"Reused policy '{pol['name']}' covers the tests", "warn" if missing else "ok",
                f"Missing {len(missing)} detectors; empty panels: {', '.join(panels)}" if missing else "",
                "Enable those detectors in the console, or let setup create the kit's own policy." if missing else "")
        except Exception as e:
            vlog(str(e))
    add("manual", "Tenant Settings > Security > Store Prompts/Responses", "info", "Can't be read through the API",
        "Turn it on in the AI Security console so prompt text shows in event details.")
    t._snap = snap
    return checks, t


def preflight_help():
    try:
        return {c["id"]: c for c in json.loads((HERE / "preflight_help.json").read_text(encoding="utf-8"))["checks"]}
    except Exception:
        return {}


def help_id(cid):
    return "read" if cid.startswith("read") else cid


def preflight_report(cfg, checks):
    """Shareable report: no secrets (client ID masked, no keys)."""
    import platform
    worst = "fail" if any(c["status"] == "fail" for c in checks) else \
        "warn" if any(c["status"] == "warn" for c in checks) else "pass"
    return {"kit_version": VERSION, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "result": worst,
            "os": f"{platform.system()} {platform.release()}", "python": platform.python_version(),
            "profile": PROFILE, "prefix": PREFIX, "tenant": cfg.get("vanity_domain"),
            "client_id": mask(cfg.get("client_id", "")), "das_host": DAS_HOST, "proxy_host": PROXY_HOST,
            "checks": [{k: c[k] for k in ("id", "label", "status", "detail")} for c in checks]}


def report_text(rep_):
    icon = {"ok": "✓", "warn": "!", "fail": "✗", "info": "·"}
    lines = [f"AI Guard SE kit {rep_['kit_version']} preflight: {rep_['result'].upper()}",
             f"tenant {rep_['tenant']} · client {rep_['client_id']} · profile {rep_['profile']} · prefix {rep_['prefix']}",
             f"{rep_['os']} · Python {rep_['python']} · {rep_['time']}", ""]
    lines += [f"{icon[c['status']]} {c['label']}" + (f" - {c['detail']}" if c["detail"] else "") for c in rep_["checks"]]
    return "\n".join(lines)


def print_checks(checks):
    icon = {"ok": f"{C['g']}✓{C['x']}", "warn": f"{C['y']}!{C['x']}", "fail": f"{C['r']}✗{C['x']}", "info": "·"}
    for c in checks:
        print(f"  {icon[c['status']]} {c['label']}" + (f"  {C['d']}{c['detail']}{C['x']}" if c["detail"] else ""))
        if c["fix"] and c["status"] in ("warn", "fail"):
            print(f"      {C['y']}Fix:{C['x']} {c['fix']}")
            print(f"      {C['d']}Details: {HERE / 'PREFLIGHT.md'}#{help_id(c['id'])}{C['x']}")


def cmd_preflight():
    """Exit codes: 0 pass, 2 warnings only, 1 failures."""
    cfg = load_cfg()
    as_json = "--json" in ARGS
    if not as_json:
        head("Preflight checks (no changes)")
    checks, _ = preflight(cfg, write_probe="--write-probe" in ARGS)
    rep_ = preflight_report(cfg, checks)
    if as_json:
        print(json.dumps(rep_, indent=2))
    else:
        print_checks(checks)
        print(f"\n  Result: {rep_['result'].upper()}.  Runbook: {HERE / 'PREFLIGHT.md'}")
        print("  Share it: ./aiguard-kit preflight --json  (no secrets)")
    sys.exit({"pass": 0, "warn": 2, "fail": 1}[rep_["result"]])


# ---------------------------------------------------------------- setup (shared by terminal and browser)
def tenant_facts(t, cfg):
    snap = getattr(t, "_snap", None) or {r: t.list(r) for r in ("policies", "policy_match_rules", "llm_providers",
                                                                 "llm_provider_credentials", "llm_applications")}
    pname = f"{PREFIX}: Test all"
    st = cfg.get("state", {})
    return {
        "tenant": cfg.get("vanity_domain"), "prefix": PREFIX,
        "existing": [o["name"] for r in ("policies", "policy_match_rules", "llm_applications") for o in snap[r] if is_mine(o)],
        "kit_policy": next((p["id"] for p in snap["policies"] if p.get("name") == pname), None),
        "policies": [{"id": p["id"], "name": p["name"]} for p in snap["policies"] if p.get("name") != pname],
        "current_policy": st.get("policy_id"),
        "competitor": cfg.get("competitor", "Palo Alto"),
        "providers": {ptype: provider_facts(snap, st, ptype, default) for ptype, (_, _, default) in PROVIDERS.items()},
    }


def pick_provider(providers, ptype):
    """The tenant's provider of this type: the built-in (public) one first."""
    return next((p for p in providers if p.get("type") == ptype and p.get("public")), None) or \
        next((p for p in providers if p.get("type") == ptype), None)


def provider_facts(snap, st, ptype, default_model):
    label = "OpenAI" if ptype == "openai" else "Anthropic"
    prov = pick_provider(snap["llm_providers"], ptype)
    creds = [{"id": c["id"], "name": c.get("name", f"credential {c['id']}"), "mine": is_mine(c)}
             for c in snap["llm_provider_credentials"] if prov and c.get("providerId") == prov["id"]]
    creds.sort(key=lambda c: (not c["mine"], c["name"].lower()))   # the kit's own key first
    return {"label": label, "available": bool(prov), "provider_name": (prov or {}).get("name"), "creds": creds,
            "has_key": bool(creds),
            "model": (st.get("apps", {}).get(f"{PREFIX}: {label} App") or {}).get("model", default_model)}


def describe_plan(facts, ans):
    lines = []
    if facts["existing"] and ans.get("existing") == "fresh":
        lines.append(f"Delete {len(facts['existing'])} earlier kit objects first")
    if ans.get("policy") == "create":
        lines.append(("Use" if facts["kit_policy"] else "Create") + f" policy '{PREFIX}: Test all' "
                     f"({'Enforce' if ans.get('mode') == 'block' else 'Monitor'}; competitor '{ans.get('competitor')}')")
    else:
        name = next((p["name"] for p in facts["policies"] if p["id"] == ans.get("policy")), ans.get("policy"))
        lines.append(f"Use existing policy '{name}' unchanged")
    for ptype, p in ans.get("providers", {}).items():
        f = facts["providers"][ptype]
        cred = next((c for c in f["creds"] if c["id"] == p.get("cred_id")), None)
        if f["available"] and cred:
            proxy = f"proxy mode ({p.get('model')}) using the existing key '{cred['name']}'"
        elif f["available"] and p.get("key"):
            proxy = f"proxy mode ({p.get('model')}) with the new key you entered"
        else:
            proxy = "detection mode only"
        lines.append(f"App '{PREFIX}: {f['label']} App', detection key, {proxy}")
    lines.append(f"Rules '{PREFIX}: detection apps' (and '{PREFIX}: proxy apps' if any proxy keys), after your rules")
    lines.append("Then confirm every app's scans are handled by the chosen policy")
    return lines


def default_answers(facts):
    return {"existing": "keep", "policy": "create", "mode": "detect", "competitor": facts["competitor"],
            "providers": {k: {"key": None, "model": v["model"], "cred_id": v["creds"][0]["id"] if v["creds"] else None}
                          for k, v in facts["providers"].items()}}


def setup_apply(t, cfg, ans, log):
    """Creates or fills in everything for the answers given. Safe to run again after a failure."""
    cfg.setdefault("state", {"apps": {}})
    st = cfg["state"]
    if ans.get("existing") == "fresh":
        log("head", "Removing earlier kit objects")
        teardown(t, cfg, confirm=False, log=log)
        st = cfg["state"]

    log("head", "Detection policy")
    pols = t.list("policies")
    pname = f"{PREFIX}: Test all"
    if ans.get("policy", "create") == "create":
        mypol = next((p for p in pols if p.get("name") == pname), None)
        cfg["competitor"] = ans.get("competitor") or cfg.get("competitor", "Palo Alto")
        if mypol:
            st["policy_id"] = mypol["id"]
            log("ok", f"Using '{pname}'")
            mode = ans.get("mode", "detect")
            if policy_mode(t, cfg)[0] != mode:
                policy_mode(t, cfg, mode)
                log("ok", f"Policy set to {'Enforce' if mode == 'block' else 'Monitor'}")
        else:
            body = json.loads((HERE / "policy_template.json").read_text().replace("{COMPETITOR}", cfg["competitor"]))
            apply_mode(body, ans.get("mode", "detect"))
            body["name"] = pname
            p = t.call("policies", "add_policy", **body)
            st["policy_id"], st["policy_mode"] = p["id"], ans.get("mode", "detect")
            log("ok", f"Created '{pname}' with {len(body['inputDetectorPolicies'])} prompt and "
                      f"{len(body['outputDetectorPolicies'])} response detectors")
    else:
        pol = next((p for p in pols if p["id"] == int(ans["policy"])), None)
        if not pol:
            raise KitError(f"Policy {ans['policy']} no longer exists.")
        st["policy_id"] = pol["id"]
        log("ok", f"Using existing '{pol['name']}' (unchanged)")
        missing, panels = audit_policy(t.call("policies", "get_policy", pol["id"]))
        if missing:
            log("warn", f"It lacks {len(missing)} detectors the tests use; these panels stay empty: {', '.join(panels)}")
    save_cfg(cfg)

    log("head", "Demo apps and keys")
    apps, providers = t.list("llm_applications"), t.list("llm_providers")
    pcreds = t.list("llm_provider_credentials")
    for ptype, (ctype, field, model) in PROVIDERS.items():
        choice = (ans.get("providers") or {}).get(ptype, {})
        prov = pick_provider(providers, ptype)
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
            log("ok", f"Created app '{app_name}'")
        a.update(provider_type=ptype, model=choice.get("model") or a.get("model", model),
                 provider_id=prov["id"] if prov else None)
        st["apps"][app_name] = a
        save_cfg(cfg)
        if not (a.get("das_cred_id") and kc_get(f"{app_name}:detections")):
            cred = t.call("llm_application_credentials", "add_credential", name=f"{PREFIX}: {label} detection key",
                          applicationId=a["id"], mode="DETECTIONS")
            kc_set(f"{app_name}:detections", cred["key"])
            a["das_cred_id"] = cred["id"]
            log("ok", f"{label}: detection key created and saved to your keychain")
        else:
            log("ok", f"{label}: detection key already in your keychain")
        save_cfg(cfg)

        if a.get("proxy_cred_id") and kc_get(f"{app_name}:proxy"):
            log("ok", f"{label}: proxy key already in your keychain")
            continue
        if not prov:
            log("warn", f"No {label} provider in this tenant, so proxy mode is skipped for this app")
            continue
        usable = {c["id"]: c for c in pcreds if c.get("providerId") == prov["id"]}
        pc_id = None
        if choice.get("key"):
            pc = t.call("llm_provider_credentials", "add_credential", name=f"{PREFIX}: {label} API key",
                        providerId=prov["id"], apiCredentials={"type": ctype, field: choice["key"]})
            pc_id = pc["id"]
            log("ok", f"{label}: new provider key stored in AI Guard")
        elif choice.get("cred_id") is not None:
            if int(choice["cred_id"]) not in usable:
                raise KitError(f"The {label} provider key chosen in setup (id {choice['cred_id']}) no longer exists "
                               f"for '{prov.get('name')}'. Go back to Choices and pick another, or enter a new key.")
            pc_id = int(choice["cred_id"])
            log("ok", f"{label}: reusing the provider key '{usable[pc_id].get('name')}' already in AI Guard")
        else:
            if usable:
                log("info", f"{label}: proxy mode skipped (you chose detection only)")
            else:
                log("info", f"{label}: no {label} key is configured in this tenant, so detection mode only. "
                            f"To add proxy mode later, rerun setup and enter a key in Choices.")
            continue
        cred = t.call("llm_application_credentials", "add_credential", name=f"{PREFIX}: {label} proxy key",
                      applicationId=a["id"], providerId=prov["id"], providerCredentialsId=pc_id, mode="PROXY")
        kc_set(f"{app_name}:proxy", cred["key"])
        a["proxy_cred_id"], a["provider_cred_id"] = cred["id"], pc_id
        log("ok", f"{label}: proxy key created and saved to your keychain")
        save_cfg(cfg)

    log("head", "Policy rules")
    rules = t.list("policy_match_rules")
    order = max([r.get("ruleOrder", 0) for r in rules if not is_mine(r)] + [0])
    for kind, rtype, credkey in (("detection", "DAS_APPLICATION", "das_cred_id"), ("proxy", "APPLICATION", "proxy_cred_id")):
        entries = [{"applicationId": a["id"], "applicationCredentialsIds": [a[credkey]]}
                   for a in st["apps"].values() if a.get(credkey)]
        rname = f"{PREFIX}: {kind} apps"
        existing = next((r for r in rules if r.get("name") == rname), None)
        if not entries:
            continue
        order += 1
        body = dict(policyId=st["policy_id"], name=rname, enabled=True,
                    ruleOrder=existing.get("ruleOrder", order) if existing else order,
                    matchCriteria={"type": rtype, "llmApplications": entries})
        if existing:
            t.call("policy_match_rules", "update_rule", existing["id"], **body)
            st[f"{kind}_rule_id"] = existing["id"]
            log("ok", f"Updated rule '{rname}'")
        else:
            r = t.call("policy_match_rules", "add_rule", **body)
            st[f"{kind}_rule_id"] = r["id"]
            log("ok", f"Created rule '{rname}' (order {body['ruleOrder']})")
    save_cfg(cfg)


def verify(cfg, log, wait=75):
    """Scans once through each app and confirms the chosen policy handled it. Retries while new keys activate."""
    st = cfg.get("state", {})
    checks = []
    for app_name in st.get("apps", {}):
        key = kc_get(f"{app_name}:detections")
        label = app_name.split(": ", 1)[-1]
        if not key:
            checks.append({"id": "verify-policy", "label": f"{label}: detection key", "status": "fail", "detail": "missing from keychain",
                           "fix": "Run setup again."})
            continue
        deadline, last = time.time() + wait, None
        while True:
            try:
                d, ms = das_scan(key, "Setup check: summarize zero trust in one line.", user="setup-check@acme-demo.com")
                same = (d.get("policyId") == st.get("policy_id")) if d.get("policyId") is not None else None
                if same is False:
                    checks.append({"id": "verify-policy", "label": f"{label}: handled by the demo policy", "status": "fail",
                                   "detail": f"handled by '{d.get('policyName')}' instead",
                                   "fix": "Another rule matched first. Disable or reorder it in AI Guard > Policies, "
                                          "or move the kit's rules higher."})
                else:
                    checks.append({"id": "verify-policy", "label": f"{label}: Detection API", "status": "ok",
                                   "detail": f"{ms} ms, policy '{d.get('policyName', '?')}'", "fix": ""})
                break
            except Exception as e:
                last = e
                if time.time() > deadline or not re.search(r"\b(401|403|404)\b", str(e)):
                    checks.append({"id": "verify-policy", "label": f"{label}: Detection API", "status": "fail", "detail": str(e)[:200],
                                   "fix": hint(e)})
                    break
                log("info", f"{label}: key not active yet, retrying…")
                time.sleep(5)
        vlog(str(last) if last else "")
    for c in checks:
        log(c["status"] if c["status"] != "fail" else "warn", f"{c['label']}: {c['detail']}" + (f". Fix: {c['fix']}" if c["fix"] else ""))
    return checks


def save_credentials(cfg, vanity, client_id, secret=None, cloud=None):
    vanity = (vanity or "").strip().replace("https://", "").split("/")[0].replace(".zslogin.net", "")
    if not vanity or not client_id:
        raise KitError("Vanity domain and client ID are required.")
    cfg["vanity_domain"], cfg["client_id"] = vanity, client_id.strip()
    if cloud:
        cfg["cloud"] = cloud
    if secret:
        kc_set("oneapi-client-secret", secret.strip())
    if not kc_get("oneapi-client-secret"):
        raise KitError("Client secret is required.")
    save_cfg(cfg)


# ---------------------------------------------------------------- setup (terminal)
def cli_log(level, msg):
    {"ok": ok, "warn": warn, "info": info, "head": head, "fail": warn}.get(level, info)(msg)


def cmd_setup():
    cfg = load_cfg()
    cfg.setdefault("state", {"apps": {}})
    head(f"AI Guard SE demo kit {VERSION} - setup")
    print("  Checks your tenant, then creates the demo policy, apps, keys and rules. Demo/eval tenants only.")
    print(f"  {C['d']}Prefer a browser? Run ./aiguard-kit gui and open the Setup tab.{C['x']}")

    head("Step 1 of 5 · OneAPI credentials")
    if cfg.get("client_id") and kc_get("oneapi-client-secret") and yesno(
            f"Use saved client {mask(cfg['client_id'])} on '{cfg['vanity_domain']}'?", True):
        pass
    else:
        env = import_claude_desktop()
        if env and yesno("Found Zscaler OneAPI credentials in Claude Desktop's config. Use them?", True):
            save_credentials(cfg, env.get("ZSCALER_VANITY_DOMAIN", ""), env["ZSCALER_CLIENT_ID"],
                             env["ZSCALER_CLIENT_SECRET"],
                             env.get("ZSCALER_CLOUD") if (env.get("ZSCALER_CLOUD") or "").upper() not in ("", "PRODUCTION") else None)
        else:
            info("ZIdentity > Integration > API Clients. The client needs full AI Guard access.")
            save_credentials(cfg, ask("Vanity domain (the part before .zslogin.net)", cfg.get("vanity_domain")),
                             ask("Client ID", cfg.get("client_id")), ask("Client secret (hidden)", secret=True))

    head("Step 2 of 5 · Preflight checks (no changes yet)")
    probe = yesno("Also test create permission with a temporary app (created and deleted)?", True)
    while True:
        checks, t = preflight(cfg, write_probe=probe)
        print_checks(checks)
        fails = [c for c in checks if c["status"] == "fail"]
        if not fails:
            break
        blocking = t is None or any(c["id"] in ("write", "das", "keychain") for c in fails)
        opts = ["Fix it, then re-run the checks"] + ([] if blocking else ["Continue anyway"]) + ["Stop"]
        i = menu(f"{len(fails)} check{'s' if len(fails) > 1 else ''} failed.", opts)
        if opts[i] == "Stop" or (YES and blocking):
            print("  Stopped. Nothing was changed.")
            return
        if opts[i] == "Continue anyway":
            break
        if YES:
            break
    if not yesno(f"'{cfg['vanity_domain']}' is a demo/eval tenant and the kit may create objects in it?", True):
        print("  Stopped. Nothing was changed.")
        return

    facts = tenant_facts(t, cfg)
    ans = default_answers(facts)

    def ask_existing():
        if facts["existing"]:
            i = menu(f"Found {len(facts['existing'])} objects from an earlier setup.",
                     ["Keep them and fill in anything missing", "Delete them and start fresh"])
            ans["existing"] = ["keep", "fresh"][i]

    def ask_policy():
        opts = [f"{'Use' if facts['kit_policy'] else 'Create'} '{PREFIX}: Test all' - every detector on (recommended)"] + \
               [f"Use existing '{p['name']}' (unchanged)" for p in facts["policies"]]
        i = menu("Which policy should the demo apps use?", opts)
        ans["policy"] = "create" if i == 0 else facts["policies"][i - 1]["id"]
        if i == 0:
            ans["mode"] = ["detect", "block"][menu("Start in:", ["Monitor - detect and log everything",
                                                                 "Enforce - block prompt injection, invisible text, "
                                                                 "toxicity and malicious URLs"])]
            ans["competitor"] = ask("Competitor name for the competition detector", ans["competitor"])

    def ask_providers():
        info("Detection mode needs no LLM keys and fills every dashboard, including Users.")
        info("A provider key adds real LLM calls through the AI Guard proxy (token usage).")
        for ptype, f in facts["providers"].items():
            label, p = f["label"], ans["providers"][ptype]
            if not f["available"]:
                warn(f"{label}: no {label} provider in this tenant, so detection mode only")
                p.update(cred_id=None, key=None)
                continue
            if f["creds"]:
                opts = [f"Reuse '{c['name']}' (already in AI Guard)" for c in f["creds"]] + \
                       ["Enter a new key", "Skip: detection mode only"]
                cur = next((i for i, c in enumerate(f["creds"]) if c["id"] == p.get("cred_id")), 0)
                i = menu(f"{label} key for proxy mode:", opts, default=cur + 1)
                if i < len(f["creds"]):
                    p.update(cred_id=f["creds"][i]["id"], key=None)
                elif i == len(f["creds"]):
                    p.update(cred_id=None, key=ask(f"{label} API key (hidden)", "", secret=True) or None)
                else:
                    p.update(cred_id=None, key=None)
            else:
                warn(f"{label}: no {label} key is configured in this tenant.")
                info(f"Paste one to enable proxy mode for {label}, or press Enter for detection mode only.")
                p.update(cred_id=None, key=None if YES else (ask(f"{label} API key (hidden, Enter to skip)", "",
                                                                    secret=True) or None))
            if p.get("cred_id") or p.get("key"):
                p["model"] = ask(f"{label} model for proxy tests", p["model"])

    head("Step 3 of 5 · Choices")
    ask_existing()
    ask_policy()
    ask_providers()

    head("Step 4 of 5 · Review")
    while True:
        for line in describe_plan(facts, ans):
            print(f"  • {line}")
        i = menu("Ready?", ["Create it", "Change the policy choice", "Change provider keys", "Cancel"])
        if i == 0:
            break
        if i == 3:
            print("  Cancelled. Nothing was changed.")
            return
        (ask_policy if i == 1 else ask_providers)()

    head("Step 5 of 5 · Create and verify")
    while True:
        try:
            setup_apply(t, cfg, ans, cli_log)
            break
        except KitError as e:
            print(f"\n  {C['r']}✗{C['x']} {e}\n    {C['y']}Fix:{C['x']} {hint(e)}")
            info("Everything created so far is saved. Retrying fills in the rest.")
            if menu("What now?", ["Retry", "Stop (re-run setup later, or ./aiguard-kit teardown)"]) == 1 or YES:
                return
    head("Verifying")
    checks = verify(cfg, lambda lv, m: None)
    print_checks(checks)
    head("Done" if all(c["status"] == "ok" for c in checks) else "Done, with warnings above")
    print("  Next:  ./aiguard-kit gui        (console: test runner, guided demo, packs)")
    print("         ./aiguard-kit run        (populate every dashboard from the terminal)")
    print(f"  Dashboards: {CONSOLE}  - allow 10-15 minutes for events to appear.")


# ---------------------------------------------------------------- teardown
def teardown(t, cfg, confirm=True, log=None):
    log = log or cli_log
    pre = PREFIX + ":"
    found = {r: [o for o in t.list(r) if str(o.get("name", "")).startswith(pre)] for r in
             ("policy_match_rules", "llm_application_credentials", "llm_applications", "llm_provider_credentials",
              "policies")}
    total = sum(len(v) for v in found.values())
    if not total:
        log("ok", f"Nothing named '{pre} …' in this tenant.")
    else:
        if confirm:
            for r, objs in found.items():
                for o in objs:
                    info(f"{r:28} {o['name']}")
        if confirm and not FORCE and not yesno(f"Delete these {total} objects?", False):
            print("  Cancelled.")
            return False
        method = {"policy_match_rules": "delete_rule", "llm_application_credentials": "delete_credential",
                  "llm_applications": "delete_application", "llm_provider_credentials": "delete_credential",
                  "policies": "delete_policy"}
        for r, objs in found.items():
            for o in objs:
                try:
                    t.call(r, method[r], o["id"])
                    log("ok", f"Deleted {o['name']}")
                except Exception as e:
                    log("warn", f"Couldn't delete {o['name']}: {e}")
    for app in (cfg.get("state") or {}).get("apps", {}):
        kc_del(f"{app}:detections")
        kc_del(f"{app}:proxy")
    cfg["state"] = {"apps": {}}
    save_cfg(cfg)
    return True


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
                return self._send(200, {"done": j["done"], "total": j["total"], "results": j["results"][since:],
                                        "verify": j.get("verify"), "error": j.get("error"), "help": j.get("help")})
            if path == "/api/setup/state":
                c = load_cfg()
                return self._send(200, {"vanity": c.get("vanity_domain", ""), "client_id": mask(c.get("client_id", "")),
                                        "saved": bool(c.get("client_id") and kc_get("oneapi-client-secret")),
                                        "claude_desktop": bool(import_claude_desktop()), "prefix": PREFIX,
                                        "set_up": bool(c.get("state", {}).get("apps")), "profile": PROFILE})
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
            if path == "/api/setup/credentials":
                try:
                    if body.get("use_claude_desktop"):
                        env = import_claude_desktop() or {}
                        save_credentials(c, env.get("ZSCALER_VANITY_DOMAIN"), env.get("ZSCALER_CLIENT_ID"),
                                         env.get("ZSCALER_CLIENT_SECRET"))
                    elif body.get("vanity") or body.get("secret"):
                        save_credentials(c, body.get("vanity"), body.get("client_id") or c.get("client_id"),
                                         body.get("secret") or None)
                    tenant_cache.clear()
                    tenant(load_cfg())
                    return self._send(200, {"ok": True, "vanity": load_cfg().get("vanity_domain")})
                except Exception as e:
                    return self._send(400, {"error": str(e), "fix": hint(e)})
            if path == "/api/setup/preflight":
                checks, t = preflight(c, write_probe=bool(body.get("write_probe")))
                facts = None
                if t:
                    tenant_cache.clear()
                    tenant_cache[(c.get("client_id"), c.get("vanity_domain"))] = t
                    facts = tenant_facts(t, c)
                    facts["defaults"] = default_answers(facts)
                rep_ = preflight_report(c, checks)
                return self._send(200, {"checks": checks, "facts": facts, "help": preflight_help(),
                                        "report": rep_, "report_text": report_text(rep_)})
            if path in ("/api/setup/apply", "/api/setup/teardown"):
                if path.endswith("teardown") and body.get("confirm") != "DELETE":
                    return self._send(400, {"error": "Type DELETE to confirm."})
                try:
                    t = tenant(c)
                except Exception as e:
                    return self._send(400, {"error": str(e), "fix": hint(e)})
                jid = uuid.uuid4().hex[:8]
                job = JOBS[jid] = {"done": False, "stop": False, "total": 0, "results": []}
                log = lambda level, msg: job["results"].append({"level": level, "msg": msg})  # noqa: E731
                answers = body.get("answers") or {}

                def setup_work():
                    try:
                        cc = load_cfg()
                        if path.endswith("teardown"):
                            teardown(t, cc, confirm=False, log=log)
                        else:
                            setup_apply(t, cc, answers, log)
                            log("head", "Verifying")
                            job["verify"] = verify(cc, log)
                            job["help"] = preflight_help()
                    except Exception as e:
                        job["error"] = {"error": str(e), "fix": hint(e)}
                        log("fail", f"{e}")
                    job["done"] = True

                threading.Thread(target=setup_work, daemon=True).start()
                return self._send(200, {"id": jid})
            if not c.get("state", {}).get("apps"):
                return self._send(400, {"error": "Not set up yet. Open the Setup tab."})
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
        info("Not set up yet: the console opens on its Setup tab.")
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
    cmds = {"setup": cmd_setup, "preflight": cmd_preflight, "gui": cmd_gui, "run": cmd_run, "status": cmd_status, "teardown": cmd_teardown,
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
