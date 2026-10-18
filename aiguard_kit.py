# /// script
# requires-python = ">=3.10,<3.15"
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
  ./aiguard-kit policy [monitor|attacks|data|everything]   show or switch what the demo policy blocks
  ./aiguard-kit schedule install|remove|status [--every 60] [--count 12]
                           keep dashboards fresh with a small batch every N minutes
  ./aiguard-kit status     check credentials, tenant objects, the detection API and kit updates
  ./aiguard-kit teardown   delete everything this kit created (objects named with the prefix)
  ./aiguard-kit repair     check this computer's demo setup in the tenant and fix anything missing (--force: rerun)
  ./aiguard-kit logs       show recent activity (--errors, --follow); files are in ~/.aiguard-se-kit/logs
  ./aiguard-kit update     install the latest release from GitHub (--check: only check, --rollback: previous version)
  ./aiguard-kit install    copy the kit to ~/.aiguard-se-kit/app, add a desktop shortcut and the `aiguard-kit` command
                           (what the double-click installers run); uninstall removes them

Internet Access (ZIA), see ZIA.md:
  ./aiguard-kit zia setup      preflight, create a test user (or --user an existing one), then the SE-Demo ZIA policy
                               scoped to that user, and activate it
  ./aiguard-kit zia preflight  read-only ZIA checks (--write-probe, --json)
  ./aiguard-kit zia status     list the kit's ZIA objects;  zia teardown removes them and activates
  ./aiguard-kit zia password   show the test user's sign-in for Client Connector (this computer only)
  ./aiguard-kit zia aws        write a CloudFormation template for a generator instance on AWS (--zcc-url s3://bucket/key or URL)
  ./aiguard-kit zia dashboards which ZIA / Insights dashboards still look empty (Insights lags about 2 days)
  ./aiguard-kit zia check      on the traffic generator machine: is traffic reaching the demo tenant? (no keys needed)
  ./aiguard-kit zia traffic    on the generator: one round of demo traffic (--types web,saas,genai,threats,dlp,files,dns,ports
                               --count N); zia schedule install|remove|status [--every 30] repeats it

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

VERSION = "1.7.2"
HERE = Path(__file__).resolve().parent
WINDOWS = os.name == "nt"
LAUNCHER = ".\\aiguard-kit.cmd" if WINDOWS else "./aiguard-kit"
for _stream in (sys.stdout, sys.stderr):  # Windows consoles and redirected output default to cp1252, which can't print ✓ ✗
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def L(text: str) -> str:
    """Messages are written with the Mac/Linux launcher; show the Windows one on Windows."""
    return text.replace("./aiguard-kit", LAUNCHER) if WINDOWS else text


if WINDOWS:
    class _LauncherNames:
        def __init__(self, stream):
            self._s = stream

        def write(self, text):
            return self._s.write(L(text))

        def __getattr__(self, name):
            return getattr(self._s, name)
    sys.stdout = _LauncherNames(sys.stdout)
HOME = Path.home()
BASE_DIR = HOME / ".aiguard-se-kit"
APP_DIR = BASE_DIR / "app"  # where the double-click installer puts the kit
KC = "aiguard-se-kit"
ARGS = sys.argv[1:]
YES = "--yes" in ARGS or "-y" in ARGS
FORCE = "--force" in ARGS
VERBOSE = "--verbose" in ARGS or "-v" in ARGS
VALUE_OPTS = ("--prefix", "--preset", "--mode", "--rounds", "--tests", "--port", "--profile", "--count", "--every",
              "--user", "--types", "--domain", "--via", "--zcc-url", "--out")


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
elif WINDOWS:
    os.system("")  # turns on ANSI colour handling in the classic Windows console


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
     "your Zscaler root CA is in the system keychain (on Windows, the Trusted Root Certification Authorities store). As a last resort set SSL_CERT_FILE to a bundle that includes it."),
    (r"Detection API HTTP (401|403)",
     "AI Guard didn't accept this computer's detection key: it was deleted (for example by setup on another computer) "
     "or isn't in the kit's rule. Click Repair setup in the console, or run ./aiguard-kit repair. New keys can take a "
     "minute to start working."),
    (r"\b401\b|NOT_AUTHORIZED|Unauthorized",
     "Authenticated but not allowed. In ZIdentity, the API client needs the AI Guard scope (and for ZIA, an API role - "
     "not an admin role - created in ZIA > Role Management)."),
    (r"\b403\b|Forbidden",
     "The API client lacks permission for this object. Give it full AI Guard access in ZIdentity."),
    (r"Insufficient Balance|insufficient_quota|\b402\b|credit balance",
     "The LLM provider account has no credit. Top it up, or use detection mode (free) instead of proxy mode."),
    (r"\b429\b|rate.?limit",
     "Rate limited. Wait a minute, or lower --rounds."),
    (r"update check was blocked|download was blocked|web policy may block GitHub",
     "Ask IT to allow github.com, objects.githubusercontent.com and release-assets.githubusercontent.com, or download "
     "the latest zip from the kit's GitHub releases page in your browser and run its installer."),
    (r"doesn't match the release checksum|incomplete or not in the expected format",
     "Try again in a few minutes. If it keeps happening, download the zip from the kit's GitHub releases page and run "
     "its installer, and tell the kit owner."),
    (r"Couldn't reach GitHub",
     "Check your internet connection, then try again. Updates are optional: the kit keeps working without them."),
    (r"keychain|Credential Manager",
     "Open Credential Manager > Windows Credentials and check you're signed in to Windows as yourself, then retry."
     if WINDOWS else
     "Unlock the login keychain (Keychain Access > File > Unlock) and choose 'Always Allow' when macOS asks whether "
     "Python may use it. Then retry."),
    (r"not one of the values accepted",
     "The API rejected an enum value - your tenant may run a newer AI Guard API. Run with --verbose and send the log to the kit owner."),
]


def hint(err) -> str:
    text = str(err)
    for pat, fix in HINTS:
        if re.search(pat, text, re.I):
            return L(fix)
    return "Run again with --verbose and send the output to the kit owner."



# ---------------------------------------------------------------- activity log
# Everything the kit does, for the console's Logs tab and for troubleshooting. Secrets never reach it: known secret
# fields are masked, and every key or secret the kit loads from the keychain is replaced wherever it appears.
LOG_DIR = BASE_DIR / "logs"
LOG_KEEP_DAYS = 7
ACTIVITY: list = []          # recent entries for the console (newest last)
_ACT_SEQ = [0]
_ACT_LOCK = threading.Lock()
_SECRETS: set = set()
_SECRET_FIELDS = re.compile(r"^(key|secret|clientsecret|client_secret|token|apikey|api_key|password|authorization|"
                            r"x-apikey|x-api-key|bearer)$", re.I)


def remember_secret(v):
    if v and isinstance(v, str) and len(v) >= 8:
        _SECRETS.add(v)
    return v


def redact(o, depth=0):
    if depth > 12:
        return "…"
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            if _SECRET_FIELDS.match(str(k)) and isinstance(v, str):
                out[k] = (v[:4] + "…") if v else v
            elif str(k) == "apiCredentials":
                out[k] = {kk: ((vv[:4] + "…") if isinstance(vv, str) and kk != "type" else vv) for kk, vv in (v or {}).items()}
            else:
                out[k] = redact(v, depth + 1)
        return out
    if isinstance(o, (list, tuple)):
        return [redact(v, depth + 1) for v in o]
    if isinstance(o, str):
        for sec in _SECRETS:
            if sec in o:
                o = o.replace(sec, sec[:4] + "…")
        return o[:20000]
    return o


def activity(kind, summary, level="info", **detail):
    """kind: api | scan | proxy | setup | policy | update | error."""
    entry = {"t": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": kind, "level": level, "summary": redact(str(summary))[:300],
             "detail": redact(detail)}
    with _ACT_LOCK:
        _ACT_SEQ[0] += 1
        entry["seq"] = _ACT_SEQ[0]
        ACTIVITY.append(entry)
        del ACTIVITY[:-3000]
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            with open(LOG_DIR / f"kit-{time.strftime('%Y-%m-%d')}.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass
    return entry


def prune_logs():
    try:
        cutoff = time.time() - LOG_KEEP_DAYS * 86400
        for f in LOG_DIR.glob("kit-*.jsonl"):
            if f.stat().st_mtime < cutoff:
                f.unlink()
    except OSError:
        pass


def diagnostics_zip():
    """A zip of the recent logs, the preflight runbook data and versions, for sending to the kit owner. No secrets."""
    import io
    import platform
    import zipfile
    buf = io.BytesIO()
    cfg = load_cfg()
    info_ = {"kit": VERSION, "profile": PROFILE, "os": platform.platform(), "python": sys.version.split()[0],
             "tenant": cfg.get("vanity_domain"), "client_id": mask(cfg.get("client_id", "")),
             "kit_dir": str(HERE), "installed": APP_DIR.exists() and HERE.resolve() == APP_DIR.resolve(),
             "state": redact(cfg.get("state", {})), "answers": redact(cfg.get("answers", {}))}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("about.json", json.dumps(info_, indent=2))
        for f in sorted(LOG_DIR.glob("kit-*.jsonl"))[-LOG_KEEP_DAYS:] if LOG_DIR.exists() else []:
            z.writestr(f"logs/{f.name}", redact(f.read_text(encoding="utf-8", errors="replace")))
        runs = CFG_DIR / "runs.jsonl"
        if runs.exists():
            z.writestr("runs.jsonl", redact("\n".join(runs.read_text(encoding="utf-8", errors="replace").splitlines()[-500:])))
    return buf.getvalue()


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
    """None when the entry doesn't exist. Access problems raise, so the kit never mistakes a locked or denied
    keychain for a missing key (which would create duplicate keys in AI Guard)."""
    import keyring
    try:
        return remember_secret(keyring.get_password(KC, KC_NS + name))
    except Exception as e:
        raise KitError(f"Couldn't read the keychain entry '{name}': {e}. Unlock your keychain or choose "
                       f"'Always Allow' when macOS asks, then try again." if not WINDOWS else
                       f"Couldn't read '{name}' from Windows Credential Manager: {e}. Sign in to Windows as yourself "
                       f"(not a different account) and try again.") from e


def kc_has(name):
    """For display only: True/False, never raises."""
    try:
        return bool(kc_get(name))
    except KitError:
        return False


def kc_set(name, value):
    import keyring
    keyring.set_password(KC, KC_NS + name, remember_secret(value))


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
        return json.loads(CFG_FILE.read_text(encoding="utf-8"))
    return {}


def save_cfg(cfg):
    CFG_DIR.mkdir(exist_ok=True)
    CFG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
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
        t0 = time.time()
        try:
            _, resp, err = fn(*a, **kw)
        except Exception as e:
            err, resp = e, None
        ms = int((time.time() - t0) * 1000)
        req = {"args": list(a), "body": kw} if (a or kw) else {}
        if err:
            vlog(f"error: {err}")
            activity("api", f"AI Guard API {resource}.{method} failed", "error", request=req, error=str(err), ms=ms)
            raise KitError(f"{resource}.{method} failed: {err}")
        body = resp.get_body() if resp is not None else None
        activity("api", f"AI Guard API {resource}.{method}", "ok", request=req, response=body, ms=ms)
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


def das_scan(key, text, direction="IN", user=None, timeout=60, trace=None):
    import requests
    body = {"content": text, "direction": direction, "transactionId": str(uuid.uuid4())}
    if user:
        body["user"] = user
    remember_secret(key)
    t0 = time.time()
    url = DAS_HOST + DAS_PATH
    try:
        r = requests.post(url, json=body, timeout=timeout,
                          headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    except requests.RequestException as e:
        activity("scan", f"Detection API {direction} scan: network error", "error", url=url, request=body, error=str(e))
        raise
    ms = int((time.time() - t0) * 1000)
    if r.status_code >= 400:
        activity("scan", f"Detection API {direction} scan: HTTP {r.status_code}", "error", url=url, request=body,
                 status=r.status_code, response=r.text[:4000], ms=ms)
        raise KitError(f"Detection API HTTP {r.status_code}: {r.text[:300]}".replace(key, "<key>"))
    d = r.json()
    if trace is not None:
        trace.update(request={"method": "POST", "url": url, "body": body}, status=r.status_code, response=d)
    activity("scan", f"Detection API {direction} scan → {d.get('action', '?')}" + (f" ({user})" if user else ""),
             "ok", url=url, request=body, status=r.status_code, response=d, ms=ms)
    return d, ms


def proxy_chat(ptype, key, model, prompt, user=None, max_tokens=300, timeout=90, trace=None):
    import requests
    remember_secret(key)
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
    req = {"method": "POST", "url": r.request.url if r.request is not None else PROXY_HOST,
           "body": json.loads(r.request.body) if getattr(r.request, "body", None) else None}
    if trace is not None:
        trace.update(request=req, status=r.status_code, response=r.text[:8000])
    if r.status_code >= 400:
        activity("proxy", f"LLM proxy ({ptype}, {model}): HTTP {r.status_code}",
                 "warn" if re.search(r"block|policy|guard|violat", r.text, re.I) else "error",
                 request=req, status=r.status_code, response=r.text[:4000], ms=ms)
        raise KitError(f"HTTP {r.status_code}: {r.text[:300]}".replace(key, "<key>"))
    d = r.json()
    activity("proxy", f"LLM proxy ({ptype}, {model}) → reply", "ok", request=req, status=r.status_code, response=d, ms=ms)
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


def _hits(d):
    dets = d.get("detectorResponses") or {}
    return [k for k, v in dets.items() if isinstance(v, dict) and v.get("triggered")], dets


def run_one(cfg, test, app_name, user, mode, tags=False):
    """Runs a single test. Returns a result dict (never raises).
    tags=True in proxy mode also scans the prompt and the model's reply with the Detection API, so the result
    carries detector tags (two extra events in Insights)."""
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
            dkey = kc_get(f"{app_name}:detections") if tags else None
            res["exchange"] = ex = {}
            try:
                reply, ms = proxy_chat(app["provider_type"], key, app["model"], text, user=user, trace=ex)
                res.update(status="OK", action="ALLOW", severity="", detectors=[], latency_ms=ms, reply=reply[:600],
                           missed=[])
            except KitError as e:  # AI Guard answers a blocked prompt with an HTTP error instead of a reply
                if re.search(r"HTTP 4\d\d", str(e)) and re.search(r"block|policy|guard|violat", str(e), re.I):
                    res.update(status="OK", action="BLOCK", severity="", detectors=[], missed=[], reply=str(e)[:600])
                else:
                    raise
            if dkey:
                try:
                    d, _ = das_scan(dkey, text, "IN", user)
                    hits, _ = _hits(d)
                    res.update(detectors=hits, severity=d.get("severity", ""), scan_action=d.get("action"),
                               missed=[x for x in res["expect"] if x not in hits])
                    if res["action"] == "ALLOW" and res.get("reply"):
                        o, _ = das_scan(dkey, res["reply"], "OUT", user)
                        res["resp_detectors"], _ = _hits(o)
                        res["resp_action"] = o.get("action")
                except Exception as e:
                    res["tag_error"] = str(e)[:200]
        else:
            key = kc_get(f"{app_name}:detections")
            if not key:
                raise KitError("This app has no detection key. Run `./aiguard-kit setup`.")
            res["exchange"] = ex = {}
            d, ms = das_scan(key, text, res["direction"], user, trace=ex)
            hits, dets = _hits(d)
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
            f.write(json.dumps({k: v for k, v in res.items() if k not in ("raw", "exchange")}) + "\n")
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
REGULATED_PII = {"CREDIT_CARD", "US_SSN", "US_BANK_NUMBER", "IBAN_CODE", "SWIFT_CODE", "US_PASSPORT", "US_ITIN"}
NEVER_BLOCK = {"language", "prompt_tags", "response_tags", "refusal", "url_reachability"}  # classification only
ATTACKS = {"inputDetectorPolicies": {"prompt_injection", "invisible_text", "toxicity"},
           "outputDetectorPolicies": {"malicious_url", "toxicity"}}
DATA = {"inputDetectorPolicies": {"secrets", "pii"}, "outputDetectorPolicies": {"secrets", "pii"}}
PROFILES = {
    "monitor": "Monitor: detect and log everything, block nothing",
    "attacks": "Block attacks: prompt injection, hidden text, toxicity, malicious URLs",
    "data": "Block attacks + data leakage: also secrets and regulated PII (cards, SSNs, bank, passport, ITIN)",
    "everything": "Block everything risky: every detector except topic and language classification",
}
ALIASES = {"detect": "monitor", "block": "attacks", "enforce": "attacks"}
SIDES = ("inputDetectorPolicies", "outputDetectorPolicies")
SIDE_NAME = {"inputDetectorPolicies": "prompt", "outputDetectorPolicies": "response"}


def _set_action(det, action, only=None):
    """Sets a detector's action; for list-style detectors (PII entities, secret types, tags…) every enabled
    item follows, or only the item types in `only` (others go back to DETECT)."""
    cfg = det.get("configuration")
    if not isinstance(cfg, dict):
        return
    if "action" in cfg:
        cfg["action"] = action
    for key in ("entities", "secretTypes", "languages", "tags", "competitors"):
        for item in cfg.get(key, []) or []:
            if item.get("action") == "DISABLE":
                continue
            kind = item.get("entityType") or item.get("secretType")
            item["action"] = action if only is None or kind in only else "DETECT"
    if "defaultAction" in cfg:  # the API rejects defaultAction BLOCK (tested); blocking is set per item
        cfg["defaultAction"] = "DETECT"
    det["severity"] = "HIGH" if action == "BLOCK" else "LOW"


def profile_blocks(profile):
    """{side: {detector: entity-filter or None}} that a named profile blocks."""
    out = {side: {} for side in SIDES}
    if profile in ("attacks", "data"):
        for side in SIDES:
            out[side].update({d: None for d in ATTACKS[side]})
    if profile == "data":
        for side in SIDES:
            out[side].update({"secrets": None, "pii": REGULATED_PII})
    if profile == "everything":
        names = template_detectors()
        for side in SIDES:
            out[side].update({d: None for d in names[side] if d not in NEVER_BLOCK})
    return out


def apply_profile(body, target):
    """target: a profile name (or alias) or {"prompt": [detectors], "response": [detectors]} for custom."""
    if isinstance(target, dict):
        blocks = {side: {d: (REGULATED_PII if d == "pii" and target.get("pii_regulated_only", True) else None)
                         for d in target.get(SIDE_NAME[side], []) if d not in NEVER_BLOCK} for side in SIDES}
    else:
        blocks = profile_blocks(ALIASES.get(target, target))
    for side in SIDES:
        for d in body.get(side, []):
            if not d.get("enabled"):
                continue
            name = d.get("detector")
            if name in blocks[side]:
                _set_action(d, "BLOCK", blocks[side][name])
            else:
                _set_action(d, "DETECT")
    return body


def apply_mode(body, mode):  # kept for setup: "detect"/"block" or a profile name
    return apply_profile(body, mode)


def blocked_map(body):
    """{"prompt": [...], "response": [...]} detectors with anything set to BLOCK."""
    def blocking(d):
        cfg = d.get("configuration") or {}
        return cfg.get("action") == "BLOCK" or any(
            i.get("action") == "BLOCK" for k in ("entities", "secretTypes", "languages", "tags", "competitors")
            for i in cfg.get(k, []) or [])
    return {SIDE_NAME[side]: sorted(d["detector"] for d in body.get(side, []) if d.get("enabled") and blocking(d))
            for side in SIDES}


def current_profile(body):
    have = blocked_map(body)
    for name in PROFILES:
        want = profile_blocks(name)
        if all(sorted(want[side]) == have[SIDE_NAME[side]] for side in SIDES):
            return name
    return "custom"


def current_mode(body):  # "block" when anything blocks
    return "block" if any(blocked_map(body).values()) else "detect"


def policy_mode(t, cfg, target=None):
    """Returns (profile, policy name, switchable). Applies target (profile name, alias or custom dict) when given."""
    pid = cfg.get("state", {}).get("policy_id")
    if not pid:
        raise KitError("No demo policy yet. Run ./aiguard-kit setup")
    body = t.call("policies", "get_policy", pid)
    name = body.get("name", "")
    switchable = name.startswith(PREFIX + ":")
    profile = current_profile(body)
    if isinstance(target, str):
        target = ALIASES.get(target, target)
        if target not in PROFILES:
            raise KitError(f"Unknown policy profile '{target}'. Use one of: {', '.join(PROFILES)}.")
    if target and target != profile:
        if not switchable:
            raise KitError(f"'{name}' isn't a kit policy, so the kit won't change it. Switch it in the console.")
        for k in ("id", "createTimeMillis", "updateTimeMillis"):
            body.pop(k, None)
        t.call("policies", "update_policy", pid, **apply_profile(body, target))
        profile = current_profile(body)
        cfg["state"]["policy_mode"] = profile
        save_cfg(cfg)
    return profile, name, switchable


def policy_details(t, cfg):
    """For the console: profile, what blocks, and every detector on each side."""
    profile, name, sw = policy_mode(t, cfg)
    body = t.call("policies", "get_policy", cfg["state"]["policy_id"])
    dets = {SIDE_NAME[side]: [d["detector"] for d in body.get(side, []) if d.get("enabled")
                              and d["detector"] not in NEVER_BLOCK] for side in SIDES}
    return {"mode": profile, "name": name, "switchable": sw, "blocked": blocked_map(body), "detectors": dets,
            "profiles": PROFILES, "regulated_pii": sorted(REGULATED_PII)}


def cmd_policy():
    cfg = load_cfg()
    target = next((a for a in ARGS if a in PROFILES or a in ALIASES), None)
    t = connect(cfg)
    profile, name, switchable = policy_mode(t, cfg, target)
    (ok if switchable else warn)(f"'{name}': {PROFILES.get(profile, 'custom: a hand-picked set of detectors block')}")
    if target:
        info("Allow about 30 seconds before the change shows in scans.")
    elif switchable:
        info("Switch with: ./aiguard-kit policy monitor | attacks | data | everything")


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


# ---------------------------------------------------------------- updates from GitHub Releases
REPO = os.getenv("AIGUARD_KIT_REPO", "Paulie631/aiguard-se-kit")
UPDATE_URL = os.getenv("AIGUARD_KIT_UPDATE_URL", f"https://github.com/{REPO}/releases/latest/download/latest.json")
UPDATE_HOSTS = "github.com, objects.githubusercontent.com and release-assets.githubusercontent.com"
_REL: dict = {}


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", str(v))[:3])


def _blocked(r):
    """True when a web policy answered instead of GitHub (ZIA and similar return an HTML block or warning page)."""
    ctype = (r.headers.get("Content-Type") or "").lower()
    return r.status_code in (403, 407, 451) or "text/html" in ctype


def _url_ok(url):
    return url.startswith("https://") or re.match(r"http://(127\.0\.0\.1|localhost)[:/]", url or "")


def fetch_release(force=False):
    """Latest release info {version, notes, zip_url, sha256}. Cached for 12 hours (in ~/.aiguard-se-kit)."""
    import requests
    cache = BASE_DIR / "update-check.json"
    if not force:
        try:
            c = json.loads(cache.read_text(encoding="utf-8"))
            if time.time() - c.get("t", 0) < 12 * 3600 and c.get("url") == UPDATE_URL:
                return c["info"]
        except Exception:
            pass
    try:
        # cache-busting query and headers, so a proxy or CDN can't answer with an old latest.json
        r = requests.get(UPDATE_URL, params={"t": int(time.time())}, timeout=15,
                         headers={"Accept": "application/json", "Cache-Control": "no-cache", "Pragma": "no-cache"})
    except requests.RequestException as e:
        raise KitError(f"Couldn't reach GitHub to check for updates: {e}") from e
    if _blocked(r):
        raise KitError(f"The update check was blocked (HTTP {r.status_code}, got a web page instead of release info). "
                       f"Your laptop's web policy may block GitHub downloads; ask IT to allow {UPDATE_HOSTS}.")
    if r.status_code == 404:
        raise KitError("No published release with update information was found yet.")
    if r.status_code != 200:
        raise KitError(f"The update check failed: HTTP {r.status_code}")
    try:
        info = r.json()
        assert info["version"] and _url_ok(info["zip_url"]) and re.fullmatch(r"[0-9a-f]{64}", info["sha256"])
    except Exception as e:
        raise KitError("The release information was incomplete or not in the expected format.") from e
    try:
        BASE_DIR.mkdir(exist_ok=True)
        cache.write_text(json.dumps({"t": time.time(), "url": UPDATE_URL, "info": info}), encoding="utf-8")
    except OSError:
        pass
    return info


def update_status(force=False):
    st = {"current": VERSION, "latest": None, "available": False, "notes": "", "error": None,
          "installed": APP_DIR.exists() and HERE.resolve() == APP_DIR.resolve(), "git": (HERE / ".git").exists(),
          "can_rollback": (APP_DIR.with_name(APP_DIR.name + ".previous") / "aiguard_kit.py").exists(),
          "releases": f"https://github.com/{REPO}/releases/latest"}
    try:
        info = fetch_release(force)
        st.update(latest=info["version"], notes=info.get("notes", ""), available=vtuple(info["version"]) > vtuple(VERSION))
    except KitError as e:
        st["error"] = str(e)
    return st


KIT_FOLDERS = ("aiguard-se-kit/", "zscaler-zia-kit/")   # the top folder of each edition's release zip


def download_release(info, log=lambda level, msg: None):
    """Download and verify the release zip, extract it, and return the folder holding the new kit."""
    import hashlib
    import shutil
    import zipfile
    import requests
    if not _url_ok(info.get("zip_url", "")):
        raise KitError("Refusing to download an update over an insecure link.")
    work = BASE_DIR / "update-staging"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    zpath = work / "kit.zip"
    log("info", f"Downloading {info['version']}…")
    h = hashlib.sha256()
    try:
        with requests.get(info["zip_url"], stream=True, timeout=60) as r:
            if _blocked(r) or r.status_code != 200:
                raise KitError(f"The download was blocked or failed (HTTP {r.status_code}). Your laptop's web policy may "
                               f"block GitHub downloads; ask IT to allow {UPDATE_HOSTS}, or download the zip from "
                               f"https://github.com/{REPO}/releases/latest and run its installer.")
            size = 0
            with open(zpath, "wb") as f:
                for chunk in r.iter_content(65536):
                    size += len(chunk)
                    if size > 50 * 1024 * 1024:
                        raise KitError("The download is far larger than expected, so it was stopped.")
                    h.update(chunk)
                    f.write(chunk)
    except requests.RequestException as e:
        raise KitError(f"The download failed: {e}") from e
    if h.hexdigest() != info["sha256"]:
        head_ = zpath.read_bytes()[:400].lower()
        why = (" It looks like a web page, so a web policy may have blocked it." if b"<html" in head_ or b"<!doctype" in head_
               else " It may have been changed or cut short.")
        raise KitError("The downloaded file doesn't match the release checksum, so it wasn't installed." + why)
    log("ok", "Download verified (SHA-256 matches the release)")
    out = work / "x"
    with zipfile.ZipFile(zpath) as z:
        for n in z.namelist():
            p = Path(n)
            if p.is_absolute() or ".." in p.parts or not n.startswith(KIT_FOLDERS):
                raise KitError(f"Unexpected file in the update: {n}")
        z.extractall(out)
    tops = {p.name for p in out.iterdir()}
    if len(tops) != 1:
        raise KitError("Unexpected layout in the update zip.")
    kit = out / tops.pop()
    m = re.search(r'^VERSION = "([^"]+)"', (kit / "aiguard_kit.py").read_text(encoding="utf-8"), re.M)
    got = m and m.group(1)
    if (kit / "edition.json").exists():   # an edition (the ZIA kit) carries its own version
        try:
            got = json.loads((kit / "edition.json").read_text(encoding="utf-8")).get("version")
        except ValueError:
            got = None
    if got != info["version"] or (bool(EDITION) != (kit / "edition.json").exists()):
        raise KitError("The downloaded kit's version doesn't match the release, so it wasn't installed.")
    for f in ("aiguard-kit", "zia-kit", "Install AI Guard Kit.command", "Install ZIA Kit.command",
              "Uninstall AI Guard Kit.command"):
        if (kit / f).exists():
            os.chmod(kit / f, 0o755)
    return kit


def apply_update(info, log=lambda level, msg: None):
    """Download, verify and install a release into APP_DIR using the new kit's own installer."""
    import subprocess
    if (HERE / ".git").exists():
        raise KitError(f"This copy is a git checkout. Update it with: git -C \"{HERE}\" pull")
    kit = download_release(info, log)
    log("info", "Installing…")
    env = {**os.environ, "NO_COLOR": "1", "PYTHONUTF8": "1"}
    r = subprocess.run([sys.executable, str(kit / "aiguard_kit.py"), "install", "--yes", "--profile", PROFILE],
                       capture_output=True, text=True, env=env, timeout=300)
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("✓"):
            log("ok", line[1:].strip())
        elif line.startswith("!"):
            log("warn", line[1:].strip())
    if r.returncode:
        raise KitError(f"The new version's installer failed: {(r.stdout + r.stderr).strip()[-400:]}")
    log("ok", f"Updated to {info['version']}. The previous version is kept for rollback.")


def rollback():
    """Swap the installed kit with the copy kept by the last install or update."""
    import shutil
    prev, tmp = APP_DIR.with_name(APP_DIR.name + ".previous"), APP_DIR.with_name(APP_DIR.name + ".rollback")
    if not (prev / "aiguard_kit.py").exists():
        raise KitError("There's no previous version to roll back to.")
    m = re.search(r'^VERSION = "([^"]+)"', (prev / "aiguard_kit.py").read_text(encoding="utf-8"), re.M)
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        APP_DIR.rename(tmp)
        prev.rename(APP_DIR)
        tmp.rename(prev)
    except OSError:  # Windows: folder in use, so swap the contents instead
        if not APP_DIR.exists() and tmp.exists():
            tmp.rename(APP_DIR)
        shutil.copytree(APP_DIR, tmp, dirs_exist_ok=True)
        shutil.copytree(prev, APP_DIR, dirs_exist_ok=True)
        shutil.rmtree(prev, ignore_errors=True)
        tmp.rename(prev)
    return m.group(1) if m else "the previous version"


def cmd_logs():
    files = sorted(LOG_DIR.glob("kit-*.jsonl")) if LOG_DIR.exists() else []
    if not files:
        info(f"No activity logged yet ({LOG_DIR}).")
        return
    errors_only = "--errors" in ARGS

    def show(line):
        try:
            e = json.loads(line)
        except ValueError:
            return
        if errors_only and e.get("level") not in ("error", "warn"):
            return
        mark = {"ok": "✓", "error": "✗", "warn": "!"}.get(e.get("level"), "·")
        ms = e.get("detail", {}).get("ms")
        print(f"  {e['t'][11:]} {mark} {e['kind']:7} {e['summary']}" + (f"  {ms} ms" if ms is not None else ""))
    lines = files[-1].read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-60:]:
        show(line)
    print(f"  {C['d']}Full details (requests and responses, secrets masked): {files[-1]}{C['x']}")
    if "--follow" in ARGS:
        pos = files[-1].stat().st_size
        try:
            while True:
                time.sleep(1)
                with open(files[-1], encoding="utf-8", errors="replace") as f:
                    f.seek(pos)
                    for line in f:
                        show(line)
                    pos = f.tell()
        except KeyboardInterrupt:
            pass


def cmd_update():
    head("Kit updates")
    if "--rollback" in ARGS:
        v = rollback()
        ok(f"Rolled back to {v}. Run the command again with --rollback to undo.")
        return
    st = update_status(force=True)
    print(f"  This copy: {st['current']}" + ("  (installed)" if st["installed"] else f"  ({HERE})"))
    if st["error"]:
        raise KitError(st["error"])
    if not st["available"]:
        ok(f"Up to date (latest release: {st['latest']})")
        return
    ok(f"Version {st['latest']} is available")
    for line in (st["notes"] or "").splitlines()[:15]:
        info(line)
    if st["git"]:
        info(f"This copy is a git checkout. Update it with: git -C \"{HERE}\" pull")
        return
    if "--check" in ARGS or not yesno(f"Install {st['latest']} now?", True):
        return
    apply_update(fetch_release(), lambda level, msg: (ok if level == "ok" else warn if level == "warn" else info)(msg))
    if not st["installed"]:
        info(f"Installed to {APP_DIR}. Use the 'AI Guard Demo Console' shortcut or `aiguard-kit gui` from now on.")
    info("If the console is open, close it and open it again to use the new version.")


# ---------------------------------------------------------------- scheduler
def ensure_windows_launcher():
    """The email-safe package leaves out aiguard-kit.cmd (mail filters block .cmd), so write it on first run."""
    p = HERE / "aiguard-kit.cmd"
    if WINDOWS and not p.exists():
        try:
            p.write_bytes(WINDOWS_LAUNCHER.replace("\n", "\r\n").encode("ascii"))
            print(f"  Created {p.name}. From now on start the kit with {LAUNCHER} gui")
        except OSError:
            pass


WINDOWS_LAUNCHER = """@echo off
rem Launcher for the AI Guard SE demo kit (Windows). Usage: .\\aiguard-kit.cmd setup|gui|run|status|teardown
rem Find uv even when this terminal was opened before uv was installed.
if exist "%USERPROFILE%\\.local\\bin\\uv.exe" set "PATH=%USERPROFILE%\\.local\\bin;%PATH%"
where uv >nul 2>nul
if errorlevel 1 (
  echo uv is not installed. In PowerShell run:
  echo   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  echo then open a new terminal and run this command again.
  exit /b 1
)
set UV_SYSTEM_CERTS=1
set UV_NATIVE_TLS=1
set PYTHONUTF8=1
rem Python 3.12: every library the kit needs has ready-made builds for it on Windows and Mac.
rem "& exit /b" keeps cmd from reading this file again after the kit exits (an update may have replaced it).
uv run --quiet --python 3.12 --script "%~dp0aiguard_kit.py" %* & exit /b
"""


SCHEDULE_BASE = None  # set by `install` so an existing schedule is re-pointed at the installed copy

# Scheduled jobs. "trickle" is the AI Guard job (names unchanged since 1.x); products add their own.
#   cfg: where the settings live in config.json; file: wrapper/log name; label/task/marker: launchd/schtasks/cron ids
SCHEDULE_JOBS = {
    "trickle": {"cfg": ("schedule",), "file": "trickle", "label": "com.aiguard-se-kit.{p}", "task": "AIGuardSEKit-{p}",
                "marker": "# aiguard-se-kit:{p}", "every": 60, "count": 12, "what": "tests"},
    "zia": {"cfg": ("zia", "schedule"), "file": "zia-traffic", "label": "com.aiguard-se-kit.zia.{p}",
            "task": "AIGuardSEKit-ZIA-{p}", "marker": "# aiguard-se-kit-zia:{p}", "every": 30, "count": 4,
            "what": "requests per traffic type"},
}


def schedule_cmdline(count, job="trickle"):
    exe = (SCHEDULE_BASE or HERE) / ("aiguard-kit.cmd" if WINDOWS else "aiguard-kit")
    if job == "zia":
        return [str(exe), "zia", "traffic", "--count", str(count), "--profile", PROFILE, "--yes"]
    return [str(exe), "run", "--trickle", "--count", str(count), "--profile", PROFILE, "--yes"]


def _job_cfg(cfg_, job, value=None, remove=False):
    path = SCHEDULE_JOBS[job]["cfg"]
    node = cfg_
    for k in path[:-1]:
        node = node.setdefault(k, {})
    if remove:
        node.pop(path[-1], None)
    elif value is not None:
        node[path[-1]] = value
    return node.get(path[-1])


def cmd_schedule(job="trickle"):
    import platform
    import subprocess
    spec = SCHEDULE_JOBS[job]
    action = next((a for a in ARGS if a in ("install", "remove", "status")), "status")
    saved = _job_cfg(load_cfg(), job) or {}
    every = max(15, int(opt("every", str(saved.get("every", spec["every"])))))
    count = int(opt("count", str(saved.get("count", spec["count"]))))
    if action in ("install", "remove"):
        cfg_ = load_cfg()
        _job_cfg(cfg_, job, {"every": every, "count": count}, remove=action == "remove")
        save_cfg(cfg_)
    label = spec["label"].format(p=PROFILE)
    log_file = CFG_DIR / f"{spec['file']}.log"
    system = platform.system()
    head(f"Scheduled {'ZIA traffic' if job == 'zia' else 'traffic'} ({system})")
    if system == "Darwin":
        import plistlib
        plist = HOME / "Library/LaunchAgents" / f"{label}.plist"
        dom = f"gui/{os.getuid()}"
        if action == "install":
            CFG_DIR.mkdir(parents=True, exist_ok=True)
            plist.parent.mkdir(parents=True, exist_ok=True)
            plist.write_bytes(plistlib.dumps({
                "Label": label, "ProgramArguments": schedule_cmdline(count, job), "StartInterval": every * 60,
                "RunAtLoad": False, "StandardOutPath": str(log_file),
                "StandardErrorPath": str(log_file),
                "EnvironmentVariables": {"PATH": f"{HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
                                         "NO_COLOR": "1"}}))
            subprocess.run(["launchctl", "bootout", dom, str(plist)], capture_output=True)
            r = subprocess.run(["launchctl", "bootstrap", dom, str(plist)], capture_output=True, text=True)
            if r.returncode:
                raise KitError(f"launchctl couldn't load the job: {r.stderr.strip()}")
            ok(f"Installed: {count} {spec['what']} every {every} minutes. Log: {log_file}")
            if job == "trickle":
                info("The first run may ask for keychain access. Choose 'Always Allow' so later runs work unattended.")
        elif action == "remove":
            subprocess.run(["launchctl", "bootout", dom, str(plist)], capture_output=True)
            plist.unlink(missing_ok=True)
            ok("Removed")
        else:
            r = subprocess.run(["launchctl", "print", f"{dom}/{label}"], capture_output=True, text=True)
            (ok if r.returncode == 0 else info)("Installed and loaded" if r.returncode == 0 else "Not installed")
    elif system == "Windows":
        name = spec["task"].format(p=PROFILE)
        wrapper = CFG_DIR / f"{spec['file']}.cmd"
        if action == "install":
            ensure_windows_launcher()
            CFG_DIR.mkdir(parents=True, exist_ok=True)
            # schtasks limits /TR to 261 characters and doesn't capture output, so run a small wrapper that logs
            cmdline = " ".join(f'"{x}"' for x in schedule_cmdline(count, job))
            wrapper.write_bytes((f'@echo off\r\nset NO_COLOR=1\r\ncd /d "{SCHEDULE_BASE or HERE}"\r\n'
                                 f'call {cmdline} >> "{log_file}" 2>&1\r\n').encode("utf-8"))
            tr = f'"{wrapper}"'
            r = subprocess.run(["schtasks", "/Create", "/F", "/SC", "MINUTE", "/MO", str(every), "/TN", name, "/TR", tr],
                               capture_output=True, text=True)
            if r.returncode:
                raise KitError(f"schtasks failed: {r.stderr.strip() or r.stdout.strip()}")
            ok(f"Installed task '{name}': {count} {spec['what']} every {every} minutes. Log: {log_file}")
            info("It runs only while you're signed in to Windows.")
        elif action == "remove":
            subprocess.run(["schtasks", "/Delete", "/F", "/TN", name], capture_output=True)
            wrapper.unlink(missing_ok=True)
            ok("Removed")
        else:
            r = subprocess.run(["schtasks", "/Query", "/TN", name], capture_output=True, text=True)
            (ok if r.returncode == 0 else info)("Installed" if r.returncode == 0 else "Not installed")
    else:
        marker = spec["marker"].format(p=PROFILE)
        cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
        lines = [x for x in cur.splitlines() if marker not in x]
        if action == "install":
            when = f"*/{every} * * * *" if every < 60 else f"0 */{max(1, every // 60)} * * *"
            cmd = " ".join(schedule_cmdline(count, job))
            lines.append(f"{when} {cmd} >> {log_file} 2>&1 {marker}")
        if action in ("install", "remove"):
            subprocess.run(["crontab", "-"], input="\n".join(lines) + "\n", text=True, check=True)
            ok("Installed" if action == "install" else "Removed")
        else:
            (ok if marker in cur else info)("Installed" if marker in cur else "Not installed")


# ---------------------------------------------------------------- install (double-click installers)
APP_NAME = "AI Guard Demo Console"
CLI_NAME = "aiguard-kit"                        # the command install puts on PATH (Mac/Linux wrapper name)
UNINSTALL_LNK = "Uninstall AI Guard Demo Kit.lnk"
INSTALL_FILES = ["aiguard-kit", "aiguard-kit.cmd", "aiguard_kit.py", "gui.html", "tests.json", "packs", "policy_template.json",
                 "preflight_help.json", "README.md", "PREFLIGHT.md", "SECURITY.md", "CHANGELOG.md", "WINDOWS.md",
                 "INSTALL.md", "Uninstall AI Guard Kit.cmd", "Uninstall AI Guard Kit.command",
                 "zia_module.py", "zia_traffic.py", "zia_aws.py", "zia_policy_template.json", "zia_traffic.json", "ZIA.md",
                 "CHANGELOG-ZIA.md", "edition.json", "zia-kit", "zia-kit.cmd"]


def _install_files():
    skip = ({"aiguard-kit", "zia-kit", "Uninstall AI Guard Kit.command"} if WINDOWS else
            {"aiguard-kit.cmd", "zia-kit.cmd", "Uninstall AI Guard Kit.cmd"})
    return [f for f in INSTALL_FILES if f not in skip and (HERE / f).exists()]


def copy_kit(dest):
    """Copy the kit into dest via a staging folder, keeping the previous copy as dest.previous for rollback."""
    import shutil
    stage, prev = dest.with_name(dest.name + ".new"), dest.with_name(dest.name + ".previous")
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    for f in _install_files():
        src = HERE / f
        if src.is_dir():
            shutil.copytree(src, stage / f, ignore=shutil.ignore_patterns("__pycache__"))
        else:
            shutil.copy2(src, stage / f)
    for f in ("aiguard-kit", "zia-kit", "Uninstall AI Guard Kit.command"):
        if (stage / f).exists():
            os.chmod(stage / f, 0o755)
    if dest.exists():
        shutil.rmtree(prev, ignore_errors=True)
        try:
            dest.rename(prev)
        except OSError:  # Windows: a folder in use can't be renamed, so copy over it instead
            shutil.copytree(stage, dest, dirs_exist_ok=True)
            shutil.rmtree(stage, ignore_errors=True)
            return
    stage.rename(dest)


def _desktop_dir():
    if WINDOWS:
        import subprocess
        r = subprocess.run(["powershell", "-NoProfile", "-Command", "[Environment]::GetFolderPath('Desktop')"],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return Path(r.stdout.strip())
    return HOME / "Desktop"


def _win_shortcut(path, target, args, workdir, description):
    import subprocess
    ps = ("$ErrorActionPreference='Stop'; try { "
          "$s=(New-Object -ComObject WScript.Shell).CreateShortcut($env:AIGK_LNK); $s.TargetPath=$env:AIGK_TGT; "
          "$s.Arguments=$env:AIGK_ARGS; $s.WorkingDirectory=$env:AIGK_WD; $s.Description=$env:AIGK_DESC; $s.Save(); "
          "if (-not (Test-Path -LiteralPath $env:AIGK_LNK)) { throw 'the shortcut file was not written' } "
          "} catch { [Console]::Out.WriteLine('ERR: ' + $_.Exception.Message); exit 1 }")
    env = {**os.environ, "AIGK_LNK": str(path), "AIGK_TGT": str(target), "AIGK_ARGS": args, "AIGK_WD": str(workdir),
           "AIGK_DESC": description}
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps],
                           capture_output=True, text=True, env=env, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise KitError(f"Couldn't create the shortcut {path.name}: {e}") from e
    if r.returncode:
        why = (r.stdout + r.stderr).strip().replace("ERR: ", "")[:300] or f"PowerShell exit code {r.returncode}"
        raise KitError(f"Couldn't create the shortcut {path.name}: {why}")


def shortcut_paths():
    """Where install puts shortcuts and the command-line wrapper, per OS."""
    if WINDOWS:
        menu_dir = Path(os.getenv("APPDATA", HOME)) / "Microsoft/Windows/Start Menu/Programs"
        return {"desktop": _desktop_dir() / f"{APP_NAME}.lnk", "start": menu_dir / f"{APP_NAME}.lnk",
                "start_uninstall": menu_dir / UNINSTALL_LNK}
    return {"desktop": HOME / "Desktop" / f"{APP_NAME}.command", "wrapper": HOME / ".local/bin" / CLI_NAME}


def _win_user_path(add=None, remove=None):
    """Read or change the user's PATH (HKCU\\Environment). Returns the entries."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
        try:
            val, kind = winreg.QueryValueEx(k, "Path")
        except FileNotFoundError:
            val, kind = "", winreg.REG_EXPAND_SZ
        parts = [p for p in val.split(";") if p]
        norm = lambda p: os.path.normcase(os.path.normpath(os.path.expandvars(p)))  # noqa: E731
        new = parts
        if add and norm(add) not in {norm(p) for p in parts}:
            new = parts + [add]
        if remove:
            new = [p for p in new if norm(p) != norm(remove)]
        if new != parts:
            winreg.SetValueEx(k, "Path", 0, kind, ";".join(new))
            try:  # tell Explorer so new terminals see the change
                import ctypes
                ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 2, 5000, None)
            except Exception:
                pass
        return new


def schedule_installed():
    return job_installed("trickle")


def job_installed(job):
    import platform
    import subprocess
    spec = SCHEDULE_JOBS[job]
    system = platform.system()
    try:
        if system == "Darwin":
            return (HOME / "Library/LaunchAgents" / f"{spec['label'].format(p=PROFILE)}.plist").exists()
        if system == "Windows":
            return subprocess.run(["schtasks", "/Query", "/TN", spec["task"].format(p=PROFILE)],
                                  capture_output=True).returncode == 0
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        return spec["marker"].format(p=PROFILE) in r.stdout
    except OSError:  # no crontab / schtasks on this machine
        return False


def cmd_install():
    global SCHEDULE_BASE
    head(f"Installing the {kit_name()} {VERSION}")
    here_is_app = HERE.resolve() == APP_DIR.resolve() if APP_DIR.exists() else False
    if not here_is_app:
        copy_kit(APP_DIR)
        ok(f"Kit copied to {APP_DIR}")
    else:
        ok(f"Kit already in {APP_DIR}; refreshing shortcuts")
    sp = shortcut_paths()
    if WINDOWS:
        launcher = APP_DIR / "aiguard-kit.cmd"
        for key, args, desc in (("desktop", "gui", "Open the AI Guard demo console"),
                                ("start", "gui", "Open the AI Guard demo console")):
            try:
                sp[key].parent.mkdir(parents=True, exist_ok=True)
                _win_shortcut(sp[key], launcher, args, HOME, desc)
                ok(f"Shortcut: {sp[key]}")
            except KitError as e:
                warn(str(e))
        try:
            _win_shortcut(sp["start_uninstall"], APP_DIR / "Uninstall AI Guard Kit.cmd", "", APP_DIR, "Remove the AI Guard demo kit")
        except KitError as e:
            vlog(str(e))
        try:
            _win_user_path(add=str(APP_DIR))
            ok(f"Added to your PATH: in a new terminal, run  {CLI_NAME} gui  from any folder")
        except Exception as e:
            warn(f"Couldn't add the kit to your PATH ({e}). Use the desktop shortcut, or {APP_DIR / 'aiguard-kit.cmd'}")
    else:
        sp["desktop"].parent.mkdir(parents=True, exist_ok=True)
        sp["desktop"].write_text(f'#!/bin/bash\n# Opens the AI Guard demo console. Close this window to stop it.\n'
                                 f'exec "{APP_DIR / "aiguard-kit"}" gui\n', encoding="utf-8")
        os.chmod(sp["desktop"], 0o755)
        ok(f"Shortcut: {sp['desktop']} (double-click to open the console)")
        sp["wrapper"].parent.mkdir(parents=True, exist_ok=True)
        sp["wrapper"].write_text(f'#!/bin/bash\nexec "{APP_DIR / "aiguard-kit"}" "$@"\n', encoding="utf-8")
        os.chmod(sp["wrapper"], 0o755)
        on_path = str(sp["wrapper"].parent) in os.getenv("PATH", "").split(os.pathsep)
        ok(f"Command: {CLI_NAME} (from any folder" + (")" if on_path else "; open a new terminal first)"))
    global ARGS
    for job in sorted(SCHEDULE_JOBS, key=lambda j: j == "trickle"):   # the AI Guard job last
        if schedule_installed() if job == "trickle" else job_installed(job):
            SCHEDULE_BASE = APP_DIR
            ARGS = ["schedule", "install"]
            again = "aiguard-kit zia schedule install" if job == "zia" else "aiguard-kit schedule install"
            try:
                cmd_schedule(job)
                ok(f"Scheduled {'ZIA traffic' if job == 'zia' else 'traffic'} now runs from the installed copy")
            except Exception as e:
                warn(f"Couldn't re-point scheduled traffic ({e}). Run: {again}")
    info(f"Settings and keys stay in {BASE_DIR} and the system keychain (unchanged).")
    ok(f"Installed. Open '{APP_NAME}' on your desktop, or run: {CLI_NAME} gui")


def cmd_uninstall():
    import shutil
    head(f"Uninstall the {kit_name()}")
    print("  Removes the installed kit, its shortcuts and its PATH entry, and stops scheduled traffic.")
    print("  Keeps your settings, keys and the demo objects in your tenant.")
    print(f"  {C['d']}To remove the tenant objects too, run  aiguard-kit teardown  first.{C['x']}")
    if not yesno("Uninstall now?", True):
        print("  Cancelled.")
        return
    global ARGS
    for job in SCHEDULE_JOBS:
        if schedule_installed() if job == "trickle" else job_installed(job):
            ARGS = ["schedule", "remove"]
            cmd_schedule(job)
    sp = shortcut_paths()
    for key in ("desktop", "start", "start_uninstall", "wrapper"):
        p = sp.get(key)
        if p and p.exists():
            p.unlink()
            ok(f"Removed {p}")
    if WINDOWS:
        try:
            _win_user_path(remove=str(APP_DIR))
            ok("Removed from your PATH")
        except Exception as e:
            vlog(f"PATH: {e}")
    for d in (APP_DIR.with_name(APP_DIR.name + ".previous"), APP_DIR.with_name(APP_DIR.name + ".new")):
        shutil.rmtree(d, ignore_errors=True)
    if APP_DIR.exists():
        if WINDOWS and HERE.resolve() == APP_DIR.resolve():
            import subprocess  # this launcher is still running from the folder, so remove it a moment after we exit
            subprocess.Popen(f'cmd /c ping -n 3 127.0.0.1 >nul & rmdir /s /q "{APP_DIR}"', shell=True,
                             creationflags=0x00000008 | 0x00000200)  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            shutil.rmtree(APP_DIR, ignore_errors=True)
        ok(f"Removed {APP_DIR}")
    ok("Uninstalled. To set it up again later, run the installer.")


# ---------------------------------------------------------------- setup
def import_claude_desktop():
    p = (Path(os.getenv("APPDATA", HOME)) / "Claude/claude_desktop_config.json" if WINDOWS
         else HOME / "Library/Application Support/Claude/claude_desktop_config.json")
    try:
        servers = json.loads(p.read_text(encoding="utf-8"))["mcpServers"]
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
        body = json.loads((HERE / "policy_template.json").read_text(encoding="utf-8"))
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
            if not c["id"].startswith(("drift-", "ready-", "gen-")):   # those explain themselves; no PREFLIGHT.md entry
                print(f"      {C['d']}Details: {HERE / 'PREFLIGHT.md'}#{help_id(c['id'])}{C['x']}")
        elif c["fix"] and c["status"] == "info":
            print(f"      {C['d']}{c['fix']}{C['x']}")


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
                     f"({PROFILES[ALIASES.get(ans.get('mode', 'monitor'), ans.get('mode', 'monitor'))].split(':')[0]}; "
                     f"competitor '{ans.get('competitor')}')")
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
    return {"existing": "keep", "policy": "create", "mode": "monitor", "competitor": facts["competitor"],
            "providers": {k: {"key": None, "model": v["model"], "cred_id": v["creds"][0]["id"] if v["creds"] else None}
                          for k, v in facts["providers"].items()}}


def kit_app_credentials(t, cfg=None):
    """All app credentials the kit may own. The list API omits DETECTIONS-mode keys, so this also follows the
    credential ids referenced by the kit's rules and saved state, and fetches each one."""
    found = {c["id"]: c for c in t.list("llm_application_credentials") if is_mine(c)}
    ids = set()
    for r in t.list("policy_match_rules"):
        if is_mine(r):
            for a in (r.get("matchCriteria") or {}).get("llmApplications") or []:
                ids.update(a.get("applicationCredentialsIds") or [])
    for a in ((cfg or {}).get("state") or {}).get("apps", {}).values():
        ids.update(x for x in (a.get("das_cred_id"), a.get("proxy_cred_id")) if x)
    st_ = (cfg or {}).get("state") or {}
    ids.update(st_.get("retire_own", []) + st_.get("retire", []))
    for cid in ids - set(found):
        try:
            c = t.call("llm_application_credentials", "get_credential", cid)
            if c and is_mine(c):
                found[cid] = c
        except Exception as e:
            if not re.search(r"404|not.?found", str(e), re.I):
                raise  # a network or permission problem must not look like a deleted key
            vlog(f"credential {cid}: gone")
    return found


def _machine():
    import platform
    return re.sub(r"[^A-Za-z0-9-]", "-", platform.node().split(".")[0])[:24] or "this-computer"


def create_app_key(t, cfg, log, label, kind, **fields):
    """Creates a kit app credential. The name includes this computer's name, so several computers can each keep
    their own key in one tenant; if the name is taken (e.g. after a reinstall), a timestamp is added."""
    base = f"{PREFIX}: {label} {kind} key"
    name = f"{base} ({_machine()})"
    taken = {c.get("name") for c in kit_app_credentials(t, cfg).values()}
    if name in taken:
        name = f"{name} {time.strftime('%Y%m%d-%H%M%S')}"
    try:
        return t.call("llm_application_credentials", "add_credential", name=name, **fields)
    except KitError as e:
        if "409" not in str(e) and "already_exists" not in str(e):
            raise
        return t.call("llm_application_credentials", "add_credential", name=f"{base} ({_machine()}) "
                      f"{time.strftime('%Y%m%d-%H%M%S')}", **fields)


def retire_old_keys(t, cfg, log):
    """Deletes keys this computer created earlier and can no longer use (its own state recorded them)."""
    st = cfg["state"]
    for cid in list(st.get("retire_own", [])):
        try:
            t.call("llm_application_credentials", "delete_credential", cid)
            log("ok", f"Removed this computer's old key (id {cid}), which it could no longer use")
        except Exception as e:
            if not re.search(r"404|not.?found", str(e), re.I):
                log("warn", f"Couldn't remove old key {cid} yet: {str(e)[:120]}")
                continue
        st["retire_own"].remove(cid)
    save_cfg(cfg)


SETUP_SCHEMA = 1  # bump when a release changes what setup creates; older setups are then flagged for repair


def saved_answers(ans):
    """The setup choices without secrets, so Repair can rebuild what the SE chose."""
    keep = {k: v for k, v in ans.items() if k in ("policy", "mode", "competitor")}
    keep["providers"] = {p: {k: v for k, v in (c or {}).items() if k in ("model", "cred_id")}
                         for p, c in (ans.get("providers") or {}).items()}
    return keep


def setup_apply(t, cfg, ans, log):
    """Creates or fills in everything for the answers given. Safe to run again after a failure."""
    cfg.setdefault("state", {"apps": {}})
    st = cfg["state"]
    if ans.get("mode") != "keep":
        cfg["answers"] = saved_answers(ans)
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
            mode = ALIASES.get(ans.get("mode", "monitor"), ans.get("mode", "monitor"))
            if mode == "keep":
                pass  # repair: leave whatever policy profile the SE has switched to
            elif policy_mode(t, cfg)[0] != mode:
                policy_mode(t, cfg, mode)
                log("ok", f"Policy set to {PROFILES[mode].split(':')[0]}")
        else:
            body = json.loads((HERE / "policy_template.json").read_text(encoding="utf-8").replace("{COMPETITOR}", cfg["competitor"]))
            if ans.get("mode") == "keep":
                ans = dict(ans, mode=st.get("policy_mode") or "monitor")
            apply_mode(body, ans.get("mode", "detect"))
            body["name"] = pname
            p = t.call("policies", "add_policy", **body)
            st["policy_id"], st["policy_mode"] = p["id"], ALIASES.get(ans.get("mode", "monitor"), ans.get("mode", "monitor"))
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
    st.pop("retire", None)  # 1.5.x marked other computers' keys for deletion; never do that
    alive = kit_app_credentials(t, cfg)  # every kit key in AI Guard, including ones the list API hides
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
        for credkey, kind in (("das_cred_id", "detection"), ("proxy_cred_id", "proxy")):
            cid = a.get(credkey)
            if cid and (cid not in alive or alive[cid].get("applicationId") not in (None, a["id"])):
                log("info", f"{label}: this computer's saved {kind} key (id {cid}) no longer exists in AI Guard "
                            f"(it may have been removed by setup or teardown on another computer); creating a new one")
                a.pop(credkey, None)
            elif cid and not kc_get(f"{app_name}:{'detections' if kind == 'detection' else 'proxy'}"):
                st.setdefault("retire_own", [])
                st["retire_own"] = sorted(set(st["retire_own"]) | {cid})  # ours, but its secret is gone
                a.pop(credkey, None)
        if not (a.get("das_cred_id") and kc_get(f"{app_name}:detections")):
            cred = create_app_key(t, cfg, log, label, "detection", applicationId=a["id"], mode="DETECTIONS")
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
            cfg.setdefault("answers", {}).setdefault("providers", {}).setdefault(ptype, {})["cred_id"] = pc_id
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
        cred = create_app_key(t, cfg, log, label, "proxy", applicationId=a["id"], providerId=prov["id"],
                              providerCredentialsId=pc_id, mode="PROXY")
        kc_set(f"{app_name}:proxy", cred["key"])
        a["proxy_cred_id"], a["provider_cred_id"] = cred["id"], pc_id
        log("ok", f"{label}: proxy key created and saved to your keychain")
        save_cfg(cfg)

    log("head", "Policy rules")
    rules = t.list("policy_match_rules")
    order = max([r.get("ruleOrder", 0) for r in rules if not is_mine(r)] + [0])
    alive = kit_app_credentials(t, cfg)
    drop = set(st.get("retire_own", []))
    for kind, rtype, credkey in (("detection", "DAS_APPLICATION", "das_cred_id"), ("proxy", "APPLICATION", "proxy_cred_id")):
        rname = f"{PREFIX}: {kind} apps"
        existing = next((r for r in rules if r.get("name") == rname), None)
        others = {}  # keys other computers added to this rule, still present in AI Guard
        if existing:
            mc = existing.get("matchCriteria") or t.call("policy_match_rules", "get_rule", existing["id"]).get("matchCriteria") or {}
            for e in mc.get("llmApplications") or []:
                others[e.get("applicationId")] = [i for i in e.get("applicationCredentialsIds") or []
                                                  if i in alive and i not in drop]
        entries = []
        for a in st["apps"].values():
            if a.get(credkey):
                ids = [a[credkey]] + [i for i in others.get(a["id"], []) if i != a[credkey]]
                entries.append({"applicationId": a["id"], "applicationCredentialsIds": ids})
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
    st["schema"] = SETUP_SCHEMA
    save_cfg(cfg)
    if st.get("retire_own"):
        retire_old_keys(t, cfg, log)   # only now: the rules no longer point at them


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
            names = list(PROFILES)
            ans["mode"] = names[menu("Start with:", [PROFILES[n] for n in names])]
            info("You can change this any time from the console's Policy menu or ./aiguard-kit policy.")
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
    creds = kit_app_credentials(t, cfg)   # includes DETECTIONS keys, which the list API omits
    found = {r: ([o for o in t.list(r) if str(o.get("name", "")).startswith(pre)] if r != "llm_application_credentials"
                 else list(creds.values())) for r in
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
            info(f"Policy: {PROFILES.get(mode, 'custom')}")
        except Exception as e:
            vlog(str(e))
    behind = update_check()
    if behind:
        warn(f"A newer kit is available ({behind} change{'s' if behind > 1 else ''}). Update with: git -C {HERE} pull")
    elif not (HERE / ".git").exists():
        u = update_status()
        if u["available"]:
            warn(f"Version {u['latest']} is available. Update with: aiguard-kit update")
        elif u["error"]:
            info(f"Couldn't check for updates: {u['error']}")
        else:
            ok(f"Kit {VERSION} is the latest release")
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
        r = run_one(cfg, t, app, user, mode, tags="--tags" in ARGS)
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


# ---------------------------------------------------------------- health check and repair
def health(t, cfg):
    """Read-only: is this computer's demo setup still intact in the tenant? Returns {set_up, ok, problems}."""
    st = cfg.get("state") or {}
    if not st.get("apps"):
        return {"set_up": False, "ok": True, "problems": []}
    problems = []
    add = lambda msg: problems.append(msg)  # noqa: E731
    if st.get("schema", 1) < SETUP_SCHEMA:
        add("This version of the kit changes what setup creates.")
    if st.get("policy_id") and st["policy_id"] not in {p["id"] for p in t.list("policies")}:
        add("The demo policy no longer exists in AI Guard.")
    app_ids = {a["id"] for a in t.list("llm_applications")}
    alive = kit_app_credentials(t, cfg)
    rules = {r.get("name"): r for r in t.list("policy_match_rules")}
    for app_name, a in st["apps"].items():
        label = app_name.split(": ", 1)[-1]
        if a.get("id") not in app_ids:
            add(f"{label}: the app no longer exists in AI Guard.")
            continue
        for credkey, kind, kc_name in (("das_cred_id", "detection", "detections"), ("proxy_cred_id", "proxy", "proxy")):
            cid = a.get(credkey)
            if not cid:
                if kind == "detection":
                    add(f"{label}: this computer has no detection key.")
                continue
            if cid not in alive:
                add(f"{label}: this computer's {kind} key was removed from AI Guard (for example by setup or teardown "
                    f"on another computer).")
                continue
            if not kc_has(f"{app_name}:{kc_name}"):
                add(f"{label}: the {kind} key's secret is missing from this computer's keychain.")
                continue
            rule = rules.get(f"{PREFIX}: {kind} apps")
            in_rule = {i for e in ((rule or {}).get("matchCriteria") or {}).get("llmApplications") or []
                       for i in e.get("applicationCredentialsIds") or []}
            if cid not in in_rule:
                add(f"{label}: this computer's {kind} key isn't in the rule '{PREFIX}: {kind} apps', so AI Guard "
                    f"won't apply the demo policy to it.")
    out = {"set_up": True, "ok": not problems, "problems": problems}
    activity("setup", "Health check: " + ("all good" if not problems else f"{len(problems)} problem(s)"),
             "ok" if not problems else "warn", problems=problems)
    return out


def repair(t, cfg, log):
    """Re-runs setup with the saved choices: fills in what's missing, keeps the policy profile, never removes the
    demo or touches other computers' keys."""
    facts = tenant_facts(t, cfg)
    ans = default_answers(facts)
    saved = cfg.get("answers") or {}
    ans.update({k: v for k, v in saved.items() if k != "providers"})
    for p, c in (saved.get("providers") or {}).items():
        ans["providers"].setdefault(p, {}).update(c)
    if ans.get("policy") not in (None, "create") and str(ans["policy"]) not in {str(p["id"]) for p in t.list("policies")}:
        ans["policy"] = "create"
    ans.update(existing="keep", mode="keep")
    activity("setup", "Repair started", "info")
    setup_apply(t, cfg, ans, log)
    log("head", "Verifying")
    return verify(cfg, log)


def cmd_repair():
    head("Checking this computer's demo setup")
    cfg = load_cfg()
    t = connect(cfg)
    h = health(t, cfg)
    if not h["set_up"]:
        raise KitError("Not set up yet. Run ./aiguard-kit setup")
    if h["ok"] and "--force" not in ARGS:
        ok("Everything is in place. Nothing to repair.")
        return
    for p in h["problems"]:
        warn(p)
    if not yesno("Repair now? (fills in what's missing; your policy profile and other computers' keys are kept)", True):
        return
    repair(t, cfg, lambda level, msg: (head if level == "head" else ok if level == "ok" else warn if level in ("warn", "fail")
                                       else info)(msg))


# ---------------------------------------------------------------- GUI server
JOBS: dict = {}
SERVER: dict = {}


def restart_console(srv, port):
    """Reopen the console from the installed copy (after an update), on the same port when possible."""
    import subprocess
    launcher = APP_DIR / ("aiguard-kit.cmd" if WINDOWS else "aiguard-kit")
    args = ["gui", "--port", str(port), "--restarted"] + (["--profile", PROFILE] if PROFILE != "default" else [])
    try:
        srv.socket.close()  # free the port for the new console
    except OSError:
        pass
    if WINDOWS:
        subprocess.Popen(["cmd", "/c", "start", APP_NAME, str(launcher), *args], cwd=str(HOME))
        os._exit(0)
    os.execv("/bin/bash", ["bash", str(launcher), *args])


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

    zia_cache = {}

    def zia_tenant(c):   # separate from the AI Guard connection: a ZIA-only machine never needs AI Guard access
        key = (c.get("client_id"), c.get("vanity_domain"))
        if key not in zia_cache:
            zia_cache.clear()
            zia_cache[key] = product("zia").connect(c)
        return zia_cache[key]
    port = int(opt("port", "8765"))

    if WINDOWS:  # on Windows SO_REUSEADDR lets a second console silently share the port
        ThreadingHTTPServer.allow_reuse_address = False

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            if VERBOSE:
                super().log_message(*a)

        def _send(self, code, obj=None, ctype="application/json", raw=None):
            data = raw if raw is not None else json.dumps(obj).replace("./aiguard-kit", json.dumps(LAUNCHER)[1:-1]).encode()
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
                    return self._send(200, policy_details(tenant(c), c))
                except Exception as e:
                    return self._send(200, {"mode": None, "error": str(e), "fix": hint(e)})
            if path == "/api/state":
                c = load_cfg()
                lib = load_tests()
                apps = [{"name": n, "label": n.split(": ", 1)[-1], "provider": a.get("provider_type"),
                         "model": a.get("model"), "detect": kc_has(f"{n}:detections"),
                         "proxy": bool(a.get("proxy_cred_id")) and kc_has(f"{n}:proxy")}
                        for n, a in c.get("state", {}).get("apps", {}).items()]
                return self._send(200, {"tenant": c.get("vanity_domain"), "version": VERSION, "apps": apps,
                                        "policy_id": c.get("state", {}).get("policy_id"), "console": CONSOLE,
                                        "lib": lib, "panels": PANELS, "prefix": PREFIX,
                                        "competitor": c.get("competitor", "Palo Alto"), "profile": PROFILE,
                                        "update_behind": _UPDATE["behind"], "kit_dir": str(HERE),
                                        "edition": (EDITION or {}).get("product"),
                                        "edition_name": (EDITION or {}).get("name"),
                                        "app_name": (EDITION or {}).get("app_name")})
            if path == "/api/update":
                return self._send(200, update_status(force="force=1" in self.path))
            if path == "/api/health":
                c = load_cfg()
                try:
                    return self._send(200, health(tenant(c), c))
                except Exception as e:
                    return self._send(200, {"set_up": bool(c.get("state", {}).get("apps")), "ok": None,
                                            "error": str(e), "fix": hint(e), "problems": []})
            if path == "/api/logs":
                q = dict(x.split("=", 1) for x in (self.path.split("?", 1)[1:] or [""])[0].split("&") if "=" in x)
                since = int(q.get("since", 0) or 0)
                with _ACT_LOCK:
                    items = [e for e in ACTIVITY if e["seq"] > since][-500:]
                return self._send(200, {"items": items, "dir": str(LOG_DIR)})
            if path == "/api/diagnostics":
                data = diagnostics_zip()
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="aiguard-kit-diagnostics-{time.strftime("%Y%m%d-%H%M")}.zip"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                activity("setup", "Diagnostics downloaded", "info")
                return
            if path.startswith("/api/zia/"):
                c = load_cfg()
                try:
                    out = product("zia").api_get(path, c, lambda: zia_tenant(c))
                except Exception as e:
                    return self._send(200, {"error": str(e), "fix": product("zia").zhint(e)})
                return self._send(200, out) if out is not None else self._send(404, {"error": "not found"})
            if path == "/api/job":
                q = dict(x.split("=", 1) for x in (self.path.split("?", 1)[1:] or [""])[0].split("&") if "=" in x)
                j = JOBS.get(q.get("id"))
                if not j:
                    return self._send(404, {"error": "no such job"})
                since = int(q.get("since", 0))
                return self._send(200, {"done": j["done"], "total": j["total"], "results": j["results"][since:],
                                        "verify": j.get("verify"), "error": j.get("error"), "help": j.get("help"),
                                        "plan": j.get("plan"), "notes": j.get("notes")})
            if path == "/api/setup/state":
                c = load_cfg()
                return self._send(200, {"vanity": c.get("vanity_domain", ""), "client_id": mask(c.get("client_id", "")),
                                        "saved": bool(c.get("client_id")) and kc_has("oneapi-client-secret"),
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
            if path == "/api/repair":
                try:
                    t = tenant(c)
                except Exception as e:
                    return self._send(400, {"error": str(e), "fix": hint(e)})
                jid = uuid.uuid4().hex[:8]
                job = JOBS[jid] = {"done": False, "stop": False, "total": 0, "results": []}

                def rlog(level, msg):
                    job["results"].append({"level": level, "msg": msg})
                    if level != "head":
                        activity("setup", msg, {"fail": "error"}.get(level, level))

                def repair_work():
                    try:
                        job["verify"] = repair(t, load_cfg(), rlog)
                    except Exception as e:
                        job["error"] = {"error": str(e), "fix": hint(e)}
                        rlog("fail", str(e))
                    job["done"] = True
                threading.Thread(target=repair_work, daemon=True).start()
                return self._send(200, {"id": jid})
            if path == "/api/update/apply":
                jid = uuid.uuid4().hex[:8]
                job = JOBS[jid] = {"done": False, "stop": False, "total": 0, "results": []}
                def ulog(level, msg):
                    job["results"].append({"level": level, "msg": msg})
                    activity("update", msg, {"fail": "error"}.get(level, level))

                def update_work():
                    try:
                        apply_update(fetch_release(force=True), ulog)
                        job["verify"] = {"restart": True}
                    except Exception as e:
                        job["error"] = {"error": str(e), "fix": ""}
                        ulog("fail", str(e))
                    job["done"] = True
                threading.Thread(target=update_work, daemon=True).start()
                return self._send(200, {"job": jid})
            if path == "/api/update/rollback":
                try:
                    return self._send(200, {"ok": True, "version": rollback()})
                except Exception as e:
                    return self._send(400, {"error": str(e)})
            if path == "/api/update/restart":
                if not (APP_DIR / "aiguard_kit.py").exists():
                    return self._send(400, {"error": "The kit isn't installed, so there's nothing to restart into."})
                self._send(200, {"ok": True})
                threading.Timer(0.5, restart_console, args=(SERVER["srv"], SERVER["port"])).start()
                return
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
                def log(level, msg):
                    job["results"].append({"level": level, "msg": msg})
                    if level != "head":
                        activity("setup", msg, {"fail": "error"}.get(level, level))
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
            if path == "/api/zia/password":   # answered directly, never through a job log
                return self._send(200, product("zia").api_password(c))
            if path == "/api/zia/aws":
                try:
                    return self._send(200, product("zia").api_aws(c, body, lambda: zia_tenant(c)))
                except Exception as e:
                    return self._send(400, {"error": str(e), "fix": product("zia").zhint(e)})
            if path.startswith("/api/zia/"):
                if path.endswith("teardown") and body.get("confirm") != "DELETE":
                    return self._send(400, {"error": "Type DELETE to confirm."})
                jid = uuid.uuid4().hex[:8]
                job = JOBS[jid] = {"done": False, "stop": False, "total": 0, "results": []}
                zlog = lambda level, msg: job["results"].append({"level": level, "msg": msg})  # noqa: E731

                def zia_work():
                    try:
                        if not product("zia").api_job(path, body, load_cfg(), lambda: zia_tenant(load_cfg()), zlog, job):
                            job["error"] = {"error": "not found", "fix": ""}
                    except Exception as e:
                        job["error"] = {"error": str(e), "fix": product("zia").zhint(e)}
                        zlog("fail", f"{e}")
                    job["done"] = True

                threading.Thread(target=zia_work, daemon=True).start()
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
                        JOBS[jid]["results"].append(run_one(c, t, app, user, body.get("mode", "detect"),
                                                            tags=bool(body.get("tags"))))
                        time.sleep(0.15)
                    JOBS[jid]["done"] = True

                threading.Thread(target=work, daemon=True).start()
                return self._send(200, {"id": jid, "total": len(jobs)})
            if path == "/api/policy":
                try:
                    policy_mode(tenant(c), c, body.get("custom") or body.get("mode"))
                    activity("policy", f"Policy switched to {body.get('mode') or 'custom'}", "ok",
                             custom=body.get("custom"))
                    return self._send(200, policy_details(tenant(c), c))
                except Exception as e:
                    activity("policy", f"Policy switch failed: {e}", "error")
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
                                               body.get("mode", "detect"), tags=bool(body.get("tags"))))
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
    SERVER.update(srv=srv, port=port)
    prune_logs()
    activity("setup", f"Console started (kit {VERSION}, profile {PROFILE})", "info")
    url = f"http://127.0.0.1:{port}/"
    head("AI Guard test console")
    print(f"  {url}   (this machine only - press Ctrl+C to stop)")
    if not cfg.get("state", {}).get("apps"):
        info("Not set up yet: the console opens on its Setup tab.")
    # after an update restart, the open browser tab reconnects by itself when the port is unchanged
    reconnects = "--restarted" in ARGS and str(port) == opt("port", "")
    if "--no-browser" not in ARGS and not reconnects:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")


# ---------------------------------------------------------------- editions
# A release zip may carry edition.json (the ZIA kit does; the AI Guard kit doesn't). It gives that edition its own
# version, install folder, shortcut, command name and update channel, so editions never replace each other.
# Credentials, keychain and settings stay shared in ~/.aiguard-se-kit.
EDITION = None
EDITION_COMMANDS = {"zia": {"setup", "preflight", "status", "teardown", "dashboards", "password", "aws", "check",
                            "traffic", "schedule"}}


def kit_name():
    return (EDITION or {}).get("name") or "AI Guard SE demo kit"


def apply_edition(path):
    global EDITION, VERSION, APP_DIR, APP_NAME, CLI_NAME, UNINSTALL_LNK, UPDATE_URL
    try:
        e = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    EDITION = e
    VERSION = e.get("version", VERSION)
    APP_DIR = BASE_DIR / e.get("app_dir", "app")
    APP_NAME = e.get("app_name", APP_NAME)
    CLI_NAME = e.get("command", CLI_NAME)
    UNINSTALL_LNK = e.get("uninstall_link", UNINSTALL_LNK)
    if not os.getenv("AIGUARD_KIT_UPDATE_URL") and e.get("update_url"):
        UPDATE_URL = e["update_url"]
    return e


apply_edition(HERE / "edition.json")


# ---------------------------------------------------------------- products
# AI Guard is built into this file. Other products are separate modules beside it that share the kit's
# credentials, keychain, config, console, installer and updater. Each module defines bind(kit) and cli(args).
PRODUCTS = {
    "aiguard": {"label": "AI Guard", "module": None},
    "zia": {"label": "Internet Access (ZIA)", "module": "zia_module.py"},
}
_PRODUCT_MODULES: dict = {}


class _KitRef:
    """What a product module sees as `kit`: this file's globals, read live (so settings and test fakes apply)."""

    def __getattr__(self, name):
        try:
            return globals()[name]
        except KeyError:
            raise AttributeError(name) from None

    def __setattr__(self, name, value):
        globals()[name] = value


def product(name):
    spec = PRODUCTS[name]
    if not spec["module"]:
        return None
    if name not in _PRODUCT_MODULES:
        import importlib.util
        path = HERE / spec["module"]
        if not path.exists():
            raise KitError(f"{spec['label']} support isn't in this copy of the kit ({path.name} is missing). "
                           f"Update the kit, or download the latest release.")
        s = importlib.util.spec_from_file_location(f"aiguard_kit_{name}", path)
        mod = importlib.util.module_from_spec(s)
        s.loader.exec_module(mod)
        mod.bind(_KitRef())
        _PRODUCT_MODULES[name] = mod
    return _PRODUCT_MODULES[name]


def cmd_zia():
    i = ARGS.index("zia")
    product("zia").cli([a for a in ARGS[i + 1:]])


# ---------------------------------------------------------------- main
def main():
    tls_setup()
    ensure_windows_launcher()
    vals = {ARGS[i + 1] for i, a in enumerate(ARGS[:-1]) if a in VALUE_OPTS}
    cmd = next((a for a in ARGS if not a.startswith("-") and a not in vals), "help")
    product_ = (EDITION or {}).get("product")
    if product_ and cmd in EDITION_COMMANDS.get(product_, ()) and product_ not in ARGS:
        ARGS.insert(ARGS.index(cmd), product_)   # the ZIA kit: `zia-kit check` means `zia check`
        cmd = product_
    cmds = {"setup": cmd_setup, "preflight": cmd_preflight, "gui": cmd_gui, "run": cmd_run, "status": cmd_status, "teardown": cmd_teardown,
            "policy": cmd_policy, "schedule": cmd_schedule, "install": cmd_install, "uninstall": cmd_uninstall,
            "update": cmd_update, "repair": cmd_repair, "logs": cmd_logs, "zia": cmd_zia}
    if cmd not in cmds:
        print(__doc__)
        return
    try:
        cmds[cmd]()
    except KitError as e:
        activity("error", str(e), "error", command=cmd, fix=hint(e))
        print(f"\n  {C['r']}✗{C['x']} {e}")
        print(f"    {C['y']}Fix:{C['x']} {hint(e)}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n  Cancelled.")
        sys.exit(130)


if __name__ == "__main__":
    main()
