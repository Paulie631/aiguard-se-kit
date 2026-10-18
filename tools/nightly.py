#!/usr/bin/env python3
"""Nightly test against a real demo tenant (run by .github/workflows/nightly-tenant.yml).

Uses its own prefix (SE-CI by default) and its own test user, so it never touches the SE-Demo objects you demo with:
  1. AI Guard preflight (read-only)
  2. ZIA preflight, with a write probe
  3. ZIA setup: creates the SE-CI test user, demo policy and Client Connector profiles, then activates
  4. drift check: nothing missing, disabled or out of order; Client Connector profiles on Z-Tunnel 2.0
  5. setup again (the update path) and drift again
  6. teardown, always, then a check that no SE-CI object is left

Needs SE_KIT_CLIENT_ID, SE_KIT_VANITY_DOMAIN and SE_KIT_ONEAPI_CLIENT_SECRET (optional SE_KIT_CLOUD). Exit code 0 when
everything passed, 1 otherwise. A Markdown summary goes to $GITHUB_STEP_SUMMARY when it's set.
"""
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PREFIX = os.environ.get("SE_KIT_PREFIX", "SE-CI")


def load_kit():
    os.environ["SE_KIT_KEYCHAIN"] = "memory"   # no keychain on a CI runner; secrets come from the environment
    sys.argv = ["aiguard_kit.py", "--prefix", PREFIX, "--yes", "--force"]
    spec = importlib.util.spec_from_file_location("aiguard_kit", ROOT / "aiguard_kit.py")
    kit = importlib.util.module_from_spec(spec)
    sys.modules["aiguard_kit"] = kit
    spec.loader.exec_module(kit)
    return kit


def main():
    missing = [v for v in ("SE_KIT_CLIENT_ID", "SE_KIT_VANITY_DOMAIN", "SE_KIT_ONEAPI_CLIENT_SECRET") if not os.environ.get(v)]
    if missing:
        print(f"Skipped: set the repository secrets {', '.join(missing)} to run the nightly tenant test.")
        return 0
    if PREFIX == "SE-Demo":
        print("Refusing to run with the SE-Demo prefix: the nightly test must never touch the demo objects.")
        return 1
    kit = load_kit()
    kit.CFG_DIR = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "se-kit-nightly"
    kit.CFG_DIR.mkdir(parents=True, exist_ok=True)
    kit.CFG_FILE = kit.CFG_DIR / "config.json"
    kit.LOG_DIR = kit.CFG_DIR / "logs"
    cfg = {"client_id": os.environ["SE_KIT_CLIENT_ID"], "vanity_domain": os.environ["SE_KIT_VANITY_DOMAIN"]}
    if os.environ.get("SE_KIT_CLOUD"):
        cfg["cloud"] = os.environ["SE_KIT_CLOUD"]
    kit.save_cfg(cfg)
    z = kit.product("zia")

    results = []   # (step, ok, detail)

    def log(level, msg):
        print(f"  [{level}] {msg}", flush=True)

    def step(name, fn):
        print(f"\n== {name}", flush=True)
        t0 = time.time()
        try:
            ok, detail = fn()
        except Exception as e:   # one failed step shouldn't hide the others, or skip teardown
            ok, detail = False, f"{type(e).__name__}: {str(e)[:300]}"
        results.append((name, ok, detail, round(time.time() - t0)))
        print(f"   -> {'PASS' if ok else 'FAIL'}: {detail}", flush=True)
        return ok

    def bad(checks, statuses=("fail",)):
        return [f"{c['label']}: {c['detail']}" for c in checks if c["status"] in statuses]

    def aig_preflight():
        checks, _ = kit.preflight(cfg)
        b = bad(checks)
        return not b, "; ".join(b) or f"{len(checks)} checks, no failures"

    def zia_preflight():
        checks, _ = z.preflight(cfg, write_probe=True)
        b = bad(checks)
        return not b, "; ".join(b) or f"{len(checks)} checks, no failures"

    state = {}

    def tenant():
        if "t" not in state:
            state["t"] = z.connect(cfg)
        return state["t"]

    def setup():
        t = tenant()
        if not z.zcfg(cfg).get("users"):
            z.create_test_user(t, cfg, log)
        res = z.setup_apply(t, cfg, log)
        if res["failed"]:
            return False, f"{res['rules']} rules; not created: {', '.join(res['failed'])}"
        zcc = res.get("client_connector") or {}
        return True, f"{res['rules']} rules" + (f"; Client Connector: {', '.join(zcc.values())}" if zcc else
                                                "; Client Connector profiles skipped")

    def drift():
        checks = z.drift(tenant(), cfg)
        b = bad(checks, ("warn", "fail"))
        return not b, "; ".join(b) or "no drift"

    def teardown():
        t = tenant()
        z.teardown(t, cfg, log, confirm=False)
        left = z.kit_objects(t, cfg)
        names = [str(z.g(o, "name") or z.g(o, "configured_name")) for _, _, o in left]
        return not left, ("left behind: " + ", ".join(names)) if left else f"no {PREFIX} objects left"

    try:
        step("AI Guard preflight (read-only)", aig_preflight)
        if step("ZIA preflight (write probe)", zia_preflight):
            if step("ZIA setup (create)", setup):
                step("Drift after create", drift)
                if step("ZIA setup again (update)", setup):
                    step("Drift after update", drift)
    finally:
        if "t" in state or z.zcfg(cfg).get("users"):
            step("Teardown", teardown)

    passed = all(ok for _, ok, _, _ in results)
    lines = [f"## Nightly tenant test ({PREFIX}): {'passed' if passed else 'FAILED'}", "",
             "| Step | Result | Seconds | Detail |", "|---|---|---|---|"]
    lines += [f"| {n} | {'✅' if ok else '❌'} | {s} | {d.replace('|', '/')} |" for n, ok, d, s in results]
    summary = "\n".join(lines) + "\n"
    print("\n" + summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(summary)
    (kit.CFG_DIR / "nightly-result.json").write_text(json.dumps(
        [{"step": n, "ok": ok, "detail": d, "seconds": s} for n, ok, d, s in results], indent=1), encoding="utf-8")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
