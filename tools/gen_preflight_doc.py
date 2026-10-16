"""Generates PREFLIGHT.md from preflight_help.json (the console uses the same file).

  python tools/gen_preflight_doc.py          write PREFLIGHT.md
  python tools/gen_preflight_doc.py --check  fail if PREFLIGHT.md is out of date (CI)
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def render():
    h = json.loads((ROOT / "preflight_help.json").read_text(encoding="utf-8"))
    out = ["# Preflight runbook", "",
           "Every check the kit runs before setup (and `./aiguard-kit preflight` runs on its own): what it checks, why it",
           "matters, how to verify it by hand, how to fix it, and how to re-test. The console shows the same text under",
           "**How to verify** next to each check.", "",
           "Statuses: ✓ pass · ! warning (setup can continue) · ✗ failure · · information.", "",
           "> Items marked **Confirm in your tenant** haven't been checked against a real tenant yet. If the wording",
           "> differs from what you see, update `preflight_help.json` and regenerate this file.", "",
           "## Contents", ""]
    out += [f"- [{c['label']}](#{c['id']})" for c in h["checks"]]
    out += ["", "## Running and sharing the checks", "",
            "```bash", "./aiguard-kit preflight                 # checklist; exit 0 = pass, 2 = warnings, 1 = failures",
            "./aiguard-kit preflight --write-probe   # also test create/delete permission",
            "./aiguard-kit preflight --json          # machine-readable report (no secrets) for tickets and scripts",
            "```", "", "In the console: Setup → step 2 → **Copy report** puts the same report on the clipboard.", ""]
    for c in h["checks"]:
        out += [f'<a id="{c["id"]}"></a>', f"## {c['label']}", "", f"**What it checks:** {c['what']}", "",
                f"**Why it matters:** {c['why']}", "", "**Verify by hand:**", ""]
        out += [f"- {v}" for v in c["verify"]]
        out += ["", "**Fix:**", ""] + [f"- {f}" for f in c["fix"]]
        out += ["", f"**Re-test:** {c['retest']}", ""]
        if c.get("confirm"):
            out += [f"> **Confirm in your tenant:** {c.get('confirm_note', '')}", ""]
    return "\n".join(out)


if __name__ == "__main__":
    text = render()
    path = ROOT / "PREFLIGHT.md"
    if "--check" in sys.argv:
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            sys.exit("PREFLIGHT.md is out of date: run python tools/gen_preflight_doc.py")
        print("PREFLIGHT.md up to date")
    else:
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
