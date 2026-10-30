"""Generates MANUAL-STEPS.md from manual_steps.json (Manual steps on the console's Setup tab and `aiguard-kit todo` use the
same file), and the deployment guide's appendix (tools/build_guide.py calls render()).

  python tools/gen_manual_doc.py          write MANUAL-STEPS.md
  python tools/gen_manual_doc.py --check  fail if MANUAL-STEPS.md is out of date (CI)
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
GENERIC = {"test_user": "the test user (for example `se-demo-traffic@<your domain>`)",
           "group": "`SE-Demo: traffic generator`", "app_profile": "SE-Demo traffic generator",
           "fwd_profile": "SE-Demo Z-Tunnel 2.0",
           "password_source": "the one the kit generated (`aiguard-kit zia password`) or, for a ZIdentity user, the "
                              "one you set in ZIdentity"}
WHEN = {"always": "Every tenant.", "aiguard": "When the AI Guard demo is set up.", "zia": "When the ZIA demo is set up.",
        "zia-zidentity-user": "When the kit created the test user in ZIdentity (SAML or ZIdentity-managed tenants).",
        "zia-zcc-manual": "When the Client Connector API refused the profiles, or you chose your own test user.",
        "zia-aws": "When you use the AWS generator and Fleet Manager offers no single sign-on.",
        "docs": "Only when the situation described applies (the console doesn't list it).",
        "aiguard-kit": "When you use the AI Guard demo.",
        "zia-zcc-auto": "When the ZIA demo is set up and the Client Connector API accepts the profiles.",
        "eai": "When you use the Endpoint AI Security demo."}
COND = {"zia-zidentity-user": "on ZIdentity tenants", "zia": "with the ZIA demo"}


def render(level=1):
    h = json.loads((ROOT / "manual_steps.json").read_text(encoding="utf-8"))
    hd = "#" * level
    titles = {s["id"]: s["title"] for s in h["steps"]}

    def needs(s):
        parts = []
        for n in s.get("needs", []):
            nid, _, cond = n.partition("?")
            parts.append(titles.get(nid, nid) + (f" ({COND.get(cond, cond)})" if cond else ""))
        return "; ".join(parts)
    out = [f"{hd} Manual steps", "",
           "Your setup path, in order: what the kit can't do through Zscaler's APIs (with the clicks to do it), and, "
           "marked *The kit*, what it does in between. Each step lists what has to be done first. **Manual steps** on the console's Setup tab "
           "and `aiguard-kit todo` show only the steps that apply to your tenant, filled in with your names, and check "
           "the ones the kit can verify.", "",
           "> Steps marked **menu names not yet confirmed** haven't been checked against a live console. If yours "
           "differ, tell the kit owner (or update `manual_steps.json` and regenerate this file).", ""]
    for key, label in h["stages"].items():
        steps = [s for s in h["steps"] if s["stage"] == key]
        if not steps:
            continue
        out += [f"{hd}# {label}", ""]
        for s in steps:
            if s.get("who") == "kit":
                out += [f"- *The kit:* **{s['title'].replace('Kit: ', '')}**. {s['why']} Start it: {s['action']}"
                        + (f" Needs first: {needs(s)}." if s.get("needs") else "")
                        + (f" Then: {s['then']}" if s.get("then") else ""), ""]
                continue
            out += [f"{hd}## {s['title']}", "", f"**Why it's manual:** {s['why']}", "",
                    f"**When:** {WHEN.get(s['applies'], s['applies'])}", ""]
            if s.get("needs"):
                out += [f"**Needs first:** {needs(s)}", ""]
            out += [f"{n}. {line.format_map(GENERIC)}" for n, line in enumerate(s["steps"], 1)]
            out += [""]
            if s.get("then"):
                out += [f"**Then:** {s['then'].format_map(GENERIC)}", ""]
            if s["help"]:
                out += ["Zscaler Help: " + " · ".join(f"[{x['title']}]({x['url']})" for x in s["help"]), ""]
            check = s.get("check")
            out += [("**Done when:** the kit checks it (Check under Setup > Manual steps)." if check not in (None, "reminder")
                     else "**Each demo.**" if check == "reminder"
                     else f"**Done when:** you mark it done (`aiguard-kit todo --done {s['id']}`)."),
                    "", f"*{'Menu path checked ' + s['confirmed'] if s['confirmed'] else 'Menu names not yet confirmed'}"
                        f" · id `{s['id']}`*", ""]
    return "\n".join(out)


if __name__ == "__main__":
    text = render()
    path = ROOT / "MANUAL-STEPS.md"
    if "--check" in sys.argv:
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            sys.exit("MANUAL-STEPS.md is out of date: run python tools/gen_manual_doc.py")
        print("MANUAL-STEPS.md up to date")
    else:
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
