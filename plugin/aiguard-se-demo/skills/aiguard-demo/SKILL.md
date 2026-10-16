---
name: aiguard-demo
description: Sets up and runs the Zscaler AI Guard SE demo kit in the user's own tenant. Use when the user says "set up the AI Guard demo", "populate my AI Guard dashboards", "run AI Guard tests", "open the AI Guard test console", "switch the demo policy to enforce/block", "keep my AI Guard dashboard fresh", "import customer prompts for an AI Guard POC", "check my AI Guard demo setup" or "tear down the AI Guard demo".
---

# AI Guard SE demo kit

The kit is a command-line tool plus a browser console that creates demo objects in the SE's own AI Guard tenant (all named `SE-Demo: …`) and sends synthetic test traffic. A bundled copy lives in the `kit/` folder next to this file.

## Where to run it

Run the kit on the user's own computer, never in a cloud sandbox: keys live in the OS keychain and the console must open in the user's browser.

1. Find the kit on the user's computer. Check, in order: a path the user gives, `~/aiguard-se-kit`, `~/.zscaler-ai-addon/aiguard-se-kit`. A git checkout is preferred (it gets updates).
2. If none exists, copy the bundled `kit/` folder to `~/aiguard-se-kit` and make `aiguard-kit` executable.
3. Check that `uv` exists (`command -v uv` or `~/.local/bin/uv`). If not, tell the user to run `brew install uv` (Mac) or the PowerShell installer in the kit README (Windows). Do not install it silently.
4. If no shell on the user's computer is available, give the user the exact commands to run themselves.

Use `./aiguard-kit` on Mac/Linux and `aiguard-kit.cmd` on Windows, from the kit folder.

## Commands

| Goal | Command | Who runs it |
|---|---|---|
| First-time setup | `./aiguard-kit gui` (Setup tab) or `./aiguard-kit setup` | **The user.** Start the console and point them to its Setup tab, or have them run the terminal wizard themselves. Both ask for the OneAPI client secret and optional LLM keys in a local form or hidden prompt. Never ask for secrets in chat and never pass them as arguments. |
| Preflight only | `./aiguard-kit preflight --json` (add `--write-probe` to test create permission) | Claude. Exit 0 = pass, 2 = warnings, 1 = failures. For each warning or failure, read that check's section in the kit's `PREFLIGHT.md` and walk the user through its "Verify by hand" and "Fix" steps. Sections marked "Confirm in your tenant" may not match the console exactly; say so. |
| Re-run setup with defaults (credentials already saved) | `./aiguard-kit setup --yes` | Claude |
| Health check | `./aiguard-kit status` | Claude |
| Populate every dashboard | `./aiguard-kit run --yes` (add `--preset=leakage|attacks|rai|output|topics`, `--rounds=N`, `--mode=proxy`) | Claude |
| Test console (GUI) | `./aiguard-kit gui` | Start it in the background and tell the user the printed `http://127.0.0.1:…` address. It runs until stopped. |
| Monitor vs enforce | `./aiguard-kit policy` (show), `./aiguard-kit policy block`, `./aiguard-kit policy detect` | Claude, when asked. Changes take ~30 s. |
| Keep dashboards fresh | `./aiguard-kit schedule install --every 60 --count 12`, `schedule status`, `schedule remove` | Claude, when asked. Mention the one-time keychain "Always Allow" prompt on Mac. |
| Remove everything | `./aiguard-kit teardown --force` | Claude, only after the user explicitly confirms deletion in chat. |
| Several tenants | add `--profile NAME` to any command | |

## Reading results

- `status` lines starting with ✓ are fine; `!` or ✗ lines include a `Fix:` hint. Relay the fix in plain words.
- `run` prints one line per test and a summary with the detectors that fired. Dashboards update 10–15 minutes later at AI Guard → Insights.
- The Users tab fills only from detection-API runs (the default) or real signed-in Client Connector traffic, not from proxy runs.
- Expected misses in fake data (for example a made-up key format) are not product failures; say so if the user asks.

## Guardrails

- Use only on demo or eval tenants. If the user mentions a production or customer tenant, stop and confirm.
- Never print, echo or store keys. Never edit `~/.aiguard-se-kit/config.json` by hand.
- Don't paste real customer data into tests unless the user confirms the customer agreed; imported CSV packs stay on the user's machine.
