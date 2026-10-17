# AI Guard SE Demo Kit

Fill every Zscaler AI Guard dashboard in **your own** tenant in about ten minutes. Then run live tests, a guided customer demo and a leave-behind report from a browser console.

> **Demo and eval tenants only.** Setup creates objects in the tenant. Everything it creates is named `SE-Demo: …`, and `teardown` removes all of it. See [SECURITY.md](SECURITY.md) for what's stored where.

## Quickstart

1. **Install uv** (one time): `brew install uv` (Mac) or see the Windows note below.
2. **Create a OneAPI client** in ZIdentity → Integration → API Clients, with AI Guard access. Copy the client ID and secret, and note your vanity domain: the `acme` in `acme.zslogin.net`.
3. **Open the console** from this folder. It starts on the **Setup** tab the first time:
   ```bash
   ./aiguard-kit gui
   ```
   Setup walks through five steps: connect, **preflight checks**, choices, review, create and verify. Nothing changes in the tenant until the last step. Prefer the terminal? `./aiguard-kit setup` runs the same wizard there.
4. At the end, press **Populate every dashboard now**.
5. **Optional: keep dashboards fresh** with a small batch every hour: `./aiguard-kit schedule install`
6. **Check AI Guard → Insights** after 10–15 minutes.

**Windows:** see [WINDOWS.md](WINDOWS.md). In short: install uv, open a new PowerShell window, and use `.\aiguard-kit.cmd` wherever this README says `./aiguard-kit` (for example `.\aiguard-kit.cmd gui`).

## The console

| Tab | What it's for |
|---|---|
| **Test runner** | 72 core tests in 7 groups, presets, industry packs and imported packs. Pick apps, users, rounds and mode. The **Live prompt** box scans anything you type. **Dashboard coverage** shows which console panels you've fed. Results show detector tags (expected-but-missed detectors in amber, which you can hide before a customer demo), and export as CSV or a **Report**. |
| **Guided demo** | Step-by-step storylines with a talk track: *AI Guard in 8 steps* and *Data protection (3 minutes)*. Use ← → to move and Enter to run. By default each step is a Detection API scan (no model call). Turn on **Send to the model** to send prompts to OpenAI or Anthropic through the AI Guard proxy and show the real reply, or AI Guard's block message in Enforce. **Detector tags** adds a Detection API scan of the prompt and of the model's reply, so you see which detectors fired (this logs extra events). Steps that switch the policy wait about 30 seconds for it to apply. Hide the talk track when sharing your screen. |
| **Test packs** | Healthcare, Financial services and Legal packs, plus **CSV import** of a customer's own prompts for a proof of concept. Imported packs stay on your machine. |

The **Policy** menu in the header sets what the kit's demo policy blocks. It only ever changes the kit's own policy, and changes take about 30 seconds to apply.

| Profile | Blocks | Still detected and logged |
|---|---|---|
| Monitor | Nothing | Everything |
| Block attacks | Prompt injection, hidden (invisible) text, toxicity; malicious URLs and toxicity in responses | Secrets, PII, everything else |
| Block attacks + data leakage | The above, plus secrets and **regulated** PII (cards, SSNs, bank numbers, IBAN/SWIFT, passport, ITIN) in prompts and responses | Email, phone, IP, personal details, topics |
| Block everything risky | Every risk detector, including code, competitor talk, brand risk, legal and financial advice | Topic and language classification |
| Custom… | Your choice of Detect or Block for each detector, separately for prompts and responses | The rest |

For a granular demo, use the guided storyline **Blocking, step by step**. It walks through each profile with a prompt that changes outcome at that level.

**Report** builds a one-page summary of the session: totals, detections by type and scenario, and examples. Enter the customer's name, then use *Print / save as PDF*.

## Setup and preflight

Preflight runs before anything is created, and on its own with `./aiguard-kit preflight` (add `--write-probe` to test create permission):

| Check | If it fails |
|---|---|
| Keychain works on this computer | Unlock the login keychain (Mac) or install a keyring service (Linux) |
| Detection API and proxy reachable | Usually TLS inspection or DNS; the fix is shown |
| OneAPI login and read access | Wrong secret or vanity domain, or the API client lacks AI Guard access |
| Create and delete permission (optional probe) | The API client can read but not change AI Guard |
| OpenAI / Anthropic providers present | Proxy mode skipped for that app; detection mode still works |
| User-based rules ahead of the kit's | Warning: they may apply their own policy to demo traffic |
| Reused policy covers the tests | Lists the missing detectors and the panels that will stay empty |
| Store Prompts/Responses | Reminder only; it can't be read through the API |

Every check has a **How to verify** panel in the console and a section in **[PREFLIGHT.md](PREFLIGHT.md)**: what it checks, how to confirm it by hand, how to fix it and how to re-test. To share results, use **Copy report** in the console or `./aiguard-kit preflight --json`. Neither includes secrets. Exit codes are 0 pass, 2 warnings, 1 failures.

If creating something fails partway, everything made so far is kept and **Retry** fills in the rest. After setup, **verification** scans once through every app, waits up to about a minute for new keys to activate, and fails if a different policy handled the traffic.

## What setup creates

| Object | Name | Notes |
|---|---|---|
| Detection policy | `SE-Demo: Test all` | Every detector on. Starts in Monitor or Enforce, your choice. You can also reuse an existing policy instead; the policy switch won't touch it. |
| Apps | `SE-Demo: OpenAI App`, `SE-Demo: Anthropic App` | Event contents included so prompt text shows in the console. |
| Detection keys | one per app | Mode `DETECTIONS`, for the Detection API. |
| Proxy keys | one per app, optional | Mode `PROXY`. Setup offers any OpenAI/Anthropic key already in the tenant (reuse it, enter a new one, or skip). If there's none, it asks for one or runs detection-only. Reused keys are never deleted by teardown. |
| Rules | `SE-Demo: detection apps`, `SE-Demo: proxy apps` | Placed after your existing rules. |

Keys are saved in your OS keychain. Settings that aren't secret are in `~/.aiguard-se-kit/config.json`.

## Modes

| | Detection API (default) | LLM proxy |
|---|---|---|
| Cost | Free, no LLM calls | Uses your provider credit |
| Needs | Nothing extra | An OpenAI or Anthropic API key, added in setup |
| Fills | Every detector panel, Prompt Classifications, **Users tab** | AI Applications, **token usage**, real model replies |
| Model-reply (OUT) tests | Yes | No (the model writes the reply) |

## Commands

```
./aiguard-kit setup                      terminal wizard; safe to rerun (fills in anything missing)
./aiguard-kit preflight [--write-probe] [--json]   checks only, no changes (exit 0/2/1)
./aiguard-kit gui                        console at http://127.0.0.1:8765 (this machine only)
./aiguard-kit run                        everything, detection mode
./aiguard-kit run --preset=attacks       everything leakage attacks rai output topics pack-healthcare …
./aiguard-kit run --mode=proxy --rounds=2
./aiguard-kit policy [monitor|attacks|data|everything]   show or switch what blocks
./aiguard-kit schedule install [--every 60] [--count 12]    also: schedule status, schedule remove
./aiguard-kit status                     login, policy, keys, Detection API, kit updates
./aiguard-kit teardown                   deletes every SE-Demo object and the local keys (--force: no prompt)

Any command: --profile NAME (separate tenants), --prefix NAME, --verbose, --yes
```

**Scheduled traffic** uses launchd (Mac), Task Scheduler (Windows) or cron (Linux) and logs to `~/.aiguard-se-kit/trickle.log`. On a Mac, the first scheduled run may ask for keychain access; choose **Always Allow**.

**Several tenants:** run `./aiguard-kit setup --profile acme`, then add `--profile acme` to any command. Each profile has its own credentials, keys, objects and schedule.

## Adding tests

- **Quick:** in the console, open **Test packs** and import a CSV with columns `prompt`, `direction` (IN/OUT), `name` and `expect`. A template is linked there.
- **Shared with every SE:** add a JSON file to `packs/` (copy an existing one) and open a pull request.
- In the files, `{COMPETITOR}` becomes the competitor chosen in setup, and `{_}` is removed at run time. It splits fake keys so GitHub secret scanning doesn't block pushes.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `invalid_client` at setup | Wrong client ID or secret. Go back to step 1 (Connect) and re-enter them. |
| Verification: "handled by '…' instead" | Another rule matched the demo traffic first. Disable or reorder it in AI Guard → Policies, then press **Retry checks**. |
| `CERTIFICATE_VERIFY_FAILED` / `UnknownIssuer` | Zscaler SSL inspection. Always start the kit with `./aiguard-kit`, which trusts the system store, and check that the Zscaler root CA is in your keychain. |
| `401` on OneAPI calls | The API client lacks AI Guard access in ZIdentity. |
| Detection API `401` or `400 … authenticate-llm-app` | Keys must be mode `DETECTIONS`; proxy keys don't work there. Rerun setup. |
| Insights shows *No Policy Control* | The traffic didn't match a rule (proxy traffic needs an `APPLICATION` rule; detection traffic a `DAS_APPLICATION` rule). Rerun setup. |
| Prompt Classifications empty | The policy needs `prompt_tags` (the kit's policy has it). Wait 15 minutes. |
| Users tab empty | Only Detection API traffic (with a user) or real signed-in Client Connector traffic fills it. Proxy traffic doesn't. |
| Policy switch says "not a kit policy" | Setup reused an existing policy. Switch it in the console, or rerun setup and create the kit's policy. |
| A blocking step still shows ALLOW | The change takes about 30 seconds to apply; run the step again. Also check the profile covers that detector: secrets and PII only block in *Block attacks + data leakage* or higher. |
| Scheduled runs don't appear | `./aiguard-kit schedule status`, then check `~/.aiguard-se-kit/trickle.log`. On a Mac, allow keychain access. |
| Proxy `402` / `insufficient_quota` | No credit left at the provider. Top it up or use detection mode. |

Attach `~/.aiguard-se-kit/runs.jsonl` (results, no keys) when asking for help.

## For maintainers

- **Before rollout:** work through [TESTPLAN.md](TESTPLAN.md), which breaks each check on purpose and settles the items the runbook marks as unconfirmed.
- **Runbook text** lives in `preflight_help.json` (used by the console). After editing it, run `python tools/gen_preflight_doc.py` to regenerate PREFLIGHT.md; CI fails if they drift.

- **Advanced:** `AIGUARD_DAS_HOST` (default `https://api.us1.zseclipse.net`) and `AIGUARD_PROXY` (default `https://proxy.zseclipse.net`) point at other AI Guard clouds.
- **Offline tests:** `uv run --with pytest --with requests --with keyring --with truststore pytest -q tests`. CI runs them on every push (`.github/workflows/ci.yml`).
- **Claude plugin:** `python tools/build_plugin.py` writes `dist/aiguard-se-demo.plugin`, bundling the kit with a skill so SEs can say "set up the AI Guard demo".
- **Updates:** SEs who cloned with git see "Update available" in the console and in `status`.

## Files

`aiguard-kit`, `aiguard-kit.cmd`: launchers (Mac/Linux, Windows; see WINDOWS.md) · `aiguard_kit.py`: the kit · `gui.html`: the console · `tests.json`: core tests and storylines · `packs/`: industry packs · `policy_template.json`: the demo policy · `preflight_help.json`, `PREFLIGHT.md`: preflight runbook · `TESTPLAN.md`: validation plan · `tests/`: offline tests · `plugin/`, `tools/`: Claude plugin.
