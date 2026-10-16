# Preflight validation test plan

Run this once in your own demo tenant before sharing the kit, and again after any change to preflight. The goal is to break each check on purpose and confirm the kit reports it clearly. Record results in the last column and fix the runbook (`preflight_help.json`, then `python tools/gen_preflight_doc.py`) wherever the real console differs.

**Before you start**
- [ ] Use a demo/eval tenant, not a customer's.
- [ ] Run `./aiguard-kit preflight --write-probe` with everything healthy. Expect **PASS** (exit code 0), or **WARN** (exit code 2) only for checks you expect, such as the user-based rule.
- [ ] Save that report: `./aiguard-kit preflight --json > baseline.json`

## Break one thing at a time

Undo each change before the next row. For each row, check the message in **both** the terminal (`./aiguard-kit preflight --write-probe`) and the console (Setup → step 2), and open **How to verify** to confirm the steps match what you see.

| # | Break it this way | Expected | Exit code | Undo | Result / notes |
|---|---|---|---|---|---|
| 1 | Setup step 1: enter a wrong client secret | ✗ OneAPI login, fix mentions the secret; console shows the error right away | 1 | Re-enter the right secret | |
| 2 | Enter the full host `acme.zslogin.net` as the vanity domain | Saved as `acme`; login ✓ | 0 | n/a | |
| 3 | Enter a vanity domain with a typo | ✗ OneAPI login with a name-resolution hint | 1 | Fix the domain | |
| 4 | ZIdentity: remove AI Guard from the API client's scope | ✗ OneAPI login or ✗ Read access, fix mentions AI Guard access | 1 | Restore the scope | |
| 5 | ZIdentity: make AI Guard access read-only (if the console allows it) | ✓ Read access, ✗ Create and delete permission | 1 | Restore full access | |
| 6 | Turn Wi-Fi off | ✗ Detection API reachable (DNS or connection error), ! proxy | 1 | Wi-Fi on | |
| 7 | Run with plain `uv run --script aiguard_kit.py preflight` (not the launcher) on an SSL-inspected laptop | If it fails, ✗ Detection API with a TLS hint | 1 or 0 | Use `./aiguard-kit` | |
| 8 | `AIGUARD_DAS_HOST=https://api.nowhere.zseclipse.net ./aiguard-kit preflight` | ✗ Detection API reachable naming that host | 1 | Unset it | |
| 9 | Mac: lock the login keychain (Keychain Access → Lock) | ✗ Keychain available, or a macOS unlock prompt | 1 | Unlock | |
| 10 | Add an enabled rule matched by **user** above all others | ! No broad rules ahead, naming the rule and its order | 2 | Delete or disable it | |
| 11 | Same rule, then finish setup | Verification either ✓ (the kit's policy) or ✗ "handled by '…' instead". **Record which.** This settles an open question in the runbook. | n/a | Delete the rule, Retry checks | |
| 12 | Setup: reuse a policy without `prompt_tags` | ! Reused policy, listing Prompt Classifications | 2 | Rerun setup with the kit's policy | |
| 13 | Run setup twice in a row (keep existing) | Second run creates nothing new; · Earlier kit objects shows the count | 0 | n/a | |
| 14 | Delete one detection key in the console, then `./aiguard-kit status` | Detection API failure for that app, with the "rerun setup" fix; rerunning setup recreates it | n/a | Rerun setup | |
| 15 | Stop the network halfway through step 5 | A failure with a fix; **Retry** completes setup without duplicates | n/a | Network on, Retry | |
| 16 | Copy report / `--json` | Contains the tenant, masked client ID, OS, kit version and checks. **No secret or key anywhere** (search for the secret's first characters) | n/a | n/a | |

## Confirm the open items

The runbook marks some steps as not yet confirmed in a real tenant. Settle each one and update `preflight_help.json`:

- [ ] Exact ZIdentity labels for the AI Guard scope and for read-only vs full access (rows 4–5)
- [ ] Console menu names for LLM providers, policy rules and AI Applications
- [ ] Whether user-matched rules apply to Detection API scans that carry a user (row 11)
- [ ] Whether the Detection API returns which policy handled a scan (verification relies on it: if it doesn't, verification shows ✓ with "policy '?'")
- [ ] Detection API host names for clouds other than us1

## Pilot

- [ ] Two or three SEs on different setups (Mac on Zscaler Client Connector, Windows, a personal network) run the Setup tab cold, using only the README.
- [ ] Each sends their `./aiguard-kit preflight --json` output and any confusing step.
- [ ] Add every new failure to `preflight_help.json` and HINTS in `aiguard_kit.py`.
