# Security and data handling

For the internal review before wide release.

## What the kit stores, and where

| Item | Where | Notes |
|---|---|---|
| OneAPI client secret | OS keychain (macOS Keychain / Windows Credential Manager) | Never written to disk in clear or printed. |
| AI Guard app keys (detection and proxy) | OS keychain | Shown by AI Guard once at creation and saved straight to the keychain. |
| LLM provider API keys | Inside AI Guard (provider credentials) | Typed at a hidden prompt and sent to AI Guard; not kept locally. |
| Vanity domain, client ID, object IDs, settings | `~/.aiguard-se-kit/config.json` (mode 600) | Nothing secret. |
| Run log | `~/.aiguard-se-kit/runs.jsonl` | Test results and prompt text; no keys. |
| Imported CSV packs | `~/.aiguard-se-kit/packs/` | Only on the SE's machine. |

## What it changes in a tenant

Only objects it creates, all named `SE-Demo: …` (or the chosen `--prefix`): one detection policy, demo apps, app credentials, provider credentials and two match rules. The policy switch only edits the kit's own policy and refuses any other. `teardown` deletes all of it.

## Network

- Zscaler OneAPI (`api.zsapi.net`, via the SDK) for configuration.
- AI Guard Detection API (`api.us1.zseclipse.net`) and proxy (`proxy.zseclipse.net`) for tests.
- LLM providers only indirectly, through the AI Guard proxy, in proxy mode.
- No telemetry. The update check runs `git fetch` against the repo the SE cloned.

## Test console

Binds to 127.0.0.1 only, uses a random per-session token on every API call, and rejects requests whose Host isn't localhost (DNS-rebinding protection). It never receives keys.

## Content

- All bundled test data is synthetic. Card numbers and SSNs are well-known test values; key-like strings are random and invalid, and they're split with `{_}` in the files so repository secret scanners don't flag them.
- The demo apps keep event contents, so prompt text is visible in the tenant's AI Guard logs. The console warns SEs not to paste real customer content without the customer's agreement.
- Use demo or eval tenants only.
