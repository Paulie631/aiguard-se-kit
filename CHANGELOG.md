# Changelog

## 1.5.3
- Fixed: on a computer with a very new Python (3.15), uv tried to compile `pyyaml` and failed with
  "Microsoft Visual C++ 14.0 or greater is required". The launchers now run the kit on Python 3.12, which uv
  downloads if needed, and the kit declares it supports up to 3.14.
- The Windows launcher finds uv in its default install folder, so it works in the same window right after installing uv.
- WINDOWS.md: fallbacks when the uv installer is blocked (winget, pip) and the Visual C++ error.
- CI checks that prebuilt libraries exist for Windows and Mac (Intel and ARM).

## 1.5.2 (Windows)
- Fixed: on Windows, the kit could crash with `UnicodeEncodeError` when printing ✓ or ✗ (redirected output,
  `preflight --json > file`, scheduled runs, older consoles). Output is now always UTF-8.
- Fixed: scheduled traffic on Windows printed into the void and could exceed Task Scheduler's command length.
  It now runs a small wrapper in `~/.aiguard-se-kit` that logs to `trickle.log`.
- The kit writes `aiguard-kit.cmd` itself on first run if it's missing (the emailed copy can't include it).
- `aiguard-kit.cmd` now has Windows line endings and sets `PYTHONUTF8`.
- Messages, hints and the console show `.\aiguard-kit.cmd` on Windows instead of `./aiguard-kit`.
- Colors work in the classic Windows console; keychain and certificate hints name the Windows equivalents.
- Reads the Claude Desktop config from `%APPDATA%` on Windows.
- Two consoles can no longer silently share the same port on Windows.
- New WINDOWS.md; CI now runs the tests on Windows and macOS too.

## 1.5.1
- Fixed: setup failed with 409 "already exists" when the tenant already had the kit's detection keys but their
  secrets weren't on this machine. The AI Guard list API doesn't return DETECTIONS-mode keys, so the kit now
  finds them through its rules and saved state, creates a uniquely named replacement, and removes the old key
  once the rules point at the new one.
- Fixed: teardown now removes detection keys too (previously they were left behind).
- A locked or denied keychain now stops with a clear message instead of looking like a missing key.

## 1.5.0
- **Policy profiles** replace the single Monitor/Enforce switch: Monitor, Block attacks, Block attacks + data
  leakage (secrets and regulated PII: cards, SSNs, bank, IBAN/SWIFT, passport, ITIN), Block everything risky.
- **Custom policy** editor in the console: choose Detect or Block per detector, separately for prompts and
  responses. Topic and language classifiers always stay on detect.
- New guided storyline **"Blocking, step by step"** walks through each profile; the Data protection story now
  ends with the same card blocked and everyday data still allowed.
- **Detector tags in LLM proxy runs**: each row shows what was detected in the prompt, the model's reply (or the
  block message) and what was detected in the reply. `./aiguard-kit run --mode=proxy --tags` in the terminal.
- Fixed: blocking is set per item (entity, secret type, language); the AI Guard API rejects `defaultAction: BLOCK`.

## 1.4.0
- Guided demo can **send each prompt to the real model** through the AI Guard proxy (Send to the model) and shows
  the model's reply, or the block message when AI Guard stops it in Enforce.
- With **Detector tags** on, each step also runs a Detection API scan for the tags, and the model's reply is
  scanned as a response so response detectors show too (extra events in Insights).
- "Risky model output" steps ask the live model to generate the risky content when proxy mode is on.

## 1.3.1
- Setup finds LLM provider keys already configured in the tenant and offers to reuse them (Reuse / Enter a new
  key / Skip). When none exist, it says so and asks for one, or runs detection-only.
- Teardown never deletes reused keys: only objects named with the kit's prefix.

## 1.3.0
- **Preflight runbook** (`PREFLIGHT.md`): for every check, what it checks, why it matters, how to verify by hand,
  how to fix and how to re-test. Steps not yet confirmed in a real tenant are marked.
- **How to verify** panels under every check in the console (same content as the runbook).
- **Copy report** / **Download .json** in the console and `./aiguard-kit preflight --json`: checklist, kit version,
  OS and tenant, with no secrets. Exit codes: 0 pass, 2 warnings, 1 failures.
- Terminal output links each warning and failure to its runbook section.
- **TESTPLAN.md**: break-each-check validation plan and pilot checklist.

## 1.2.0
- Guided setup in two forms: a **Setup tab** in the console (browser wizard) and a step-by-step terminal wizard.
- **Preflight checks** before any change: keychain, Detection API and proxy reachability, login, read access,
  optional create/delete permission probe, providers, earlier kit objects, user-based rules that could take over
  demo traffic, and gaps in a reused policy. Also `./aiguard-kit preflight`.
- **Review step** shows exactly what will be created; answers can be changed before anything happens.
- **Retry on failure**: progress is saved after every object, so retry fills in the rest.
- **Verification** after setup scans through every app, retries while new keys activate, and fails if a
  different policy handled the traffic.
- Remove-the-demo button in the console (type DELETE to confirm).

## 1.1.0
- Policy switch: Monitor/Enforce toggle in the console and `./aiguard-kit policy detect|block`.
- Guided demo tab with two storylines, talk track, keyboard control and automatic policy steps.
- Scheduled background traffic: `./aiguard-kit schedule install` (launchd, Task Scheduler, cron) and `run --trickle`.
- Industry packs (Healthcare, Financial services, Legal) and CSV import of a customer's own prompts.
- Leave-behind report: printable summary of a session, saved as PDF from the browser.
- Profiles (`--profile NAME`) for SEs with several tenants; update notice when the git checkout is behind.
- Offline test suite and CI; Claude plugin build.

## 1.0.0
- Setup, test console, CLI runs, status and teardown.
