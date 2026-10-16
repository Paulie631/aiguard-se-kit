# Changelog

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
