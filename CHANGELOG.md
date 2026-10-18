# Changelog

## 1.8.0
- **Internet Access (ZIA) demo.** A new console tab and `aiguard-kit zia` commands fill ZIA and Insights dashboards
  in the same demo tenant: `zia setup` creates `SE-Demo` rules for one test user only (URL filtering, Cloud App Control,
  File Type Control, DLP, firewall, DNS, SSL inspection) and a Client Connector profile for its group, and creates the
  test user with a generated password. A separate Windows machine running Client Connector as that user sends safe test
  traffic (`zia traffic`, `zia schedule install`); **Download CloudFormation template** builds one on AWS. Never run the
  generator on a corporate laptop. Runbook: ZIA.md.
- **Drift check.** `zia status` (and **Check for drift** in the console) compares the tenant with what setup made:
  missing, disabled or out-of-order rules, Client Connector profiles not on Z-Tunnel 2.0, and look-alike objects
  (reported, never touched). `zia status --fix` repairs the kit's own objects.
- **Demo readiness.** `aiguard-kit ready` and **Demo readiness** in the console: AI Guard policy in Monitor, app keys,
  and the ZIA checks when the ZIA demo is set up (drift, dashboards, the generator's last round, the AWS schedule).
  Start ZIA traffic at least 3 days before a demo: Insights trails by about two days.
- **Guided demo refresh.** Each step can carry a **Say** line, what to **Show**, **presenter notes** (so what, a
  discovery question, objection answers, a line for the policy wait), sourced **In the news** cards and **OWASP Top 10
  for LLM Applications (2025)** tags. Older steps with one talk paragraph show as before. **Recap** on the last step
  lists what each step caught, with a copy button for the follow-up email.
- **New storylines:** Healthcare, Financial services, Legal, and *AI security end to end* (ZIA + AI Guard). The
  original three keep their order and steps; their talk tracks gained the new fields.
- **Rolling back** is documented in the README, and installing an older release over a newer one is tested.
- The separate **Zscaler ZIA SE Demo Kit** (`zia-v*` pre-releases) continues on its own update channel; see
  CHANGELOG-ZIA.md.

## 1.7.2
- **Setup health check and Repair.** When the console opens (and after setup or an update) it checks, read-only, that
  this computer's keys still exist in AI Guard and are in the kit's rules, and that the demo policy and apps are
  there. If not, a banner lists what's wrong with **Repair now**, which reruns setup with your saved choices. Repair
  keeps your current policy profile and never touches other computers' keys. Test errors caused by a missing key
  show a **Repair setup** button. From a terminal: `aiguard-kit repair`.
- Setup now saves your choices (never secrets), so Repair rebuilds exactly what you set up.
- **Logs tab.** Every AI Guard API call, Detection API scan, LLM proxy call, setup step, policy change and update,
  with the full request and response. It has filters, an **Errors only** view, a **Hide prompt text** switch and
  **Download diagnostics** (a zip of logs and versions to send to the kit owner). Logs are saved in
  `~/.aiguard-se-kit/logs` for 7 days. Keys and secrets are always masked. From a terminal: `aiguard-kit logs`
  (`--errors`, `--follow`).
- **Under the hood** on every result and guided-demo step: the exact request sent to AI Guard and its full JSON
  response, with Copy.
- A Detection API 401 or 403 now explains that this computer's key was deleted or isn't in the rule, and to rerun setup, instead of pointing at ZIdentity permissions.
- The update check asks proxies and CDNs not to answer from cache, so **Check again** always sees a new release.
- **Internet Access (ZIA).** New `aiguard-kit zia …` commands and a console tab (see ZIA.md):
  - `zia setup` creates an `SE-Demo:` ZIA policy through OneAPI and activates it. It covers URL filtering (with a
    tenant-check category), Browser Isolation where licensed, Cloud App Control, File Type Control, DLP, firewall
    with a demo-ports service, and DNS. Every rule is scoped to one test user and labeled `SE-Demo`. Anything the
    tenant lacks is skipped and named. `zia teardown` removes it all and activates.
  - Setup creates the test user for you: `se-demo-traffic@<tenant domain>` as a ZIA Internet & SaaS user, in a
    group and department called `SE-Demo: traffic generator`, with a generated password kept in the keychain.
    `zia password` (or **Show password** in the console) shows it, on this computer only, when you sign in to
    Client Connector. `--via zidentity` creates a ZIdentity user instead (you set its password by hand). `--user`
    uses an existing user. Teardown removes the user, group and department only if the kit created them.
  - `zia preflight` checks ZIA API access, the test user, DLP engines, SSL inspection, Browser Isolation and create
    permission.
  - `zia dashboards` lists which Insights panels are still empty.
  - The traffic generator (`zia check`, `zia traffic`, `zia schedule`) runs on a separate VM with Client Connector
    signed in as the test user. It needs no keys. It sends web categories, 60 SaaS apps, GenAI apps, EICAR over
    HTTP/HTTPS, Safe Browsing test pages, fake-data DLP posts, file uploads and downloads, DNS and unusual ports.
    `zia check` proves it reaches the demo tenant as the test user and that Z-Tunnel 2.0 is on.
- `zia aws` (or **Download CloudFormation template** in the console) writes a template for a Windows generator on
  AWS. It has its own VPC with no inbound ports and Fleet Manager remote desktop. The first-boot script installs uv,
  the kit and, optionally, Client Connector, and registers SYSTEM tasks for traffic every 30 minutes and a check at
  startup. It also adds a weekday start and nightly stop. No AWS CLI or secrets are needed; deleting the stack
  removes it all.
- Traffic rounds only run once ip.zscaler.com confirms the machine goes through Zscaler (`--anyway` overrides).
- Products are now modules beside `aiguard_kit.py` (`PRODUCTS`), sharing credentials, config, console, installer and
  updater. AI Guard behavior is unchanged.
- The scheduler supports more than one job. The AI Guard job keeps its names (`AIGuardSEKit-<profile>`,
  `trickle.log`), and install/uninstall re-point or remove every job.

## 1.7.1
- Fixed: setup failed at "Policy rules" with `applicationCredentialsId … not found` when this computer's saved key
  had been deleted in AI Guard (for example by setup on another computer). Setup now checks every saved key still
  exists, and creates a new one if it doesn't.
- Several computers can now share one demo tenant: each keeps its own keys (named with the computer's name), the
  kit's rules keep every computer's keys, and setup never deletes keys another computer created. Only this
  computer's own key is replaced if its secret is lost.
- A network or permission error while checking keys no longer looks like a deleted key.

## 1.7.0
- **Updates from the console.** An **Updates** button in the header checks the kit's GitHub releases (at most every
  12 hours, or on demand) and turns into **Update to x.y.z** when a new version is out. **Install update** shows the
  release notes, downloads the release, checks its SHA-256 checksum, installs it with the new version's own installer,
  and restarts the console. **Roll back** returns to the previous version.
- `aiguard-kit update` does the same from the terminal (`--check` only checks; `--rollback` goes back one version).
  `status` reports when an update is available.
- Blocked downloads (for example a web-policy block page instead of the file) are detected and explained.
- Releases now include `latest.json`, which the update check reads.
- Windows: shortcuts now start in your home folder, and the launcher no longer re-reads itself after the kit exits,
  so an update can replace the kit safely while the console runs.

## 1.6.2
- Windows: creating the desktop and Start menu shortcuts could fail with an empty error message. The installer
  now runs PowerShell non-interactively with errors caught, checks the shortcut was written, and reports why if not.
- Tests now run on real Windows in CI (shortcut creation and PATH changes included).

## 1.6.1
- The installers detect being run from inside the zip (Windows opens only that one file) and explain how to extract first.

## 1.6.0
- Double-click installers: `Install AI Guard Kit.cmd` (Windows) and `Install AI Guard Kit.command` (Mac). They install
  uv if needed (official installer, then winget or Homebrew), prepare Python 3.12, copy the kit to
  `~/.aiguard-se-kit/app`, add an **AI Guard Demo Console** desktop shortcut (and Start menu entries on Windows),
  add `aiguard-kit` to PATH, and open the console.
- New commands `install` and `uninstall`. Uninstall keeps settings, keys and tenant objects.
- Installing re-points existing scheduled traffic at the installed copy. The schedule's interval and count are now
  remembered.
- The command line is unchanged. New INSTALL.md.

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
