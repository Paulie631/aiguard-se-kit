# Changelog

## 1.8.18
- **ZIA traffic generator on CloudShare (or any Windows VM).** `zia script`, or **Download setup script** on the ZIA
  tab, writes a PowerShell script with the same setup as the AWS template: the verified Client Connector, the kit and
  the traffic schedule. Run it once as Administrator on the VM, then sign in to Client Connector.
- **Client Connector arrives with the kit's app profile.** The AWS template and the script pass the app profile's
  policy token to the installer, so Z-Tunnel 2.0 and the Zscaler certificate are in place before anyone signs in.
  You still sign in once as the test user.

## 1.8.17
- **No terminal window.** The desktop shortcut now starts the console in the background and opens it in the
  browser (Mac: no Terminal; Windows: no command window). Clicking it again brings back the running console instead
  of starting a second one, and the new **Quit** button stops it. `aiguard-kit gui` in a terminal works as before.
- **Setup repair on a Mac: "Can't store password on keychain (-25244)".** macOS won't let the kit update a keychain
  entry saved by an earlier Python (uv moves it on updates). The kit now replaces its own stale entry instead of
  failing, and if even that fails, says exactly which entry to delete.
- **Guided demo: Monitor / Block no longer disappears silently.** If the console couldn't read the AI Guard policy
  (for example, no network when it started), the steps showed no switch and ran without changing the policy. The
  step now says so with a **Retry** link, and opening the Guided demo tab reads the policy again.

## 1.8.16
- **Missing ZIA entitlement:** the console's Fix line under the error now gives the entitlement steps instead of
  a generic hint.

## 1.8.15
- **ZIdentity tenants that entitle only chosen users** (typical with Okta): ZIdentity never sends the kit's test
  user to ZIA without the Internet & SaaS entitlement, and setup used to say "wait and rerun". It now checks the
  user's entitlements and says to assign Internet & SaaS to the group `SE-Demo: traffic generator` (the API can
  read entitlements but not grant them). A rerun afterwards picks up where it left off.
- **AWS generator: remote desktop without single sign-on.** Fleet Manager only offers single sign-on to people
  signed in through IAM Identity Center. The template's new **SetAdministratorPassword** output, ZIA.md and the
  deployment guide give the other way in (set an Administrator password through Session Manager, then User
  credentials). The NextSteps output now names the right Client Connector password for ZIdentity users too.

## 1.8.14
- **The SE deployment guide ships with each release**, as Word and Markdown files stamped with the kit version
  (source: `docs/DEPLOYMENT-GUIDE.md`, also inside the kit zip).
- **ZIA setup messages are now in the Logs tab and diagnostics** (the warnings and manual steps setup shows), not
  only the API calls, so a diagnostics zip tells the whole story.
- **No more red "user_management.add_group failed" on ZIdentity tenants.** That refusal is the expected sign that
  ZIdentity manages users; it's logged as info. The kit remembers it, so setup after a teardown goes straight to
  ZIdentity.

## 1.8.13
- **ZIdentity test users go on `<vanity>.zslogin.net`.** On a domain routed to an identity provider, ZIdentity
  can't set the user's password, so the test user couldn't sign in. Setup now creates it on ZIdentity's own domain
  (`--domain` still overrides). A test user an earlier version created on the company domain is replaced, and
  teardown removes both.
- **Client Connector API that refuses every forwarding profile:** when even the minimal Z-Tunnel 2.0 profile gets
  a bare `400`, setup says so once with the exact names and settings to create by hand, and doesn't retry on later
  runs. Setup and Fix drift now use a forwarding profile that is already Z-Tunnel 2.0, and an app profile that's
  already right, as they are, without writing to them.

## 1.8.12
- **Client Connector forwarding profile: more fallbacks.** A tenant whose profiles carry newer Unified Tunnel
  settings refused every copy with a bare `400`. Setup now also tries without the Unified Tunnel settings, then
  without the ZPA tunnel settings, and finally a minimal profile (a name and Tunnel + Z-Tunnel 2.0 for each network
  type). Each attempt is in the Logs tab.
- **Diagnostics:** long log entries stay valid JSON (they used to be cut mid-line).

## 1.8.11
- **Diagnostics now include the newest log entries.** The zip kept only the first 20,000 characters of each day's
  log, so a morning's entries crowded out the afternoon's setup. It now keeps the newest 5,000 lines per day.
- **ZIA, ZIdentity and Client Connector changes and failures are in the activity log** (Logs tab and diagnostics),
  with the request the kit sent and the error, passwords masked. Reads stay out of the log.

## 1.8.10
- **Client Connector forwarding profile: retries when the copy is refused.** Client Connector's API can answer a
  bare `400` to a forwarding profile copied from the tenant's own (seen with a profile that uses trusted-network
  conditions). Setup now retries without the trusted-network conditions and copied ids, then from the default
  profile's actions switched to Z-Tunnel 2.0, and says which copy it saved. The Windows app profile follows.

## 1.8.9
- **Fixed: Cloud App Control rules left out DeepSeek, Character.AI, Claude, WeTransfer, TeamViewer and others.**
  ZIA lists actions only for apps with fine-grained controls (ChatGPT, Dropbox, Slack…); most apps list none but
  still take the category's basic allow/deny web-use action, as the console shows. Setup now gives those apps that
  basic action, learning its exact name from ChatGPT, Dropbox or Slack instead of guessing. Where the template
  wanted a finer action (blocking uploads), the note says the rule blocks the whole site instead.

## 1.8.8
- **Fixed: no Client Connector profiles when the test user is created in ZIdentity.** Setup skipped the
  `SE-Demo traffic generator` app profile and the Z-Tunnel 2.0 forwarding profile, saying the user "wasn't created
  by the kit". It now scopes them to ZIA's synced copy of the kit's ZIdentity group. ZIdentity syncs that group
  after the test user's first sign-in, so if it isn't there yet, setup says to sign in once and run it again.

## 1.8.7
- **Desktop shortcut with an icon.** The installer's shortcut now has the kit's own icon (blue for the AI Guard
  kit, teal for the ZIA kit). On a Mac it's now an app, **AI Guard Demo Console**, with no `.command` extension; it
  opens the console in a Terminal window as before, and replaces the old `.command` shortcut. The AWS generator's
  **SE-Demo ZIA console** shortcut gets the icon too.

## 1.8.6
- **Rejected OneAPI sign-in.** When the client secret stops working (rotated, deleted, expired, client disabled),
  the kit now says so once, with the fix (Setup > Connect > Use different credentials), instead of a wall of
  `401 Unauthorized - token refresh attempts exhausted` lines from the SDK. `--verbose` still shows them.
- **Tenants whose users are managed in ZIdentity.** ZIA refuses to create users there ("UNMODIFIABLE ...
  OneIdentityUserLogin enabled users will have read only access"). Preflight used to blame the API role's User
  Management access; it now says the users live in ZIdentity, and setup creates the test user in ZIdentity
  automatically (the API client needs ZIAM = Role: Users Admin).

## 1.8.5
- **Exact console menus.** The *AI security end to end* steps point at Data Security > Inline CASB > Shadow IT and
  SaaS/Cloud App Policy (AI & ML Applications) and at Data Security > Inline DLP > Data Loss Prevention. The Store Prompts/Responses check points at AI Guard >
  Tenant Settings > Security. The README and ZIA.md give the
  API client's exact roles per service (ZGUARD, ZIA, ZCC, ZINSIGHTS, and ZIAM for SAML tenants) and the ZIA API
  role path (Administration > Role Management > Internet & SaaS > Add API Role).

## 1.8.4
- **AWS traffic generator installs Client Connector for you.** The CloudFormation template now points at the kit's
  copy of the Windows installer (4.10.0.477, on the `zcc-installer` release). The instance installs it only if its
  SHA-256 matches the pinned value and it carries a valid Zscaler code signature; any installer you supply gets the
  signature check too. `--zcc-url none` (or `none` in the console field) installs by hand as before.

## 1.8.3
- **Guided demo: shorter policy wait.** After a switch the kit re-checks the step's prompt every few seconds and
  ends the wait as soon as AI Guard enforces the new policy, with 30 seconds as the upper limit. The checks are
  logged under the user `kit-policy-check`, so they're easy to filter out in Insights.
- **Guided demo: quieter policy wait.** The countdown is on the Run button ("Run step · 13s") in place of a
  line of text; press Run early and the result area shows "Applying policy… 13s" before it runs.

## 1.8.2
- **Guided demo: the switch just says Block,** and switches to the smallest profile that covers what the step tests
  (Block attacks for injection and toxicity, Block attacks + data for secrets and PII), or the step's own level when
  it sets a higher one. Steps whose prompt triggers nothing a policy can block no longer offer the switch.

## 1.8.1
- **Guided demo: Monitor / Block on every step.** Run a step in Monitor, flip to Block and run it again; the recap
  lists both results with the policy each ran under.
- **Guided demo: no more 30-second countdown.** A step switches the policy when you open it, so the change applies
  while you talk. Run waits only for whatever is left of the ~30 seconds AI Guard needs.
- **AI security end to end:** the ZIA show-steps point at the new console's menus (Analytics > Data Security > Inline
  CASB / Inline DLP, Internet Access > Dashboards), with the older Analytics paths noted.

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
