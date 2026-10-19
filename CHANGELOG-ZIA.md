# Zscaler ZIA SE Demo Kit: changelog

The ZIA kit is a separate edition of the SE demo kit. It installs beside the AI Guard kit (its own folder,
shortcut and `zia-kit` command) and shares its saved OneAPI login. Releases are tagged `zia-v<version>`.

## Unreleased
- Client Connector forwarding profile: more fallbacks, ending with a minimal Z-Tunnel 2.0 profile (see AI Guard
  kit CHANGELOG). Diagnostics keep long entries as valid JSON.

## 0.2.6
- Diagnostics include the newest log entries, and ZIA / ZIdentity / Client Connector changes and failures are
  logged with the request sent (see AI Guard kit CHANGELOG).

## 0.2.5
- Client Connector forwarding profile: setup retries plainer copies when Client Connector refuses the first one
  with a bare 400 (see AI Guard kit CHANGELOG).

## 0.2.4
- Fixed: Cloud App Control rules left out apps that list no actions of their own (DeepSeek, Claude, WeTransfer,
  TeamViewer…); they now get the basic allow/deny web-use action (see AI Guard kit CHANGELOG).

## 0.2.3
- Fixed: Client Connector profiles weren't created when the test user is created in ZIdentity (see AI Guard kit
  CHANGELOG).

## 0.2.2
Brings the ZIA kit up to date with AI Guard kit 1.8.1–1.8.7:
- **Desktop shortcut with its own icon** (teal). On a Mac it's now an app, **Zscaler ZIA Demo Console**, with no
  `.command` extension.
- **Tenants whose users are managed in ZIdentity:** setup creates the test user in ZIdentity automatically instead of
  failing with "UNMODIFIABLE … read only access" (the API client needs ZIAM = Role: Users Admin).
- **One clear message when Zscaler rejects the OneAPI sign-in**, instead of a wall of SDK retry errors.
- **AWS generator installs Client Connector 4.10.0.477 itself**, checked by SHA-256 and Zscaler signature.
- **Guided demo:** Monitor / Block on each step, no 30-second countdown (the wait ends as soon as the policy is
  enforced), and the exact new-console menus for the ZIA show-steps.

## 0.2.1
- Fixed: the ZIA kit's console hid the AI Guard **Policy** menu (Monitor, Block attacks, … and **Custom…**, where
  you choose Detect or Block per detector) and the Insights link, even when AI Guard is set up on that computer.
  They're hidden now only until AI Guard is set up.

## 0.2.0
- **Drift check.** `zia status` compares the tenant with what setup made: rules missing, disabled or out of order,
  rules no longer scoped to the test user, Client Connector profiles not on Tunnel + Z-Tunnel 2.0 or behind another
  profile, and objects named like the kit's that aren't (reported, never touched). `zia status --fix` repairs the kit's
  own objects; the console has **Check for drift** and **Fix drift**.
- **Demo readiness.** `zia-kit ready` (and **Demo readiness** in the console) checks the demo policy, Insights data,
  the generator's last round (on the generator), the AWS stop schedule, and reminds you to start traffic at least
  3 days before a demo.
- **Guided demo refresh** (the ZIA kit carries the full console): structured talk tracks with presenter notes,
  sourced "In the news" cards, OWASP Top 10 for LLM Applications (2025) tags, a recap with a copy button, industry
  storylines and *AI security end to end* (ZIA + AI Guard).
- **Rolling back** is documented, and installing an older release over a newer one is tested.

## 0.1.7
- Fixed: the kit's `SE-Demo Z-Tunnel 2.0` forwarding profile kept your default profile's "Tunnel with Local Proxy"
  action, so Client Connector stayed on Z-Tunnel 1.0. Setup now sets the action to **Tunnel** with **Z-Tunnel 2.0**,
  or, if you already have a forwarding profile set that way in the console, copies its settings. Run `zia setup`
  again, then turn Client Connector off and on (or log out and back in) on the traffic generator.

## 0.1.6
- Setup reads the Client Connector profiles back after saving them and prints what ZCC stored: Z-Tunnel 2.0 per
  network type, and the app profile's order, groups, forwarding profile and certificate setting.
- The runbook walks through installing Client Connector by hand on the AWS generator.

## 0.1.5
- AWS template: the instance can install Client Connector from **your own S3 bucket**. Give
  `zia-kit aws --zcc-url s3://bucket/key` (or paste `s3://bucket/key` into the console's installer field). The stack
  lets the instance read only that object, so there's no presigned link to expire.

## 0.1.4
- Fixed: setup created the demo rules of each kind in reverse order, so `SE-Demo: Monitor PII and PCI` (allow) sat
  above `SE-Demo: Block card numbers` and DLP never blocked. Setup now keeps each kind in the template's order and
  puts rules from earlier versions back in order. Run `zia setup` again to fix an existing tenant.

## 0.1.3
- Setup now turns on **SSL inspection for the test user** (`SE-Demo: Inspect test user`), so EICAR over HTTPS, DLP
  and Cloud App Control show up. A `SE-Demo: AWS SSM bypass` rule above it never decrypts AWS Systems Manager
  traffic, so inspection can't cut off the AWS traffic generator's remote desktop.
- Setup now gives the test user's group its own **Client Connector Windows app profile** (`SE-Demo traffic
  generator`): a copy of your default Windows profile that installs the Zscaler root certificate and uses
  `SE-Demo Z-Tunnel 2.0`, a copy of its forwarding profile switched to Z-Tunnel 2.0, so firewall and DNS rules
  apply. Your own profiles aren't changed. If the API client has no Client Connector access, setup says so and
  the ZIA policy still applies. Teardown removes both profiles.
- The console's header shows the ZIA kit's name, and AI Guard-only controls are hidden in the ZIA kit.

## 0.1.2
- Generator check: a blocked HTTPS site now counts as **blocked** when ZIA answers with its block page on a
  Zscaler-signed certificate the machine doesn't trust. Before, it showed as `error:SSLError`.
- AWS template: the person who signs in over remote desktop can now open the SE-Demo ZIA console. Before, it
  stopped with "Could not acquire lock ... Access is denied".

## 0.1.1
- The zip now unpacks to a **zscaler-zia-kit** folder, and the installer's messages name it.
- Fixed: at the end of installing, the installer opened the console from the AI Guard kit's folder instead of
  the ZIA kit's (`~/.aiguard-se-kit/app-zia`). On a machine with only the ZIA kit, that last step failed.
- If you installed 0.1.0, install 0.1.1 from the zip once: 0.1.0's Update button can't read the new folder name.
  From 0.1.1 on, updates install from the console.

## 0.1.0
First preview. Fills ZIA and Insights dashboards in a demo tenant: an SE-Demo policy for one test user, plus a
traffic generator that runs on a separate Windows machine.
- **Demo policy.** `zia-kit setup` runs preflight checks, then creates the policy through OneAPI and activates it.
  - What it creates: URL filtering (block, caution and tenant-check rules), Browser Isolation where licensed, Cloud
    App Control using the tenant's own action names, File Type Control, DLP, firewall (demo ports) and DNS.
  - Every rule is scoped to the test user, labeled, and placed above your own rules.
  - Anything the tenant doesn't have is skipped and named in the review.
  - Names ZIA rejects (for example a `:` in category and label names) are retried in a safe form.
  - Teardown removes only what the kit created.
- **Test user, created for you.** `se-demo-traffic@<your domain>` is created where Client Connector signs users in:
  - Hosted DB tenants: a ZIA user with a generated password kept in the keychain. `zia-kit password` shows it, on
    that computer only.
  - SAML tenants: a ZIdentity user.
  - Preflight checks the API role can manage users before setup changes anything.
- **Traffic generator** (`zia-kit traffic`, `zia-kit schedule install`).
  - Sends: 40+ URL categories, 60 SaaS apps, 18 GenAI apps, EICAR over HTTP and HTTPS, Safe Browsing test pages,
    fake-data DLP posts, file uploads and downloads, DNS and unusual ports.
  - Safe test data only.
  - Sends nothing unless ip.zscaler.com confirms the traffic goes through Zscaler.
- **`zia-kit check`** proves the generator reaches the demo tenant as the test user (a tenant-only block), and
  checks SSL inspection, EICAR, DLP and Z-Tunnel 2.0.
- **`zia-kit dashboards`** lists which Insights panels are still empty.
- **`zia-kit aws`** writes a CloudFormation template for a Windows generator.
  - The stack: its own VPC, no inbound ports, and Fleet Manager remote desktop.
  - First boot installs the kit and, optionally, Client Connector, then schedules the traffic.
  - A weekday start and nightly stop are optional.
- **Console:** the Internet Access (ZIA) tab does all of the above.
