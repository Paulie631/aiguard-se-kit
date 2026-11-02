# AI Guard + ZIA SE Demo Kit: Deployment Guide

*Versioned with the kit: the copy attached to each GitHub release (Word and Markdown) is stamped with the kit version it describes. The source is `docs/DEPLOYMENT-GUIDE.md` in the repo.*

## Overview

By the end of this guide you have AI Guard and ZIA dashboards full of demo data in your own demo tenant, and a browser console that runs a scripted customer demo. Plan about 1.5 hours of hands-on work, then let the traffic generator run for **3 days** before the first ZIA demo.

| Piece | Runs on | What it does |
| --- | --- | --- |
| SE Demo Kit (`aiguard-kit`) | Your laptop | Creates the `SE-Demo:` objects in AI Guard and ZIA, runs tests, hosts the console and Guided demo |
| Traffic generator | A separate Windows VM (a copy of your team's CloudShare image, an AWS stack, or a lab VM) | Sends safe test traffic through Client Connector as a test user, so ZIA logs and dashboards fill |
| Your demo tenant | Zscaler cloud | Holds the objects; everything the kit creates is named `SE-Demo` and removed by teardown |

**Golden rules**

- **Demo and eval tenants only.** Never point the kit at a customer or production tenant.
- **Never run the traffic generator on your corporate laptop.** Its Client Connector belongs to a different tenant, and the traffic includes blocks, the EICAR test file and fake card numbers.
- **Safe test data only.** The kit uses EICAR, Google's Safe Browsing test pages and generated fake cards and SSNs. Never add real malware or real personal data.
- **Keep secrets out of chat, email and tickets.** API secrets and the test user's password live in your computer's keychain; the console shows them only when you ask.
- **The kit only touches its own objects.** Anything you made by hand is reported, never changed or deleted.

## Prerequisites

Tick every box before you start; most setup failures trace back to one of these.

**Tenant and access**

- [ ] A Zscaler **demo or eval tenant** you administer, signed in at console.zscaler.com (the Experience Center).
- [ ] AI Guard licensed in that tenant. In **Administration > Subscription > Internet & SaaS**, look for `AI_GUARD_PUBLIC_GENAI`.
- [ ] ZIA licensed, with Cloud App Control and DLP (for the ZIA part).
- [ ] Rights to create API clients and API roles in **Administration**.
- [ ] Your tenant's **vanity domain**: the `acme` in `acme.zslogin.net`.
- [ ] Your tenant's **user domain** (for example `pyite.buzz`), used for the test user. Not needed if your users sign in with SAML or are managed in ZIdentity: the kit then uses `<vanity>.zslogin.net`.

**Your laptop (Windows or Mac)**

- [ ] Downloads from `github.com` and `astral.sh` allowed. The installer fetches uv and Python from there.
- [ ] Optional: an **OpenAI or Anthropic API key** with credit, to show real model replies through the AI Guard proxy. Without one, everything runs on the free Detection API.

**Traffic generator (for ZIA)**

Pick one:

- [ ] **CloudShare, from your team's image (fastest):** access to the CloudShare template your team built (or build it once, Part 5).
- [ ] **AWS:** an AWS account you may use for demos, with rights to create CloudFormation stacks, a VPC, an IAM role and an EC2 instance. Cost is about a Windows t3.medium for working hours.
- [ ] **Your own VM:** Windows Server 2019 or 2022 (or Windows 10/11), with remote desktop, internet access that doesn't go through a corporate proxy, and no other Zscaler tenant's Client Connector on it.
- [ ] Nothing else for Client Connector: all three options install the kit's verified copy. Only if that's skipped, the **Windows installer (.msi) from your demo tenant**, never from the corporate tenant.

**Calendar**

- [ ] At least **3 days** between starting traffic and your first ZIA demo. Insights only reports on windows that ended a day or two ago.

## Part 1: Create the API client (10 minutes)

The kit talks to your tenant through one OneAPI client with access to AI Guard, ZIA and Client Connector. You create it once.

1. **Create a ZIA API role.**
   1. Open the **≡** menu and choose **Administration > Role Management > Internet & SaaS**.
   2. Click **Add API Role** and name it `SE-Demo kit`.
   3. Set **Full Access** for every area. This is a demo tenant, and the kit creates URL filtering, Cloud App Control, File Type Control, DLP, firewall, DNS and SSL inspection rules, creates the test user and activates changes.
   4. Save.
2. **Create the API client.**
   1. Go to **Administration > API > OneAPI > API Clients** and click **Add API Client**.
   2. **Client** tab: name it `SE-Demo kit` and leave **Status** on. Under **Client Authentication**, keep **Secret** selected and click **Add**. Copy the secret now; it's shown only once and expires after a year.
   3. **Resources** tab: each Zscaler service is listed with its roles. Pick these and leave the rest on **None**:

| Service (as listed) | Role | Used for |
| --- | --- | --- |
| ZGUARD (AI Guard) | Role: Administrator | Policy, apps, keys, rules |
| ZIA | the `SE-Demo kit` role from step 1 | ZIA rules, test user, activation |
| ZCC | Role: Super Admin | Z-Tunnel 2.0 and certificate profiles for the generator |
| ZINSIGHTS | Role: ZINSIGHTS Reader | The dashboard and readiness checks |
| ZIAM (if users sign in with SAML or are managed in ZIdentity; if unsure, set it) | Role: Users Admin | Creating the test user in ZIdentity |

Then click **Update** (or **Save**) and copy the **Client ID** from the client list.

3. **Note your vanity domain:** the `acme` in `acme.zslogin.net`, the address you sign in at.

> If you already have an API client for the kit, edit it and add any missing resource in step 2.3 instead of making a new one.

## Part 2: Install the kit on your laptop (5 minutes)

One install gives you the console, the AI Guard demo and the ZIA admin commands.

1. Download **`aiguard-se-kit-<version>.zip`** from [the latest release](https://github.com/Paulie631/aiguard-se-kit/releases/latest). If your mail filter strips the full zip, use the `-email` version and the command line.
2. **Extract it.** On Windows, right-click the zip > **Extract All**. Running the installer from inside the zip won't work.
3. Open the `aiguard-se-kit` folder and double-click the installer:
   - Windows: **Install AI Guard Kit.cmd**
   - Mac: **Install AI Guard Kit.command**
4. Answer the one-time security prompt:
   - Windows: **Run**, or **More info > Run anyway**.
   - Mac: right-click the installer > **Open > Open**, or **System Settings > Privacy & Security > Open Anyway**.
5. Press a key (Windows) or Return (Mac). The installer fetches uv and Python (1–2 minutes the first time), copies the kit to `~/.aiguard-se-kit/app`, adds an **AI Guard Demo Console** desktop shortcut and the `aiguard-kit` command, then opens the console in your browser. The console runs in the background, so you can close the installer window.
6. From now on, start it from the **AI Guard Demo Console** shortcut. It runs in the background (no terminal window) and opens in your browser; the first start after an install or update can take up to a minute. Click the shortcut again to bring it back, and **Quit** (top right) to stop it. If nothing opens, run `aiguard-kit gui` in a terminal to see why.

The console runs at `http://127.0.0.1:8765` and only on your machine. You can delete the extracted folder afterwards.

## Part 3: Set up AI Guard (15 minutes)

The console's **Setup** tab walks you through five screens. Nothing changes in the tenant until you click **Create it**.

1. **Connect.** Enter your **Vanity domain** (`acme`, not the full URL), **Client ID** and **Client Secret**, then **Save and test**. The secret goes into your computer's keychain.
2. **Preflight checks.** Tick **Also test create permission** and run the checks. Fix anything red before continuing; each check has a **How to verify** panel. Common ones:
   - Detection API unreachable: usually SSL inspection or DNS on your network.
   - OneAPI 401: the API client is missing AI Guard access (Part 1, step 2.3).
   - User-based rules ahead of the kit's: another AI Guard rule may grab demo traffic. Note it; you'll check verification in step 5.
3. **Choices.**
   - **Prefix:** keep `SE-Demo:` unless you share the tenant with another SE.
   - **Providers:** for OpenAI and Anthropic, reuse a key the tenant already has, paste a new one, or skip (detection-only).
   - **Starting policy:** choose **Monitor**. The Guided demo switches it per step.
4. **Review**, then **Create it**. Setup creates the policy `SE-Demo: Test all`, the apps `SE-Demo: OpenAI App` and `SE-Demo: Anthropic App`, their keys and two rules placed after your own. If anything fails partway, **Retry** fills in the rest.
5. **Verify.** Setup scans through each app and waits up to a minute for new keys to activate. If it says traffic was "handled by '…' instead", another rule matched first: disable or reorder it in the AI Guard console, then **Retry checks**.
6. Click **Populate every dashboard now**. This sends the full test library once.
7. **Keep dashboards fresh (optional).** In a terminal: `aiguard-kit schedule install` sends a small batch every hour while your laptop is on.
8. **Check the result.** After 10–15 minutes, open the AI Security console (**≡ > AI Security**, which opens in a new tab) and go to **AI Guard > Insights**. Every detector panel should have data.
9. **One AI Guard setting to check by hand:** in the AI Security console, go to **AI Guard > Tenant Settings**, open the **Security** tab and turn on **Store Prompts/Responses**, so prompt text shows in Insights. The same tab has **Enable Data Sharing for AI Training**: fine to leave on in your demo tenant, but never switch it on in a customer's tenant without their agreement. The API can't read or set either setting, so the kit can't check them for you.

## Part 4: Set up the ZIA demo policy (10 minutes)

The kit creates ZIA rules that apply **only to one test user**, so the rest of the tenant is unaffected. Do this on your laptop, in the console's **Internet Access (ZIA)** tab, section **1 · Demo policy**.

1. **Test user.** Click **Create one for me**. The kit creates `se-demo-traffic@<your user domain>` as a ZIA Internet & SaaS user, in the group and department `SE-Demo: traffic generator`, with a generated password saved in your keychain. If your tenant's users sign in with SAML or are managed in ZIdentity, the kit instead creates `se-demo-traffic@<vanity>.zslogin.net` in ZIdentity (an identity provider such as Okta can't take over that domain). ZIdentity's API can't set passwords, so set one once in Administration > Authentication > Directory > Users, and skip Show password. If setup says the user lacks the **Internet & SaaS** entitlement, assign that entitlement to the group `SE-Demo: traffic generator` in ZIdentity and run setup again.
   - Never use your own account. To use an existing dedicated user, type its User ID instead.
2. Click **Run checks** (preflight). It confirms ZIA API access, how users sign in (Hosted DB with Form-Based is the usual demo setup), and what your tenant has licensed. Fix anything red.
3. Click **Create or update policy**, read the review, and confirm. The kit creates and activates:
   - URL filtering, Cloud App Control (allow mainstream GenAI, block risky GenAI), File Type Control, DLP (block 5+ card numbers), firewall (block TCP 23, 2222, 4444, 8888), DNS and SSL inspection rules, all named `SE-Demo:` and placed above your own rules.
   - A Client Connector app profile `SE-Demo traffic generator` and forwarding profile `SE-Demo Z-Tunnel 2.0`, for the test user's group only. They install the Zscaler root certificate and use Z-Tunnel 2.0. If setup says the Client Connector API refused the forwarding profile, create both by hand with those exact names (see Troubleshooting), then click Fix drift.
4. Click **Show kit objects** to see what was made, and **Check for drift** to confirm it all matches (no findings expected).
5. Click **Show password** and keep the window open for Part 5. Don't copy it anywhere else.

Prefer a terminal? `aiguard-kit zia preflight`, then `aiguard-kit zia setup`, then `aiguard-kit zia password`.

## Part 5: Build the traffic generator (20 minutes)

ZIA dashboards fill only from real traffic, so a separate Windows machine browses as the test user through Client Connector. Pick one:

- **Option A: CloudShare, from your team's image.** Fastest: deploy a copy, paste a setup code, done.
- **Option B: AWS CloudFormation.** One stack, started and stopped on a weekday schedule.
- **Option C: CloudShare or any Windows VM, with the setup script.** When there's no team image yet.

### Option A: CloudShare, from your team's image

**Use the image (each SE, about 5 minutes):**

1. In CloudShare, create an environment from your team's **SE-Demo traffic generator** template.
2. On your laptop, on the console's ZIA tab, click **Copy setup code** (terminal: `aiguard-kit zia setup-code`). The code names your test user, your Zscaler cloud and the kit's Client Connector app profile. It holds no password, but keep it within your team.
3. Connect to the copy and sign in. The **SE-Demo set up this generator** window opens on its own. If it doesn't, double-click that shortcut on the desktop. Paste the code and press Enter. The setup:
   - gives the copy its own computer name, `SEDEMO-xxxxxx`, so no two copies look like one device to Client Connector or Endpoint AI;
   - installs Client Connector for your tenant, with the kit's app profile;
   - schedules a traffic round every 30 minutes, then restarts.
4. Write down the new name (it's shown before the restart and saved in `C:\SE-Demo\generator.json`). You need it for Endpoint AI.
5. Continue at **Sign in to Client Connector** below.

If the setup stops (a mistyped code, say), nothing is half-done: it runs again from the shortcut or at the next sign-in. Its log is `C:\SE-Demo\first-logon.log`.

**Build the image (once per team, about 30 minutes):**

1. In CloudShare, create an environment with a **Windows Server 2022** VM (2019 works too) that has direct internet access.
2. On your laptop's ZIA tab, click **Download image build script** (terminal: `aiguard-kit zia image`). It holds no tenant settings, so anyone on the team can make it.
3. Upload it to the VM (CloudShare's **File Upload** puts it in `C:\Uploads`). Open PowerShell **as Administrator** and run it with the path in quotes. Browsers add `(2)`, `(3)` to repeat downloads, and PowerShell misreads those without quotes:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "C:\Uploads\se-demo-generator-image-build.ps1"
   ```
   About 10 minutes; progress in `C:\SE-Demo\image-build.log`.
   - It downloads the Client Connector installer and keeps it only if its SHA-256 matches and it's signed by Zscaler. It **doesn't install it**: each copy installs it for its own tenant.
   - It adds uv, the kit, the traffic and Endpoint AI wrappers, the desktop shortcuts and the one-time setup.
4. Don't run **SE-Demo set up this generator** and don't sign in to Client Connector on this VM. If the setup window opens when you sign in again, close it.
5. Shut the VM down from Windows, save it in CloudShare as a template, and share it with your team.

The Setup tab's manual steps include this as the optional step **Build the CloudShare generator image (once per team)**.

### Option B: AWS CloudFormation

1. **Download the template.** In the console's ZIA tab, section **2 · Traffic generator**, click **Download CloudFormation template**. It saves `se-demo-zia-generator.cfn.json` to your Downloads folder, already filled in with your cloud, domain and test user.
2. **Create the stack.**
   1. Sign in to the AWS console and pick a US region.
   2. Go to **CloudFormation > Create stack > With new resources (standard)**.
   3. Choose **Upload a template file**, select the file, then **Next**.
   4. Stack name: `se-demo-zia-generator`. Keep the default parameters.
   5. Click **Next** twice, tick the IAM acknowledgement, then **Submit**.
   6. Wait for **CREATE\_COMPLETE** (about 5 minutes), then another 10 minutes for first boot to install the kit.

   The stack makes its own small VPC, a security group with no inbound ports, an SSM role, a Windows Server 2022 t3.medium, and a weekday 7am–9pm New York start/stop schedule.
3. **Connect.** Open the stack's **Outputs** tab, follow **ConnectWithFleetManager**, then **Node actions > Connect > Connect with Remote Desktop**. Fleet Manager offers three ways in. Use the first one you have:
   - **Single sign-on:** only shown if you signed in to the AWS console through IAM Identity Center (AWS SSO). No password needed.
   - **User credentials** (no single sign-on, no rebuild): go to **Systems Manager > Session Manager > Start session**, pick the instance, and run the command in the stack's **SetAdministratorPassword** output:
     ```powershell
     $p = Read-Host -AsSecureString 'New password'; Set-LocalUser -Name Administrator -Password $p; Enable-LocalUser Administrator
     ```
     Type a strong password at the prompt (it isn't echoed, and never goes in chat or email). Then connect with **User credentials** as `Administrator`.
   - **Key pair:** if you set the stack's `KeyPairName` parameter (adding it later replaces the instance), choose **Key pair** and upload the `.pem` file.
4. Continue at **Sign in to Client Connector** below.

> Account won't let stacks create a VPC or IAM roles? Set `NetworkMode` to `ExistingSubnet` (with a subnet that doesn't route through corporate inspection) and/or `ExistingInstanceProfile` to a profile with `AmazonSSMManagedInstanceCore`, plus `WeekdaySchedule` = `false`.

### Option C: CloudShare or any Windows VM, with the setup script

1. Create a Windows Server 2019 or 2022 (or Windows 10/11) VM with direct internet access and no other tenant's Client Connector. In CloudShare, start an environment from a Windows Server template.
2. On your laptop, in the console's ZIA tab, section **2 · Traffic generator**, click **Download setup script (CloudShare / any Windows VM)**. It saves `se-demo-zia-generator-setup.ps1`, filled in for your tenant. (Terminal: `aiguard-kit zia script`.)
3. Copy the file to the VM. CloudShare's **File Upload** puts it in `C:\Uploads`, and a repeat download may be named `se-demo-zia-generator-setup(3).ps1`. Open PowerShell **as Administrator** and run it with the full path in quotes, using the file's actual name:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "C:\Uploads\se-demo-zia-generator-setup.ps1"
   ```
   Signed in as the built-in `Administrator` account, right-clicking the file and choosing **Run with PowerShell** also works. It installs the verified Client Connector (with the kit's app profile), the kit, the 30-minute traffic schedule and the desktop shortcuts, like the AWS stack. Progress: `C:\SE-Demo\setup.log` (the **SE-Demo setup log** shortcut), about 10 minutes. It ends with "Setup finished".
4. Continue below. Traffic only runs while the VM is running, so check CloudShare's suspend policy before a demo.

### Sign in to Client Connector (every option)

1. **Get Client Connector onto the machine.**
   - **The team image, AWS or the setup script:** it's already installed, with the kit's app profile (Z-Tunnel 2.0 and the Zscaler certificate) loaded before you sign in. The stack downloads Client Connector 4.10.0.477 from the kit's `zcc-installer` release and installs it only if the file's SHA-256 matches and it's signed by Zscaler. If `C:\SE-Demo\setup.log` (the **SE-Demo setup log** shortcut) says it was skipped, install by hand as below.
   - **Your own VM, or the AWS install was skipped:** in Edge, sign in to your **demo tenant's** admin console, download the latest Windows 64-bit .msi from the Client Connector App Store and run it with the defaults. Never use an installer from the corporate tenant.
2. Sign in to Client Connector as the test user (`se-demo-traffic@<your user domain>`) with the password from Part 4. On a ZIdentity tenant, sign in as `se-demo-traffic@<vanity>.zslogin.net` with the password you set in ZIdentity.
3. Open Client Connector > **More > Update Policy**. This picks up the kit's app profile: the Zscaler certificate and **Z-Tunnel 2.0**.
4. Confirm the Client Connector status shows **Tunnel Version v2.0**. If it still says v1.0, see Troubleshooting.

## Part 6: Start traffic and verify (10 minutes)

On the generator, run the machine check first; traffic rounds only start once it passes.

1. On the generator's desktop, open **SE-Demo ZIA console > Internet Access (ZIA)** and click **Check this machine**. (Terminal: `zia-kit zia check`.)
2. Every row should pass:

| Check | Proves | If it fails |
| --- | --- | --- |
| Client Connector running | It's installed and started | Install and sign in (Part 5) |
| Traffic goes through Zscaler | ip.zscaler.com sees the right cloud | Turn on Internet Security in Client Connector |
| SSL inspection | wikipedia.org's certificate is issued by Zscaler | Rerun **Create or update policy** on your laptop, then **Update Policy** here |
| Demo tenant, as the test user | www.example.com is blocked (only the kit's rule does that) | Wrong tenant or user, or changes not activated |
| URL filtering | A gambling site is blocked | Rerun the policy setup |
| Malware protection | EICAR over HTTP and HTTPS is blocked | HTTPS needs SSL inspection |
| DLP | A post of fake card numbers is blocked | SSL inspection and the DLP rule |
| Z-Tunnel 2.0 | TCP 2222 is reset by the demo firewall rule | Client Connector > **Update Policy**; check Tunnel Version v2.0 |

3. Click **Send one round** to send traffic now instead of waiting. On AWS a round also runs every 30 minutes on its own.
4. **See it in ZIA within minutes.** In the Zscaler console:
   - **Internet Access > Dashboards > Web Overview**: `se-demo-traffic` appears under **Top Users**.
   - **Internet Access > Dashboards > SaaS/Cloud Apps**, **Firewall Overview** and **DNS Overview** start to fill.
   - **Analytics > Cybersecurity**: threats blocked (EICAR and test phishing pages).
   - **Analytics > Data Security > Inline DLP** and **Inline CASB**: DLP blocks and AI app usage. For AI apps specifically, **≡ > Data Security > Inline CASB > Shadow IT** and **GenAI Security Report**.
5. **Insights takes about 2 days.** Back on your laptop, the ZIA tab's **Check Insights** button lists which Insights panels are still empty.

## Optional: Endpoint AI Security (20 minutes)

Shows an AI coding agent on the generator trying something risky: Endpoint AI records it in **Monitor** and stops it in **Block**. There are 44 scenes in nine risk categories (secrets, destructive actions, credentials, supply chain, agent misuse, data exfiltration, cloud, developer workflow, machine and OS). Full runbook: ENDPOINT-AI.md.

Two machines do this: your **laptop** holds the Endpoint AI credential and shows the Live feed; the **generator** runs the scenes. The kit refuses to run scenes on the machine that holds the credential.

1. **Create the API credential** (Endpoint AI console, **Administration > API Access**): name `se-demo-kit`, role **Admin**, expiry 90 days. Copy the client_id and the secret (`sqrx_sk_…`, shown once). Note the region in the API host: the `use2` in `https://use2.api.<domain>`.
2. **Connect** on the kit's **Endpoint AI** tab on your laptop: console domain, region, client_id, secret, then **Save and test**.
3. **Turn on the Endpoint AI agent** for the generator's app profile in the Client Connector portal, and check the generator shows under **Administration > Devices**.
4. **Name the generator.** Under **Generator hostnames**, enter its computer name: `SEDEMO-xxxxxx` for a copy of the team image, `EC2AMAZ-…` on AWS (the kit also finds it by the test user).
5. **Check the rules.** Click **Check rules with Endpoint AI** under Per-rule actions. Every rule should show *accepted*. A rejected rule shows Endpoint AI's reason; set it to **Allow (rule off)** and tell the kit owner.
6. **Create the demo policy**: **Create or update**. The kit makes the device group `SE-Demo: traffic generator` (only the generator) and the policy `SE-Demo: Agentic Guardrails`, assigned to that group only. It checks the rules first and changes nothing if any is rejected. Run it again after each kit update that adds scenes, to add their rules.
7. **On the generator**, as the Windows user who'll run the demo, double-click **SE-Demo install Claude Code**, then sign in to Claude Code once (`claude` in a terminal; or `C:\SE-Demo\eai.cmd demo --set-key` for an API key).
8. Open the generator's **Endpoint AI** tab, click **Demo set** (one scene per risk category), then **Run**. Watch the **Live feed** tab on your laptop.

Endpoint AI stops a blocked action on the generator straight away, but its events take a few minutes to appear, in its own console as well as on the Live feed. The line under the feed's status shows how far behind Endpoint AI is.

The scenes use only safe test data: AWS's published example key (`AKIAIOSFODNN7EXAMPLE`), decoy files in a throwaway folder the kit creates and puts back after every scene, and commands that are only printed, never run. **Build PDF** on the tab gives you the Executive Brief as a leave-behind.

## Part 7: Before every demo (5 minutes)

Run the readiness check the morning of the demo, and give yourself time to fix what it finds.

- [ ] **3+ days before:** the generator is running (AWS schedule on, or `zia schedule` on your VM).
- [ ] **Morning of:** start the console and click **Demo readiness** on the Guided demo tab (or run `aiguard-kit ready`). It checks:
  - the AI Guard policy is back in **Monitor**;
  - the app keys work;
  - ZIA drift: kit rules missing, disabled or out of order, or Client Connector profiles off Z-Tunnel 2.0;
  - recent traffic rounds and Insights panels with data;
  - the AWS start/stop schedule, so the generator isn't asleep during the demo.
  - Endpoint AI (if set up): the credential isn't about to expire, the generator is online, the policy is assigned, and demo events arrived in the last 24 hours.
- [ ] **Endpoint AI:** on your laptop, switch the Live feed's policy to **Monitor**, run the **Demo set** once on the generator, and wait until its events show on the Live feed (a few minutes), so there's recent activity to show.
- [ ] **Drift found?** On the ZIA tab, click **Check for drift**, then **Fix drift**. It only changes the kit's own objects.
- [ ] **Demo after 9pm New York or on a weekend?** Start the AWS instance by hand in the EC2 console.
- [ ] **Clean up the screen.** Close tabs with secrets, turn off **Show talk track** if you'll share the whole screen, and update the kit (**Updates** button).
- [ ] **Filter `kit-policy-check` out of AI Guard Insights** before showing it. The Guided demo logs a few check scans under that user each time it switches the policy.

## Running the demo

Open the console's **Guided demo** tab, pick a storyline and follow the steps; the screen tells you what to say and what to show.

| Storyline | Length | Use when |
| --- | --- | --- |
| AI Guard in 8 steps | \~8 min | First meeting, general audience |
| Data protection | 4 min | DLP or privacy-led conversation |
| Blocking, step by step | 5 min | Showing granular policy, Monitor to Block everything |
| Healthcare / Financial services / Legal | 5–6 min | Industry audiences |
| AI security end to end (ZIA + AI Guard) | \~10 min | Platform story: discover and control AI apps with ZIA, then protect your own AI apps with AI Guard. Needs Parts 4–6 |

**On each step**

1. Read the **Say** line (the bar on the left); **Show** says what to point at. Tick **Presenter notes** for the "so what", a discovery question and objection handling.
2. **Run step** sends the prompt. Turn on **Send to the model (LLM proxy)** and pick an app to show the real model reply, or AI Guard's block message.
3. **Monitor / Block:** on steps that test a blockable detector, run it in **Monitor** (logged, user unaffected), click **Block**, and run it again (stopped). Block uses just enough policy for that step.
4. The policy switches as soon as you open a step. While it applies, the button reads **Run step · 12s**; keep talking, or press it and it waits.
5. **Show-in-console steps** (ZIA end to end): click **Open the ZIA console** and go where the step says, for example **Data Security > Inline CASB > Shadow IT**. Then **Mark as shown**.
6. On the last step, click **Recap**, then **Copy for the follow-up email**.

**Keys:** ← → move between steps, Enter runs the step.

**Endpoint AI demo (about 10 minutes, two machines)**

1. On your laptop, open the **Live feed** tab with the policy switch (top right) on **Monitor**.
2. On the generator, click **Demo set**, then **Run**. Each action runs and is recorded. While the events arrive, talk through what the agent is attempting.
3. On the Live feed, click **Block**, then run the Demo set again. The feed checks every 5 seconds for 10 minutes after a switch, marks the switch on the timeline, and a card compares the risky actions before and after it ("0 blocked, then 9 blocked").
4. Walk through the charts: risk categories, the rules that fired, Endpoint AI's own built-in detections next to your rules, and OWASP Agentic and MITRE ATLAS. Click a row for the rule, the message the agent got and the raw event.
5. Click **Download recap** for a one-page summary to print or save as a PDF, and leave it with the customer.

Blocking happens on the generator immediately, and the record follows a few minutes later. Say so, so a short wait on the feed reads as normal.

## Updating, rolling back and tearing down

**Update:** when a new version is out, the **Updates** button turns into **Update to x.y.z**. Click it, then **Install update**. It verifies the download, installs and restarts the console; your settings, keys and tenant objects stay. Terminal: `aiguard-kit update`. If your network blocks GitHub downloads, install the newest zip from the Releases page by hand.

**Roll back one version:** **Roll back** in the same dialog, or `aiguard-kit update --rollback`. For an older version, run that release's installer; your settings stay.

**Tear down** (removes only `SE-Demo` objects, never yours), in this order:

1. AWS: in **CloudFormation**, delete the `se-demo-zia-generator` stack. Own VM: `zia-kit zia schedule remove`, then uninstall Client Connector.
2. ZIA: on the ZIA tab, click **Remove ZIA demo** (or `aiguard-kit zia teardown`). It deletes the kit's rules, Client Connector profiles and the test user it created, then activates.
3. AI Guard: `aiguard-kit schedule remove`, then `aiguard-kit teardown`. It deletes the kit's policy, apps, keys and rules. Provider keys you reused are kept.
4. Laptop: `aiguard-kit uninstall` (Windows also has **Uninstall AI Guard Demo Kit** in the Start menu).
5. Administration: delete the `SE-Demo kit` API client and role if nobody else uses them.

## Troubleshooting

Start with the **Logs** tab: it shows every call with the request and response, and **Download diagnostics** makes a zip (no secrets) to send to the kit owner.

| Symptom | Fix |
| --- | --- |
| `invalid_client` at setup | Wrong Client ID or secret. Setup > Connect, re-enter them |
| OneAPI `401` | The API client lacks AI Guard (or ZIA) access. Part 1, step 2.3 |
| `CERTIFICATE_VERIFY_FAILED` | Your network's SSL inspection. Start the kit from its shortcut or `aiguard-kit`, which trusts the system store |
| Verification: "handled by '…' instead" | Another AI Guard rule matched first. Disable or reorder it, then **Retry checks** |
| A Block step still shows ALLOW | Run it again once the button countdown ends. Secrets and PII only block in Block attacks + data or higher |
| Proxy `402` / `insufficient_quota` | No credit left with OpenAI or Anthropic. Top up, or turn off **Send to the model** |
| ZIA setup can't create the test user | The API role lacks User Management. Create the user in **Administration > Internet & SaaS Authentication > Internet & SaaS Users > Add User**, then type its User ID in the ZIA tab |
| ZIdentity won't let you set the test user's password (your domain signs in through an IdP such as Okta) | Kit 1.8.13 and later create the ZIdentity test user as `se-demo-traffic@<vanity>.zslogin.net`, which an IdP doesn't take over. Rerun ZIA setup: it replaces an older company-domain user, and teardown removes both. Set the new user's password once in Administration > Authentication > Directory > Users |
| Setup: "Client Connector API refused every version of the forwarding profile" | Some tenants' Client Connector API refuses new forwarding profiles. Create them by hand with exactly these names: forwarding profile SE-Demo Z-Tunnel 2.0 (Tunnel with Z-Tunnel 2.0 on every network type), and Windows app profile SE-Demo traffic generator (group SE-Demo: traffic generator, Install Zscaler SSL Certificate on, that forwarding profile, nothing broader above it). Then click Fix drift: the kit adopts them as they are |
| Client Connector shows Tunnel Version v1.0 | Click **More > Update Policy**. Still v1.0: on your laptop, **Check for drift** then **Fix drift**, and update policy again |
| HTTPS blocks show as errors, not blocks | SSL inspection isn't applied yet: **Update Policy** in Client Connector so it installs the Zscaler certificate |
| DLP or TCP 2222 not blocked | **Check for drift**; out-of-order or Z-Tunnel 1.0 findings explain it. **Fix drift** |
| Setup: "hasn't given it the Internet & SaaS (ZIA) service entitlement" | Your tenant entitles only chosen users or groups (typical with Okta). In ZIdentity, assign the Internet & SaaS entitlement to the group `SE-Demo: traffic generator`, then run setup again |
| Fleet Manager has no single sign-on option | You didn't sign in to AWS through IAM Identity Center. Set an Administrator password with Session Manager (Part 5, step 3) and connect with **User credentials** |
| AWS remote desktop: TargetNotConnected | The instance is stopped (weekday 7am–9pm New York schedule). Start it in EC2 |
| Generator console: "Access is denied" | Use a stack made from a current template; older stacks need the kit folder permissions reset |
| Insights panels empty | Normal for the first \~2 days. Use the Internet Access dashboards meanwhile; **Check Insights** lists what's still empty |
| On the VM: "The term '-ExecutionPolicy' is not recognized", or "The term 'C:\Uploads\se-demo-…-setup' is not recognized" | Start the line with `powershell`, and put the file's full path in quotes, as in Part 5. A repeat download is named like `…-setup(3).ps1`, and the `(3)` breaks an unquoted path |
| CloudShare image copy: the setup window didn't open at sign-in | Double-click **SE-Demo set up this generator** on the desktop. Already set up? It says so and shows the copy's name |
| Installing Claude Code: "The process cannot access the file … because it is being used by another process" | Windows Defender is still scanning the download, or an earlier install is still running. Wait a minute, run `Remove-Item "$env:USERPROFILE\.claude\downloads\*" -Force` in PowerShell, then double-click **SE-Demo install Claude Code** again |
| Live feed empty right after running the scenes | Endpoint AI takes a few minutes to record events, even in its own console. The line under the feed's status shows the newest event's age and the typical delay |
| Live feed on the generator: "This computer isn't connected to Endpoint AI" | Expected: open the Live feed on your laptop, which holds the credential |
| Endpoint AI: "rejected 1 rule: …" at Create or update | Endpoint AI's rule check refused that pattern. Nothing was changed. Set the rule to **Allow (rule off)** under Per-rule actions, save, and send the reason to the kit owner |
| Endpoint AI scenes show "Ran" in Block | That scene's rule isn't in your policy yet (new in a kit update). Click **Create or update** on your laptop |
| A Guided demo menu path doesn't match your console | Zscaler renames menus between console versions. Tell the kit owner the path you see |
