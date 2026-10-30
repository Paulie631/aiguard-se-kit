# Manual steps

Your setup path, in order: what the kit can't do through Zscaler's APIs (with the clicks to do it), and, marked *The kit*, what it does in between. Each step lists what has to be done first. **Manual steps** on the console's Setup tab and `aiguard-kit todo` show only the steps that apply to your tenant, filled in with your names, and check the ones the kit can verify.

> Steps marked **menu names not yet confirmed** haven't been checked against a live console. If yours differ, tell the kit owner (or update `manual_steps.json` and regenerate this file).

## Before you start

### Create the OneAPI client and its roles

**Why it's manual:** The kit reaches your tenant through this client, so it has to exist before the kit can do anything.

**When:** Every tenant.

1. In the Zscaler console (console.zscaler.com), open the ≡ menu and choose **Administration > Role Management > Internet & SaaS**. Click **Add API Role**, name it `SE-Demo kit`, set **Full Access** for every area, and save.
2. Go to **Administration > API > OneAPI > API Clients** and click **Add API Client**. On the **Client** tab, name it `SE-Demo kit`; under **Client Authentication** keep **Secret**, click **Add** and copy the secret now (it's shown once).
3. On the **Resources** tab set: **ZGUARD** = Role: Administrator; **ZIA** = the `SE-Demo kit` role; **ZCC** = Role: Super Admin; **ZINSIGHTS** = Role: ZINSIGHTS Reader; **ZIAM** = Role: Users Admin (needed when users sign in with SAML or are managed in ZIdentity; if unsure, set it). Leave the rest on None, then **Update**.
4. Copy the **Client ID** from the list, and note your vanity domain: the `acme` in `acme.zslogin.net`.
5. In the kit's console, **Setup > Connect**: enter the vanity domain, client ID and secret, then **Save and test**.

**Done when:** the kit checks it (Check under Setup > Manual steps).

*Menu path checked 2026-10 · id `oneapi-client`*

### Create the Endpoint AI API credential

**Why it's manual:** Endpoint AI Security has its own API, separate from OneAPI, and an API credential can't create credentials: only the console can.

**When:** When you use the Endpoint AI Security demo.

1. In the Endpoint AI Security console (for example console.zsai.sqrx.io), open **Administration > API Access**.
2. Under **Create a credential**, name it `se-demo-kit`, choose the **Admin** role (roles can't be changed later) and an expiry such as **90 days**, then click **Create credential**.
3. Copy the **client_id** and the **client_secret** now: the secret (it starts with `sqrx_sk_`) is shown once. Note the **API host** on the same page: the `use2` in `https://use2.api.<domain>` is your region.
4. In the kit's console, open the **Endpoint AI** tab: enter the console domain, region, client_id and secret, then **Save and test**. Never paste the secret into chat, email or tickets.

**Done when:** the kit checks it (Check under Setup > Manual steps).

*Menu path checked 2026-10-30 · id `eai-credential`*

## During setup

- *The kit:* **create the AI Guard demo**. The demo policy, the two apps, their keys and rules. Start it: Setup wizard above: Preflight checks, Choices, then Create it. Needs first: Create the OneAPI client and its roles.

### Turn on Store Prompts/Responses in AI Guard

**Why it's manual:** Without it, Insights shows detections but not the prompt text. The API can't read or set this, so the kit can't check it.

**When:** When you use the AI Guard demo.

**Needs first:** Kit: create the AI Guard demo

1. In the Zscaler console, open the ≡ menu and choose **AI Security** (it opens in a new tab).
2. Go to **AI Guard > Tenant Settings** and open the **Security** tab.
3. Turn on **Store Prompts/Responses** and save.
4. **Enable Data Sharing for AI Training** is on the same tab: fine in your demo tenant, but never turn it on in a customer's tenant without their agreement.

**Done when:** you mark it done (`aiguard-kit todo --done store-prompts`).

*Menu path checked 2026-10 · id `store-prompts`*

### Give the test group the Internet & SaaS entitlement

**Why it's manual:** ZIdentity only sends a user to ZIA when it has the Internet & SaaS (ZIA) service entitlement. Tenants that grant it to chosen users or groups (common with Okta or Entra ID) don't give it to the kit's user, and the API can read entitlements but not grant them.

**When:** When the kit created the test user in ZIdentity (SAML or ZIdentity-managed tenants).

1. In the Zscaler console, open ZIdentity's entitlements for **Internet & SaaS** (see Zscaler Help below for where it sits in your console version).
2. Assign the entitlement to the group **`SE-Demo: traffic generator`** (or to the user **the test user (for example `se-demo-traffic@<your domain>`)**).

**Then:** Run ZIA setup again (Internet Access (ZIA) > Create or update policy); it continues from the test user.

Zscaler Help: [Assigning entitlements to users](https://help.zscaler.com/unified/assigning-entitlements-users) · [Managing entitlements](https://help.zscaler.com/unified/managing-entitlements)

**Done when:** the kit checks it (Check under Setup > Manual steps).

*Menu names not yet confirmed · id `zid-entitlement`*

- *The kit:* **create the ZIA test user**. The dedicated user the demo rules apply to (in ZIdentity on SAML or ZIdentity-managed tenants). Start it: Internet Access (ZIA) tab > Create or update policy. Needs first: Create the OneAPI client and its roles; Give the test group the Internet & SaaS entitlement (on ZIdentity tenants).

### Set the ZIdentity test user's password

**Why it's manual:** Your tenant manages users in ZIdentity, and ZIdentity's API can't set passwords. The kit created the user; you give it a password once.

**When:** When the kit created the test user in ZIdentity (SAML or ZIdentity-managed tenants).

1. In the Zscaler console, go to **Administration > Authentication > Directory > Users**.
2. Find and click **the test user (for example `se-demo-traffic@<your domain>`)**.
3. Set a password and save. Keep it out of chat, email and tickets.
4. You'll use it once, to sign in to Client Connector on the traffic generator.

**Then:** Sign in to Client Connector on the generator with it.

**Done when:** you mark it done (`aiguard-kit todo --done zid-password`).

*Menu names not yet confirmed · id `zid-password`*

- *The kit:* **create the ZIA demo rules**. URL filtering, Cloud App Control, File Type Control, DLP, firewall, DNS and SSL inspection rules for the test user. Start it: Internet Access (ZIA) tab > Create or update policy. Needs first: Kit: create the ZIA test user.

- *The kit:* **create the Client Connector profiles**. The Windows app profile and Z-Tunnel 2.0 forwarding profile for the test user's group. On a ZIdentity tenant, ZIA only gets that group after the first Client Connector sign-in. Start it: Internet Access (ZIA) tab > Check for drift, then Fix drift (or Create or update policy). Needs first: Kit: create the ZIA demo rules; Sign in to Client Connector on the generator (on ZIdentity tenants). Then: Then, on the generator: Client Connector > More > Update Policy.

### Create the two Client Connector profiles

**Why it's manual:** The kit normally creates them. This shows when your tenant's Client Connector API refused the forwarding profile, or when you chose your own test user (so there's no kit group to scope them to).

**When:** When the Client Connector API refused the profiles, or you chose your own test user.

**Needs first:** Kit: create the ZIA demo rules

1. In the Zscaler console, open the Client Connector administration area.
2. Add a **forwarding profile** named exactly `SE-Demo Z-Tunnel 2.0`. Set the ZIA action to **Tunnel** with **Z-Tunnel 2.0** on every network type (on corporate network, off corporate network, VPN, split VPN), and save.
3. Add a **Windows app profile** named exactly `SE-Demo traffic generator`. Assign it to the group **`SE-Demo: traffic generator`** (your own test user's group if you picked one), turn on **Install Zscaler SSL Certificate**, select the forwarding profile `SE-Demo Z-Tunnel 2.0`, and save.
4. Make sure no broader Windows app profile (for example one for all users) sits above it in the order.

**Then:** Click Check for drift, then Fix drift: the kit finds both profiles by name and uses them as they are.

**Done when:** the kit checks it (Check under Setup > Manual steps).

*Menu names not yet confirmed · id `zcc-profiles`*

- *The kit:* **create the Endpoint AI demo policy**. A device group holding only the generator, and the SE-Demo policy assigned to that group alone, in Monitor or Block mode. Start it: Endpoint AI tab > Create or update. Needs first: Create the Endpoint AI API credential; Get the generator into Endpoint AI.

### Create the test user in your directory (AD or LDAP tenants)

**Why it's manual:** When ZIA signs users in from Active Directory or LDAP, the user has to exist there; the kit can't create it.

**When:** Only when the situation described applies (the console doesn't list it).

1. Create a dedicated user in your directory (never your own account) and let it sync to ZIA.
2. Run ZIA setup with `--user <that email>`, or type it in the ZIA tab instead of **Create one for me**.
3. Create the two Client Connector profiles by hand for that user's group (see 'Create the two Client Connector profiles').

**Done when:** you mark it done (`aiguard-kit todo --done directory-user`).

*Menu names not yet confirmed · id `directory-user`*

## On the traffic generator

### Build the traffic generator machine

**Why it's manual:** ZIA dashboards fill only from real traffic, from a separate Windows machine. The kit writes the template or script; creating the machine happens in AWS or CloudShare.

**When:** When the ZIA demo is set up.

**Needs first:** Kit: create the ZIA demo rules

1. **AWS:** in the kit's ZIA tab, **Download CloudFormation template**. In the AWS console, **CloudFormation > Create stack > With new resources (standard) > Upload a template file**, choose the file, keep the parameters, tick the IAM acknowledgement and **Submit**. Wait about 15 minutes.
2. **CloudShare or any Windows VM:** create a Windows Server 2022 VM with direct internet access. In the kit's ZIA tab, **Download setup script**, copy it to the VM, open PowerShell **as Administrator** and run `powershell -ExecutionPolicy Bypass -File .\se-demo-zia-generator-setup.ps1`. Progress: `C:\SE-Demo\setup.log`, about 10 minutes.
3. Make the template or script after the Client Connector profiles exist, so Client Connector is installed with the kit's app profile.

**Then:** Connect to the machine and sign in to Client Connector.

**Done when:** you mark it done (`aiguard-kit todo --done generator-build`).

*Menu path checked 2026-10 · id `generator-build`*

### Connect to the AWS generator without single sign-on

**Why it's manual:** Fleet Manager offers single sign-on only to people signed in to AWS through IAM Identity Center, and the template sets no Windows password.

**When:** When you use the AWS generator and Fleet Manager offers no single sign-on.

**Needs first:** Build the traffic generator machine

1. Open the stack's **Outputs** and follow **ConnectWithFleetManager**, then **Node actions > Connect > Connect with Remote Desktop**. If **Single sign-on** is offered, use it and skip the rest.
2. Otherwise: **Systems Manager > Session Manager > Start session**, pick the instance, and run the command in the stack's **SetAdministratorPassword** output. Type a strong password at the prompt (it isn't shown).
3. Back in Fleet Manager, choose **User credentials** and sign in as `Administrator` with that password.

**Done when:** you mark it done (`aiguard-kit todo --done generator-connect`).

*Menu path checked 2026-10 · id `generator-connect`*

### Sign in to Client Connector on the generator

**Why it's manual:** Client Connector needs the test user signed in once; a password can't be supplied silently.

**When:** When the ZIA demo is set up.

**Needs first:** Build the traffic generator machine; Set the ZIdentity test user's password (on ZIdentity tenants); Kit: create the ZIA test user

1. On the generator, open Client Connector and sign in as **the test user (for example `se-demo-traffic@<your domain>`)**. Password: the one the kit generated (`aiguard-kit zia password`) or, for a ZIdentity user, the one you set in ZIdentity.
2. Click **More > Update Policy**, then check that the status shows **Tunnel Version v2.0**.
3. On the generator's desktop, open **SE-Demo ZIA console > Internet Access (ZIA)** and click **Check this machine**. Every row should pass; traffic rounds start on their own after that.

**Then:** On a ZIdentity tenant, ZIA only receives the test group after this first sign-in: if the Client Connector profiles are still waiting, click Fix drift on your laptop now, then More > Update Policy here. Traffic rounds start by themselves.

**Done when:** you mark it done (`aiguard-kit todo --done generator-signin`).

*Menu path checked 2026-10 · id `generator-signin`*

### Get the generator into Endpoint AI

**Why it's manual:** Client Connector delivers the Endpoint AI agent. Turning that on for the generator's app profile is a Client Connector setting the kit can't change through the API.

**When:** When you use the Endpoint AI Security demo.

**Needs first:** Sign in to Client Connector on the generator (with the ZIA demo); Create the Endpoint AI API credential

1. Work on the **traffic generator VM** (the AWS or CloudShare Windows machine), never your own laptop: the kit only puts the generator in its device group.
2. On the generator, sign in to **Client Connector** as **the test user (for example `se-demo-traffic@<your domain>`)** (password: the one the kit generated (`aiguard-kit zia password`) or, for a ZIdentity user, the one you set in ZIdentity). That's the same sign-in the ZIA demo uses. If you chose your own test user instead of letting the kit create one, also note the generator's Windows hostname (run `hostname` in a Command Prompt there).
3. In the Client Connector portal, open the app profile **SE-Demo traffic generator** and turn on the **Endpoint AI** agent for it. Then, on the generator, open Client Connector and click **Update Policy** (or restart the VM) so the agent installs.
4. In the Endpoint AI console, open **Administration > Devices** and wait for the generator's hostname to show as online (up to about 15 minutes).
5. Back on the kit's **Endpoint AI** tab, click **Create or update** again (if you noted a hostname, enter it under **Generator hostnames** first). The status line **Generator enrolled in Endpoint AI** turns green.

**Done when:** the kit checks it (Check under Setup > Manual steps).

*Menu names not yet confirmed · id `eai-agent`*

### Install Claude Code on the generator and sign it in

**Why it's manual:** Endpoint AI records what AI coding agents do, so the generator needs one to run the scenes. Signing in needs your Claude account or an API key, which only you can provide.

**When:** When you use the Endpoint AI Security demo.

**Needs first:** Get the generator into Endpoint AI

1. On the generator, signed in to Windows as the user who will run the demo, double-click **SE-Demo Endpoint AI scenes** on the desktop once to check it starts (or run `C:\SE-Demo\eai.cmd demo` in a Command Prompt).
2. Install Claude Code for that user: `C:\SE-Demo\eai.cmd demo --install` (Anthropic's installer; no admin needed; the kit checks the signature).
3. Sign it in: run `claude` once and follow the browser sign-in, **or** save an Anthropic API key in that user's Credential Manager with `C:\SE-Demo\eai.cmd demo --set-key`.
4. Run the scenes once: double-click **SE-Demo Endpoint AI scenes**. Events show on the kit's Live feed tab on your laptop within a few minutes.

**Done when:** you mark it done (`aiguard-kit todo --done eai-claude`).

*Menu names not yet confirmed · id `eai-claude`*

### Install Client Connector by hand

**Why it's manual:** Only when the generator's setup log says the installer was skipped (its download failed, or it didn't match the pinned hash or Zscaler's signature).

**When:** Only when the situation described applies (the console doesn't list it).

1. On the generator, sign in to your **demo tenant's** admin console in Edge and download the latest Windows 64-bit .msi from the Client Connector App Store. Never use an installer from your corporate tenant.
2. Run it with the defaults, then sign in as the test user.

**Done when:** you mark it done (`aiguard-kit todo --done zcc-manual-install`).

*Menu names not yet confirmed · id `zcc-manual-install`*

## Before every demo

### Filter kit-policy-check out of AI Guard Insights

**Why it's manual:** The Guided demo checks each policy switch with a few scans under the user kit-policy-check. Insights views can't be saved through the API.

**When:** When you use the AI Guard demo.

**Needs first:** Kit: create the AI Guard demo

1. In **AI Guard > Insights**, add a filter on the user that excludes `kit-policy-check` before you share your screen.

**Each demo.**

*Menu names not yet confirmed · id `insights-filter`*

### Endpoint AI: start in Monitor and run the scenes once

**Why it's manual:** The story is 'see it, then stop it': Monitor shows the agent's risky actions running and recorded, Block shows them stopped.

**When:** When you use the Endpoint AI Security demo.

**Needs first:** Kit: create the Endpoint AI demo policy; Install Claude Code on the generator and sign it in

1. On the Endpoint AI tab set **Mode** to **Monitor**, and run the scenes on the generator once so there's recent activity to show.
2. During the demo, switch **Mode** to **Block** and run the scenes again: the same commands are stopped before they run.

**Each demo.**

*Menu names not yet confirmed · id `eai-before-demo`*
