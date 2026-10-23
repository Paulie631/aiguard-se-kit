# Manual steps

What the kit can't do through Zscaler's APIs, and the clicks to do it. The console's **Manual steps** tab and `aiguard-kit todo` show only the steps that apply to your tenant, filled in with your names, and check the ones the kit can verify.

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

**Done when:** the kit checks it (Check in the Manual steps tab).

*Menu path checked 2026-10 · id `oneapi-client`*

## During setup

### Set the ZIdentity test user's password

**Why it's manual:** Your tenant manages users in ZIdentity, and ZIdentity's API can't set passwords. The kit created the user; you give it a password once.

**When:** When the kit created the test user in ZIdentity (SAML or ZIdentity-managed tenants).

1. In the Zscaler console, go to **Administration > Authentication > Directory > Users**.
2. Find and click **the test user (for example `se-demo-traffic@<your domain>`)**.
3. Set a password and save. Keep it out of chat, email and tickets.
4. You'll use it once, to sign in to Client Connector on the traffic generator.

**Done when:** you mark it done (`aiguard-kit todo --done zid-password`).

*Menu names not yet confirmed · id `zid-password`*

### Give the test group the Internet & SaaS entitlement

**Why it's manual:** ZIdentity only sends a user to ZIA when it has the Internet & SaaS (ZIA) service entitlement. Tenants that grant it to chosen users or groups (common with Okta or Entra ID) don't give it to the kit's user, and the API can read entitlements but not grant them.

**When:** When the kit created the test user in ZIdentity (SAML or ZIdentity-managed tenants).

1. In the Zscaler console, open ZIdentity's entitlements for **Internet & SaaS** (see Zscaler Help below for where it sits in your console version).
2. Assign the entitlement to the group **`SE-Demo: traffic generator`** (or to the user **the test user (for example `se-demo-traffic@<your domain>`)**).
3. In the kit, run ZIA setup again (console: Internet Access (ZIA) > Create or update policy). It picks up where it left off once ZIA has the user.

Zscaler Help: [Assigning entitlements to users](https://help.zscaler.com/unified/assigning-entitlements-users) · [Managing entitlements](https://help.zscaler.com/unified/managing-entitlements)

**Done when:** the kit checks it (Check in the Manual steps tab).

*Menu names not yet confirmed · id `zid-entitlement`*

### Create the two Client Connector profiles

**Why it's manual:** The kit normally creates them. This shows when your tenant's Client Connector API refused the forwarding profile, or when you chose your own test user (so there's no kit group to scope them to).

**When:** When the Client Connector API refused the profiles, or you chose your own test user.

1. In the Zscaler console, open the Client Connector administration area.
2. Add a **forwarding profile** named exactly `SE-Demo Z-Tunnel 2.0`. Set the ZIA action to **Tunnel** with **Z-Tunnel 2.0** on every network type (on corporate network, off corporate network, VPN, split VPN), and save.
3. Add a **Windows app profile** named exactly `SE-Demo traffic generator`. Assign it to the group **`SE-Demo: traffic generator`** (your own test user's group if you picked one), turn on **Install Zscaler SSL Certificate**, select the forwarding profile `SE-Demo Z-Tunnel 2.0`, and save.
4. Make sure no broader Windows app profile (for example one for all users) sits above it in the order.
5. In the kit, click **Check for drift**, then **Fix drift**: it finds both profiles by name and uses them as they are.

**Done when:** the kit checks it (Check in the Manual steps tab).

*Menu names not yet confirmed · id `zcc-profiles`*

### Turn on Store Prompts/Responses in AI Guard

**Why it's manual:** Without it, Insights shows detections but not the prompt text. The API can't read or set this, so the kit can't check it.

**When:** When the AI Guard demo is set up.

1. In the Zscaler console, open the ≡ menu and choose **AI Security** (it opens in a new tab).
2. Go to **AI Guard > Tenant Settings** and open the **Security** tab.
3. Turn on **Store Prompts/Responses** and save.
4. **Enable Data Sharing for AI Training** is on the same tab: fine in your demo tenant, but never turn it on in a customer's tenant without their agreement.

**Done when:** you mark it done (`aiguard-kit todo --done store-prompts`).

*Menu path checked 2026-10 · id `store-prompts`*

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

1. **AWS:** in the kit's ZIA tab, **Download CloudFormation template**. In the AWS console, **CloudFormation > Create stack > With new resources (standard) > Upload a template file**, choose the file, keep the parameters, tick the IAM acknowledgement and **Submit**. Wait about 15 minutes.
2. **CloudShare or any Windows VM:** create a Windows Server 2022 VM with direct internet access. In the kit's ZIA tab, **Download setup script**, copy it to the VM, open PowerShell **as Administrator** and run `powershell -ExecutionPolicy Bypass -File .\se-demo-zia-generator-setup.ps1`. Progress: `C:\SE-Demo\setup.log`, about 10 minutes.
3. Make the template or script after the Client Connector profiles exist, so Client Connector is installed with the kit's app profile.

**Done when:** you mark it done (`aiguard-kit todo --done generator-build`).

*Menu path checked 2026-10 · id `generator-build`*

### Connect to the AWS generator without single sign-on

**Why it's manual:** Fleet Manager offers single sign-on only to people signed in to AWS through IAM Identity Center, and the template sets no Windows password.

**When:** When you use the AWS generator and Fleet Manager offers no single sign-on.

1. Open the stack's **Outputs** and follow **ConnectWithFleetManager**, then **Node actions > Connect > Connect with Remote Desktop**. If **Single sign-on** is offered, use it and skip the rest.
2. Otherwise: **Systems Manager > Session Manager > Start session**, pick the instance, and run the command in the stack's **SetAdministratorPassword** output. Type a strong password at the prompt (it isn't shown).
3. Back in Fleet Manager, choose **User credentials** and sign in as `Administrator` with that password.

**Done when:** you mark it done (`aiguard-kit todo --done generator-connect`).

*Menu path checked 2026-10 · id `generator-connect`*

### Sign in to Client Connector on the generator

**Why it's manual:** Client Connector needs the test user signed in once; a password can't be supplied silently.

**When:** When the ZIA demo is set up.

1. On the generator, open Client Connector and sign in as **the test user (for example `se-demo-traffic@<your domain>`)**. Password: the one the kit generated (`aiguard-kit zia password`) or, for a ZIdentity user, the one you set in ZIdentity.
2. Click **More > Update Policy**, then check that the status shows **Tunnel Version v2.0**.
3. On the generator's desktop, open **SE-Demo ZIA console > Internet Access (ZIA)** and click **Check this machine**. Every row should pass; traffic rounds start on their own after that.

**Done when:** you mark it done (`aiguard-kit todo --done generator-signin`).

*Menu path checked 2026-10 · id `generator-signin`*

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

**When:** When the AI Guard demo is set up.

1. In **AI Guard > Insights**, add a filter on the user that excludes `kit-policy-check` before you share your screen.

**Each demo.**

*Menu names not yet confirmed · id `insights-filter`*
