# Internet Access (ZIA) demo

The kit fills ZIA and Insights dashboards in your **demo or eval tenant**. It works in two parts:

| Part | Runs on | Needs | Does |
|---|---|---|---|
| Demo policy | Your admin machine (the kit's usual home) | The OneAPI client from Setup, with a ZIA API role | Creates `SE-Demo:` rules for one test user and activates |
| Traffic generator | A lab Windows VM or cloud machine | Client Connector enrolled in the demo tenant, signed in as the test user. **No API keys.** | Sends real traffic through Zscaler so logs and dashboards fill |

APIs can create ZIA policy but can't create log entries. Only real traffic through Zscaler does that. **Never run the generator on a corporate laptop**: its Client Connector belongs to a different tenant, and the traffic includes demo blocks, test malware and fake sensitive data.

## Get the ZIA kit

Download the latest **Zscaler ZIA SE Demo Kit** from the repo's Releases page: `zscaler-zia-kit-<version>.zip`, tagged `zia-v<version>` (pre-release).
1. Extract the zip.
2. Double-click **Install ZIA Kit**.

What you get:
- **Installs beside the AI Guard kit,** in its own folder (`~/.aiguard-se-kit/app-zia`), with its own **Zscaler ZIA Demo Console** shortcut and a `zia-kit` command. It never replaces the AI Guard kit.
- **Shares the AI Guard kit's saved OneAPI login,** so you don't enter it twice.
- **Updates itself only from ZIA releases,** through its own update channel. AI Guard users never get ZIA releases offered.

With the ZIA kit, `zia-kit setup` is the same as `aiguard-kit zia setup`, and likewise for every command below.

## 1. Admin machine: the demo policy

The ZIA tab of the console does the same as these commands.

1. Give the OneAPI client ZIA access (one time):
   - **Administration > Role Management**: add an **API** role with full access to URL Filtering, Cloud App Control, File Type Control, DLP, Firewall, Activation and **User Management** (for creating the test user; without it, create the user yourself and pass `--user`).
   - **Administration > API > OneAPI > API Clients**: edit the kit's client and add Zscaler Internet Access with that role.
2. Create the policy. Setup creates the test user for you:
   ```
   ./aiguard-kit zia preflight
   ./aiguard-kit zia setup
   ```
   - **The test user.** With no `--user`, setup creates `se-demo-traffic@<your tenant's domain>` as a ZIA **Internet & SaaS user**, in a new group and department called `SE-Demo: traffic generator`.
     - Use `--domain` to choose the domain.
     - Use `--user someone@yourdomain` to use a dedicated user you already have (never your own account).
   - **The password.** Setup generates one and saves it in this computer's keychain. It isn't printed during setup. When you sign in to Client Connector on the generator, show it with `./aiguard-kit zia password`, or **Show password** on the console's ZIA tab. Keep it out of chat, email and tickets.
   - **API access.** The OneAPI client's ZIA role needs User Management access. Without it, setup says so; create the user yourself (below) and pass `--user`.
   - **Teardown.** `zia teardown` removes the user, group and department only if the kit created them, and forgets the password.

### Setting a test user's password by hand

You only need this for a user you created yourself, or to reset a password. The menu names match the Zscaler Experience Center (console.zscaler.com) as of October 2026.

1. In the left menu, choose **Administration**. Under **Internet & SaaS Authentication**, choose **Internet & SaaS Users**.
2. On the **Users** tab, find the user (filter with **User ID or Name** if the list is long). Click the **pencil** icon under **Actions**.
3. In the **Edit User** panel, scroll to **Change Password**. Enter the new password in **Password** and again in **Confirm Password**. The password has to meet **Password Strength** in **Administration > Internet & SaaS Authentication > Internet Authentication Settings**.
4. Click **Save**.
5. Sign in to Client Connector on the generator with the **User ID** (the email) and that password.

To create a user by hand instead:
1. Go to the same **Internet & SaaS Users** page and click **Add User**.
2. Give it a User ID on your tenant's domain, a group and a department, and a password.
3. Run `./aiguard-kit zia setup --user <that User ID>`.

### How the kit decides where to create the user

Setup reads **Administration > Internet & SaaS Authentication > Internet Authentication Settings** (`zia preflight` shows the result as "How Client Connector users sign in"):

| User Repository Type / Authentication Type | Setup |
|---|---|
| **Hosted DB** with **Form-Based** (typical demo tenant) | Creates a ZIA Internet & SaaS user with a generated password. Nothing to do by hand |
| **SAML** | Creates the user and the group `SE-Demo: traffic generator` in ZIdentity. Set its password in **Administration > Authentication > Directory > Users** (the API can't set it; this guide doesn't have click-by-click steps for that page yet). ZIA lists a ZIdentity user only after its first sign-in, so if setup says ZIA hasn't received the user, sign in once on the generator and rerun setup |
| **Active Directory** or **OpenLDAP** | Stops and asks you to create the user in your directory, then rerun with `--user` |

`--via zia` or `--via zidentity` overrides the choice.

### What setup creates

Every object is scoped to the test user only, labeled `SE-Demo`, placed above your own rules, and removed by `zia teardown`.

| Area | Rules |
|---|---|
| URL filtering | Block: tenant check, gambling, anonymizers, weapons. Caution: social, streaming |
| Browser Isolation (if licensed) | Isolate games |
| Cloud App Control | Block file-share uploads and risky GenAI. Allow mainstream GenAI. Block remote-access tools |
| File Type Control | Block EXE/MSI downloads. Allow-and-log documents, CSV, ZIP |
| DLP | Block 5+ card numbers. Monitor PCI, PII and secrets |
| Firewall | Block TCP 23, 2222, 4444 and 8888 (network service `SE-Demo: demo ports`) |
| DNS | Block the marijuana category. The web sweep never visits it, so DNS blocks don't hide URL blocks |
| Shared objects | URL category `SE-Demo - tenant check` (example.com), network service `SE-Demo: demo ports`, rule label `SE-Demo demo kit`. ZIA rejects `:` in category and label names, so these use `-` |
| Test user (unless you pass `--user`) | ZIA user `se-demo-traffic@<domain>` with a generated password, in group and department `SE-Demo: traffic generator` (with `--via zidentity`: a ZIdentity user and group) |

The rules are defined in `zia_policy_template.json`. Setup checks the template against your tenant and skips or trims anything it doesn't have (an isolation profile, a DLP engine, an app action), saying which in the review.

### Other admin commands

```
./aiguard-kit zia status       the kit's ZIA objects and the last traffic round
./aiguard-kit zia dashboards   which Insights panels are still empty (7 days ending 2 days ago)
./aiguard-kit zia teardown     delete every SE-Demo ZIA object and activate
```

## 2. The traffic generator machine

1. **Machine.** Use a Windows 10/11 or Windows Server 2022 VM, either a lab VM or a cloud instance. Remote desktop is enough. If it's in a cloud account whose traffic already goes through a Cloud Connector into another tenant, put it on a subnet that bypasses that connector.
2. **Client Connector.** Install it and enroll in the demo tenant as the test user.
3. **Z-Tunnel 2.0.** Firewall, DNS and unusual-port traffic only reach ZIA through Z-Tunnel 2.0. Z-Tunnel 1.0 carries web traffic only. In the Client Connector portal:
   1. Under Forwarding Profile, copy your profile as `SE-Demo: Z-Tunnel 2.0`, with Tunnel version set to **Z-Tunnel 2.0** for on-trusted and off-trusted networks.
   2. Add a Windows app profile `SE-Demo: …` that uses that forwarding profile, assigned only to the group `SE-Demo: traffic generator` (setup creates it), or to the test user.
   
   This leaves your other devices as they are.
4. **SSL inspection.** It must decrypt the test user's traffic, which `zia preflight` checks. EICAR over HTTPS, DLP and Cloud App Control need it.
5. **The kit.** Install it with the double-click installer (no setup or keys needed on this machine), then:
   ```
   aiguard-kit zia check                       is this machine reaching the demo tenant, as the test user?
   aiguard-kit zia traffic                     one round of every traffic type
   aiguard-kit zia schedule install --every 30 a round every 30 minutes, while you're signed in
   ```

### On AWS: one CloudFormation stack

The simplest generator is a Windows instance in an AWS account you can use for demos. You don't need the AWS CLI or AWS keys on your laptop: the kit writes the template, and you upload it in the AWS console.

1. **Write the template.** On your admin machine, after `zia setup`, run `./aiguard-kit zia aws`. Or use **Download CloudFormation template** on the console's ZIA tab. It's saved to `~/Downloads/se-demo-zia-generator.cfn.json`, filled in with your cloud, user domain and test user.
   - **Optional: the Client Connector installer.** Give `--zcc-url <https URL of the Windows .msi or .exe>` (for example an S3 presigned URL) to have the instance install Client Connector itself, already pointed at your cloud and domain. Without it, you install Client Connector over remote desktop in step 3.
2. **Create the stack.**
   1. In the AWS console, go to **CloudFormation > Create stack > With new resources (standard) > Upload a template file**, choose the file, then **Next**.
   2. Name the stack, for example `se-demo-zia-generator`, and check the parameters. The defaults are fine for most accounts.
   3. Tick the IAM acknowledgement, then **Submit**.

   The stack creates:
   - its own small VPC with direct internet access, so no corporate inspection sits in front of Zscaler;
   - a security group with **no inbound ports**;
   - an SSM role;
   - a Windows Server 2022 instance (t3.medium);
   - unless you turn it off, a weekday 7am start and a 9pm stop (New York time).

   On first boot, the instance installs uv and the kit (from `KitZipUrl`, currently the `zia-traffic` branch) into `C:\SE-Demo`. It also registers two tasks that run as SYSTEM:
   - **SE-Demo ZIA traffic**, every 30 minutes;
   - **SE-Demo ZIA check**, at startup.

   Rounds only send traffic once ip.zscaler.com confirms it goes through Zscaler, so nothing is sent before you sign in.
3. **Sign in once.**
   1. After about 10 minutes, open the stack's **Outputs** and follow **ConnectWithFleetManager**, then **Node actions > Connect > Connect with Remote Desktop**. Sign in with your AWS single sign-on if offered, or with the Administrator password if you set `KeyPairName`.
   2. Install Client Connector if step 1 didn't.
   3. Sign in to Client Connector as the test user. `./aiguard-kit zia password` on your admin machine shows the password.
4. **Check it.** On the instance's desktop, open **SE-Demo ZIA console > Internet Access (ZIA) > Check this machine**, or open **SE-Demo traffic log**. The next scheduled round starts within 30 minutes.

**If the account restricts what stacks can create:**
- **No new VPC.** Set `NetworkMode` to `ExistingSubnet` and fill in `ExistingVpcId` and `ExistingSubnetId`. Use a subnet whose internet route doesn't go through a corporate inspection appliance.
- **No new IAM roles.** Set `ExistingInstanceProfile` to an instance profile with `AmazonSSMManagedInstanceCore`, and `WeekdaySchedule` to `false`. The start/stop schedule needs its own role.

**Removing it:** delete the stack. That removes the instance, network, role and schedule. `zia teardown` removes the ZIA side.

**Cost:** roughly what a Windows t3.medium costs in your region. The weekday schedule keeps it to working hours.

### What `zia check` proves

| Check | How | If it fails |
|---|---|---|
| Client Connector running | Process list | Install, enroll and sign in |
| Traffic goes through Zscaler | ip.zscaler.com, and the cloud name | Turn on Internet Security |
| SSL inspection | Certificate issuer for wikipedia.org is Zscaler | Add a DECRYPT rule for the test user |
| **Demo tenant, as the test user** | `www.example.com` is blocked: only the kit's rule does that, and only for this user | Wrong tenant or user, or changes not activated |
| URL filtering | Gambling is blocked | Run `zia setup` |
| Malware protection | The EICAR test string over HTTP and HTTPS is blocked | HTTPS needs SSL inspection |
| DLP | A post of fake card numbers is blocked | SSL inspection and DLP rules |
| Z-Tunnel 2.0 | TCP 2222 to portquiz.net is reset by the demo firewall rule | Use the Z-Tunnel 2.0 profile (step 3) |

### What one round sends

Change the amounts with `--count` (default 4) and choose types with `--types`.

| Type | Traffic |
|---|---|
| `web` | Up to ~12 sites across 40+ URL categories, always including the tenant check and some blocked categories |
| `saas` | ~16 of 60 SaaS apps (file sharing, collaboration, dev, webmail, chat), rotating so Shadow IT fills over a few rounds |
| `genai` | ~8 of 18 GenAI apps (ChatGPT, Gemini, Copilot, Claude, Perplexity, DeepSeek…) |
| `threats` | The EICAR test string over HTTP and HTTPS, EICAR files from eicar.org, Google's Safe Browsing phishing and malware **test pages** |
| `dlp` | Posts of generated fake card numbers (network test ranges, Luhn-valid), fake SSNs and an AWS-style fake key to dlptest.com and httpbin.org |
| `files` | Uploads of CSV, TXT, JSON, PDF and ZIP. Downloads of PDF, CSV and EXE (EXE is blocked) |
| `dns` | System lookups, UDP/53 to public resolvers, DNS over HTTPS, and a few random names |
| `ports` | TCP 23, 2222, 4444, 8888, 8080 and 3389 to portquiz.net |

Safe test data only:
- The EICAR string is put together at runtime, so the kit's own files never trip antivirus.
- No real malware or exploit sites are used.
- Fake data is generated fresh each round.

GenAI visits fill app usage. Prompt-level GenAI logs need signed-in test accounts, and browser automation for that is a later phase.

## Timing

- **ZIA logs** (Analytics > Web Insights / Firewall Insights): within minutes.
- **Insights dashboards and `zia dashboards`:** Insights answers for 7- or 14-day windows that end a day or two ago, so new traffic shows after about two days.
- **Shadow IT:** fills as rounds rotate through the SaaS list.

## Later phases

ZPA (App Connector, a test app, AppProtection test strings), ZDX probes, CASB/SSPM with a test SaaS account, Deception, and Cloud Connector. Each will be its own module, like `zia_module.py`.
