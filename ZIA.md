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
   - **Administration > Role Management > Internet & SaaS > Add API Role**: name it `SE-Demo kit` and give it **Full Access** to every area (it needs at least the policy areas, Activation and **User Management**; without User Management, create the test user yourself and pass `--user`).
   - **Administration > API > OneAPI > API Clients**: edit the kit's client and, on its **Resources** tab, set **ZIA** to that role, **ZCC** to Role: Super Admin (Z-Tunnel 2.0 and certificate profiles) and **ZINSIGHTS** to Role: ZINSIGHTS Reader (dashboard and readiness checks). Tenants whose users sign in with SAML, or whose users are managed in ZIdentity, also need **ZIAM** set to Role: Users Admin.
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
| **SAML** | Creates the user `se-demo-traffic@<vanity>.zslogin.net` and the group `SE-Demo: traffic generator` in ZIdentity. The user goes on ZIdentity's own `zslogin.net` domain because ZIdentity can't set a password for a user on a domain routed to an identity provider (Okta, Entra ID…); `--domain` overrides this. Set its password in **Administration > Authentication > Directory > Users** (the API can't set it; this guide doesn't have click-by-click steps for that page yet). ZIA lists a ZIdentity user only after its first sign-in, so if setup says ZIA hasn't received the user, sign in once on the generator and rerun setup |
| **Users managed in ZIdentity** (ZIA answers `UNMODIFIABLE ... OneIdentityUserLogin enabled users will have read only access`) | Same as SAML: creates the user (on `<vanity>.zslogin.net`) and group in ZIdentity. A test user an earlier kit version created on your company domain is replaced, and teardown removes both. The API client needs **ZIAM = Role: Users Admin**. Preflight says so instead of asking for User Management, which wouldn't help |
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
./aiguard-kit zia status       the kit's ZIA objects, the last traffic round, and drift: rules missing, disabled or out
                               of order, Client Connector profiles not on Z-Tunnel 2.0, look-alike objects
./aiguard-kit zia status --fix repairs drift in the kit's own objects (runs setup again); never touches yours
./aiguard-kit zia ready        demo readiness, also on the generator: last round, dashboards, AWS schedule
./aiguard-kit zia dashboards   which Insights panels are still empty (7 days ending 2 days ago)
./aiguard-kit zia teardown     delete every SE-Demo ZIA object and activate
```

## 2. The traffic generator machine

1. **Machine.** Use a Windows 10/11 or Windows Server 2022 VM, either a lab VM or a cloud instance. Remote desktop is enough. If it's in a cloud account whose traffic already goes through a Cloud Connector into another tenant, put it on a subnet that bypasses that connector.
2. **Client Connector.** Install it and enroll in the demo tenant as the test user.
3. **Z-Tunnel 2.0 and the Zscaler certificate.** Setup does this for you (kit 0.1.3 and later). It creates the Windows app profile `SE-Demo traffic generator` for the group `SE-Demo: traffic generator` only. The profile is a copy of your default Windows profile that installs the Zscaler root certificate and uses the forwarding profile `SE-Demo Z-Tunnel 2.0`, a copy of yours switched to Z-Tunnel 2.0. Firewall, DNS and unusual-port traffic only reach ZIA through Z-Tunnel 2.0. After setup, on this machine open Client Connector > More > **Update Policy**. Your other devices keep their profiles.

   Some tenants' Client Connector API refuses every new forwarding profile with a bare `400`, even a minimal one. Setup then says so once, prints the exact steps and doesn't retry on later runs. Create both profiles by hand with exactly these names: forwarding profile `SE-Demo Z-Tunnel 2.0` (ZIA action Tunnel with **Z-Tunnel 2.0** on every network type), and Windows app profile `SE-Demo traffic generator` (group `SE-Demo: traffic generator`, **Install Zscaler SSL Certificate** on, that forwarding profile, no broader profile above it). Then run `./aiguard-kit zia status --fix`: it finds them by name, uses them as they are, and teardown removes them with the rest of the kit's objects.

   If setup reports that it couldn't for another reason (the API client has no Client Connector access, or you picked your own test user instead of letting setup create one), do it by hand in the Client Connector portal: copy your forwarding profile with the ZIA action set to Tunnel, **Z-Tunnel 2.0**, then add a Windows app profile for the test user's group with **Install Zscaler SSL Certificate** on and that forwarding profile.
4. **SSL inspection.** Setup adds `SE-Demo: Inspect test user` (decrypt, test user only) and, above it, `SE-Demo: AWS SSM bypass` (never decrypt AWS Systems Manager traffic, so the AWS generator's remote desktop keeps working). EICAR over HTTPS, DLP and Cloud App Control need inspection.
5. **The kit.** Install it with the double-click installer (no setup or keys needed on this machine), then:
   ```
   aiguard-kit zia check                       is this machine reaching the demo tenant, as the test user?
   aiguard-kit zia traffic                     one round of every traffic type
   aiguard-kit zia schedule install --every 30 a round every 30 minutes, while you're signed in
   ```

### On AWS: one CloudFormation stack

The simplest generator is a Windows instance in an AWS account you can use for demos. You don't need the AWS CLI or AWS keys on your laptop: the kit writes the template, and you upload it in the AWS console.

1. **Write the template.** On your admin machine, after `zia setup`, run `./aiguard-kit zia aws`. Or use **Download CloudFormation template** on the console's ZIA tab. It's saved to `~/Downloads/se-demo-zia-generator.cfn.json`, filled in with your cloud, user domain and test user.
   - **Client Connector is installed for you.** By default the template points the instance at the kit's copy of the Windows installer (Client Connector 4.10.0.477, attached to the `zcc-installer` release, unchanged from Zscaler's App Store). The instance installs it with your cloud and domain only if its SHA-256 matches the value pinned in the kit **and** it carries a valid Zscaler code signature; otherwise it skips it and `C:\SE-Demo\setup.log` says to install by hand. To use your own copy instead, give `--zcc-url s3://<bucket>/<key>` (same account and region; the stack may read only that object) or an https URL; the signature check still applies. `--zcc-url none` skips the install. You still sign in to Client Connector once over remote desktop: a hosted-database user can't be signed in silently.
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
   2. **Install Client Connector** only if the setup log says it was skipped (or you chose `none`). On the instance, open Edge, sign in to your **demo tenant's** admin console, and download the latest Windows 64-bit .msi from the Client Connector App Store (in the Client Connector admin area; the menu name varies by console version). Never use an installer from your corporate tenant. Run it with the defaults.
   3. **Sign in to Client Connector** as the test user (for example `se-demo-traffic@<your domain>`). The domain sends it to your tenant; then the sign-in page asks for the password, which `./aiguard-kit zia password` shows on your admin machine.
   4. **Pick up the kit's profile.** Client Connector > **More > Update Policy**. That applies the `SE-Demo traffic generator` app profile from `zia setup` (Zscaler root certificate and Z-Tunnel 2.0). If the remote desktop window drops, reconnect after a minute.
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
| SSL inspection | Certificate issuer for wikipedia.org is Zscaler | Run `zia setup` again (it adds the inspection rule) |
| **Demo tenant, as the test user** | `www.example.com` is blocked: only the kit's rule does that, and only for this user | Wrong tenant or user, or changes not activated |
| URL filtering | Gambling is blocked | Run `zia setup` |
| Malware protection | The EICAR test string over HTTP and HTTPS is blocked | HTTPS needs SSL inspection |
| DLP | A post of fake card numbers is blocked | SSL inspection and DLP rules |
| Z-Tunnel 2.0 | TCP 2222 to portquiz.net is reset by the demo firewall rule | Client Connector > Update Policy, after `zia setup` (step 3) |

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

- **ZIA logs and dashboards** (Internet Access > Dashboards, such as Web Browsing, SaaS/Cloud Apps and Firewall Overview, plus Analytics > Cybersecurity and Analytics > Data Security > Inline CASB / Inline DLP; Analytics > Web Insights in older consoles): within minutes.
- **Insights dashboards and `zia dashboards`:** Insights answers for 7- or 14-day windows that end a day or two ago, so new traffic shows after about two days.
- **Shadow IT:** fills as rounds rotate through the SaaS list.

**Before a demo:** start the generator at least **3 days** ahead so the Insights dashboards have data, and run `zia ready` (or **Demo readiness** in the console) the morning of.

## Rolling back

See [README > Rolling back](README.md#rolling-back). In short: run `zia teardown` with the version that created the objects, then install the older `zia-v*` release (skip `zia-v0.1.0`), then run `zia setup` again.

## Later phases

ZPA (App Connector, a test app, AppProtection test strings), ZDX probes, CASB/SSPM with a test SaaS account, Deception, and Cloud Connector. Each will be its own module, like `zia_module.py`.
