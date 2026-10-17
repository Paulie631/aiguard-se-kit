# Internet Access (ZIA) demo

The kit fills ZIA and Insights dashboards in your **demo or eval tenant**. It works in two parts:

| Part | Runs on | Needs | Does |
|---|---|---|---|
| Demo policy | Your admin machine (the kit's usual home) | The OneAPI client from Setup, with a ZIA API role | Creates `SE-Demo:` rules for one test user and activates |
| Traffic generator | A lab Windows VM or cloud machine | Client Connector enrolled in the demo tenant, signed in as the test user. **No API keys.** | Sends real traffic through Zscaler so logs and dashboards fill |

APIs can create ZIA policy but can't create log entries. Only real traffic through Zscaler does that. **Never run the generator on a corporate laptop**: its Client Connector belongs to a different tenant, and the traffic includes demo blocks, test malware and fake sensitive data.

## 1. Admin machine: the demo policy

The ZIA tab of the console does the same as these commands.

1. Give the OneAPI client ZIA access (one time):
   - ZIA > Administration > Role Management: add an **API** role with full access to URL Filtering, Cloud App Control, File Type Control, DLP, Firewall and Activation.
   - ZIdentity > Integration > API Clients: edit the kit's client and add Zscaler Internet Access with that role.
2. Create a dedicated test user, for example `se-demo-traffic@yourdomain`, in ZIdentity or your IdP. Never use your own account.
3. Check, then create:
   ```
   ./aiguard-kit zia preflight
   ./aiguard-kit zia setup --user se-demo-traffic@yourdomain
   ```

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
| Shared objects | URL category `SE-Demo: tenant check` (example.com), rule label `SE-Demo: SE-Demo` |

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
   2. Add a Windows app profile `SE-Demo: …` that uses that forwarding profile, assigned to the test user's group only.
   
   This leaves your other devices as they are.
4. **SSL inspection.** It must decrypt the test user's traffic, which `zia preflight` checks. EICAR over HTTPS, DLP and Cloud App Control need it.
5. **The kit.** Install it with the double-click installer (no setup or keys needed on this machine), then:
   ```
   aiguard-kit zia check                       is this machine reaching the demo tenant, as the test user?
   aiguard-kit zia traffic                     one round of every traffic type
   aiguard-kit zia schedule install --every 30 a round every 30 minutes, while you're signed in
   ```

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
