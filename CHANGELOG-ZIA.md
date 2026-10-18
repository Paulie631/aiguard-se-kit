# Zscaler ZIA SE Demo Kit: changelog

The ZIA kit is a separate edition of the SE demo kit. It installs beside the AI Guard kit (its own folder,
shortcut and `zia-kit` command) and shares its saved OneAPI login. Releases are tagged `zia-v<version>`.

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
