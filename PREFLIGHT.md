# Preflight runbook

Every check the kit runs before setup (and `./aiguard-kit preflight` runs on its own): what it checks, why it
matters, how to verify it by hand, how to fix it, and how to re-test. The console shows the same text under
**How to verify** next to each check.

Statuses: ✓ pass · ! warning (setup can continue) · ✗ failure · · information.

> Items marked **Confirm in your tenant** haven't been checked against a real tenant yet. If the wording
> differs from what you see, update `preflight_help.json` and regenerate this file.

## Contents

- [Keychain available](#keychain)
- [Detection API reachable](#das)
- [AI Guard proxy reachable](#proxy)
- [OneAPI credentials saved](#creds)
- [OneAPI login](#login)
- [Read access to AI Guard](#read)
- [Create and delete permission](#write)
- [OpenAI provider available](#prov-openai)
- [Anthropic provider available](#prov-anthropic)
- [Earlier kit objects](#existing)
- [No broad rules ahead of the kit's](#rules)
- [Reused policy covers the tests](#policy)
- [Tenant Settings > Security > Store Prompts/Responses](#manual)
- [Verification: handled by the demo policy](#verify-policy)

## Running and sharing the checks

```bash
./aiguard-kit preflight                 # checklist; exit 0 = pass, 2 = warnings, 1 = failures
./aiguard-kit preflight --write-probe   # also test create/delete permission
./aiguard-kit preflight --json          # machine-readable report (no secrets) for tickets and scripts
```

In the console: Setup → step 2 → **Copy report** puts the same report on the clipboard.

<a id="keychain"></a>
## Keychain available

**What it checks:** Writes, reads back and deletes a test entry in the OS keychain (service 'aiguard-se-kit').

**Why it matters:** Every key the kit uses (OneAPI secret, detection and proxy keys) lives only in the keychain. Without it the kit can't save or use keys.

**Verify by hand:**

- Mac: open Keychain Access, select the login keychain and make sure it shows as unlocked (no padlock).
- Mac, after setup: run `security find-generic-password -s aiguard-se-kit -a oneapi-client-secret`. Attributes printed (no secret) means the entry exists.
- Windows: Control Panel → Credential Manager → Windows Credentials. Look for entries containing 'aiguard-se-kit'.
- Linux: a Secret Service provider must be running (`gnome-keyring-daemon` or KWallet).

**Fix:**

- Mac: unlock the login keychain (Keychain Access → File → Unlock Keychain "login"). If macOS asks whether Python may access the keychain, choose Always Allow.
- Windows: keys go to Credential Manager for the signed-in user. Run the kit as yourself, not from an admin or shared account, and don't use "Run as administrator".
- Linux: install and start gnome-keyring, or run the kit from a desktop session.
- Managed laptops: if policy blocks keychain access for command-line apps, ask IT for an exception for uv's Python.

**Re-test:** `./aiguard-kit preflight` → ✓ Keychain available

<a id="das"></a>
## Detection API reachable

**What it checks:** Opens an HTTPS connection to the AI Guard Detection API (https://api.us1.zseclipse.net). Any HTTP answer counts as reachable.

**Why it matters:** Every detection-mode test, the guided demo, the live prompt and verification go through this API.

**Verify by hand:**

- Run `curl -sS -o /dev/null -w '%{http_code}\n' https://api.us1.zseclipse.net/`.
- A number (for example 401, 404 or 405) means the network path is fine.
- 'SSL certificate problem' or 'unable to get local issuer certificate' means TLS inspection: the Zscaler root CA isn't trusted by the tool.
- 'Could not resolve host' means DNS or a proxy setting; 'Connection timed out' means a firewall or proxy is blocking it.

**Fix:**

- Start the kit with ./aiguard-kit (it trusts the OS certificate store) and make sure the Zscaler root CA is in the System keychain (Mac) or Trusted Root store (Windows).
- If your tenant is on another AI Guard cloud, set AIGUARD_DAS_HOST before running, e.g. `AIGUARD_DAS_HOST=https://api.<cloud>.zseclipse.net ./aiguard-kit preflight`.
- On a restricted network, ask for api.*.zseclipse.net to be allowed.

**Re-test:** `./aiguard-kit preflight` → ✓ Detection API reachable

> **Confirm in your tenant:** us1 is the only Detection API host confirmed so far; other cloud host names are unverified.

<a id="proxy"></a>
## AI Guard proxy reachable

**What it checks:** Opens an HTTPS connection to the AI Guard proxy (https://proxy.zseclipse.net).

**Why it matters:** Only needed for LLM proxy mode (real model calls and token usage). Detection mode works without it, so this is a warning, not a failure.

**Verify by hand:**

- Run `curl -sS -o /dev/null -w '%{http_code}\n' https://proxy.zseclipse.net/`. A number means reachable; read errors as for the Detection API check.

**Fix:**

- Same as the Detection API check. To use another proxy host, set AIGUARD_PROXY.

**Re-test:** `./aiguard-kit preflight` → ✓ AI Guard proxy reachable

<a id="creds"></a>
## OneAPI credentials saved

**What it checks:** Confirms a vanity domain and client ID are saved in ~/.aiguard-se-kit/config.json and the client secret is in the keychain.

**Why it matters:** Every configuration call to your tenant uses these.

**Verify by hand:**

- Open ~/.aiguard-se-kit/config.json: it should show vanity_domain and client_id (never the secret).
- The vanity domain is only the subdomain: 'acme' for acme.zslogin.net.

**Fix:**

- Console: Setup → step 1 → Use different credentials. Terminal: rerun `./aiguard-kit setup` and decline the saved credentials.

**Re-test:** `./aiguard-kit preflight` → ✓ OneAPI credentials saved

<a id="login"></a>
## OneAPI login

**What it checks:** Gets an OAuth token from ZIdentity with the client ID and secret, then lists AI Guard policies.

**Why it matters:** Proves the credentials, vanity domain and API scope work together.

**Verify by hand:**

- ZIdentity admin portal → Integration → API Clients: the client exists, is enabled, and its secret hasn't been rotated since you saved it.
- The client's resources/scopes include AI Guard.
- The error text tells you which part failed: 'invalid_client' = ID or secret; a name-resolution error = vanity domain; 401 = scope.

**Fix:**

- invalid_client: copy the client ID again and create a new secret, then re-enter both in step 1.
- Name resolution: re-enter the vanity domain as the bare subdomain.
- 401 / not authorized: add AI Guard to the API client's scopes in ZIdentity and save.

**Re-test:** `./aiguard-kit preflight` → ✓ OneAPI login

> **Confirm in your tenant:** The exact label of the AI Guard scope in ZIdentity hasn't been captured yet; update this text from a screenshot.

<a id="read"></a>
## Read access to AI Guard

**What it checks:** Lists policies, rules, providers, provider credentials, apps and app credentials.

**Why it matters:** Setup needs the current state to avoid duplicates and pick rule order.

**Verify by hand:**

- The detail line shows counts. Compare them with the AI Security console: AI Guard policies, rules and AI Applications.

**Fix:**

- A failure on one list (for example 'Read llm provider credentials') means the API client's AI Guard access is partial. Give it full AI Guard access.

**Re-test:** `./aiguard-kit preflight` → ✓ Read access to AI Guard

<a id="write"></a>
## Create and delete permission

**What it checks:** Optional probe: creates an app named '<prefix>: preflight probe' and deletes it immediately.

**Why it matters:** Without create permission, setup fails at its first object. Finding out here means nothing is half-created.

**Verify by hand:**

- AI Security console → AI Applications: there should be no '<prefix>: preflight probe' app afterwards.
- In ZIdentity, the API client's AI Guard access should be full, not read-only.

**Fix:**

- Grant the API client full AI Guard access, save, wait a minute, then run the checks again.
- If a probe app was left behind (only possible if the delete failed), delete it in the console or run teardown.

**Re-test:** `./aiguard-kit preflight --write-probe` → ✓ Create and delete permission

> **Confirm in your tenant:** The ZIdentity wording for read-only vs full AI Guard access hasn't been confirmed.

<a id="prov-openai"></a>
## OpenAI provider available

**What it checks:** Looks for an LLM provider of type 'openai' in the tenant.

**Why it matters:** Only needed for proxy mode with OpenAI. Detection mode is unaffected.

**Verify by hand:**

- AI Security console → LLM providers: a provider of type OpenAI is listed (tenants normally include 'Default OpenAI Provider').

**Fix:**

- If it's missing, add an OpenAI provider in the console, or skip proxy mode for this app.

**Re-test:** `./aiguard-kit preflight` → ✓ OpenAI provider available

> **Confirm in your tenant:** Console menu name for providers not captured yet.

<a id="prov-anthropic"></a>
## Anthropic provider available

**What it checks:** Looks for an LLM provider of type 'anthropic' in the tenant.

**Why it matters:** Only needed for proxy mode with Anthropic. Detection mode is unaffected.

**Verify by hand:**

- AI Security console → LLM providers: a provider of type Anthropic is listed (normally 'Default Anthropic Provider').

**Fix:**

- If it's missing, add an Anthropic provider in the console, or skip proxy mode for this app.

**Re-test:** `./aiguard-kit preflight` → ✓ Anthropic provider available

> **Confirm in your tenant:** Console menu name for providers not captured yet.

<a id="existing"></a>
## Earlier kit objects

**What it checks:** Counts policies, rules and apps whose names start with the kit prefix (default 'SE-Demo:').

**Why it matters:** Lets setup keep and fill in an earlier setup, or replace it, instead of creating duplicates.

**Verify by hand:**

- Search the console for 'SE-Demo:' in policies, rules and AI Applications.

**Fix:**

- Nothing to fix. In step 3, choose Keep (fill in gaps) or Delete and start fresh.
- If someone else in a shared tenant uses the same prefix, run the kit with --prefix 'SE-Demo-<yourname>'.

**Re-test:** Informational only.

<a id="rules"></a>
## No broad rules ahead of the kit's

**What it checks:** Looks for enabled rules that don't match by application (for example match type USER).

**Why it matters:** The kit's rules match only its own apps, so app-based rules can't take its traffic. A rule that matches by user might, and then that rule's policy judges the demo traffic.

**Verify by hand:**

- AI Guard policy rules in the console: check the listed rules' match criteria and order.
- After setup, verification reports which policy actually handled each app's test scan. If it names the kit's policy, the warning didn't matter.

**Fix:**

- If verification shows another policy: disable that rule for the demo, narrow its users, or move the kit's rules above it in the console.
- Then press Retry checks (console) or run `./aiguard-kit status`.

**Re-test:** Verification after setup → ✓ '<app>: Detection API … policy '<prefix>: Test all''

> **Confirm in your tenant:** Whether user-matched rules apply to Detection API scans that carry a user hasn't been tested.

<a id="policy"></a>
## Reused policy covers the tests

**What it checks:** Only when you reuse an existing policy: compares its enabled detectors with the kit's template.

**Why it matters:** Each missing detector leaves a console panel empty (for example no prompt_tags = no Prompt Classifications).

**Verify by hand:**

- Open the policy in the console and check the listed detectors are enabled for prompts and responses.

**Fix:**

- Enable the missing detectors in the console, or let setup create the kit's own policy (recommended; it can also be switched between Monitor and Enforce).

**Re-test:** `./aiguard-kit preflight` → ✓ Reused policy covers the tests

<a id="manual"></a>
## Tenant Settings > Security > Store Prompts/Responses

**What it checks:** A reminder. This setting can't be read through the API.

**Why it matters:** When it's off, events still appear but prompt and response text isn't shown in event details.

**Verify by hand:**

- AI Security console (≡ > AI Security) → AI Guard → Tenant Settings → Security tab → Store Prompts/Responses is on.

**Fix:**

- Turn it on and save. It applies to new events only.

**Re-test:** Run one test, then open its event in the console and check the prompt text shows.

<a id="verify-policy"></a>
## Verification: handled by the demo policy

**What it checks:** After setup, scans one prompt through each app's detection key and compares the policy that handled it with the kit's policy. Retries for about a minute while new keys activate.

**Why it matters:** This is the end-to-end proof that keys, rules and policy are wired correctly.

**Verify by hand:**

- ✓ lines name the kit's policy and show a response time.
- In the console, AI Guard events for the apps '<prefix>: OpenAI App' and '<prefix>: Anthropic App' appear within a few minutes.

**Fix:**

- 'handled by … instead': another rule matched first (see 'No broad rules ahead of the kit's').
- 401 / 404 after a minute: the key isn't active or was deleted. Rerun setup (it recreates missing keys).
- 400 mentioning authenticate-llm-app: the request used a proxy key. Rerun setup to create detection keys.

**Re-test:** Console: Retry checks on the last setup step. Terminal: `./aiguard-kit status`.
