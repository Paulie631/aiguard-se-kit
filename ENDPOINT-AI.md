# Endpoint AI Security demo

The kit can also show **Zscaler Endpoint AI Security**: an AI coding agent on the traffic generator tries something
risky, Endpoint AI records it in **Monitor** mode, and stops it in **Block** mode. Everything the kit creates is
scoped to the generator alone, and the scenes use only safe test data.

Demo and evaluation tenants only.

## What the kit creates

| Object | Name | Scope |
| --- | --- | --- |
| Device group | `SE-Demo: traffic generator` | only the generator's device(s) |
| Runtime policy | `SE-Demo: Agentic Guardrails` | assigned to that device group only, priority 900 |

The policy's rules (`eai_policy_template.json`):

- **Cloud access key in a tool call**: a command containing an AWS access key (`AKIA` plus 16 characters).
- **Recursive force-delete**: `rm -rf` or `Remove-Item -Recurse`.
- **Shell lock** (optional, off by default): every shell command from an AI agent.

**Monitor** sets every rule to `audit` (the command runs and is recorded); **Block** sets them to `block`. Before
saving, the kit checks the rules with Endpoint AI's dry-run validator.

What the kit never touches: tenant-wide Settings, identity domains, console admins, sign-in settings, other
policies or groups, and resource-control (file quarantine and delete) rules. Teardown deletes only the policy and
device group above, found by the id setup saved and confirmed by exact name. `--devices` also removes the
generator devices setup itself added to the group, never devices someone added by hand.

## Setup

1. **Credential (manual, once).** In the Endpoint AI console, open **Administration > API Access** and create a
   credential named `se-demo-kit` with the **Admin** role and an expiry (90 days is a good choice). Copy the
   client_id and the client_secret: the secret starts with `sqrx_sk_` and is shown once. An API credential can't
   create credentials, so this step stays manual.
2. **Connect.** On the console's **Endpoint AI** tab, enter the console domain (`zsai.sqrx.io` or your
   Zscaler-branded domain), the region (the `use2` in the API host `https://use2.api.<domain>`), the client_id and
   the secret, then click **Save and test**. Or run `./aiguard-kit eai connect`. The secret goes into the
   keychain; logs and diagnostics mask anything shaped like `sqrx_sk_…`.
3. **Agent on the generator (manual).** Client Connector delivers the Endpoint AI agent. Turn it on for the
   generator's app profile in the Client Connector portal, and check the generator shows under **Administration >
   Devices** in the Endpoint AI console.
4. **Demo policy.** Click **Create or update** on the Endpoint AI tab (or run `./aiguard-kit eai setup`). The kit
   finds the generator by the test user it created for ZIA, or by a hostname you enter (`--host EC2AMAZ-1A2B3C`),
   and adds it to the device group. Every device the API returns is checked against that hostname or user, and if
   more than three match, setup stops and asks for the exact hostname. A ZIA test user you picked yourself is never
   used to find devices (it could be a real person's laptop): enter the generator's hostname instead. If the agent
   isn't on yet, run setup again once it is.
5. **Claude Code on the generator (manual, once).** Signed in to Windows on the generator as the user who will run
   the demo:
   - `C:\SE-Demo\eai.cmd demo --install` installs Claude Code with Anthropic's installer, for that user (no admin).
     The kit checks the binary is signed by Anthropic.
   - Then sign it in: run `claude` once and follow the browser sign-in, **or** save an Anthropic API key with
     `C:\SE-Demo\eai.cmd demo --set-key` (stored in that user's Credential Manager; never in the setup script, the
     CloudFormation template or the kit's config).

## The scenes

Double-click **SE-Demo Endpoint AI scenes** on the generator's desktop (or run `aiguard-kit eai demo`). Claude
Code runs headless (`claude -p`) with a fixed prompt for each scene, in the kit's own work folder:

| Scene | Command the agent runs | Safe because |
| --- | --- | --- |
| Agent writes a cloud access key to disk | `Set-Content -Path demo-credentials.txt -Value 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE'` | `AKIAIOSFODNN7EXAMPLE` is AWS's published documentation example |
| Agent runs a recursive force-delete | `Remove-Item -Recurse -Force .\decoy-project` | a throwaway folder the kit creates (and puts back) in its work folder |

Claude Code may run only each scene's exact command (`--allowedTools` names the full command, nothing broader),
with at most three turns. The scenes refuse to run on a computer that holds the Endpoint AI credential (your own
machine), and ask before they start. What Claude Code says about a scene is shown, but Endpoint AI's own events
are the record of what was blocked.

The story: start in **Monitor**, run the scenes, show the activity (the commands ran and were recorded, with
OWASP Agentic and MITRE ATLAS tags). Switch **Mode** to **Block** and run them again: Endpoint AI stops each command
before it runs and tells the agent why.

## Showing the results

- **Generator activity** on the Endpoint AI tab (or `./aiguard-kit eai events --hours 24`): the generator's recent AI
  events, the demo's own on top, with verdict, tool, command and detections.
- **Build PDF**: the **AI Security Executive Brief** or **AI Asset Report** for the last 7 days
  (`./aiguard-kit eai report --edition executive`), saved under the kit's folder in `reports/` and downloadable
  from the tab. A leave-behind for the customer.
- **Check status** / **Demo readiness**: the credential (and when it expires), the device group, whether the
  generator is online, the policy's mode and assignment, and whether demo events arrived in the last 24 hours.

## Commands

```
./aiguard-kit eai connect                    save and test the API credential
./aiguard-kit eai setup [--host NAME] [--mode monitor|block] [--shell-lock]
./aiguard-kit eai mode monitor|block         switch the demo policy
./aiguard-kit eai status                     credential, device group, generator, policy, recent events
./aiguard-kit eai events [--hours 24]        the generator's recent AI activity
./aiguard-kit eai report [--edition executive|ai-asset] [--days 7]
./aiguard-kit eai teardown [--devices]       delete the policy and device group (--devices: also the generator's devices)
./aiguard-kit eai demo [--scene secret,destructive] [--install] [--set-key]   on the generator
```

## Troubleshooting

| Message | What to do |
| --- | --- |
| `invalid_client` | The client_id or secret is wrong, or the credential was revoked or expired. Create a new one in API Access. |
| `forbidden` | The credential's role can't write. Create one with the Admin role (roles can't be edited). |
| `token_invalid` | Wrong region for this tenant. Copy the API host from API Access. |
| No generator device | The agent isn't on the generator yet (Client Connector app profile), or the generator is signed in as a different user. Enter its hostname and run setup again. |
| Scenes say Claude Code didn't run | Sign in with `claude`, or save an API key with `eai demo --set-key`. |
| No events after the scenes | Events take a few minutes. Check the generator is online under Administration > Devices. |
| `too_many_reports` | Five reports are already being built. Wait, then try again. |

Every API error the kit logs carries Endpoint AI's `request_id`, which is what Zscaler support needs to trace a
failed call.
