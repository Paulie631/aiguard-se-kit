# Running the kit on Windows

Use **PowerShell** or **Windows Terminal**. Run every command from inside the `aiguard-se-kit` folder.

## 1. Install uv (one time)

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Close the terminal and open a new one** so `uv` is on your PATH. Check with `uv --version`. (`.\aiguard-kit.cmd` also finds uv in its default folder, so it works even in the old window.)

If the installer is blocked on your laptop, try `winget install --id=astral-sh.uv -e`, or `pip install uv` if Python is installed.

## 2. Start the console

If the folder has `aiguard-kit.cmd`:

```powershell
.\aiguard-kit.cmd gui
```

PowerShell needs the leading `.\`. Typing `aiguard-kit.cmd gui` without it gives "is not recognized".

If `aiguard-kit.cmd` is missing (the emailed copy leaves it out because mail filters block `.cmd` files), run this once instead. The kit creates `aiguard-kit.cmd` for next time.

```powershell
$env:UV_NATIVE_TLS=1; $env:UV_SYSTEM_CERTS=1; uv run --python 3.12 --script .\aiguard_kit.py gui
```

Everywhere the README says `./aiguard-kit`, use `.\aiguard-kit.cmd`.

## If something goes wrong

| Symptom | Fix |
|---|---|
| `uv : The term 'uv' is not recognized` | Open a new terminal after installing uv. If it still fails, sign out of Windows and back in. |
| `aiguard-kit.cmd : The term ... is not recognized` | Add `.\` in front: `.\aiguard-kit.cmd gui`. |
| Windows asks which app to open `aiguard-kit` with | That file is the Mac launcher. Use `.\aiguard-kit.cmd`. |
| `CERTIFICATE_VERIFY_FAILED`, `UnknownIssuer` or uv can't download packages | Zscaler SSL inspection. Start through `.\aiguard-kit.cmd` (or set `UV_NATIVE_TLS=1` as above), and check the Zscaler root CA is in Windows' Trusted Root Certification Authorities. |
| `Failed to build pyyaml` or `Microsoft Visual C++ 14.0 or greater is required` | uv picked a Python too new for the kit's libraries. Use `.\aiguard-kit.cmd` (it pins Python 3.12), or add `--python 3.12` to the `uv run` command. You don't need Visual C++. |
| `running scripts is disabled on this system` | That's PowerShell's script policy blocking the uv installer. Use the exact install command above, which bypasses it for that one command. |
| Credential Manager error | Keys are saved in Windows Credential Manager under `aiguard-se-kit`. Make sure you're signed in to Windows as yourself, not a shared or admin account. |
| The browser doesn't open | Copy the `http://127.0.0.1:...` address from the terminal into your browser. |
| `Copy report` / `--json` output | `.\aiguard-kit.cmd preflight --json > preflight.json`, then send the file. It contains no secrets. |

Scheduled traffic (`.\aiguard-kit.cmd schedule install`) uses Task Scheduler. It runs while you're signed in and logs to `%USERPROFILE%\.aiguard-se-kit\trickle.log`.
