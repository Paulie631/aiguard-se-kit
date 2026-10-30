# Installing the AI Guard SE Demo Kit

## Double-click install (recommended)

1. Unzip `aiguard-se-kit-<version>.zip` anywhere, for example in Downloads. **On Windows, right-click the zip → Extract All.** Double-clicking a file inside the zip without extracting won't work.
2. Open the `aiguard-se-kit` folder and double-click the installer for your computer:
   - **Windows:** `Install AI Guard Kit.cmd`
   - **Mac:** `Install AI Guard Kit.command`
3. Press a key (Windows) or Return (Mac) to start. The installer:
   - installs **uv**, the free tool the kit runs on, if it isn't installed yet
   - downloads Python 3.12 and the kit's libraries (a minute or two the first time)
   - copies the kit to `~/.aiguard-se-kit/app` (Windows: `%USERPROFILE%\.aiguard-se-kit\app`)
   - adds an **AI Guard Demo Console** shortcut to your desktop (and the Start menu on Windows)
   - adds the `aiguard-kit` command, so `aiguard-kit gui` works from any folder in a new terminal
   - re-points scheduled traffic at the installed copy, if you'd set it up
   - opens the console on its Setup tab, in your browser and in the background: you can close the installer window
4. From then on, double-click **AI Guard Demo Console** on your desktop. It runs in the background (no terminal window) and opens in your browser; the first start after an install or update can take up to a minute. Click the shortcut again to bring the console back, and **Quit** (top right) to stop it. If nothing opens, run `aiguard-kit gui` in a terminal to see why.

You can delete the unzipped folder afterwards. Your settings, keys and test results stay in `~/.aiguard-se-kit` and the system keychain, so reinstalling or upgrading never asks you to set up again.

### First-run security prompts

The installers aren't code-signed yet, so your computer asks once:

- **Windows:** "Open File - Security Warning" → **Run**. If you see "Windows protected your PC", click **More info** → **Run anyway**.
- **Mac:** "cannot be opened because it is from an unidentified developer". Right-click the installer → **Open** → **Open**. On recent macOS, go to **System Settings → Privacy & Security** and click **Open Anyway**.

If your laptop's policy blocks this entirely, use the command-line steps below, or ask IT.

### Updating

The console checks for new versions. When one is out, the **Updates** button at the top turns into **Update to x.y.z**. Click it, read what's new, and click **Install update**. The console downloads the release from GitHub, checks it against the release's SHA-256 checksum, installs it and restarts itself. Your settings, keys and tenant objects aren't touched. **Roll back** in the same dialog returns to the previous version.

From a terminal: `aiguard-kit update` (add `--check` to only check, or `--rollback` to go back).

If your laptop's web policy blocks GitHub downloads, the console says so. Then download the newest zip from https://github.com/Paulie631/aiguard-se-kit/releases/latest in your browser, extract it, and double-click its installer. The previous copy is always kept in `~/.aiguard-se-kit/app.previous`.

### Uninstalling

- **Windows:** Start menu → **Uninstall AI Guard Demo Kit**, or run `aiguard-kit uninstall`
- **Mac:** run `aiguard-kit uninstall` in Terminal, or double-click `Uninstall AI Guard Kit.command` in `~/.aiguard-se-kit/app`

Uninstalling removes the kit, its shortcuts, its PATH entry and scheduled traffic. It keeps your settings, keys and the demo objects in your tenant. To remove the tenant objects, run `aiguard-kit teardown` **before** uninstalling.

## Command line (unchanged)

Nothing about the command line changed. From the unzipped folder:

- **Mac:** `./aiguard-kit gui`
- **Windows (PowerShell):** `.\aiguard-kit.cmd gui` (see [WINDOWS.md](WINDOWS.md))

After installing, `aiguard-kit gui` also works from any folder.

## If the installer can't install uv

Your laptop's security policy may block the download. The installer tries the official installer, then winget (Windows) or Homebrew (Mac). If all of them fail, ask IT to allow downloads from `astral.sh` and `github.com`, or install uv another way (https://docs.astral.sh/uv/getting-started/installation/), then run the installer again.
