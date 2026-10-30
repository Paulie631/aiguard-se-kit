"""Build the release files into dist/:

  aiguard-se-kit-<v>.zip              full kit with the double-click installers (share via Teams/OneDrive/GitHub)
  aiguard-se-kit-<v>-email.zip        no .cmd/.command files, so mail filters don't block it
  aiguard-se-demo-<v>.plugin          Claude plugin
  aiguard-se-demo-<v>-email.plugin    plugin without .cmd files
  SHA256SUMS.txt
  latest.json                         what the kit's update check reads (version, notes, zip link, SHA-256)

Run: python tools/package.py   (uses the committed files at HEAD)

The ZIA kit (a separate edition with its own version, install folder and update channel):
  python tools/package.py --edition zia
  zscaler-zia-kit-<v>.zip, zscaler-zia-kit-<v>-email.zip, zscaler-zia-kit.zip (unversioned copy for the rolling
  zia-latest release), SHA256SUMS-zia.txt and zia/latest.json, all in dist/
"""
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
SHIP = ["Install AI Guard Kit.cmd", "Install AI Guard Kit.command", "Uninstall AI Guard Kit.cmd",
        "Uninstall AI Guard Kit.command", "aiguard-kit", "aiguard-kit.cmd", "aiguard_kit.py", "gui.html", "tests.json",
        "packs", "policy_template.json", "preflight_help.json", "manual_steps.json", "MANUAL-STEPS.md", "README.md", "INSTALL.md", "PREFLIGHT.md", "SECURITY.md",
        "TESTPLAN.md", "CHANGELOG.md", "WINDOWS.md",
        "zia_module.py", "zia_traffic.py", "zia_aws.py", "zia_policy_template.json", "zia_traffic.json", "ZIA.md", "assets", "docs",
        "eai_module.py", "eai_policy_template.json", "ENDPOINT-AI.md"]
EMAIL_BLOCKED = re.compile(r"\.(cmd|command|bat|ps1|exe)$", re.I)


def version():
    return re.search(r'^VERSION = "([^"]+)"', (ROOT / "aiguard_kit.py").read_text(encoding="utf-8"), re.M).group(1)


def archive():
    data = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=zip", "--prefix=aiguard-se-kit/", "HEAD", *SHIP],
                          capture_output=True, check=True).stdout
    return zipfile.ZipFile(io.BytesIO(data))


def rezip(src, dest, keep=lambda name: True):
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for info in src.infolist():
            if keep(info.filename):
                out.writestr(info, src.read(info.filename))


def changelog_notes(v):
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    m = re.search(rf"^## {re.escape(v)}\b.*?\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    return (m.group(1) if m else "").strip()


ZIA_EDITION = {"product": "zia", "name": "Zscaler ZIA SE Demo Kit", "app_name": "Zscaler ZIA Demo Console",
               "app_dir": "app-zia", "command": "zia-kit", "uninstall_link": "Uninstall Zscaler ZIA Demo Kit.lnk"}
ZIA_EXTRA = ["CHANGELOG-ZIA.md"]


def zia_version():
    return re.search(r'^ZIA_VERSION = "([^"]+)"', (ROOT / "zia_module.py").read_text(encoding="utf-8"), re.M).group(1)


def changelog_notes_zia(v):
    text = (ROOT / "CHANGELOG-ZIA.md").read_text(encoding="utf-8")
    m = re.search(rf"^## {re.escape(v)}\b.*?\n(.*?)(?=^## |\Z)", text, re.M | re.S)
    return (m.group(1) if m else "").strip()


def zia_files(kit):
    """The ZIA kit's files: the whole kit (ZIA needs its core), plus edition.json and ZIA-named launchers."""
    repo = os.getenv("GITHUB_REPOSITORY", "Paulie631/aiguard-se-kit")
    v = zia_version()
    edition = dict(ZIA_EDITION, version=v,
                   update_url=f"https://github.com/{repo}/releases/download/zia-latest/latest.json")
    files = {}
    for info in kit.infolist():
        data = kit.read(info.filename)
        name = info.filename
        name = "zscaler-zia-kit/" + name.split("/", 1)[1]   # the zip unpacks to a zscaler-zia-kit folder
        if name.endswith(("Install AI Guard Kit.cmd", "Install AI Guard Kit.command")):
            name = name.replace("Install AI Guard Kit", "Install ZIA Kit")
            for a, b in ((b"AI Guard SE Demo Kit", b"Zscaler ZIA SE Demo Kit"),
                         (b"AI Guard Demo Console", b"Zscaler ZIA Demo Console"),
                         (b"Install AI Guard Kit", b"Install ZIA Kit"),
                         (b'aiguard-kit" from any terminal', b'zia-kit" from any terminal'),
                         (b"aiguard-se-kit zip", b"zscaler-zia-kit zip"),
                         (b"aiguard-se-kit folder", b"zscaler-zia-kit folder"),
                         # the installed copy lives in app-zia, so open that console at the end, not the AI Guard one
                         (b"\\.aiguard-se-kit\\app", b"\\.aiguard-se-kit\\app-zia"),
                         (b"/.aiguard-se-kit/app", b"/.aiguard-se-kit/app-zia")):
                data = data.replace(a, b)
        files[name] = (info, data)
    pre = "zscaler-zia-kit/"
    for src, dst in (("aiguard-kit", "zia-kit"), ("aiguard-kit.cmd", "zia-kit.cmd")):
        info, data = files[pre + src]
        files[pre + dst] = (info, data)
    files[pre + "edition.json"] = (None, json.dumps(edition, indent=2).encode())
    return v, edition, files


def write_zip(dest, files, keep=lambda name: True):
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for name, (info, data) in files.items():
            if not keep(name):
                continue
            zi = zipfile.ZipInfo(name, date_time=info.date_time if info else (2026, 1, 1, 0, 0, 0))
            zi.external_attr = info.external_attr if info else 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            out.writestr(zi, data)


def main_zia():
    data = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=zip", "--prefix=aiguard-se-kit/", "HEAD",
                           *SHIP, *ZIA_EXTRA], capture_output=True, check=True).stdout
    v, edition, files = zia_files(zipfile.ZipFile(io.BytesIO(data)))
    (DIST / "zia").mkdir(parents=True, exist_ok=True)
    out = [DIST / f"zscaler-zia-kit-{v}.zip", DIST / f"zscaler-zia-kit-{v}-email.zip", DIST / "zscaler-zia-kit.zip"]
    write_zip(out[0], files)
    write_zip(out[1], files, lambda n: not EMAIL_BLOCKED.search(n))
    out[2].write_bytes(out[0].read_bytes())
    sums = "".join(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n" for f in out[:2])
    (DIST / "SHA256SUMS-zia.txt").write_text(sums)
    repo = os.getenv("GITHUB_REPOSITORY", "Paulie631/aiguard-se-kit")
    (DIST / "zia" / "latest.json").write_text(json.dumps({
        "version": v, "tag": f"zia-v{v}", "edition": "zia", "notes": changelog_notes_zia(v),
        "zip_url": f"https://github.com/{repo}/releases/download/zia-v{v}/{out[0].name}",
        "sha256": hashlib.sha256(out[0].read_bytes()).hexdigest()}, indent=2))
    for f in out + [DIST / "SHA256SUMS-zia.txt", DIST / "zia" / "latest.json"]:
        print(f.relative_to(ROOT))


def main():
    if "--edition" in sys.argv:
        edition = sys.argv[sys.argv.index("--edition") + 1]
        if edition != "zia":
            raise SystemExit(f"Unknown edition {edition}")
        DIST.mkdir(exist_ok=True)
        return main_zia()
    v = version()
    DIST.mkdir(exist_ok=True)
    kit = archive()
    files = [DIST / f"aiguard-se-kit-{v}.zip", DIST / f"aiguard-se-kit-{v}-email.zip"]
    rezip(kit, files[0])
    rezip(kit, files[1], lambda n: not EMAIL_BLOCKED.search(n))
    subprocess.run([sys.executable, str(ROOT / "tools/build_plugin.py")], check=True, capture_output=True)
    plugin = zipfile.ZipFile(DIST / "aiguard-se-demo.plugin")
    files += [DIST / f"aiguard-se-demo-{v}.plugin", DIST / f"aiguard-se-demo-{v}-email.plugin"]
    rezip(plugin, files[2])
    rezip(plugin, files[3], lambda n: not EMAIL_BLOCKED.search(n))
    sums = "".join(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n" for f in files)
    (DIST / "SHA256SUMS.txt").write_text(sums)
    repo = os.getenv("GITHUB_REPOSITORY", "Paulie631/aiguard-se-kit")
    (DIST / "latest.json").write_text(json.dumps({
        "version": v, "tag": f"v{v}", "notes": changelog_notes(v),
        "zip_url": f"https://github.com/{repo}/releases/download/v{v}/{files[0].name}",
        "sha256": hashlib.sha256(files[0].read_bytes()).hexdigest()}, indent=2))
    for f in files + [DIST / "SHA256SUMS.txt", DIST / "latest.json"]:
        print(f.relative_to(ROOT))


if __name__ == "__main__":
    main()
