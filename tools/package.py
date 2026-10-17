"""Build the release files into dist/:

  aiguard-se-kit-<v>.zip              full kit with the double-click installers (share via Teams/OneDrive/GitHub)
  aiguard-se-kit-<v>-email.zip        no .cmd/.command files, so mail filters don't block it
  aiguard-se-demo-<v>.plugin          Claude plugin
  aiguard-se-demo-<v>-email.plugin    plugin without .cmd files
  SHA256SUMS.txt

Run: python tools/package.py   (uses the committed files at HEAD)
"""
import hashlib
import io
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
SHIP = ["Install AI Guard Kit.cmd", "Install AI Guard Kit.command", "Uninstall AI Guard Kit.cmd",
        "Uninstall AI Guard Kit.command", "aiguard-kit", "aiguard-kit.cmd", "aiguard_kit.py", "gui.html", "tests.json",
        "packs", "policy_template.json", "preflight_help.json", "README.md", "INSTALL.md", "PREFLIGHT.md", "SECURITY.md",
        "TESTPLAN.md", "CHANGELOG.md", "WINDOWS.md"]
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


def main():
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
    for f in files + [DIST / "SHA256SUMS.txt"]:
        print(f.relative_to(ROOT))


if __name__ == "__main__":
    main()
