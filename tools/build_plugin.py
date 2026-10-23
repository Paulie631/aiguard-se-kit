"""Builds dist/aiguard-se-demo.plugin: the plugin folder plus a copy of the kit inside the skill.

  python tools/build_plugin.py          build
  python tools/build_plugin.py --check  validate the plugin structure only (used in CI)
"""
import json
import pathlib
import re
import shutil
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "plugin" / "aiguard-se-demo"
KIT_FILES = ["aiguard-kit", "aiguard-kit.cmd", "aiguard_kit.py", "gui.html", "tests.json", "policy_template.json",
             "README.md", "SECURITY.md", "CHANGELOG.md", "PREFLIGHT.md", "preflight_help.json", "WINDOWS.md",
             "zia_module.py", "zia_traffic.py", "zia_aws.py", "zia_policy_template.json", "zia_traffic.json", "ZIA.md"]


def check():
    manifest = json.loads((SRC / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert re.fullmatch(r"[a-z0-9-]+", manifest["name"]), "plugin name must be kebab-case"
    skills = list((SRC / "skills").glob("*/SKILL.md"))
    assert skills, "no skills found"
    for s in skills:
        assert s.read_text(encoding="utf-8").startswith("---\nname: "), f"{s} needs YAML frontmatter"
    kit_version = re.search(r'VERSION = "([^"]+)"', (ROOT / "aiguard_kit.py").read_text(encoding="utf-8")).group(1)
    assert manifest["version"] == kit_version, f"plugin {manifest['version']} != kit {kit_version}"
    return manifest


def build():
    manifest = check()
    out = ROOT / "dist"
    stage = out / "stage"
    shutil.rmtree(stage, ignore_errors=True)
    shutil.copytree(SRC, stage)
    kit = stage / "skills" / "aiguard-demo" / "kit"
    kit.mkdir(parents=True)
    for f in KIT_FILES:
        shutil.copy2(ROOT / f, kit / f)
    shutil.copytree(ROOT / "packs", kit / "packs")
    target = out / f"{manifest['name']}.plugin"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(stage.rglob("*")):
            if p.is_file():
                info = zipfile.ZipInfo.from_file(p, p.relative_to(stage).as_posix())
                if p.name == "aiguard-kit":
                    info.external_attr = 0o755 << 16
                z.writestr(info, p.read_bytes(), zipfile.ZIP_DEFLATED)
    shutil.rmtree(stage)
    print(f"built {target}")


if __name__ == "__main__":
    check() if "--check" in sys.argv else build()
    if "--check" in sys.argv:
        print("plugin structure ok")
