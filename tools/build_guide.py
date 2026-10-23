"""Build the SE deployment guide for a release into dist/:

  AI-Guard-ZIA-SE-Demo-Kit-Deployment-Guide-<v>.md     docs/DEPLOYMENT-GUIDE.md stamped with the kit versions
  AI-Guard-ZIA-SE-Demo-Kit-Deployment-Guide-<v>.docx   the same, as a Word file (needs pandoc)

Run: python tools/build_guide.py [--require]   (--require: fail if pandoc is missing, as the release workflow does)
The source of truth is docs/DEPLOYMENT-GUIDE.md: change it in the same branch as the behavior it describes.
"""
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
SRC = ROOT / "docs" / "DEPLOYMENT-GUIDE.md"
NAME = "AI-Guard-ZIA-SE-Demo-Kit-Deployment-Guide"


def versions():
    kit = re.search(r'^VERSION = "([^"]+)"', (ROOT / "aiguard_kit.py").read_text(encoding="utf-8"), re.M).group(1)
    zia = re.search(r'^ZIA_VERSION = "([^"]+)"', (ROOT / "zia_module.py").read_text(encoding="utf-8"), re.M).group(1)
    return kit, zia


def stamped(text, kit, zia):
    """The title, a line naming the versions this copy describes, and the manual steps as an appendix (generated
    from manual_steps.json, like the console's Manual steps tab)."""
    title, _, rest = text.partition("\n")
    sys.path.insert(0, str(ROOT / "tools"))
    import gen_manual_doc
    appendix = gen_manual_doc.render(level=2).replace("## Manual steps", "## Appendix: manual steps", 1)
    return f"{title}\n\n**AI Guard SE Demo Kit {kit} · ZIA SE Demo Kit {zia}**\n{rest.rstrip()}\n\n{appendix}\n"


def build(require=False):
    kit, zia = versions()
    DIST.mkdir(exist_ok=True)
    md = DIST / f"{NAME}-{kit}.md"
    md.write_text(stamped(SRC.read_text(encoding="utf-8"), kit, zia), encoding="utf-8")
    out = [md]
    if shutil.which("pandoc"):
        docx = md.with_suffix(".docx")
        subprocess.run(["pandoc", str(md), "-f", "gfm", "-o", str(docx),
                        "--metadata", f"title=AI Guard + ZIA SE Demo Kit: Deployment Guide ({kit})"], check=True)
        out.append(docx)
    elif require:
        sys.exit("pandoc not found: install it to build the Word copy")
    else:
        print("pandoc not found: built the Markdown copy only")
    for f in out:
        print(f.relative_to(ROOT))
    return out


if __name__ == "__main__":
    build("--require" in sys.argv)
