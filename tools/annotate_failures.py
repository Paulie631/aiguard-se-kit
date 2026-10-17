"""Turn pytest output into GitHub error annotations, one per failing test (readable without signing in)."""
import re
import sys

text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
parts = re.split(r"^_{3,} (\S.*?) _{3,}$", text, flags=re.M)
blocks = list(zip(parts[1::2], parts[2::2])) or [("pytest", text[-3000:])]
for name, body in blocks[:10]:
    msg = body.strip()[-3500:].replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::error title={name}::{msg}")
