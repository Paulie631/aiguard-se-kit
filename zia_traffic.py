"""ZIA traffic generator: real traffic through Client Connector so ZIA, Insights and Shadow IT dashboards fill.

Run it on a machine whose Client Connector is enrolled in the DEMO tenant and signed in as the kit's test user
(a lab or cloud VM), never on a corporate laptop. It needs no API keys: it only browses.

  ./aiguard-kit zia check     is this machine's traffic reaching the demo tenant? (one request per check)
  ./aiguard-kit zia traffic   one round: --types web,saas,genai,threats,dlp,files,dns,ports  --count N

Safe test data only: the EICAR test string (assembled at runtime so the kit's own files never trip antivirus),
Google's Safe Browsing test pages, and generated fake card numbers, SSNs and keys.
"""
from __future__ import annotations

import base64
import io
import json
import random
import re
import socket
import string
import struct
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TYPES = ("web", "saas", "genai", "threats", "dlp", "files", "dns", "ports")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/141.0.0.0 Safari/537.36")
TIMEOUT = 15
MAX_DOWNLOAD = 3 * 1024 * 1024

# The EICAR antivirus test string, in pieces so no kit file contains it whole.
_EICAR_PARTS = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-", "TEST-FILE!$H+H*")


def eicar():
    return "".join(_EICAR_PARTS)


def catalog():
    return json.loads((HERE / "zia_traffic.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------- fake data (never real)
TEST_BINS = ("411111", "401288", "555555", "510510", "601111", "378282")  # card networks' published test ranges


def luhn_ok(num: str) -> bool:
    total = 0
    for i, d in enumerate(reversed([int(c) for c in num])):
        total += (d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 else d
    return total % 10 == 0


def fake_card(rnd=random):
    bin_ = rnd.choice(TEST_BINS)
    length = 15 if bin_.startswith("37") else 16
    body = bin_ + "".join(rnd.choice(string.digits) for _ in range(length - len(bin_) - 1))
    for check in string.digits:
        if luhn_ok(body + check):
            return body + check
    raise AssertionError("unreachable")


def fake_ssn(rnd=random):
    area = rnd.choice([a for a in range(100, 900) if a != 666])
    return f"{area:03d}-{rnd.randint(1, 99):02d}-{rnd.randint(1, 9999):04d}"


def fake_aws_key(rnd=random):
    """Same shape as an AWS access key pair; random, so it was never issued to anyone."""
    kid = "AKIA" + "".join(rnd.choice(string.ascii_uppercase + "234567") for _ in range(16))
    sec = "".join(rnd.choice(string.ascii_letters + string.digits + "/+") for _ in range(40))
    return kid, sec


FIRST = ("Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Jamie", "Avery", "Quinn", "Drew")
LAST = ("Rivera", "Chen", "Patel", "Okafor", "Nguyen", "Schmidt", "Kowalski", "Haddad", "Silva", "Brooks")


def fake_records(n=8, rnd=random):
    rows = []
    for _ in range(n):
        rows.append({"name": f"{rnd.choice(FIRST)} {rnd.choice(LAST)}", "ssn": fake_ssn(rnd), "card": fake_card(rnd),
                     "exp": f"{rnd.randint(1, 12):02d}/{rnd.randint(27, 31)}",
                     "dob": f"{rnd.randint(1960, 2000)}-{rnd.randint(1, 12):02d}-{rnd.randint(1, 28):02d}"})
    return rows


def records_text(rows):
    return "\n".join(f"{r['name']}, SSN {r['ssn']}, DOB {r['dob']}, Visa/MC {r['card']} exp {r['exp']}" for r in rows)


def records_csv(rows):
    return "name,ssn,dob,card,exp\n" + "\n".join(f"{r['name']},{r['ssn']},{r['dob']},{r['card']},{r['exp']}" for r in rows) + "\n"


def tiny_pdf(text):
    """A valid one-page PDF with the given text, no libraries needed."""
    t = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")[:400]
    stream = f"BT /F1 11 Tf 40 760 Td ({t}) Tj ET".encode()
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offsets = io.BytesIO(), []
    out.write(b"%PDF-1.4\n")
    for i, o in enumerate(objs, 1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode() + o + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    out.write("".join(f"{o:010d} 00000 n \n" for o in offsets).encode())
    out.write(f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return out.getvalue()


def upload_files(rows):
    csv_ = records_csv(rows)
    z = io.BytesIO()
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("customers.csv", csv_)
    return [("customers.csv", csv_.encode(), "text/csv"),
            ("notes.txt", ("Quarterly notes\n" + records_text(rows[:3])).encode(), "text/plain"),
            ("export.json", json.dumps(rows, indent=1).encode(), "application/json"),
            ("statement.pdf", tiny_pdf("Statement for " + records_text(rows[:1])), "application/pdf"),
            ("archive.zip", z.getvalue(), "application/zip")]


# ---------------------------------------------------------------- what Zscaler did
def session():
    import requests
    s = requests.Session()
    s.headers.update({"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
                      "Accept-Language": "en-US,en;q=0.9"})
    return s


ZS_PAGE = re.compile(r"zscaler", re.I)
BLOCK_WORDS = re.compile(r"blocked|not allowed|restricted|acceptable use|policy|virus|malware|threat|denied|"
                         r"sorry|prohibited|data loss|sensitive", re.I)


def peer_issuer(host, port=443):
    """Who issued the certificate this host presents, without verifying it ('' if unknown)."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True) or b""
    except Exception:
        return ""
    # Unverified certs aren't parsed by getpeercert(); the issuer's O=/CN= text is readable in the DER bytes.
    return "Zscaler" if b"Zscaler" in der else "other"


def classify(resp=None, error=None, url=None):
    """-> block | caution | isolate | allow | error:<why>. A Zscaler page or redirect counts as Zscaler acting."""
    if error is not None:
        e = str(error)
        if re.search(r"reset|refused|aborted|10054|10061", e, re.I):
            return "block"  # a firewall BLOCK_RESET, or HTTPS blocked without inspection
        if url and re.search(r"ssl|certificate|tls", type(error).__name__ + " " + e, re.I):
            # Without SSL inspection, ZIA still answers a blocked HTTPS site with its block page on a Zscaler-signed
            # certificate. If this machine doesn't trust the Zscaler root, that shows up as a TLS error.
            host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
            if peer_issuer(host) == "Zscaler":
                return "block"
        return "error:" + type(error).__name__
    hops = [h.headers.get("Location", "") for h in getattr(resp, "history", [])] + [str(getattr(resp, "url", ""))]
    trail = " ".join(hops).lower()
    if "zscaler" in trail and re.search(r"isolat|cbi|zsisolation", trail):
        return "isolate"
    ctype = resp.headers.get("Content-Type", "")
    text = ""
    if "html" in ctype or "text" in ctype or not ctype:
        try:
            text = resp.text[:40000]
        except Exception:
            text = ""
    zs = ZS_PAGE.search(text) or "gateway.zscaler" in trail or "zscaler.net" in trail
    if zs and re.search(r"caution|continue to|proceed", text, re.I) and not re.search(r"virus|malware|data loss", text, re.I):
        return "caution"
    if zs and (BLOCK_WORDS.search(text) or resp.status_code in (403, 451)):
        return "block"
    if resp.status_code >= 400:
        return f"allow:{resp.status_code}"  # the site's own error page: Zscaler let it through
    return "allow"


def fetch(s, method, url, stream_limit=False, **kw):
    """One request -> a result row. stream_limit: a download, read up to MAX_DOWNLOAD and discarded."""
    kw.setdefault("timeout", TIMEOUT)
    t0 = time.time()
    try:
        if stream_limit:
            r = s.request(method, url, stream=True, **kw)
            first, got = b"", 0
            try:
                for chunk in r.iter_content(65536):
                    first = first or chunk
                    got += len(chunk)
                    if got >= MAX_DOWNLOAD:
                        break
            finally:
                r.close()
            r._content = first   # a Zscaler block replaces the file with its HTML page, which classify() reads
        else:
            r = s.request(method, url, **kw)
        return {"url": url, "method": method, "outcome": classify(r), "status": r.status_code,
                "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"url": url, "method": method, "outcome": classify(error=e, url=url), "error": str(e)[:200],
                "ms": int((time.time() - t0) * 1000)}


# ---------------------------------------------------------------- traffic types
def _sample(seq, n, rnd):
    seq = list(seq)
    return seq if n >= len(seq) else rnd.sample(seq, n)


def gen_web(s, cat, n, rnd):
    must = [w for w in cat["web"] if w["expect"] == "block"][:1]   # always the tenant check
    rest = _sample([w for w in cat["web"] if w not in must], max(0, n * 3 - 1), rnd)
    for w in must + rest:
        yield dict(fetch(s, "GET", w["url"]), type="web", category=w["category"], expect=w["expect"])


def gen_saas(s, cat, n, rnd):
    for url in _sample(cat["saas"], n * 4, rnd):
        yield dict(fetch(s, "GET", url), type="saas")


def gen_genai(s, cat, n, rnd):
    for url in _sample(cat["genai"], n * 2, rnd):
        yield dict(fetch(s, "GET", url), type="genai")


def gen_threats(s, cat, n, rnd):
    b64 = base64.urlsafe_b64encode(eicar().encode()).decode()
    for tmpl in cat["threats"]["eicar_hosts"]:
        yield dict(fetch(s, "GET", tmpl.format(b64=b64)), type="threats", what="EICAR test string", expect="block")
    for url in cat["threats"]["eicar_files"]:
        yield dict(fetch(s, "GET", url, stream_limit=True), type="threats", what="EICAR test file", expect="block")
    for p in cat["threats"]["test_pages"]:
        yield dict(fetch(s, "GET", p["url"]), type="threats", what=p["what"], expect="block")


def gen_dlp(s, cat, n, rnd):
    for i in range(max(1, n // 2)):
        rows = fake_records(8, rnd)
        kid, sec = fake_aws_key(rnd)
        text = records_text(rows) + f"\naws_access_key_id = {kid}\naws_secret_access_key = {sec}\n"
        for url in cat["dlp"]["post_urls"]:
            yield dict(fetch(s, "POST", url, data={"item_meta[6]": text, "message": text, "submit": "Submit"}),
                       type="dlp", what="fake cards, SSNs and an AWS-style key", expect="block")


def gen_files(s, cat, n, rnd):
    rows = fake_records(6, rnd)
    for name, data, ctype in _sample(upload_files(rows), max(2, n), rnd):
        yield dict(fetch(s, "POST", cat["files"]["upload_url"], files={"file": (name, data, ctype)}),
                   type="files", what=f"upload {name}")
    for d in cat["files"]["downloads"]:
        yield dict(fetch(s, "GET", d["url"], stream_limit=True), type="files", what=f"download .{d['type']}",
                   expect=d["expect"])


def dns_query(server, name, qtype=1, timeout=4):
    """One A-record query over UDP/53, so DNS control sees resolver traffic (needs Z-Tunnel 2.0)."""
    qid = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"".join(
        bytes([len(p)]) + p.encode() for p in name.strip(".").split(".")) + b"\x00" + struct.pack(">HH", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
        sk.settimeout(timeout)
        sk.sendto(q, (server, 53))
        data, _ = sk.recvfrom(2048)
    rcode = data[3] & 0x0F
    answers = struct.unpack(">H", data[6:8])[0]
    return {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}.get(rcode, f"RCODE{rcode}"), answers


def gen_dns(s, cat, n, rnd):
    d = cat["dns"]
    names = _sample(d["names"], n * 2, rnd) + [
        "".join(rnd.choice(string.ascii_lowercase + string.digits) for _ in range(14)) + ".com"
        for _ in range(d.get("random_names", 3))]
    for name in names:
        t0 = time.time()
        try:
            addrs = sorted({a[4][0] for a in socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)})
            out = {"outcome": "resolved", "answer": addrs[:3]}
        except Exception as e:
            out = {"outcome": "no-answer", "error": str(e)[:120]}
        yield dict(out, type="dns", what=f"system lookup {name}", url=name, ms=int((time.time() - t0) * 1000))
    for server in d["resolvers"]:
        name = rnd.choice(d["names"])
        try:
            rcode, n_ans = dns_query(server, name)
            out = {"outcome": "resolved" if rcode == "NOERROR" and n_ans else rcode.lower()}
        except Exception as e:
            out = {"outcome": "block" if isinstance(e, ConnectionError) else "error:" + type(e).__name__, "error": str(e)[:120]}
        yield dict(out, type="dns", what=f"UDP/53 to {server} for {name}", url=f"dns://{server}/{name}")
    for tmpl in d["doh"]:
        url = tmpl.format(name=rnd.choice(d["names"]))
        yield dict(fetch(s, "GET", url, headers={"Accept": "application/dns-json"}), type="dns", what="DNS over HTTPS")


def tcp_probe(host, port, timeout=6):
    """-> open | block | timeout. portquiz.net answers HTTP on every port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sk:
            sk.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {UA}\r\n\r\n".encode())
            sk.settimeout(timeout)
            data = sk.recv(600)
        if not data:
            return "block"
        return "block" if b"zscaler" in data.lower() else "open"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        return "block" if re.search(r"reset|refused|10054|10061|aborted", str(e), re.I) else "error:" + type(e).__name__


def gen_ports(s, cat, n, rnd):
    p = cat["ports"]
    for port in p["tcp"]:
        t0 = time.time()
        yield {"type": "ports", "url": f"tcp://{p['host']}:{port}", "what": f"TCP {port}",
               "outcome": tcp_probe(p["host"], port), "expect": "block" if port in p["blocked_by_demo"] else "allow",
               "ms": int((time.time() - t0) * 1000)}


GENERATORS = {"web": gen_web, "saas": gen_saas, "genai": gen_genai, "threats": gen_threats, "dlp": gen_dlp,
              "files": gen_files, "dns": gen_dns, "ports": gen_ports}


def run(types=None, count=4, log=None, log_dir=None, stop=None, quiet=False, seed=None, sess=None,
        require_zscaler=True):
    """One round of demo traffic. Returns {"results", "summary", "total", "errors"}.
    require_zscaler: first confirm (ip.zscaler.com) that this machine's traffic goes through Zscaler, and send
    nothing otherwise, so a generator that isn't signed in yet, or a laptop, never sends test traffic directly."""
    rnd = random.Random(seed)
    cat = catalog()
    s = sess or session()
    if require_zscaler:
        try:
            via, clouds = via_zscaler(s)
        except Exception as e:
            via, clouds = False, [f"check failed: {str(e)[:80]}"]
        if not via:
            msg = ("skipped: this machine's traffic isn't going through Zscaler yet "
                   f"({', '.join(clouds) or 'ip.zscaler.com says no'}). Sign in to Client Connector as the test user.")
            if log:
                log("warn", msg)
            elif not quiet:
                print("  " + msg)
            return {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "summary": msg, "total": 0, "errors": 0,
                    "by_type": {}, "results": [], "skipped": True}
    types = [t for t in (types or TYPES) if t in GENERATORS]
    results = []
    for kind in types:
        if stop and stop():
            break
        for r in GENERATORS[kind](s, cat, count, rnd):
            results.append(r)
            line = f"{kind:7} {r['outcome']:12} {r.get('what') or r.get('category') or ''} {r.get('url', '')}"
            if log:
                log("ok" if not r["outcome"].startswith("error") else "warn", line.strip())
            elif not quiet:
                print("  " + line.strip())
            time.sleep(rnd.uniform(0.2, 0.8))   # roughly human pacing
            if stop and stop():
                break
    by = {}
    for r in results:
        k = by.setdefault(r["type"], {"n": 0, "block": 0, "errors": 0})
        k["n"] += 1
        k["block"] += r["outcome"] in ("block", "caution", "isolate")
        k["errors"] += r["outcome"].startswith("error")
    summary = " ".join(f"{k}={v['n']}(zscaler {v['block']}" + (f", errors {v['errors']})" if v["errors"] else ")")
                       for k, v in by.items())
    out = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "summary": summary, "total": len(results),
           "errors": sum(v["errors"] for v in by.values()), "by_type": by, "results": results}
    if log_dir:
        try:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
            (Path(log_dir) / "zia-traffic-last.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
        except OSError:
            pass
    return out


# ---------------------------------------------------------------- generator checks
def zcc_running():
    import platform
    import subprocess
    system = platform.system()
    try:
        if system == "Windows":
            out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=15).stdout
            return bool(re.search(r"ZSATray|ZSAService|ZSATunnel", out, re.I))
        out = subprocess.run(["ps", "-A", "-o", "comm="], capture_output=True, text=True, timeout=15).stdout
        return bool(re.search(r"zscaler|zstunnel|ZscalerTunnel", out, re.I))
    except Exception:
        return None


def via_zscaler(s):
    """ip.zscaler.com says whether this request came through Zscaler, and which cloud."""
    r = s.get("https://ip.zscaler.com/", timeout=TIMEOUT)
    text = re.sub(r"<[^>]+>", " ", r.text)
    low = text.lower()
    clouds = sorted(set(re.findall(r"\b(zscaler[a-z]*\.net)\b", low)))
    if re.search(r"not (going|accessing|connected)[^.]{0,40}zscaler|not using zscaler", low):
        return False, clouds
    return bool(re.search(r"(via|through|using)[^.]{0,30}zscaler", low)), clouds


def tls_issuer(host="www.wikipedia.org"):
    import ssl
    ctx = ssl.create_default_context()
    try:
        import truststore
        ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except Exception:
        pass
    with socket.create_connection((host, 443), timeout=TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
    issuer = {k: v for part in cert.get("issuer", ()) for k, v in part}
    return issuer.get("organizationName") or issuer.get("commonName") or "unknown"


def check(cloud=None, log=None, sess=None):
    """Generator-side checks. Each sends one or two requests. Returns kit-style check dicts."""
    s = sess or session()
    cat = catalog()
    checks = []

    def add(cid, label, status, detail="", fix=""):
        checks.append({"id": cid, "label": label, "status": status, "detail": detail, "fix": fix})
        if log:
            log({"ok": "ok", "fail": "warn", "warn": "warn"}.get(status, "info"), f"{label}: {detail}")

    z = zcc_running()
    add("gen-zcc", "Client Connector running", "ok" if z else ("info" if z is None else "warn"),
        "" if z else "couldn't see it" if z is None else "no Zscaler process found",
        "" if z else "Install Client Connector, enroll in the demo tenant and sign in as the kit's test user.")
    try:
        via, clouds = via_zscaler(s)
        want = (cloud or "").lower()
        if via and want and not any(want in c for c in clouds):
            add("gen-via", "Traffic goes through Zscaler", "warn", f"cloud {', '.join(clouds) or '?'} (expected {cloud})",
                "Client Connector may be enrolled in a different tenant. Check its Internet Security page.")
        else:
            add("gen-via", "Traffic goes through Zscaler", "ok" if via else "fail", ", ".join(clouds),
                "" if via else "ip.zscaler.com says this machine isn't using Zscaler. Turn on Internet Security in "
                               "Client Connector and sign in as the test user.")
    except Exception as e:
        add("gen-via", "Traffic goes through Zscaler", "fail", str(e)[:160], "Check internet access and Client Connector.")
    try:
        iss = tls_issuer()
        ok_ = "zscaler" in iss.lower()
        add("gen-ssl", "SSL inspection", "ok" if ok_ else "warn", f"certificate issued by {iss}",
            "" if ok_ else "HTTPS isn't decrypted for this user, so EICAR over HTTPS, DLP and app controls won't show. "
                           "Add a DECRYPT SSL inspection rule for the test user.")
    except Exception as e:
        bad_ca = "CERTIFICATE_VERIFY_FAILED" in str(e) or "certificate verify failed" in str(e).lower()
        add("gen-ssl", "SSL inspection", "warn", str(e)[:160],
            "This machine doesn't trust the Zscaler root CA. Client Connector normally installs it; reinstall it or "
            "import the CA into the Windows certificate store." if bad_ca else "Couldn't open a TLS connection.")
    tenant_url = next(w["url"] for w in cat["web"] if w["category"] == "SE-Demo tenant check")
    r = fetch(s, "GET", tenant_url)
    add("gen-tenant", "This machine is in the demo tenant, as the test user", "ok" if r["outcome"] == "block" else "fail",
        f"{tenant_url} -> {r['outcome']}",
        "" if r["outcome"] == "block" else "Only the kit's SE-Demo rule blocks this page, and only for the test user. "
        "Check: Client Connector is enrolled in the demo tenant, signed in as the user chosen in `zia setup`, and the "
        "ZIA changes were activated (`zia status` on the admin machine).")
    r = fetch(s, "GET", "https://www.bet365.com/")
    add("gen-url", "URL filtering blocks a demo category", "ok" if r["outcome"] == "block" else "warn",
        f"gambling -> {r['outcome']}", "" if r["outcome"] == "block" else "Run `zia setup` on the admin machine.")
    b64 = base64.urlsafe_b64encode(eicar().encode()).decode()
    for scheme in ("http", "https"):
        r = fetch(s, "GET", f"{scheme}://httpbin.org/base64/{b64}")
        add(f"gen-eicar-{scheme}", f"EICAR test file blocked over {scheme.upper()}", "ok" if r["outcome"] == "block" else "warn",
            r["outcome"], "" if r["outcome"] == "block" else
            ("Needs SSL inspection for the test user." if scheme == "https" else "Check Malware Protection is on."))
    rows = fake_records(8)
    r = fetch(s, "POST", cat["dlp"]["post_urls"][-1], data={"message": records_text(rows)})
    add("gen-dlp", "DLP blocks fake card numbers", "ok" if r["outcome"] == "block" else "warn", r["outcome"],
        "" if r["outcome"] == "block" else "Needs SSL inspection and the kit's DLP rules (`zia setup`).")
    port = cat["ports"]["blocked_by_demo"][1]
    res = tcp_probe(cat["ports"]["host"], port)
    add("gen-tunnel2", f"Non-web traffic is tunneled (TCP {port} blocked)", "ok" if res == "block" else "warn",
        f"TCP {port} -> {res}", "" if res == "block" else
        "The demo firewall rule didn't stop this port, so Client Connector is probably on Z-Tunnel 1.0 (web only). "
        "Give the test user a forwarding profile with Z-Tunnel 2.0 (ZIA.md, step 2), then reconnect.")
    return checks


if __name__ == "__main__":   # quick manual run without the kit: python zia_traffic.py [check]
    import sys
    if "check" in sys.argv:
        for c in check():
            print(f"{c['status']:5} {c['label']}: {c['detail']}" + (f"\n      fix: {c['fix']}" if c["fix"] else ""))
    else:
        print(run(count=int(sys.argv[1]) if len(sys.argv) > 1 else 2)["summary"])
