#!/usr/bin/env python3
"""
Download labeled C2 / malware traffic from malware-traffic-analysis.net.

For each case in CASES this fetches ONLY:
  * the traffic capture(s)  (*.pcap.zip)
  * the IOC list            (*IOC*.txt.zip)
Malware samples / "artifacts" archives on the same pages are never fetched.

Archives use the site's password scheme (see its "about" page):
    infected_<YYYYMMDD of the post>

Output layout (engine-ml/datasets/mta/<case>/):
    *.pcap        extracted captures (untrusted data: only parsed by sensor)
    *IOC*.txt     IOC list, used to label flows by IP
    SOURCE.json   URLs, sizes and SHA-256 of everything extracted

Usage:  python3 engine-ml/datasets/fetch_mta.py [--only 2024/04/18 ...]
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://www.malware-traffic-analysis.net"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mta")

# (post path, family). Chosen for family diversity: Cobalt Strike, RATs,
# loaders with VNC/BackConnect, and stealers that exfiltrate.
CASES = [
    ("2024/04/18", "SSLoad + Cobalt Strike"),
    ("2023/12/18", "Pikabot + Cobalt Strike"),
    ("2023/10/03", "Pikabot + Cobalt Strike"),
    ("2023/07/12", "Gozi/ISFB + Cobalt Strike"),
    ("2023/05/10", "Qakbot + Cobalt Strike + VNC"),
    ("2024/03/14", "AsyncRAT + XWorm"),
    ("2024/01/09", "AsyncRAT"),
    ("2025/11/19", "XWorm"),
    ("2025/03/10", "Remcos RAT"),
    ("2024/12/17", "NetSupport RAT"),
    ("2024/06/25", "Latrodectus + BackConnect + Keyhole VNC"),
    ("2023/10/31", "IcedID"),
    ("2024/03/19", "DarkGate"),
    ("2024/06/12", "KoiLoader/KoiStealer"),
    ("2024/10/23", "Redline Stealer"),
    ("2025/01/31", "AgentTesla-style exfil (FTP + SMTP)"),
    ("2024/09/19", "Lumma Stealer"),
    # Added in Part 7: a second capture for families seen once, and new C2
    # families. Not added: Pikabot / Gozi (already 75 % of malicious flows),
    # SectopRAT (kept unseen for the holdout), holdout dates.
    ("2023/01/03", "Rhadamanthys Stealer"),
    ("2023/04/13", "MetaStealer"),
    ("2023/08/01", "Bandook"),
    ("2023/08/03", "DanaBot (fake TurboTax ad)"),
    ("2023/09/28", "IcedID + Keyhole VNC + Cobalt Strike"),
    ("2023/10/11", "Lumma Stealer"),
    ("2023/11/22", "AgentTesla (FTP exfil)"),
    ("2023/11/27", "IcedID variant"),
    ("2024/01/12", "StealC"),
    ("2024/01/23", "UltraVNC"),
    ("2024/04/17", "SSLoad"),
    ("2024/05/14", "DarkGate"),
    ("2024/06/17", "Matanbuchus + DanaBot"),
    ("2024/08/12", "XLoader/Formbook"),
    ("2024/09/16", "Snake KeyLogger (SMTP exfil)"),
    ("2024/12/04", "AgentTesla variant (FTP exfil)"),
    ("2025/02/10", "StrelaStealer"),
    ("2025/05/12", "PureLogs-style RAT (unidentified)"),
    ("2025/06/26", "Lumma Stealer + Rsockstun"),
    ("2025/07/08", "Koi Loader/Koi Stealer"),
    ("2026/01/20", "XWorm"),
    ("2026/01/29", "njRAT + MassLogger"),
    ("2026/02/02", "KongTuke ClickFix + MintsLoader + GhostWeaver RAT"),
]

# Held out from training entirely: fetched into datasets/mta_holdout/,
# which build_dataset.py never reads. Used only by evaluate_holdout.py.
HOLDOUT_CASES = [
    ("2023-11-06", "404 TDS + Cobalt Strike"),
    ("2023-11-20", "DarkGate"),
    ("2024-02-21", "SocGholish + AsyncRAT"),
    ("2025-08-15", "Lumma Stealer + SectopRAT"),
    ("2025-12-29", "ClickFix + NetSupport RAT"),
]
HOLDOUT_CASES = [(d.replace("-", "/"), f) for d, f in HOLDOUT_CASES]

UA = {"User-Agent": "SentinelFlow-dataset-fetch/1.0 (research)"}


def get(url, tries=3):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
        except urllib.error.URLError:
            if i == tries - 1:
                raise
            time.sleep(3 * (i + 1))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_case(post, family, out=OUT):
    case = post.replace("/", "-")
    dest = os.path.join(out, case)
    if os.path.exists(os.path.join(dest, "SOURCE.json")):
        print(f"[skip] {case} already fetched")
        return
    page_url = f"{BASE}/{post}/index.html"
    html = get(page_url).decode("utf-8", "replace")
    links = sorted({l.strip() for l in re.findall(r'href="([^"]+\.zip)"', html)})
    wanted = [l for l in links
              if l.lower().endswith(".pcap.zip") or l.lower().endswith(".pcapng.zip")
              or (l.lower().endswith(".txt.zip") and "artifact" not in l.lower()
                  and "malware" not in l.lower())]
    if not any(".pcap" in w.lower() for w in wanted):
        print(f"[warn] {case}: no pcap zip found among {links}")
        return
    password = "infected_" + post.replace("/", "")
    os.makedirs(dest, exist_ok=True)
    files = []
    with tempfile.TemporaryDirectory() as tmp:
        for link in wanted:
            url = f"{BASE}/{post}/{urllib.parse.quote(link)}"
            zpath = os.path.join(tmp, os.path.basename(link))
            with open(zpath, "wb") as f:
                f.write(get(url))
            xdir = os.path.join(tmp, "x_" + os.path.basename(link))
            os.makedirs(xdir)
            # 7z handles both ZipCrypto and AES zips; -y never prompts.
            p = subprocess.run(["7z", "x", "-y", f"-p{password}", f"-o{xdir}", zpath],
                               capture_output=True, text=True)
            if p.returncode != 0:
                print(f"[error] {case}: 7z failed on {link}: {p.stdout[-300:]}")
                continue
            for root, _, names in os.walk(xdir):
                for n in names:
                    if not n.lower().endswith((".pcap", ".pcapng", ".txt")):
                        print(f"[drop] {case}: unexpected file in archive: {n}")
                        continue
                    target = os.path.join(dest, n)
                    shutil.move(os.path.join(root, n), target)
                    files.append({"file": n, "from": url, "bytes": os.path.getsize(target),
                                  "sha256": sha256(target)})
    with open(os.path.join(dest, "SOURCE.json"), "w") as f:
        json.dump({"case": case, "family": family, "page": page_url,
                   "password_scheme": "infected_YYYYMMDD", "files": files}, f, indent=2)
    print(f"[ok]   {case}: {family}: " +
          ", ".join(f"{x['file']} ({x['bytes']:,} B)" for x in files))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", help="post paths like 2024/04/18")
    ap.add_argument("--holdout", action="store_true",
                    help="fetch HOLDOUT_CASES into datasets/mta_holdout/")
    args = ap.parse_args()
    if not shutil.which("7z"):
        sys.exit("7z is required to extract the password-protected archives")
    out = OUT + "_holdout" if args.holdout else OUT
    os.makedirs(out, exist_ok=True)
    for post, family in (HOLDOUT_CASES if args.holdout else CASES):
        if args.only and post not in args.only:
            continue
        try:
            fetch_case(post, family, out)
        except Exception as e:  # keep going; report per case
            print(f"[error] {post}: {e}")


if __name__ == "__main__":
    main()
