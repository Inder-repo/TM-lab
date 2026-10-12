#!/usr/bin/env python3
"""Verify the local ATT&CK / CAPEC datasets against OFFICIAL STIX 2.x bundles and write
catalogue_verification.json (read by tm_catalog.catalogue_meta()).

Usage (needs the official files, downloaded by you):
  python tools/verify_catalogues.py --attack enterprise-attack.json --attack-version "ATT&CK v18.1" \\
                                    --capec stix-capec.json --capec-version "CAPEC 3.9" [--out catalogue_verification.json]

Sources:  https://github.com/mitre-attack/attack-stix-data   https://capec.mitre.org/data/downloads.html
The tool NEVER marks a catalogue verified if any local entry is missing, renamed, revoked or deprecated.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import tm_catalog  # noqa: E402


def _load(path):
    raw = open(path, "rb").read()
    return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--attack"); ap.add_argument("--attack-version", default="")
    ap.add_argument("--capec"); ap.add_argument("--capec-version", default="")
    ap.add_argument("--out", default=os.path.join(ROOT, "catalogue_verification.json"))
    args = ap.parse_args(argv)
    if not (args.attack or args.capec):
        ap.error("provide --attack and/or --capec")
    stamp, rc = {}, 0
    for fw, path, ver in (("ATT&CK", args.attack, args.attack_version), ("CAPEC", args.capec, args.capec_version)):
        if not path:
            continue
        if not ver:
            ap.error(f"--{'attack' if fw == 'ATT&CK' else 'capec'}-version is required (record which release you verified against)")
        bundle, digest = _load(path)
        rep = tm_catalog.verify_against_stix(bundle, fw)
        print(f"{fw}: {rep['matching']}/{rep['checked']} entries match; {len(rep['problems'])} problem(s)")
        for p in rep["problems"]:
            print("   ", p)
        stamp[fw] = {"status": rep["status"], "declared_version": ver, "verified_on": date.today().isoformat(), "retrieved": date.today().isoformat(),
                     "source": path, "source_sha256": digest, "problems": rep["problems"]}
        rc |= 0 if rep["status"] == "verified" else 1
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(stamp, f, indent=2)
    print("wrote", args.out)
    return rc


if __name__ == "__main__":
    sys.exit(main())
