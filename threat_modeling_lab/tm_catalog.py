"""ATT&CK / CAPEC reference datasets with explicit provenance and verification state.

IMPORTANT - provenance.  The entries below were carried over from the legacy application. They
have NOT been validated against the official MITRE sources in this repository's build
environment (no network access). Therefore every entry is reported as
``curated-unverified`` until ``tools/verify_catalogues.py`` is run against an official STIX
bundle and writes ``catalogue_verification.json`` next to this file.

Rules enforced by this module (and by tm_model.add_mapping):
  * IDs must match the official ID syntax.
  * Names/URLs shown to learners come from this dataset - they are never generated.
  * Nothing is presented as "current" unless catalogue_verification.json says so.
  * An ID that is not in the local dataset can only be recorded as
    ``unlisted-pending-verification`` and is flagged in every export.
"""
import json
import os
import re
from datetime import date

ATTACK_VERSION = "v19"
ATTACK_TACTICS = [
    ("TA0001", "Initial Access"), ("TA0002", "Execution"), ("TA0003", "Persistence"), ("TA0004", "Privilege Escalation"),
    ("TA0005", "Stealth"), ("TA0112", "Defense Impairment"), ("TA0006", "Credential Access"), ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"), ("TA0009", "Collection"), ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"), ("TA0040", "Impact"),
]
ATTACK_MITIGATIONS = {
    "M1048": "Application Isolation and Sandboxing", "M1050": "Exploit Protection", "M1030": "Network Segmentation",
    "M1026": "Privileged Account Management", "M1051": "Update Software", "M1016": "Vulnerability Scanning",
    "M1032": "Multi-factor Authentication", "M1027": "Password Policies", "M1018": "User Account Management",
    "M1036": "Account Use Policies", "M1017": "User Training", "M1035": "Limit Access to Resource Over Network",
    "M1042": "Disable or Remove Feature or Program", "M1021": "Restrict Web-Based Content", "M1034": "Limit Hardware Installation",
    "M1038": "Execution Prevention", "M1047": "Audit", "M1022": "Restrict File and Directory Permissions",
    "M1041": "Encrypt Sensitive Information", "M1029": "Remote Data Storage", "M1054": "Software Configuration",
    "M1031": "Network Intrusion Prevention", "M1037": "Filter Network Traffic", "M1057": "Data Loss Prevention",
    "M1053": "Data Backup",
}


def _T(tid, name, tactics, stride, mits, hint, domain="Enterprise"):
    return {"id": tid, "name": name, "tactics": tactics, "stride": stride, "m": mits, "hint": hint, "domain": domain}


ATTACK_TECHNIQUES = [
    _T("T1190", "Exploit Public-Facing Application", ["Initial Access"], "TIE", ["M1048", "M1050", "M1030", "M1026", "M1051", "M1016"], "Patch and harden internet-facing apps; validate all input."),
    _T("T1078", "Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation"], "SE", ["M1032", "M1027", "M1026", "M1018", "M1036", "M1017"], "Stolen or default credentials make the attacker look legitimate."),
    _T("T1566", "Phishing", ["Initial Access"], "S", ["M1017"], "Train users, filter email and verify senders."),
    _T("T1199", "Trusted Relationship", ["Initial Access"], "SE", ["M1030", "M1032", "M1018"], "A compromised partner or vendor connection becomes the way in."),
    _T("T1195", "Supply Chain Compromise", ["Initial Access"], "T", ["M1051", "M1016"], "Verify dependencies, build pipelines and update channels."),
    _T("T1133", "External Remote Services", ["Initial Access", "Persistence"], "S", ["M1032", "M1030", "M1042", "M1035"], "Expose remote access only through MFA-protected, segmented paths."),
    _T("T1189", "Drive-by Compromise", ["Initial Access"], "TE", ["M1048", "M1050", "M1051", "M1021"], "Harden browsers and restrict web content."),
    _T("T1200", "Hardware Additions", ["Initial Access"], "ST", ["M1034"], "Control which devices may attach or enrol."),
    _T("T1059", "Command and Scripting Interpreter", ["Execution"], "TE", ["M1038", "M1026", "M1042"], "Restrict interpreters and never pass user input to a shell."),
    _T("T1203", "Exploitation for Client Execution", ["Execution"], "TE", ["M1048", "M1050", "M1051"], "Keep clients patched and sandboxed."),
    _T("T1505", "Server Software Component", ["Persistence"], "TE", ["M1047", "M1026", "M1022"], "Monitor and lock down server extensions (for example web shells)."),
    _T("T1098", "Account Manipulation", ["Persistence", "Privilege Escalation"], "E", ["M1032", "M1026", "M1018"], "Alert on permission and credential changes."),
    _T("T1136", "Create Account", ["Persistence"], "SE", ["M1032", "M1026", "M1018"], "Control and audit account creation."),
    _T("T1068", "Exploitation for Privilege Escalation", ["Privilege Escalation"], "E", ["M1048", "M1050", "M1051", "M1016"], "Patch, sandbox and scan for vulnerable components."),
    _T("T1548", "Abuse Elevation Control Mechanism", ["Privilege Escalation"], "E", ["M1026", "M1022", "M1047"], "Enforce least privilege and audit elevation."),
    _T("T1134", "Access Token Manipulation", ["Privilege Escalation"], "SE", ["M1026", "M1018"], "Limit who can mint or impersonate tokens."),
    _T("T1611", "Escape to Host", ["Privilege Escalation"], "E", ["M1048", "M1038", "M1026"], "Isolate containers and drop unnecessary privileges."),
    _T("T1070", "Indicator Removal", ["Stealth"], "R", ["M1041", "M1029", "M1022"], "Forward logs off-host quickly and protect them with permissions."),
    _T("T1685", "Disable or Modify Tools", ["Defense Impairment"], "R", [], "Protect logging and security tooling; alert when it stops reporting (this includes clearing or disabling logs)."),
    _T("T1689", "Downgrade Attack", ["Defense Impairment"], "TI", [], "Disable legacy protocol and cipher fallback (for example TLS downgrade)."),
    _T("T1599", "Network Boundary Bridging", ["Defense Impairment"], "TE", ["M1030"], "Protect the devices that separate trusted and untrusted networks."),
    _T("T1556", "Modify Authentication Process", ["Credential Access", "Persistence", "Defense Impairment"], "SE", ["M1032", "M1026", "M1047"], "Protect and audit the authentication path."),
    _T("T1553", "Subvert Trust Controls", ["Defense Impairment"], "ST", [], "Protect signing keys; enforce certificate and code-signing validation."),
    _T("T1110", "Brute Force", ["Credential Access"], "S", ["M1032", "M1036", "M1027", "M1018"], "Lock out, rate-limit and require MFA."),
    _T("T1528", "Steal Application Access Token", ["Credential Access"], "SI", ["M1032", "M1018", "M1017"], "Short-lived, scoped tokens; monitor consent and usage."),
    _T("T1539", "Steal Web Session Cookie", ["Credential Access"], "SI", ["M1017", "M1054"], "Harden session cookies (HttpOnly, Secure, SameSite) and expiry."),
    _T("T1552", "Unsecured Credentials", ["Credential Access"], "I", ["M1041", "M1027", "M1022", "M1047"], "Keep secrets in a vault, never in code, config or logs."),
    _T("T1555", "Credentials from Password Stores", ["Credential Access"], "I", ["M1027"], "Protect and rotate credential stores."),
    _T("T1606", "Forge Web Credentials", ["Credential Access"], "S", ["M1047", "M1026"], "Protect signing keys and validate tokens strictly."),
    _T("T1557", "Adversary-in-the-Middle", ["Credential Access", "Collection"], "STI", ["M1041", "M1030", "M1031"], "Encrypt and authenticate traffic end to end."),
    _T("T1040", "Network Sniffing", ["Credential Access", "Discovery"], "I", ["M1041"], "Encrypt data in transit."),
    _T("T1087", "Account Discovery", ["Discovery"], "I", [], "Limit directory and user enumeration."),
    _T("T1046", "Network Service Discovery", ["Discovery"], "I", ["M1030", "M1031"], "Segment networks and detect scanning."),
    _T("T1021", "Remote Services", ["Lateral Movement"], "SE", ["M1032", "M1030", "M1035"], "Restrict remote services between zones; require MFA."),
    _T("T1550", "Use Alternate Authentication Material", ["Lateral Movement"], "S", ["M1026", "M1018"], "Short-lived credentials and token binding."),
    _T("T1530", "Data from Cloud Storage", ["Collection"], "I", ["M1047", "M1041", "M1032", "M1018"], "Private buckets, least privilege and access logging."),
    _T("T1213", "Data from Information Repositories", ["Collection"], "I", ["M1047", "M1018"], "Restrict and audit access to wikis, tickets and shared repositories."),
    _T("T1005", "Data from Local System", ["Collection"], "I", ["M1057"], "Encrypt local data; apply data-loss prevention."),
    _T("T1119", "Automated Collection", ["Collection"], "I", [], "Rate limits and anomaly detection on bulk access."),
    _T("T1114", "Email Collection", ["Collection"], "I", ["M1032"], "Protect mail access with MFA and audit rules."),
    _T("T1185", "Browser Session Hijacking", ["Collection"], "STI", ["M1017"], "Short sessions, re-authentication for sensitive actions."),
    _T("T1041", "Exfiltration Over C2 Channel", ["Exfiltration"], "I", ["M1031"], "Monitor and filter outbound traffic."),
    _T("T1567", "Exfiltration Over Web Service", ["Exfiltration"], "I", ["M1021"], "Restrict outbound web destinations."),
    _T("T1048", "Exfiltration Over Alternative Protocol", ["Exfiltration"], "I", ["M1037", "M1031", "M1030"], "Egress filtering and protocol allow-lists."),
    _T("T1537", "Transfer Data to Cloud Account", ["Exfiltration"], "I", [], "Restrict cross-account sharing; alert on snapshots and copies."),
    _T("T1499", "Endpoint Denial of Service", ["Impact"], "D", ["M1037"], "Rate limiting, quotas and request-cost limits."),
    _T("T1498", "Network Denial of Service", ["Impact"], "D", ["M1037"], "Upstream filtering and capacity planning."),
    _T("T1496", "Resource Hijacking", ["Impact"], "D", [], "Quotas, budget alerts and workload monitoring."),
    _T("T1489", "Service Stop", ["Impact"], "D", ["M1022", "M1018"], "Protect service control; alert on stopped services."),
    _T("T1485", "Data Destruction", ["Impact"], "DT", ["M1053"], "Tested, isolated backups."),
    _T("T1486", "Data Encrypted for Impact", ["Impact"], "D", ["M1053"], "Offline backups and tested recovery."),
    _T("T1531", "Account Access Removal", ["Impact"], "D", [], "Protect admin accounts; alert on mass password resets or deletions."),
    _T("T1565", "Data Manipulation", ["Impact"], "T", ["M1041", "M1030", "M1022"], "Integrity checks, signing and strict write permissions (includes stored and transmitted data)."),
    _T("T1491", "Defacement", ["Impact"], "T", ["M1053"], "Integrity monitoring and restorable content."),
    _T("T1657", "Financial Theft", ["Impact"], "TS", [], "Out-of-band verification for payment changes; transaction monitoring."),
    # ICS-domain techniques that matter for connected medical / IoT devices (new naming in v19)
    _T("T1692", "Unauthorized Message", ["ICS"], "ST", [], "Authenticate and integrity-protect device commands and reports.", "ICS"),
    _T("T1693", "Modify Firmware", ["ICS"], "T", [], "Signed firmware and secure boot.", "ICS"),
    _T("T1694", "Insecure Credentials", ["ICS"], "S", [], "No default or hard-coded device credentials.", "ICS"),
    _T("T1691", "Block Operational Technology Message", ["ICS"], "D", [], "Detect missing or blocked device messages.", "ICS"),
    _T("T1695", "Block Communications", ["ICS"], "D", [], "Redundant paths and heartbeat monitoring.", "ICS"),
]

CAPEC_CANDIDATES_RAW = {
    "CAPEC-1 — Accessing Functionality Not Properly Constrained by ACLs": "Missing or incorrect authorisation checks.",
    "CAPEC-21 — Exploitation of Trusted Identifiers": "An attacker-controlled or predictable identifier exposes another object.",
    "CAPEC-62 — Cross Site Request Forgery (CSRF)": "A victim's authenticated browser is induced to perform an unintended action.",
    "CAPEC-66 — SQL Injection": "Untrusted input alters a database query's structure.",
    "CAPEC-18 — XSS Targeting Non-Script Elements": "Attacker-controlled content is interpreted as executable or active content in a victim context; confirm the specific XSS variant fits.",
    "CAPEC-588 — DOM-Based XSS": "Client-side code uses attacker-controlled input in an unsafe DOM sink.",
    "CAPEC-591 — Reflected XSS": "Attacker-controlled input is reflected into a response and executed in a victim context.",
    "CAPEC-592 — Stored XSS": "Attacker-controlled content is stored and later executed in another user's context.",
    "CAPEC-115 — Authentication Bypass": "An authentication mechanism can be bypassed.",
    "CAPEC-153 — Input Data Manipulation": "Input changes alter business logic or processing.",
    "CAPEC-560 — Use of Known Domain Credentials": "The scenario involves valid credentials obtained or reused by an attacker.",
    "No suitable CAPEC pattern identified": "Valid when the scenario does not support a confident CAPEC mapping."
}

ATTACK_BY_ID = {t["id"]: t for t in ATTACK_TECHNIQUES}
ATTACK_TACTIC_BY_NAME = {n: i for i, n in ATTACK_TACTICS}

_CAPEC_RAW = CAPEC_CANDIDATES_RAW
CAPEC_PATTERNS = []
for _k, _note in _CAPEC_RAW.items():
    _m = re.match(r"^(CAPEC-\d+)\s+\u2014\s+(.*)$", _k)
    if _m:
        CAPEC_PATTERNS.append({"id": _m.group(1), "name": _m.group(2), "note": _note})
CAPEC_BY_ID = {c["id"]: c for c in CAPEC_PATTERNS}

ATTACK_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CAPEC_ID_RE = re.compile(r"^CAPEC-\d{1,4}$")
FRAMEWORKS = ("ATT&CK", "CAPEC")

_META_DEFAULT = {
    "ATT&CK": {"declared_version": ATTACK_VERSION + " (as declared by the legacy app; unverified)",
               "status": "curated-unverified", "retrieved": None, "verified_on": None,
               "source": "https://attack.mitre.org/", "entries": len(ATTACK_TECHNIQUES)},
    "CAPEC": {"declared_version": "unknown (as declared by the legacy app; unverified)",
              "status": "curated-unverified", "retrieved": None, "verified_on": None,
              "source": "https://capec.mitre.org/", "entries": len(CAPEC_PATTERNS)},
}
_VERIFICATION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalogue_verification.json")


def catalogue_meta(path=None):
    """Return provenance per framework, merging a verification stamp if one exists."""
    meta = json.loads(json.dumps(_META_DEFAULT))
    p = path or _VERIFICATION_FILE
    if os.path.exists(p):
        try:
            with open(p, encoding="utf-8") as f:
                stamp = json.load(f)
            for fw in FRAMEWORKS:
                if fw in stamp and stamp[fw].get("status") == "verified" and not stamp[fw].get("problems"):
                    meta[fw].update({k: stamp[fw].get(k) for k in ("status", "declared_version", "verified_on", "retrieved", "source", "source_sha256")
                                     if stamp[fw].get(k) is not None})
        except (OSError, ValueError):
            pass
    return meta


def normalise_id(framework, raw):
    s = str(raw or "").strip().upper().replace(" ", "")
    if framework == "CAPEC":
        if s.isdigit():
            s = "CAPEC-" + s
        s = s.replace("CAPEC", "CAPEC-") if re.match(r"^CAPEC\d+$", s) else s
    return s


def valid_id_syntax(framework, ident):
    rx = ATTACK_ID_RE if framework == "ATT&CK" else CAPEC_ID_RE if framework == "CAPEC" else None
    return bool(rx and rx.match(str(ident)))


def lookup(framework, ident):
    ident = normalise_id(framework, ident)
    if framework == "ATT&CK":
        return ATTACK_BY_ID.get(ident)
    if framework == "CAPEC":
        return CAPEC_BY_ID.get(ident)
    return None


def reference_url(framework, ident):
    ident = normalise_id(framework, ident)
    if not valid_id_syntax(framework, ident):
        return ""
    if framework == "ATT&CK":
        return "https://attack.mitre.org/techniques/" + ident.replace(".", "/") + "/"
    return "https://capec.mitre.org/data/definitions/" + ident.split("-")[1] + ".html"


def official_name(framework, ident):
    e = lookup(framework, ident)
    return e["name"] if e else ""


def search(framework, text="", stride_letter=None, limit=40):
    """Candidate list for pickers. STRIDE alignment is only a sort hint, never a filter or a rule."""
    text = (text or "").lower().strip()
    pool = ATTACK_TECHNIQUES if framework == "ATT&CK" else CAPEC_PATTERNS
    out = []
    for e in pool:
        hay = " ".join([e["id"], e["name"], e.get("hint", e.get("note", "")), " ".join(e.get("tactics", []))]).lower()
        if text and text not in hay:
            continue
        aligned = bool(stride_letter and stride_letter in e.get("stride", ""))
        out.append((0 if aligned else 1, e["id"], e))
    out.sort(key=lambda x: (x[0], x[1]))
    return [e for _, _, e in out][:limit]


def verify_against_stix(bundle, framework):
    """Compare the local dataset with an official STIX 2.x bundle (dict). Returns a report dict.

    ATT&CK: attack-pattern objects with external_references[source_name == 'mitre-attack'].
    CAPEC : attack-pattern objects with external_references[source_name == 'capec'].
    Revoked / deprecated objects are reported as problems, not silently accepted.
    """
    src = "mitre-attack" if framework == "ATT&CK" else "capec"
    official = {}
    for o in bundle.get("objects", []):
        if o.get("type") != "attack-pattern":
            continue
        for r in o.get("external_references", []):
            if r.get("source_name") == src and r.get("external_id"):
                official[r["external_id"]] = {"name": o.get("name", ""), "revoked": bool(o.get("revoked")),
                                              "deprecated": bool(o.get("x_mitre_deprecated")),
                                              "tactics": [p.get("phase_name") for p in o.get("kill_chain_phases", [])]}
    local = ATTACK_TECHNIQUES if framework == "ATT&CK" else CAPEC_PATTERNS
    problems, ok = [], 0
    for e in local:
        o = official.get(e["id"])
        if not o:
            problems.append({"id": e["id"], "problem": "not found in official source"}); continue
        if o["revoked"] or o["deprecated"]:
            problems.append({"id": e["id"], "problem": "revoked/deprecated in official source"}); continue
        if o["name"].strip().lower() != e["name"].strip().lower():
            problems.append({"id": e["id"], "problem": "name mismatch", "local": e["name"], "official": o["name"]}); continue
        ok += 1
    return {"framework": framework, "checked": len(local), "matching": ok, "problems": problems,
            "official_objects": len(official), "status": "verified" if not problems and local else "problems-found"}
