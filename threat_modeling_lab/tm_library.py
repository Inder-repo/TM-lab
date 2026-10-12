"""Threat-pattern and attack-tree library (pure data + matching; no Streamlit).

15 threat patterns and 6 reusable attack-tree templates. Every entry has:
  * applicability conditions (kinds + context tags + disqualifiers) AND a plain-language
    "applies when / does not apply when" explanation,
  * a worked example on a NEUTRAL system ("BookSwap", a book-lending web app) that is not any lab scenario,
  * candidate ATT&CK / CAPEC IDs that exist in the local dataset (checked by tests). Candidates are
    prompts for the learner to justify, never automatic mappings.
References are topic-level only (no section numbers) - check the current edition of each source.

Contextual matching reads the learner's own DFD (element type, flow protocol/classification,
trust-boundary crossings, security domain) and scenario text. Tags are keyword heuristics - they
explain WHY an entry is suggested, and the learner decides whether it actually applies.
"""
import copy
import re

TAG_DESC = {
    "internet_facing": "reachable from outside the organisation (external source, public/untrusted domain)",
    "has_login": "involves authentication, identity, session or token handling",
    "handles_credentials": "carries credentials, tokens, sessions or secrets",
    "api": "is an API/service interface",
    "stores_sensitive": "holds or carries sensitive/regulated data (classification or keywords)",
    "sql": "uses a SQL/relational database interface",
    "queue": "is a queue, broker or stream shared by producers/consumers",
    "device": "involves a device, firmware or embedded component",
    "third_party": "involves a third party or vendor",
    "multi_tenant": "the scenario mentions tenants / shared multi-tenant components",
    "admin_interface": "is an administrative or management interface",
    "log_store": "is a log/audit store or monitoring component",
    "file_upload": "accepts files or bulk imports",
    "encryption_unstated": "the flow's protocol does not state encryption",
    "encrypted_protocol": "the flow's protocol states encryption (TLS/SSH/etc.)",
    "crosses_boundary": "crosses a trust boundary",
    "inbound_crossing": "enters a trust boundary",
    "outbound_crossing": "leaves a trust boundary",
    "no_auth_recorded": "no caller-authentication method is recorded on the flow",
    "sensitive_flow": "carries Confidential/Restricted data",
    "service_to_service": "connects two processes (service-to-service)",
}
TAGS = set(TAG_DESC)

_K = {
    "internet": ("internet", "public", "untrusted", "external", "dmz", "browser", "mobile app", "client"),
    "login": ("login", "auth", "identity", "session", "token", "sso", "oauth", "mfa", "credential", "password", "user service", "idp"),
    "cred": ("credential", "password", "token", "session", "cookie", "api key", "secret", "certificate", "jwt"),
    "api": ("api", "gateway", "service", "rest", "graphql", "grpc", "backend", "endpoint"),
    "sens": ("pii", "phi", "health", "payment", "card", "customer", "patient", "personal", "financial", "account", "glucose", "telemetry", "record"),
    "sql": ("sql", "jdbc", "odbc", "postgres", "mysql", "aurora", "redshift", "database", " db", "db "),
    "queue": ("kafka", "queue", "topic", "broker", "mq", "msk", "stream", "sqs", "pubsub"),
    "device": ("device", "sensor", "firmware", "wearable", "iot", "ble", "mqtt", "embedded", "home gateway"),
    "human": ("user", "customer", "clinician", "patient", "employee", "admin", "operator", "attendee", "visitor"),
    "vendor": ("stripe", "sendgrid", "provider", "vendor", "third", "partner", "payment", "saas", "hospital", "ehr"),
    "tenant": ("tenant", "multi-tenant", "multitenant", "shared"),
    "admin": ("admin", "console", "portal", "dashboard", "management"),
    "log": ("log", "audit", "siem", "monitor"),
    "file": ("upload", "file", "attachment", "import", "batch"),
    "enc": ("tls", "https", "ssl", "mtls", "ssh", "sftp", "wss", "quic", "ipsec", "vpn"),
}


def _has(text, key):
    t = " " + str(text or "").lower() + " "
    return any(k in t for k in _K[key])


def _etext(e):
    return " ".join([e.get("name", ""), e.get("description", ""), e.get("security_domain", ""), e.get("justification", "")])


def _find(coll, rid):
    for r in coll:
        if r["id"] == rid:
            return r
    return None


def _crossings(ws):
    out = {}
    for b in ws["dfd"]["boundaries"]:
        mem = set(b["members"])
        for f in ws["dfd"]["flows"]:
            s, d = f["source"] in mem, f["destination"] in mem
            if s != d:
                out.setdefault(f["id"], set()).add("inbound_crossing" if d else "outbound_crossing")
    return out


def _scenario_text(ws):
    sc = ws["scope"]
    parts = [sc.get("purpose", ""), sc.get("business_context", ""), sc.get("data_sensitivity", "")]
    parts += [f["text"] for f in sc.get("facts", [])] + [a["text"] for a in sc.get("assumptions", [])]
    return " ".join(parts)


def element_tags(ws, e):
    dfd = ws["dfd"]
    t = {e["type"]}
    txt = _etext(e)
    adj = [f for f in dfd["flows"] if e["id"] in (f["source"], f["destination"])]
    inbound = [f for f in dfd["flows"] if f["destination"] == e["id"]]
    ftxt = " ".join(f["data"] + " " + f["protocol"] for f in adj)
    cross = _crossings(ws)
    if _has(txt, "internet") or e["type"] == "external_entity" or any((_find(dfd["elements"], f["source"]) or {}).get("type") == "external_entity" for f in inbound):
        t.add("internet_facing")
    if _has(txt, "login") or _has(ftxt, "login"):
        t.add("has_login")
    if _has(ftxt, "cred"):
        t.add("handles_credentials")
    if _has(txt, "api") or e["type"] == "process":
        t.add("api") if (_has(txt, "api") or any(re.search(r"https|rest|grpc|http", f["protocol"].lower()) for f in adj)) else None
    if any(f["classification"] in ("Confidential", "Restricted") for f in adj) or _has(txt + " " + ftxt, "sens"):
        t.add("stores_sensitive")
    if _has(txt + " " + ftxt, "sql") and e["type"] in ("datastore", "process"):
        t.add("sql")
    if _has(txt, "queue"):
        t.add("queue")
    if _has(txt, "device"):
        t.add("device")
    if e["type"] == "external_entity" and (_has(txt, "vendor") or not _has(txt, "human")):
        t.add("third_party")
    if _has(txt + " " + _scenario_text(ws), "tenant"):
        t.add("multi_tenant")
    if _has(txt, "admin"):
        t.add("admin_interface")
    if _has(txt, "log"):
        t.add("log_store")
    if _has(ftxt, "file"):
        t.add("file_upload")
    if any(f["id"] in cross for f in adj):
        t.add("crosses_boundary")
    if any(not f["authenticated"] for f in inbound):
        t.add("no_auth_recorded")
    return t


def flow_tags(ws, f):
    t = {"flow"}
    proto = f["protocol"].lower()
    if proto:
        t.add("encrypted_protocol" if _has(proto, "enc") else "encryption_unstated")
    else:
        t.add("encryption_unstated")
    if f["classification"] in ("Confidential", "Restricted"):
        t.add("sensitive_flow")
        t.add("stores_sensitive")
    if _has(f["data"], "cred"):
        t.add("handles_credentials")
        t.add("has_login")
    if _has(f["data"], "file"):
        t.add("file_upload")
    if not f["authenticated"]:
        t.add("no_auth_recorded")
    t |= _crossings(ws).get(f["id"], set())
    if t & {"inbound_crossing", "outbound_crossing"}:
        t.add("crosses_boundary")
    s, d = _find(ws["dfd"]["elements"], f["source"]), _find(ws["dfd"]["elements"], f["destination"])
    if s and d:
        if s["type"] == "process" and d["type"] == "process":
            t.add("service_to_service")
        for e in (s, d):
            et = element_tags(ws, e)
            t |= et & {"internet_facing", "has_login", "api", "multi_tenant", "queue", "device", "third_party", "sql", "admin_interface"}
            if "stores_sensitive" in et:
                t.add("stores_sensitive")
    if _has(_scenario_text(ws), "tenant"):
        t.add("multi_tenant")
    return t


def context_tags(ws, target_id):
    e = _find(ws["dfd"]["elements"], target_id)
    if e:
        return element_tags(ws, e)
    f = _find(ws["dfd"]["flows"], target_id)
    return flow_tags(ws, f) if f else set()


def target_kind(ws, target_id):
    e = _find(ws["dfd"]["elements"], target_id)
    if e:
        return e["type"]
    return "flow" if _find(ws["dfd"]["flows"], target_id) else None


def _match(when, kind, tags):
    reasons, why_not = [], []
    if kind not in when["kinds"]:
        return False, [], ["applies to " + ", ".join(when["kinds"])], 0
    if when.get("all") and not set(when["all"]) <= tags:
        return False, [], ["needs: " + ", ".join(TAG_DESC[x] for x in when["all"] if x not in tags)], 0
    bad = set(when.get("none", [])) & tags
    if bad:
        return False, [], ["does not apply when " + ", ".join(TAG_DESC[x] for x in sorted(bad))], 0
    hits = [x for x in when.get("any", []) if x in tags]
    if when.get("any") and not hits:
        return False, [], ["no signal found: " + " / ".join(TAG_DESC[x] for x in when["any"])], 0
    reasons = [TAG_DESC[x] for x in list(when.get("all", [])) + hits]
    return True, reasons, [], len(hits) + len(when.get("all", []))


# ═════════════════════════════════════════════════════════════════════════════════════
# Threat patterns
# ═════════════════════════════════════════════════════════════════════════════════════
def _p(id_, name, stride, when, applies, not_when, source, pre, action, impact, prop, example, tree=None, controls=(), attack=(), capec=(), refs=()):
    return {"id": id_, "name": name, "stride": stride, "when": when, "applies_when": applies, "not_applicable_when": not_when,
            "source": source, "preconditions": pre, "action": action, "impact": impact, "security_property": prop,
            "worked_example": example, "tree_ids": list(tree or []), "control_themes": list(controls),
            "attack_ids": list(attack), "capec_ids": list(capec), "references": list(refs)}


def _ex(target, statement, why):
    return {"system": "BookSwap (neutral example: a book-lending web app with a browser client, an API, a user database and a card-payment provider)",
            "target": target, "statement": statement, "why_it_is_strong": why}


R_ASVS_AUTH = "OWASP ASVS - authentication and session management topics"
R_63B = "NIST SP 800-63B - digital identity: authenticators"
R_API = "OWASP API Security Top 10 - object- and function-level authorisation"
R_TLS = "RFC 8446 (TLS 1.3); OWASP Transport Layer Security Cheat Sheet"
R_53 = "NIST SP 800-53 control families (IA, AC, SC, AU, SI)"
R_MS = "NIST SP 800-204 - security strategies for microservices-based systems"

PATTERNS = [
    _p("TP-01", "Spoofed user or client identity at an authentication point", "S",
       {"kinds": ["external_entity", "process"], "any": ["has_login", "internet_facing"]},
       "Callers prove who they are with a password, token or certificate and the receiving component acts on that identity.",
       "Identity is established by a trusted upstream component AND re-verified here (then analyse the upstream component instead).",
       "A remote attacker holding guessed, reused or phished credentials",
       "{target} accepts a single factor and has no effective rate limiting or anomaly detection",
       "authenticate as another legitimate user to {target}",
       "unauthorised access to {asset} under the victim's identity", "Authenticity",
       _ex("API login endpoint", "Given the login endpoint accepts a password alone and does not throttle attempts, a remote attacker with credentials leaked from another site could sign in as a member against the login endpoint, resulting in unauthorised access to borrowing history and saved addresses.",
           "It names the actor's capability, the missing control that makes it possible, the exact target and the asset harmed - so it can be rated, mapped and tested."),
       ["AT-01"], ["Multi-factor or step-up authentication", "Rate limiting, lockout and credential-stuffing detection", "Breached-password screening"],
       ["T1110", "T1078", "T1566"], ["CAPEC-560", "CAPEC-115"], [R_ASVS_AUTH, R_63B]),
    _p("TP-02", "Session or token theft and replay", "S",
       {"kinds": ["flow", "process"], "any": ["handles_credentials", "has_login"]},
       "Sessions, cookies or bearer tokens identify the caller after login and can be copied by whoever obtains them.",
       "Tokens are bound to the client (e.g. sender-constrained), short-lived and never exposed outside the trusted component.",
       "An attacker who can read traffic, logs, browser storage or a client-side injection point",
       "the token is long-lived, bearer-style and visible in {data} or in client-side storage",
       "capture a valid token from {target} and replay it as the victim",
       "account takeover and actions attributed to the victim on {asset}", "Authenticity",
       _ex("Browser to API flow", "Given the session token is a long-lived bearer value held in browser storage, an attacker able to inject script into a page could replay the token against the browser-to-API flow, resulting in actions performed as the member on their lending account.",
           "The precondition names the real weakness (token lifetime and storage) so a control (shorter lifetime, httpOnly cookie, binding) maps directly to it."),
       ["AT-01", "AT-05"], ["Short token lifetime and rotation", "HttpOnly/Secure cookies or sender-constrained tokens", "Revocation and anomaly detection"],
       ["T1539", "T1528", "T1550"], ["CAPEC-21"], [R_ASVS_AUTH, R_63B]),
    _p("TP-03", "Service impersonation or unauthenticated service-to-service call", "S",
       {"kinds": ["flow", "process"], "any": ["service_to_service", "no_auth_recorded", "crosses_boundary"], "none": []},
       "One service calls another and the callee trusts the caller because of network position or a shared network, not a verified identity.",
       "Mutual authentication (mTLS, signed service tokens) is enforced and recorded on the flow.",
       "An attacker or compromised workload with network access to the internal network",
       "{target} is reachable from other workloads and does not verify the caller's identity cryptographically",
       "send requests to {target} pretending to be a trusted service",
       "unauthorised operations on {asset} that bypass the intended gateway checks", "Authenticity",
       _ex("Checkout service to warehouse service flow", "Given the warehouse service trusts any caller on the internal network, a compromised workload could call the warehouse service directly while posing as the checkout service, resulting in shipments released without any order record.",
           "It rests on a recordable design fact (trust by network position) and names a concrete abuse, not a generic 'internal attacker'."),
       ["AT-05"], ["Mutual TLS or signed service credentials", "Network segmentation and allow-listed callers", "Per-service authorisation checks"],
       ["T1199", "T1021", "T1550"], ["CAPEC-21"], [R_MS, R_53]),
    _p("TP-04", "Request or message tampering in transit", "T",
       {"kinds": ["flow"], "any": ["encryption_unstated", "crosses_boundary"], "none": ["service_to_service"]},
       "Data crosses a network the organisation does not fully control, or the flow does not state integrity protection.",
       "The flow is protected by authenticated encryption (TLS with certificate validation) end to end.",
       "An adversary on the network path or a compromised intermediary (proxy, load balancer, broker)",
       "traffic on {target} is not integrity-protected end to end or terminates at an untrusted intermediary",
       "modify {data} in transit on {target}",
       "corrupted or fraudulent records in {asset}", "Integrity",
       _ex("Browser to API flow over public Wi-Fi", "Given the browser reaches the API over a network a member may share with strangers and no request signing exists, an adversary on that network could change the quantity and delivery address in a lending request, resulting in orders shipped to the wrong person.",
           "The impact is business-specific (misdirected shipment), which is what makes the rating in Step 6 defensible."),
       ["AT-03"], ["TLS 1.2+ with certificate validation", "Message signing for high-value requests", "Server-side re-validation of all values"],
       ["T1557", "T1565"], ["CAPEC-153"], [R_TLS]),
    _p("TP-05", "Tampering with stored data", "T",
       {"kinds": ["datastore"], "any": ["stores_sensitive", "sql"]},
       "A data store holds records whose integrity matters and is written by more than one component or credential.",
       "Writes are restricted to one component, integrity is checked and changes are audited.",
       "An attacker with a stolen service credential, an injection foothold or a malicious insider",
       "{target} accepts writes from multiple components with broad privileges and no integrity checks",
       "alter or delete records in {target}",
       "loss of integrity of {asset} that may go undetected", "Integrity",
       _ex("Loans database", "Given three services share one database account with write access to every table, an attacker who compromises any one of them could change loan due dates and fines in the loans database, resulting in incorrect charges to members.",
           "It highlights the shared-privilege design choice, which suggests per-service accounts as the control."),
       ["AT-02"], ["Least-privilege database accounts per component", "Row-level integrity checks and change auditing", "Backups with tested restore"],
       ["T1565", "T1485", "T1078"], ["CAPEC-1"], [R_53]),
    _p("TP-06", "Injection through untrusted input", "T",
       {"kinds": ["process"], "any": ["api", "internet_facing", "sql", "file_upload"]},
       "The component builds queries, commands or documents using data received from a less-trusted source.",
       "Inputs reach interpreters only through parameterised APIs and are validated against an allow-list.",
       "A remote attacker able to submit input through the exposed interface",
       "{target} concatenates request data into a query, command or template",
       "submit crafted input that changes how {target} interprets its own query or command",
       "unauthorised reading or modification of {asset} and possible remote code execution", "Integrity",
       _ex("Book-search endpoint", "Given the search endpoint builds its SQL by string concatenation, a remote attacker could submit crafted search terms that alter the query, resulting in disclosure of member records beyond the catalogue.",
           "It states the vulnerable construction explicitly; reviewers can verify it in code and a test can prove it is fixed."),
       ["AT-02"], ["Parameterised queries / ORM", "Allow-list input validation", "Least-privilege database role and WAF as a secondary layer"],
       ["T1190", "T1059"], ["CAPEC-66", "CAPEC-153"], ["OWASP Cheat Sheet Series - injection prevention", R_API]),
    _p("TP-07", "Missing or repudiable audit trail", "R",
       {"kinds": ["process", "datastore", "external_entity"], "any": ["admin_interface", "stores_sensitive", "log_store", "has_login"]},
       "Privileged or sensitive actions occur without an attributable, tamper-resistant record.",
       "Security-relevant events are logged with identity, time and outcome to a store the actor cannot alter.",
       "A malicious or compromised user, or an insider acting through an admin function",
       "{target} performs sensitive actions without recording who did what, or logs can be altered by the same actor",
       "perform and later deny a sensitive action on {target}, or erase the evidence",
       "inability to investigate or prove what happened to {asset}", "Non-repudiation",
       _ex("Admin console", "Given the admin console logs only successful logins and logs are writable by the console's own service account, an administrator who is also an attacker could change a member's fines and delete the log lines, resulting in changes that cannot be attributed.",
           "It shows two linked weaknesses (what is logged and who can alter the log), which gives two distinct controls."),
       [], ["Structured audit logging of security events", "Append-only or externally shipped logs", "Alerting on log tampering"],
       ["T1070"], [], [R_53]),
    _p("TP-08", "Sensitive data exposure in transit", "I",
       {"kinds": ["flow"], "any": ["encryption_unstated", "sensitive_flow", "crosses_boundary"]},
       "Confidential data crosses a network segment and the flow does not state confidentiality protection.",
       "The flow uses authenticated encryption and sensitive fields are minimised or tokenised.",
       "An adversary able to observe traffic on the path (shared network, compromised host, tap)",
       "{data} on {target} travels without confirmed encryption or beyond a boundary where it is decrypted unnecessarily",
       "read {data} by observing {target}",
       "disclosure of {asset} and regulatory exposure", "Confidentiality",
       _ex("API to payment provider flow", "Given card tokens are sent to the payment provider over a connection whose TLS configuration is not documented, an adversary on the network could capture the tokens, resulting in disclosure of payment details and PCI exposure.",
           "'Not documented' is recorded as an uncertainty, which is honest and is exactly what Step 4 evidence is for."),
       ["AT-03"], ["TLS with verified certificates and modern cipher suites", "Data minimisation and tokenisation", "Network egress allow-lists"],
       ["T1040", "T1557"], [], [R_TLS]),
    _p("TP-09", "Broken object-level authorisation / excessive data exposure", "I",
       {"kinds": ["process", "flow"], "any": ["api", "multi_tenant", "stores_sensitive"]},
       "Requests reference records by ID or name and the service must check that the caller may access that particular record.",
       "Every object access is authorised server-side against the caller's identity and tenant.",
       "An authenticated low-privilege user",
       "{target} authorises the endpoint but not the specific object (or tenant) being requested",
       "change an identifier in a request to read another user's records through {target}",
       "disclosure of other users' {asset}", "Confidentiality",
       _ex("Member profile endpoint", "Given the profile endpoint checks that the caller is logged in but not that the profile belongs to them, an authenticated member could iterate member IDs and read other members' profiles, resulting in disclosure of addresses and borrowing history.",
           "It separates 'authenticated' from 'authorised for this object', the distinction that most API breaches turn on."),
       ["AT-02"], ["Object-level authorisation checks in the service", "Unpredictable identifiers (defence in depth, not a control by itself)", "Authorisation tests per endpoint"],
       ["T1190", "T1213"], ["CAPEC-1", "CAPEC-21"], [R_API]),
    _p("TP-10", "Data store disclosure through leaked credentials or misconfiguration", "I",
       {"kinds": ["datastore"], "any": ["stores_sensitive", "internet_facing", "sql"]},
       "A store holds sensitive data and is protected mainly by credentials, network rules or cloud permissions.",
       "Access is least-privilege, network-restricted, encrypted at rest and credentials are rotated and not embedded.",
       "An attacker who obtains credentials from code, config or logs, or reaches an over-exposed endpoint",
       "credentials for {target} exist in configuration or code, or its network access is broader than needed",
       "connect to {target} directly and read stored records",
       "bulk disclosure of {asset}", "Confidentiality",
       _ex("User database", "Given the database password is stored in an environment file that is also copied into build logs, an attacker with read access to the build system could connect to the user database and export member records, resulting in bulk disclosure.",
           "The path (build logs to database) is concrete enough to become attack-tree steps."),
       ["AT-02"], ["Secrets management and rotation", "Network isolation and private endpoints", "Encryption at rest with separate key access"],
       ["T1552", "T1530", "T1078"], [], [R_53]),
    _p("TP-11", "Resource exhaustion of an exposed service", "D",
       {"kinds": ["process", "flow"], "any": ["internet_facing", "api", "queue"]},
       "A component accepts requests from sources the organisation does not control and has finite capacity.",
       "Rate limits, quotas, timeouts and autoscaling limits protect each caller class.",
       "A remote attacker or botnet, or a legitimate client with a bug",
       "{target} has no per-caller limits or expensive operations are reachable without authentication",
       "flood {target} with valid-looking requests until capacity is exhausted",
       "unavailability of {asset} for legitimate users", "Availability",
       _ex("Public search API", "Given the search endpoint is unauthenticated and runs an unindexed query, a botnet could send sustained queries that exhaust the database, resulting in the whole site being unavailable.",
           "It identifies why a small request is expensive (unindexed query), which determines the control (index, cache, limit)."),
       ["AT-04"], ["Rate limiting and quotas per caller", "Caching and query cost limits", "Graceful degradation and capacity monitoring"],
       ["T1499", "T1498"], [], [R_53]),
    _p("TP-12", "Shared dependency or queue saturation", "D",
       {"kinds": ["datastore", "flow", "process"], "any": ["queue", "multi_tenant", "sql"]},
       "Several callers (or tenants) share a store, broker or downstream service, so one caller's load affects the others.",
       "Isolation per caller (quotas, partitions, bulkheads) and backpressure are in place.",
       "A heavy or malicious tenant or a runaway producer",
       "{target} is shared and one producer can fill it or slow it for all other consumers",
       "saturate {target} with high-volume work",
       "delayed or lost processing of {asset} for other users", "Availability",
       _ex("Shared job queue", "Given all members' email jobs go through one queue without per-sender limits, a script that enqueues millions of jobs could delay all other members' notifications, resulting in missed return reminders.",
           "It shows the shared-resource condition that makes a single actor's behaviour affect everyone."),
       ["AT-04"], ["Per-tenant quotas and partitions", "Backpressure and dead-letter handling", "Capacity alerts"],
       ["T1499", "T1496"], [], [R_MS]),
    _p("TP-13", "Privilege escalation through flawed authorisation or confused service identity", "E",
       {"kinds": ["process"], "any": ["api", "multi_tenant", "admin_interface", "service_to_service"]},
       "A component performs privileged actions on behalf of callers whose rights it must check or whose token it must validate fully.",
       "Authorisation uses the caller's verified identity and scope, and services hold only the privileges they need.",
       "A low-privilege user or a compromised low-privilege service",
       "{target} acts with broader rights than its caller and does not fully validate the caller's token audience or scope",
       "make {target} perform an action the caller is not entitled to",
       "unauthorised administrative or cross-account actions on {asset}", "Authorisation",
       _ex("Fine-waiver function", "Given the waiver function runs with librarian rights and trusts a role claim in the request body, an ordinary member could add that claim and waive their own fines, resulting in unauthorised financial adjustments.",
           "It names the exact trust error (a client-controlled claim), which determines the control."),
       ["AT-05"], ["Server-side role checks from a verified token", "Audience and scope validation", "Least-privilege service roles"],
       ["T1548", "T1134", "T1068"], ["CAPEC-1"], [R_API, R_MS]),
    _p("TP-14", "Cross-tenant data access through a shared component", "I",
       {"kinds": ["process", "datastore"], "all": ["multi_tenant"]},
       "Several tenants share code, storage or caches and isolation depends on application logic reading the right tenant context.",
       "Tenant context comes from the verified identity, is enforced at every data access, and isolation is tested.",
       "A user of tenant A, or an attacker holding a tenant-A credential",
       "{target} derives tenant context from a client-supplied value or a shared cache key not scoped by tenant",
       "request or infer tenant B's data through {target}",
       "cross-tenant disclosure of {asset} and contractual breach", "Confidentiality",
       _ex("Shared reporting service", "Given the reporting service reads the tenant ID from a request header rather than from the signed token, a user of one library could set another library's ID and download its loan reports, resulting in cross-tenant disclosure.",
           "It combines identity, derivation of tenant context and impact - and exposes an assumption that can be tested."),
       ["AT-02"], ["Tenant context from verified identity only", "Tenant-scoped data access layer and cache keys", "Automated cross-tenant tests"],
       ["T1213", "T1078"], ["CAPEC-1", "CAPEC-21"], [R_API, R_MS]),
    _p("TP-15", "Malicious or tampered update, dependency or integration", "T",
       {"kinds": ["process", "external_entity", "flow"], "any": ["device", "third_party"]},
       "Code, firmware or data is received from a build pipeline, vendor or update channel and then trusted.",
       "Updates are signed and verified on the receiver, dependencies are pinned and vendor access is least-privilege.",
       "An attacker who compromises a supplier, build system or update channel",
       "{target} installs or trusts content without verifying a signature or provenance",
       "deliver a malicious update or poisoned data through {target}",
       "execution of attacker code or corrupted data affecting {asset}", "Integrity",
       _ex("Payment-provider integration", "Given the shop's server automatically trusts webhook payloads from the payment provider without verifying their signature, an attacker who finds the webhook URL could post a forged 'payment succeeded' event, resulting in orders marked paid.",
           "It identifies a third-party trust point and a specific missing verification."),
       ["AT-06"], ["Signature verification and provenance checks", "Dependency pinning and review", "Least-privilege vendor integrations"],
       ["T1195", "T1199", "T1553"], [], ["SLSA framework (supply-chain integrity levels)", R_53]),
]


# ═════════════════════════════════════════════════════════════════════════════════════
# Attack-tree templates
# ═════════════════════════════════════════════════════════════════════════════════════
def L(id_, label, desc, hint, attack=(), capec=(), detect="", controls=()):
    return {"id": id_, "type": "leaf", "label": label, "description": desc, "hint_difficulty": hint, "attack_ids": list(attack),
            "capec_ids": list(capec), "detect": detect, "control_themes": list(controls), "children": [], "logic": "leaf"}


def N(id_, typ, label, children, desc="", logic="or"):
    """Non-leaf node. 'or' = any child achieves it; 'and' = every child is needed. A goal node's logic defaults to 'or'."""
    return {"id": id_, "type": typ, "label": label, "description": desc, "children": children, "logic": typ if typ in ("or", "and") else logic}


def T(id_, name, goal, when, applies, not_when, root, example, patterns=()):
    return {"id": id_, "name": name, "goal": goal, "when": when, "applies_when": applies, "not_applicable_when": not_when,
            "root": root, "worked_example": example, "pattern_ids": list(patterns)}


TREES = [
    T("AT-01", "Account takeover", "Take over a legitimate user's account",
      {"kinds": ["external_entity", "process", "flow"], "any": ["has_login", "handles_credentials", "internet_facing"]},
      "Users authenticate to the system and an attacker gains from acting as one of them.",
      "There is no concept of an individual account (e.g. anonymous public data only).",
      N("AT-01.0", "goal", "Take over a legitimate user's account", [
          N("AT-01.1", "or", "Obtain the user's credentials", [
              L("AT-01.1.1", "Guess or stuff credentials against the login", "Automated attempts using breached or common passwords.", 2, ["T1110"], ["CAPEC-560"], "Spikes of failed logins across many accounts", ["Rate limiting", "Breached-password screening", "MFA"]),
              L("AT-01.1.2", "Phish the user", "Trick the user into entering credentials on a look-alike page.", 2, ["T1566"], [], "Reports, lookalike-domain monitoring", ["Phishing-resistant MFA", "User awareness"]),
              L("AT-01.1.3", "Find credentials left in code, logs or configuration", "Secrets exposed in repositories, build output or support tickets.", 3, ["T1552"], [], "Secret scanning alerts", ["Secrets management", "Log scrubbing"])]),
          N("AT-01.2", "or", "Take over an active session", [
              L("AT-01.2.1", "Steal the session cookie through a client-side flaw", "Script injection or malicious extension reads the cookie.", 3, ["T1539"], [], "CSP violation reports", ["HttpOnly cookies", "Content security policy", "Output encoding"]),
              L("AT-01.2.2", "Steal an access token from storage or logs", "Tokens stored insecurely or written to logs.", 3, ["T1528"], [], "Tokens appearing in logs", ["Short lifetimes", "No tokens in logs"]),
              L("AT-01.2.3", "Intercept the token on an unprotected hop", "Token visible on a path without confirmed encryption.", 3, ["T1557"], [], "TLS downgrade or certificate alerts", ["TLS everywhere", "Sender-constrained tokens"])]),
          N("AT-01.3", "or", "Bypass authentication", [
              L("AT-01.3.1", "Exploit a flaw in login or recovery logic", "Logic errors in login, MFA or password reset.", 4, ["T1190"], ["CAPEC-115"], "Anomalous recovery requests", ["Secure recovery flows", "Pen-testing"]),
              L("AT-01.3.2", "Abuse weak recovery or MFA enrolment", "Attacker enrols their own factor or resets via a weak channel.", 3, ["T1556"], [], "Factor changes without reauthentication", ["Reauthenticate on factor change", "Notify user"])])]),
      {"system": "BookSwap member login", "reading": "A viable path exists only where every step in it is plausible. Assess each leaf, then look at the cheapest viable path.",
       "assessments": {"AT-01.1.1": {"status": "plausible", "difficulty": 2, "rationale": "No throttling is recorded and password reuse is common; tooling is freely available."},
                       "AT-01.2.1": {"status": "implausible", "rationale": "Session cookie is HttpOnly and a strict CSP is enforced - verified in the last pen-test."},
                       "AT-01.3.1": {"status": "plausible", "difficulty": 4, "rationale": "Password reset uses emailed links with no expiry recorded; needs skill and luck."}},
       "outcome": "The cheapest viable path is credential stuffing (difficulty 2). Likelihood evidence points there; controls should target that step first."},
      ["TP-01", "TP-02"]),
    T("AT-02", "Unauthorised data access or modification through an API or service", "Read or alter data the attacker is not entitled to",
      {"kinds": ["process", "datastore", "flow"], "any": ["api", "sql", "multi_tenant", "stores_sensitive"]},
      "A service or store holds data and requests reach it through an API, where object-level checks and input handling matter.",
      "The component exposes no data-bearing interface and no direct credentials exist for the store.",
      N("AT-02.0", "goal", "Read or alter data the attacker is not entitled to", [
          N("AT-02.1", "and", "Abuse missing object- or tenant-level authorisation", [
              L("AT-02.1.1", "Obtain any valid low-privilege access", "Register, buy or steal an ordinary account.", 1, ["T1078"], [], "New-account anomalies", ["Registration controls"]),
              L("AT-02.1.2", "Substitute another object or tenant identifier in a request", "Change IDs, names or headers to reference someone else's data.", 2, ["T1190"], ["CAPEC-1", "CAPEC-21"], "Sequential-ID access patterns, 403 spikes", ["Object-level authorisation", "Tenant context from token"])]),
          N("AT-02.2", "and", "Inject through untrusted input", [
              L("AT-02.2.1", "Reach an input that feeds a query, command or template", "Find a parameter that is interpreted rather than treated as data.", 2, ["T1190"], ["CAPEC-153"], "WAF and error-rate alerts", ["Input validation"]),
              L("AT-02.2.2", "Craft input that changes the interpreter's behaviour", "Alter query structure to read or write beyond intent.", 3, ["T1059"], ["CAPEC-66"], "Database errors, unusual queries", ["Parameterised queries", "Least-privilege DB role"])]),
          N("AT-02.3", "or", "Reach the store directly", [
              L("AT-02.3.1", "Use leaked store or service credentials", "Credentials from code, logs or backups.", 3, ["T1552"], [], "Logins from unexpected sources", ["Secrets management", "Network restrictions"]),
              L("AT-02.3.2", "Pivot from a compromised neighbouring component", "Use network reachability from another workload.", 3, ["T1021"], [], "East-west traffic anomalies", ["Segmentation", "Per-service identities"]),
              L("AT-02.3.3", "Use a misconfigured cloud storage permission", "Public or over-shared bucket/share.", 2, ["T1530"], [], "Config drift alerts", ["Block public access", "Policy as code"])])]),
      {"system": "BookSwap profile API", "reading": "AND nodes need every child. Branch 2 needs both an injectable input and a crafted payload - assess them separately.",
       "assessments": {"AT-02.1.1": {"status": "plausible", "difficulty": 1, "rationale": "Anyone can register with an email address."},
                       "AT-02.1.2": {"status": "plausible", "difficulty": 2, "rationale": "Profile IDs are sequential and the endpoint only checks that the caller is logged in."},
                       "AT-02.2.1": {"status": "implausible", "rationale": "All queries use the ORM with bound parameters; code review confirms no raw SQL."}},
       "outcome": "Branch 1 is the viable path (max difficulty 2). Branch 2 is cut by design evidence - note that evidence in the rationale."},
      ["TP-05", "TP-06", "TP-09", "TP-10", "TP-14"]),
    T("AT-03", "Interception or tampering of data in transit", "Read or modify data while it moves between components",
      {"kinds": ["flow"], "any": ["encryption_unstated", "crosses_boundary", "sensitive_flow"]},
      "Data crosses a network path the organisation does not wholly control, or the protocol does not state protection.",
      "The flow stays inside one process or one host, or end-to-end authenticated encryption is verified.",
      N("AT-03.0", "goal", "Read or modify data in transit", [
          N("AT-03.1", "or", "Gain a position on the path", [
              L("AT-03.1.1", "Act as adversary-in-the-middle on an untrusted network", "Shared Wi-Fi, rogue access point or ARP/DNS manipulation.", 2, ["T1557"], [], "Certificate warnings, DNS anomalies", ["TLS with certificate validation"]),
              L("AT-03.1.2", "Compromise an intermediary (proxy, balancer, broker)", "Component that terminates or relays the connection.", 4, ["T1190"], [], "Intermediary integrity monitoring", ["Harden and monitor intermediaries", "End-to-end encryption"])]),
          N("AT-03.2", "or", "Exploit missing protection", [
              L("AT-03.2.1", "Read data sent without confirmed encryption", "Passive sniffing of plaintext or weakly protected traffic.", 2, ["T1040"], [], "Protocol audits", ["Enforce encryption"]),
              L("AT-03.2.2", "Modify messages that lack integrity protection", "Change values without detection.", 3, ["T1565"], ["CAPEC-153"], "Integrity-check failures", ["Authenticated encryption", "Message signing"])])], logic="and"),
      {"system": "BookSwap checkout over public Wi-Fi", "reading": "This goal needs a position AND an exploitable weakness; the tree is an AND at the root (position + weakness).",
       "assessments": {"AT-03.1.1": {"status": "plausible", "difficulty": 2, "rationale": "Members use café Wi-Fi; tooling for rogue access points is common."},
                       "AT-03.2.2": {"status": "implausible", "rationale": "HTTPS with HSTS is enforced and the mobile app pins the certificate (verified)."}},
       "outcome": "Remaining viable path is read-only sniffing, which HTTPS already blocks - so the residual concern is intermediary compromise."},
      ["TP-04", "TP-08"]),
    T("AT-04", "Service disruption", "Make the service unavailable or unusable for legitimate users",
      {"kinds": ["process", "flow", "datastore"], "any": ["internet_facing", "queue", "multi_tenant", "api"]},
      "The service has finite capacity and depends on shared or external components.",
      "No availability requirement exists for this component.",
      N("AT-04.0", "goal", "Make the service unavailable", [
          L("AT-04.1", "Flood an exposed interface", "Volumetric or application-layer request floods.", 2, ["T1498", "T1499"], [], "Traffic and latency alerts", ["Rate limiting", "CDN/DDoS protection"]),
          L("AT-04.2", "Exhaust a shared resource with legitimate-looking work", "One caller or tenant consumes the pool.", 3, ["T1499", "T1496"], [], "Per-tenant utilisation", ["Quotas", "Bulkheads"]),
          L("AT-04.3", "Take down or poison a dependency", "Stop or degrade a service the system needs.", 4, ["T1489"], [], "Dependency health checks", ["Redundancy", "Timeouts and circuit breakers"]),
          L("AT-04.4", "Destroy or corrupt data needed to operate", "Delete or encrypt data/config the service needs.", 4, ["T1485"], [], "Backup and integrity alerts", ["Immutable backups", "Tested restores"])]),
      {"system": "BookSwap search and notification queue", "reading": "A pure OR tree: any one viable leaf achieves the goal, so the cheapest viable leaf sets the likelihood.",
       "assessments": {"AT-04.1": {"status": "plausible", "difficulty": 2, "rationale": "No CDN or rate limiting; the site is single-region."},
                       "AT-04.2": {"status": "plausible", "difficulty": 3, "rationale": "All members' jobs share one queue without limits."}},
       "outcome": "Two viable single-step paths exist; fixing only the flood path leaves the queue path open."},
      ["TP-11", "TP-12"]),
    T("AT-05", "Privilege escalation via service identity or token misuse", "Perform actions beyond the attacker's entitlement",
      {"kinds": ["process", "flow"], "any": ["api", "service_to_service", "has_login", "admin_interface"]},
      "Services pass identity or tokens between each other and decide what a caller may do.",
      "Only one component exists and it holds all privileges by design with no delegation.",
      N("AT-05.0", "goal", "Perform an action beyond entitlement", [
          N("AT-05.1", "and", "Gain a foothold, then abuse trust", [
              N("AT-05.1.1", "or", "Gain a low-privilege foothold", [
                  L("AT-05.1.1.1", "Compromise a low-privilege workload or service", "Exploit a vulnerable service to run code with its identity.", 3, ["T1190"], [], "Runtime anomaly detection", ["Patch management", "Workload isolation"]),
                  L("AT-05.1.1.2", "Use a stolen low-privilege user token", "Token from XSS, logs or interception.", 3, ["T1528"], [], "Token reuse from new locations", ["Short lifetimes", "Binding"])]),
              N("AT-05.1.2", "or", "Escalate using weak trust decisions", [
                  L("AT-05.1.2.1", "Replay a token at a service that does not check audience or scope", "Token valid for service A accepted by service B.", 3, ["T1550"], ["CAPEC-21"], "Tokens seen at unexpected audiences", ["Audience and scope validation"]),
                  L("AT-05.1.2.2", "Forge or alter claims in an unprotected token", "Role claim editable by the client.", 2, ["T1606", "T1134"], [], "Signature failures", ["Signed tokens verified server-side"]),
                  L("AT-05.1.2.3", "Use an over-privileged service role", "Service permitted far more than its function needs.", 3, ["T1548"], ["CAPEC-1"], "IAM access analyser findings", ["Least privilege"]),
                  L("AT-05.1.2.4", "Confused deputy: privileged service acts for an unverified caller", "Service performs actions based on caller-supplied parameters.", 3, ["T1548"], [], "Privileged actions without caller context", ["Pass and verify caller identity"])])])]),
      {"system": "BookSwap fine-waiver service", "reading": "Nested AND/OR: you need a foothold AND an escalation step. Assess leaves in each OR group; the AND combines the cheapest of each group.",
       "assessments": {"AT-05.1.1.2": {"status": "plausible", "difficulty": 3, "rationale": "Tokens are valid for 24h and appear in client logs."},
                       "AT-05.1.2.2": {"status": "plausible", "difficulty": 2, "rationale": "The service trusts a role claim in the request body."}},
       "outcome": "Path = stolen token + forged claim, effort 3. A control that signs and verifies claims cuts the escalation half of the AND."},
      ["TP-02", "TP-03", "TP-13"]),
    T("AT-06", "Malicious update or supply-chain compromise", "Get attacker-controlled code or data trusted by the system",
      {"kinds": ["process", "external_entity", "flow"], "any": ["device", "third_party"]},
      "Software, firmware, dependencies or vendor data are received from outside the team and then trusted.",
      "The component accepts no externally supplied code, updates or vendor data.",
      N("AT-06.0", "goal", "Get attacker-controlled code or data trusted", [
          L("AT-06.1", "Compromise a dependency or the build pipeline", "Poisoned library, build script or CI credential.", 4, ["T1195"], [], "Dependency and build provenance checks", ["Pinning", "Signed builds"]),
          L("AT-06.2", "Tamper with an update at the distribution point or in transit", "Replace an artefact on a mirror or intercept its download.", 3, ["T1195", "T1557"], [], "Hash and signature mismatches", ["Signed artefacts", "TLS"]),
          L("AT-06.3", "Install an unsigned or forged update on the target", "Receiver accepts an update without verifying signature.", 3, ["T1553"], [], "Update verification failures", ["Signature verification on device", "Rollback protection"]),
          L("AT-06.4", "Abuse the trust given to a vendor integration", "Forged webhook or compromised vendor credential.", 3, ["T1199"], [], "Unexpected vendor-originated calls", ["Webhook signature checks", "Least-privilege vendor access"])]),
      {"system": "BookSwap payment webhook", "reading": "Four independent routes; the webhook route needs no sophistication if signatures are not verified.",
       "assessments": {"AT-06.4": {"status": "plausible", "difficulty": 2, "rationale": "Webhook URL is guessable and payloads are accepted without a signature."},
                       "AT-06.1": {"status": "implausible", "rationale": "Dependencies are pinned and CI uses short-lived credentials (audited)."}},
       "outcome": "Only the webhook route is viable; one verification step would cut it."},
      ["TP-15"]),
]

PATTERN_BY_ID = {p["id"]: p for p in PATTERNS}
TREE_BY_ID = {t["id"]: t for t in TREES}


def walk(node, parent=None):
    yield node, parent
    for c in node.get("children", []):
        yield from walk(c, node)


def tree_leaves(tree):
    return [n for n, _ in walk(tree["root"]) if n["type"] == "leaf"]


# ═════════════════════════════════════════════════════════════════════════════════════
# Contextual suggestion
# ═════════════════════════════════════════════════════════════════════════════════════
def _fill(text, ws, target_id, asset):
    e = _find(ws["dfd"]["elements"], target_id)
    f = _find(ws["dfd"]["flows"], target_id)
    if e:
        name, data = e["name"], "the data it handles"
    elif f:
        s, d = _find(ws["dfd"]["elements"], f["source"]), _find(ws["dfd"]["elements"], f["destination"])
        name = f"{s['name'] if s else f['source']} \u2192 {d['name'] if d else f['destination']}"
        data = f["data"]
    else:
        name, data = target_id, "the data"
    return text.format(target=name, data=data, asset=asset)


def suggest_patterns(ws, target_id, with_drafts=True, limit=6):
    """Rank library patterns for one DFD element or flow. Each result explains WHY it was suggested."""
    kind = target_kind(ws, target_id)
    if not kind:
        return []
    tags = context_tags(ws, target_id) | {kind}
    assets = [a["name"] for a in ws["scope"].get("assets", [])]
    asset = assets[0] if assets else "the affected asset"
    out = []
    for p in PATTERNS:
        ok, reasons, why_not, score = _match(p["when"], kind, tags)
        if not ok:
            continue
        item = {"pattern_id": p["id"], "name": p["name"], "stride": p["stride"], "score": score, "reasons": reasons or ["applies to this element type"],
                "specific": bool(reasons), "applies_when": p["applies_when"], "not_applicable_when": p["not_applicable_when"],
                "tree_ids": p["tree_ids"], "attack_ids": p["attack_ids"], "capec_ids": p["capec_ids"], "control_themes": p["control_themes"]}
        if with_drafts:
            item["draft"] = {"stride": p["stride"], "source": p["source"], "preconditions": _fill(p["preconditions"], ws, target_id, asset),
                             "action": _fill(p["action"], ws, target_id, asset), "impact": _fill(p["impact"], ws, target_id, asset),
                             "security_property": p["security_property"], "targets": [target_id], "assets": [asset] if assets else []}
        out.append(item)
    if not out:      # beginners still get a starting point: patterns for this element type, clearly marked as generic
        for p in PATTERNS:
            w_ = p["when"]
            if kind in w_["kinds"] and not w_.get("all") and not (set(w_.get("none", [])) & tags):
                item = {"pattern_id": p["id"], "name": p["name"], "stride": p["stride"], "score": 0, "reasons": ["applies to this element type"], "specific": False,
                        "applies_when": p["applies_when"], "not_applicable_when": p["not_applicable_when"], "tree_ids": p["tree_ids"],
                        "attack_ids": p["attack_ids"], "capec_ids": p["capec_ids"], "control_themes": p["control_themes"]}
                if with_drafts:
                    item["draft"] = {"stride": p["stride"], "source": p["source"], "preconditions": _fill(p["preconditions"], ws, target_id, asset),
                                     "action": _fill(p["action"], ws, target_id, asset), "impact": _fill(p["impact"], ws, target_id, asset),
                                     "security_property": p["security_property"], "targets": [target_id], "assets": [asset] if assets else []}
                out.append(item)
        out = out[:3]
    out.sort(key=lambda i: (-int(i["specific"]), -i["score"], i["pattern_id"]))
    return out[:limit]


def suggest_trees(ws, threat, limit=3):
    """Templates for a threat: from its library pattern (if any) first, then by context of its targets."""
    tags = set()
    kinds = set()
    for tid in threat["targets"]:
        tags |= context_tags(ws, tid)
        k = target_kind(ws, tid)
        if k:
            kinds.add(k)
            tags.add(k)
    out = {}
    pid = (threat.get("library_ref") or {}).get("pattern_id")
    if pid in PATTERN_BY_ID:
        for tid_ in PATTERN_BY_ID[pid]["tree_ids"]:
            out[tid_] = {"tree_id": tid_, "reasons": [f"linked to library pattern {pid}"], "score": 99}
    for t in TREES:
        if any(ok_ for ok_, *_ in [_match(t["when"], k, tags) for k in kinds]):
            hits = []
            for k in kinds:
                ok_, reasons, _, sc = _match(t["when"], k, tags)
                if ok_:
                    hits = reasons or ["applies to this element type"]
                    break
            same_stride = any(threat["stride"] == PATTERN_BY_ID[p]["stride"] for p in t["pattern_ids"])
            if t["id"] not in out:
                out[t["id"]] = {"tree_id": t["id"], "reasons": hits + (["same STRIDE category as its linked patterns"] if same_stride else []), "score": len(hits) + (2 if same_stride else 0)}
    res = []
    for v in sorted(out.values(), key=lambda v: (-v["score"], v["tree_id"]))[:limit]:
        t = TREE_BY_ID[v["tree_id"]]
        res.append({**v, "name": t["name"], "goal": t["goal"], "applies_when": t["applies_when"], "not_applicable_when": t["not_applicable_when"]})
    return res


def instantiate_nodes(template_id):
    """Flat node list (template ids kept in 'template_node') ready for the model to assign stable IDs."""
    t = TREE_BY_ID[template_id]
    flat = []

    def rec(n, parent):
        flat.append({"template_node": n["id"], "parent_template": parent, "type": n["type"], "logic": n.get("logic", "or"), "label": n["label"], "description": n.get("description", ""),
                     "hint_difficulty": n.get("hint_difficulty"), "attack_ids": list(n.get("attack_ids", [])), "capec_ids": list(n.get("capec_ids", [])),
                     "detect": n.get("detect", ""), "control_themes": list(n.get("control_themes", []))})
        for c in n.get("children", []):
            rec(c, n["id"])
    rec(copy.deepcopy(t["root"]), None)
    return flat
