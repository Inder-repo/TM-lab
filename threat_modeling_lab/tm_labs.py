"""Pedagogical profiles for the four labs (pure data + small resolvers, no Streamlit).

All four labs use the SAME nine-step methodology and the SAME canonical data model
(tm_model). What differs is deliberate: how much scaffolding is given, how ambiguous the
brief is, what reference material can be revealed, and which assessment expectations apply.

Everything under ``instructor_only`` is never shown directly; it is reachable only through
tm_model.get_reference(), which enforces the discover-first gate.
"""
import copy

import lab_data

LAB_IDS = tuple(lab_data.WORKSHOPS.keys())

PROFILES = {
    "1": {
        "role": "Guided fundamentals",
        "scaffold": "guided",
        "purpose": "Learn the method on a small two-tier system with a worked example, "
                   "threat-statement scaffolding and immediate explanatory feedback.",
        "discover_first_default": False, "discover_first_locked": False,
        "reference_dfd": "load",          # reference DFD can be loaded as an editable starting point
        "worked_example": True,           # one fully worked STRIDE threat statement is shown
        "statement_scaffold": "fields+examples",
        "hint_level": "full",
        "immediate_feedback": True,
        "seed_scope_assets_objectives": True,
        "expectations": {
            "scope": "A clear scope statement, in/out of scope and at least one confirmed fact and one assumption to validate.",
            "dfd": "All brief components and flows present with protocol and data classification; trust boundaries drawn.",
            "stride": "Every applicability prompt considered; threats are specific to this system, not generic.",
            "statements": "Statements follow the structured template and name concrete actions.",
            "mappings": "Mappings come from the attack path; 'no defensible mapping' is acceptable with a reason.",
            "risk": "Likelihood and impact each have a short rationale.",
            "controls": "Controls are proposed first; verification needs evidence.",
            "residual": "Residual risk is reassessed only from verified controls; acceptance has an owner.",
            "review": "An owner, a next review date and re-modelling triggers.",
        },
    },
    "2": {
        "role": "Applied service architecture",
        "scaffold": "reduced",
        "purpose": "Apply the method to an API/microservice design where identity propagation, "
                   "authorisation and service-to-service trust drive the threats.",
        "discover_first_default": True, "discover_first_locked": False,
        "reference_dfd": "inventory",     # only the component inventory (no flows/boundaries) is available
        "worked_example": False,
        "statement_scaffold": "fields",
        "hint_level": "reduced",
        "immediate_feedback": True,
        "seed_scope_assets_objectives": True,
        "expectations": {
            "scope": "Scope covers the service mesh edge and states how identity is established.",
            "dfd": "Service-to-service flows are explicit with authentication method noted; you decide where trust boundaries sit.",
            "stride": "Identity propagation and authorisation are analysed per flow, not only per component.",
            "statements": "Statements name the identity/authorisation precondition that fails.",
            "mappings": "Mappings follow the actual attack path (e.g. token abuse) and cite scenario evidence.",
            "risk": "Ratings justify likelihood using exposure and prerequisites.",
            "controls": "Controls address the failed trust assumption (not just 'add TLS').",
            "residual": "Remaining attack paths are named, with limitations of each control.",
            "review": "Triggers include identity-provider, gateway and service-contract changes.",
        },
    },
    "3": {
        "role": "Multi-tenant and shared-service risk",
        "scaffold": "minimal",
        "purpose": "Reason about tenant isolation, shared components and chained cross-tenant attack paths "
                   "when the brief leaves important facts unstated.",
        "discover_first_default": True, "discover_first_locked": False,
        "reference_dfd": "compare",       # read-only comparison after the learner's own DFD exists
        "worked_example": False,
        "statement_scaffold": "fields",
        "hint_level": "minimal",
        "immediate_feedback": False,
        "seed_scope_assets_objectives": False,
        "expectations": {
            "scope": "Scope states which tenant-isolation properties are in and out of scope, with unknowns recorded as assumptions.",
            "dfd": "Shared vs tenant-specific components are distinguishable; isolation boundaries are justified.",
            "stride": "At least some threats target more than one element/flow (attack paths), with interacting threats noted.",
            "statements": "Statements identify the tenant as threat source or victim and the isolation assumption that fails.",
            "mappings": "Mappings are justified per step of the path; some threats may legitimately have no CAPEC mapping.",
            "risk": "Prioritisation is evidence-backed and states uncertainty explicitly.",
            "controls": "Control design addresses shared-service failure modes and defines how isolation is verified.",
            "residual": "Residual risk reflects only verified isolation controls; accepted risk is escalated appropriately.",
            "review": "Triggers include new tenant tiers, shared-component changes and key-management changes.",
        },
    },
    "4": {
        "role": "Independent unfamiliar application",
        "scaffold": "independent",
        "purpose": "Produce a complete, traceable threat model for an unfamiliar system from an incomplete brief, "
                   "identifying what you do not know before analysing what you do.",
        "discover_first_default": True, "discover_first_locked": True,
        "reference_dfd": "compare",
        "worked_example": False,
        "statement_scaffold": "none",
        "hint_level": "none",
        "immediate_feedback": False,
        "seed_scope_assets_objectives": False,
        "expectations": {
            "scope": "Scope separates confirmed facts from assumptions and lists the information you still need.",
            "dfd": "Your DFD includes elements the brief implies but does not draw; every inferred element is marked as an assumption.",
            "stride": "Applicability is reasoned for each element; departures from the standard model are explained.",
            "statements": "Statements are specific and traceable to DFD IDs and assets, including safety impact.",
            "mappings": "Mappings and non-mappings are each justified; no forced mappings.",
            "risk": "Risk ratings consider safety/regulatory context and state uncertainty.",
            "controls": "Controls have owners, verification methods and evidence plans.",
            "residual": "Residual decisions have accountable owners, due dates and escalation conditions.",
            "review": "Review plan and change triggers are tailored to the device/cloud/legacy lifecycle.",
        },
    },
}

BRIEFS = {
    "1": ("**TechMart** runs an online store (about 50K monthly users). Customers use a React single-page app in their "
          "browser. The SPA calls a Node.js/Express API over HTTPS. The API reads and writes a PostgreSQL database that "
          "holds customer PII and orders. Card payments are sent from the API to Stripe and order e-mails are sent through "
          "SendGrid.\n\n"
          "*What this lab asks of you:* build the DFD with guidance, work through one fully worked STRIDE example, then "
          "write your own threats using the structured template."),
    "2": ("**CloudBank** is a regional bank's mobile banking platform. A mobile app talks to an API gateway. The gateway "
          "routes authentication requests to a User Service and payment requests to a Payment Service (both on containers). "
          "User profiles live in DynamoDB; financial records live in Aurora. The Payment Service also receives tokens from "
          "the User Service.\n\n"
          "*Things to decide yourself:* where trust boundaries really sit, how the user's identity is propagated to the "
          "Payment Service, and what the gateway does versus what each service must still check. "
          "The architecture overview mentions message queues, but no queue appears in the flow list - decide whether "
          "they are in scope and what they would add."),
    "3": ("**DataInsight** is a B2B analytics SaaS used by about 500 enterprise customers. Tenants share one set of "
          "services and storage; isolation is logical. Users reach a dashboard that calls a gateway. Data is uploaded through "
          "an ingestion service into a streaming platform and queried by a query service against a shared data warehouse.\n\n"
          "*The brief does not tell you:* how the tenant identity reaches each service, whether tenant data is separated "
          "by topic, schema, row or key, whether encryption keys are per tenant, or whether any resource limits are "
          "enforced per tenant. Treat each as an open question or an explicit assumption - and decide what each answer "
          "would change in your threat model."),
    "4": ("**HealthMonitor Connected Care** is a continuous glucose monitoring service for about 10,000 patients. A wearable "
          "sensor sends readings to a home gateway. The gateway forwards telemetry to a cloud service. Clinicians are alerted "
          "through a web portal, and records are exchanged with hospital systems. The device is FDA-registered.\n\n"
          "*This brief is deliberately incomplete.* Before analysing threats, list what you need to know that is not written "
          "here (people, data, interfaces, lifecycle, operations). Build your own DFD, mark inferred elements as assumptions "
          "and record questions with owners."),
}

# Facts that are genuinely stated in each brief. Seeded into scope.facts as "confirmed - lab brief".
BRIEF_FACTS = {
    "1": ["React SPA in the customer's browser", "Node.js/Express API", "PostgreSQL holds PII and orders",
          "Payments go to Stripe", "E-mails go through SendGrid"],
    "2": ["Mobile app is the client", "AWS API Gateway is the entry point", "User Service handles authentication and identity",
          "Payment Service handles financial transfers", "DynamoDB holds user profiles, Aurora holds financial records"],
    "3": ["Tenants share services and storage with logical isolation", "Kong gateway performs tenant routing",
          "Ingestion and query services are shared", "Shared Kafka topics (MSK) and one Redshift warehouse hold tenant data"],
    "4": ["Wearable glucose sensor in the patient's home", "Home gateway forwards telemetry to the cloud",
          "Alerts are dispatched to clinicians through a portal", "Records are exchanged with hospital systems (HL7 v2)",
          "The device is FDA-registered"],
}

# Instructor-only: information the Lab 4 brief omits. Matched against the learner's own questions
# with keywords; a match is a *hint for the instructor*, never an automatic grade.
INSTRUCTOR_ONLY = {
    "4": {"gaps": [
        {"id": "G1", "topic": "Firmware update and signing path for sensor and gateway", "keywords": ["firmware", "update", "ota", "signing", "signed"]},
        {"id": "G2", "topic": "Device identity, pairing and provisioning", "keywords": ["pairing", "provision", "device identity", "certificate", "enrol", "enroll", "ble"]},
        {"id": "G3", "topic": "How clinicians are authenticated and authorised", "keywords": ["clinician", "sso", "mfa", "identity provider", "login", "authenticat"]},
        {"id": "G4", "topic": "Audit logging of PHI access and alert handling", "keywords": ["audit", "log", "who accessed", "access record"]},
        {"id": "G5", "topic": "Alert delivery fallback if the portal or network is unavailable", "keywords": ["fallback", "redundan", "sms", "push", "offline", "notification", "escalat"]},
        {"id": "G6", "topic": "Backups, key management and encryption at rest", "keywords": ["backup", "kms", "key", "encryption at rest", "restore"]},
        {"id": "G7", "topic": "Hospital integration path (interface engine, network, VPN)", "keywords": ["interface engine", "vpn", "mllp", "hl7", "integration", "hospital network"]},
        {"id": "G8", "topic": "Consent, retention and deletion of patient data", "keywords": ["consent", "retention", "delete", "deletion", "gdpr", "right to"]},
    ]},
}

_WORKED_EXAMPLE = {
    "1": {
        "title": "Worked example - tampering with an order in transit between the SPA and the API",
        "stride": "T",
        "source": "An attacker on the same untrusted network as the customer (e.g. public Wi-Fi) or a malicious browser extension",
        "preconditions": "the customer submits an order while the browser trusts attacker-controlled network infrastructure or a malicious extension",
        "action": "modify the quantity and price fields of the order request before it reaches the API",
        "impact": "incorrect orders and loss of order integrity",
        "asset": "Order history",
        "why": ("The flow crosses the Internet boundary (applicability prompt: data flow -> Tampering). The threat is specific "
                "because it names the actor, the precondition that makes it possible, the data altered and the business effect. "
                "Note what it does NOT do: it does not claim the threat is high or low (that is Step 6), and it does not pick an "
                "ATT&CK technique yet (that is Step 5, and only if the attack path supports one)."),
    },
}


def profile(lab_id):
    return PROFILES[str(lab_id)]


def brief(lab_id):
    return BRIEFS[str(lab_id)]


def worked_example(lab_id):
    return copy.deepcopy(_WORKED_EXAMPLE.get(str(lab_id)))


def scenario(lab_id):
    return lab_data.WORKSHOPS[str(lab_id)]["scenario"]


def lab_name(lab_id):
    return lab_data.WORKSHOPS[str(lab_id)]["name"]


def reference_model(lab_id):
    """The lab author's reference DFD as plain data (INSTRUCTOR REFERENCE - gate before showing)."""
    sc = scenario(lab_id)
    return {
        "elements": [{"name": c["name"], "type": c["type"], "description": c.get("description", ""),
                      "security_domain": c.get("zone", "")} for c in sc["components"]],
        "flows": [{"source": f["source"], "destination": f["destination"], "data": f["data"], "protocol": f["protocol"]}
                  for f in sc["data_flows"]],
        "boundaries": [{"name": b["name"], "description": b["description"], "members": list(b["components"])}
                       for b in sc["trust_boundaries"]],
    }


def reference_threats(lab_id):
    """Instructor reference threats. Targets that do not exist in the lab's reference DFD are
    reported as ``unresolved_targets`` (the legacy data referenced e.g. 'S3 Storage', 'Data Lake',
    'HL7 Interface' which are not DFD elements) instead of being silently dropped."""
    ref = reference_model(lab_id)
    names = {e["name"] for e in ref["elements"]}
    flow_keys = {(f["source"], f["destination"]) for f in ref["flows"]}
    out = []
    for t in lab_data.PREDEFINED_THREATS.get(str(lab_id), []):
        comp = t["component"]
        targets, unresolved = [], []
        if " \u2192 " in comp:
            a, b = [p.strip() for p in comp.split(" \u2192 ", 1)]
            if (a, b) in flow_keys:
                targets.append({"kind": "flow", "source": a, "destination": b})
            else:
                unresolved.append(comp)
        elif comp in names:
            targets.append({"kind": "element", "name": comp})
        else:
            unresolved.append(comp)
        out.append({"ref_id": t["id"], "stride": t["stride"], "stride_letter": _letter(t["stride"]),
                    "summary": t["threat"], "explanation": t["explanation"], "targets": targets,
                    "unresolved_targets": unresolved, "owasp": t.get("owasp_categories", []),
                    "mitigation_examples": t.get("correct_mitigations", []),
                    "real_world": t.get("real_world", "")})
    return out


def _letter(stride_name):
    return {"Spoofing": "S", "Tampering": "T", "Repudiation": "R", "Information Disclosure": "I",
            "Denial of Service": "D", "Elevation of Privilege": "E"}.get(stride_name, "")


def known_gaps(lab_id):
    return copy.deepcopy(INSTRUCTOR_ONLY.get(str(lab_id), {}).get("gaps", []))
