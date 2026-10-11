"""Canonical, Streamlit-free threat-model data model (workspace schema v3).

One workspace per (learner session, lab). Every page of the app reads and writes THESE records:
  scope -> dfd(elements, flows, boundaries) -> threats -> mappings -> risks(inherent+residual)
  -> controls -> treatment decisions -> questions -> review plan.
Stable IDs are never reused. Changing the DFD flags downstream records as stale until a learner
revalidates them with a note. Risk is never reduced automatically: residual ratings are entered
by the learner and may only fall below inherent when VERIFIED controls support the reduction.
"""
import copy
import hashlib
import json
import os
import re
import tempfile
import uuid
from datetime import date, datetime

import tm_catalog
import tm_labs

WORKSPACE_VERSION = 3
STATE_VERSION = 5

STRIDE = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation",
          "I": "Information Disclosure", "D": "Denial of Service", "E": "Elevation of Privilege"}
STRIDE_ORDER = "STRIDE"
ELEMENT_TYPES = ("external_entity", "process", "datastore")
KIND_LABEL = {"external_entity": "External entity", "process": "Process", "datastore": "Data store", "flow": "Data flow"}
# Classic STRIDE-per-element APPLICABILITY PROMPTS (not proof that a threat exists).
APPLICABILITY = {"external_entity": "SR", "process": "STRIDE", "datastore": "TRID", "flow": "TID"}
SECURITY_PROPERTIES = ["Authenticity", "Integrity", "Non-repudiation", "Confidentiality", "Availability", "Authorisation"]
PROPERTY_FOR_STRIDE = {"S": "Authenticity", "T": "Integrity", "R": "Non-repudiation",
                       "I": "Confidentiality", "D": "Availability", "E": "Authorisation"}
CONFIDENCE = ["Low", "Medium", "High"]
CLASSIFICATIONS = ["Public", "Internal", "Confidential", "Restricted"]
DIRECTIONS = ["one-way", "bidirectional"]
ASSUMPTION_STATUS = ["needs validation", "validated", "invalidated"]
CELL_DISPOSITIONS = ["threat", "not_applicable", "mitigated_by_design", "deferred"]
RELATIONSHIPS = ["Technique/pattern used in this attack path", "Closely related (indirect)", "Tactic context only"]
CONTROL_FUNCTIONS = ["preventive", "detective", "responsive", "recovery"]
CONTROL_STATUS = ["proposed", "planned", "implemented", "verified", "verification_failed", "rejected"]
TREATMENTS = ["mitigate", "transfer", "avoid", "accept"]
BOUNDARY_PROPERTIES = ["Identity", "Authorisation", "Input validation", "Integrity", "Confidentiality", "Availability"]
THREAT_SOURCES = ["External attacker (opportunistic)", "Skilled external attacker (targeted)", "Malicious or compromised user",
                  "Adversary with network access", "Malicious insider / privileged administrator", "Compromised third party / supply chain",
                  "Adversary with physical or device access", "Automated bot / botnet", "Another tenant", "Faulty component (non-malicious failure)"]
CADENCES = ["Every sprint / iteration", "Monthly", "Quarterly", "On every release"]

PREFIX = {"external_entity": "EE", "process": "P", "datastore": "DS", "flow": "DF", "boundary": "TB",
          "threat": "THR", "mapping": "MAP", "risk": "RSK", "control": "CTL", "question": "Q",
          "assumption": "A", "fact": "F", "asset": "AS", "stakeholder": "SH", "dependency": "DEP",
          "exclusion": "EX", "change": "CH"}

# ── Risk model (documented, configurable) ─────────────────────────────────────────────
RISK_MODEL = {
    "version": "1.0",
    "method": "Qualitative 5x5: score = likelihood x impact; band from thresholds below.",
    "likelihood": {1: "Rare - needs unusual access/conditions", 2: "Unlikely - needs significant skill or insider access",
                   3: "Possible - realistic with moderate effort", 4: "Likely - known technique, exposed path",
                   5: "Almost certain - trivial or already observed"},
    "impact": {1: "Negligible", 2: "Minor - limited, easily recovered", 3: "Moderate - noticeable data/service harm",
               4: "Major - significant regulated-data, financial or safety harm", 5: "Severe - systemic, irreversible or life-safety harm"},
    "bands": [(1, 4, "Low"), (5, 9, "Medium"), (10, 16, "High"), (17, 25, "Critical")],
    "priority": {"Critical": ("P1", "Treat immediately; do not release without a verified control or an escalated decision"),
                 "High": ("P2", "Plan and start within the current iteration / <= 30 days"),
                 "Medium": ("P3", "Schedule within 90 days"),
                 "Low": ("P4", "Backlog; accept with a named owner if no action is taken")},
}


class ValidationError(ValueError):
    def __init__(self, errors):
        self.errors = [errors] if isinstance(errors, str) else list(errors)
        super().__init__("; ".join(self.errors))


class DuplicateError(ValidationError):
    pass


class RevealLocked(PermissionError):
    pass


def issue(severity, code, message, ref=None, step=None):
    return {"severity": severity, "code": code, "message": message, "ref": ref, "step": step}


def now():
    return datetime.now().replace(microsecond=0).isoformat()


def today():
    return date.today().isoformat()


def norm(s):
    return re.sub(r"\s+", " ", str(s or "").strip()).lower()


def clean(s):
    return re.sub(r"[ \t]+", " ", str(s or "").strip())


def parse_date(s):
    try:
        return date.fromisoformat(str(s))
    except (TypeError, ValueError):
        return None


# ═════════════════════════════════════════════════════════════════════════════════════
# Workspace + IDs
# ═════════════════════════════════════════════════════════════════════════════════════
def new_workspace(lab_id, learner="learner"):
    lab_id = str(lab_id)
    prof = tm_labs.profile(lab_id)
    ws = {
        "workspace_version": WORKSPACE_VERSION, "lab_id": lab_id, "learner": learner,
        "created": now(), "updated": now(),
        "settings": {"discover_first": bool(prof["discover_first_default"]), "risk_model_version": RISK_MODEL["version"]},
        "counters": {}, "deleted_ids": [], "_tokens": {},
        "scope": {"purpose": "", "business_context": "", "in_scope": [], "exclusions": [], "objectives": [],
                  "assets": [], "stakeholders": [], "facts": [], "assumptions": [], "dependencies": [],
                  "data_sensitivity": "", "regulatory": [], "success_criteria": [],
                  "version": 0, "committed_hash": ""},
        "dfd": {"elements": [], "flows": [], "boundaries": [], "assumptions": [], "version": 0, "committed_hash": "", "no_boundary_rationale": ""},
        "stride_cells": {}, "threats": [], "mappings": [], "risks": [], "controls": [],
        "boundary_reviews": {}, "crossing_reviews": {}, "questions": [],
        "review": {"model_owner": "", "security_reviewer": "", "next_review": "", "cadence": "", "full_triggers": [],
                   "change_triggers": [], "required_approval": "", "required_evidence": "", "approved_by": "", "approved_on": ""},
        "remodel": {"completed": False, "summary": "", "completed_on": ""},
        "hypotheses": {}, "reveals": [], "versions": [], "changelog": [], "gap_feedback_given": False,
    }
    for f in tm_labs.BRIEF_FACTS.get(lab_id, []):
        add_scope_item(ws, "facts", {"text": f, "source": "Lab brief"}, origin="seeded", _quiet=True)
    if prof["seed_scope_assets_objectives"]:
        sc = tm_labs.scenario(lab_id)
        for a in sc.get("assets", []):
            add_scope_item(ws, "assets", {"name": a, "sensitivity": "", "note": "from lab brief"}, origin="seeded", _quiet=True)
        for o in sc.get("objectives", []):
            ws["scope"]["objectives"].append(o)
        ws["scope"]["regulatory"] = list(sc.get("compliance", []))
        ws["scope"]["business_context"] = sc.get("business_context", "")
    return ws


def next_id(ws, kind):
    p = PREFIX[kind]
    n = ws["counters"].get(p, 0) + 1
    ws["counters"][p] = n
    return f"{p}-{n:03d}"


def _touch_ws(ws):
    ws["updated"] = now()


def log_change(ws, kind, ref, summary, affected=None):
    cid = next_id(ws, "change")
    ws["changelog"].append({"id": cid, "at": now(), "kind": kind, "ref": ref, "summary": summary,
                            "affected": sorted(set(affected or []))})
    _touch_ws(ws)
    return cid


def _once(ws, token):
    if token and token in ws["_tokens"]:
        return ws["_tokens"][token]
    return None


def _remember(ws, token, rid):
    if token:
        ws["_tokens"][token] = rid
        while len(ws["_tokens"]) > 300:
            ws["_tokens"].pop(next(iter(ws["_tokens"])))


def find(coll, rid):
    for r in coll:
        if r.get("id") == rid:
            return r
    return None


def canonical_hash(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


# ═════════════════════════════════════════════════════════════════════════════════════
# Step 1 - Scope
# ═════════════════════════════════════════════════════════════════════════════════════
SCOPE_TEXT_FIELDS = ("purpose", "business_context", "data_sensitivity")
SCOPE_STR_LISTS = ("in_scope", "objectives", "regulatory", "success_criteria")
SCOPE_ITEM_LISTS = {"exclusions": ("text", "reason"), "assets": ("name", "sensitivity", "note"),
                    "stakeholders": ("name", "role", "accountable"), "facts": ("text", "source"),
                    "assumptions": ("text", "status", "validation_owner", "validation_method"),
                    "dependencies": ("name", "note")}
_ITEM_KIND = {"exclusions": "exclusion", "assets": "asset", "stakeholders": "stakeholder", "facts": "fact",
              "assumptions": "assumption", "dependencies": "dependency"}


def set_scope_text(ws, field, value):
    if field not in SCOPE_TEXT_FIELDS:
        raise ValidationError(f"Unknown scope field '{field}'")
    ws["scope"][field] = clean(value)
    _touch_ws(ws)


def add_scope_string(ws, listname, text, token=None):
    if listname not in SCOPE_STR_LISTS:
        raise ValidationError(f"Unknown scope list '{listname}'")
    text = clean(text)
    if not text:
        raise ValidationError("Enter some text first.")
    if norm(text) in [norm(x) for x in ws["scope"][listname]]:
        raise DuplicateError(f"'{text}' is already in {listname.replace('_', ' ')}.")
    ws["scope"][listname].append(text)
    _touch_ws(ws)
    return text


def remove_scope_string(ws, listname, text):
    ws["scope"][listname] = [x for x in ws["scope"][listname] if x != text]
    _touch_ws(ws)


def add_scope_item(ws, listname, item, origin="learner", token=None, _quiet=False):
    if listname not in SCOPE_ITEM_LISTS:
        raise ValidationError(f"Unknown scope list '{listname}'")
    prior = _once(ws, token)
    if prior:
        return prior
    fields = SCOPE_ITEM_LISTS[listname]
    rec = {k: (item.get(k) if k == "accountable" else clean(item.get(k, ""))) for k in fields}
    main = fields[0]
    if not rec[main]:
        raise ValidationError(f"'{main}' is required.")
    if any(norm(x.get(main)) == norm(rec[main]) for x in ws["scope"][listname]):
        raise DuplicateError(f"'{rec[main]}' is already recorded.")
    if listname == "assumptions" and rec["status"] not in ASSUMPTION_STATUS:
        rec["status"] = "needs validation"
    if listname == "stakeholders":
        rec["accountable"] = bool(rec["accountable"])
    rec["id"] = next_id(ws, _ITEM_KIND[listname])
    rec["origin"] = origin
    ws["scope"][listname].append(rec)
    _remember(ws, token, rec["id"])
    _touch_ws(ws)
    return rec["id"]


def update_scope_item(ws, listname, rid, **fields):
    rec = find(ws["scope"][listname], rid)
    if not rec:
        raise ValidationError(f"{rid} not found")
    for k, v in fields.items():
        if k in SCOPE_ITEM_LISTS[listname]:
            rec[k] = bool(v) if k == "accountable" else clean(v)
    _touch_ws(ws)


def remove_scope_item(ws, listname, rid):
    ws["scope"][listname] = [x for x in ws["scope"][listname] if x["id"] != rid]
    ws["deleted_ids"].append(rid)
    _touch_ws(ws)


def _scope_payload(ws):
    sc = {k: v for k, v in ws["scope"].items() if k not in ("version", "committed_hash")}
    return sc


def scope_changed_since_commit(ws):
    return canonical_hash(_scope_payload(ws)) != ws["scope"]["committed_hash"]


def commit_scope(ws, note, author=""):
    """Create a new immutable scope version when content has changed. Returns the version number."""
    note = clean(note)
    if not scope_changed_since_commit(ws):
        return ws["scope"]["version"]
    if not note:
        raise ValidationError("Describe what changed in this scope version.")
    ws["scope"]["version"] += 1
    ws["scope"]["committed_hash"] = canonical_hash(_scope_payload(ws))
    ws["versions"].append({"kind": "scope", "version": ws["scope"]["version"], "at": now(), "author": clean(author),
                           "note": note, "hash": ws["scope"]["committed_hash"], "snapshot": copy.deepcopy(_scope_payload(ws))})
    log_change(ws, "scope_version", f"scope v{ws['scope']['version']}", note)
    return ws["scope"]["version"]


# ═════════════════════════════════════════════════════════════════════════════════════
# Step 2 - DFD (elements, flows, boundaries) with stale tracking
# ═════════════════════════════════════════════════════════════════════════════════════
def elements(ws):
    return ws["dfd"]["elements"]


def flows(ws):
    return ws["dfd"]["flows"]


def boundaries(ws):
    return ws["dfd"]["boundaries"]


def get_target(ws, rid):
    return find(elements(ws), rid) or find(flows(ws), rid)


def target_kind(ws, rid):
    e = find(elements(ws), rid)
    if e:
        return e["type"]
    return "flow" if find(flows(ws), rid) else None


def target_name(ws, rid):
    e = find(elements(ws), rid)
    if e:
        return e["name"]
    f = find(flows(ws), rid)
    if f:
        a, b = find(elements(ws), f["source"]), find(elements(ws), f["destination"])
        return f"{a['name'] if a else f['source']} \u2192 {b['name'] if b else f['destination']} ({f['data']})"
    return rid


def element_by_name(ws, name):
    for e in elements(ws):
        if norm(e["name"]) == norm(name):
            return e
    return None


def add_element(ws, etype, name, description="", security_domain="", justification="", origin="learner", token=None, assumed=False):
    prior = _once(ws, token)
    if prior:
        return prior
    name = clean(name)
    if etype not in ELEMENT_TYPES:
        raise ValidationError(f"Element type must be one of {ELEMENT_TYPES}")
    if not name:
        raise ValidationError("An element needs a name.")
    if element_by_name(ws, name):
        raise DuplicateError(f"An element named '{name}' already exists ({element_by_name(ws, name)['id']}).")
    rec = {"id": next_id(ws, etype), "type": etype, "name": name, "description": clean(description),
           "security_domain": clean(security_domain), "justification": clean(justification),
           "assumed": bool(assumed), "origin": origin, "rev": 1}
    elements(ws).append(rec)
    _remember(ws, token, rec["id"])
    log_change(ws, "dfd_add", rec["id"], f"Added {KIND_LABEL[etype]} '{name}'")
    return rec["id"]


_ELEMENT_TRACKED = ("name", "type", "description", "security_domain", "assumed")


def update_element(ws, rid, **fields):
    e = find(elements(ws), rid)
    if not e:
        raise ValidationError(f"{rid} not found")
    new = dict(fields)
    if "name" in new:
        new["name"] = clean(new["name"])
        other = element_by_name(ws, new["name"])
        if not new["name"] or (other and other["id"] != rid):
            raise DuplicateError(f"Another element is already named '{new['name']}'.")
    if "type" in new and new["type"] not in ELEMENT_TYPES:
        raise ValidationError("Invalid element type")
    changed = []
    for k, v in new.items():
        if k in ("justification",):
            e[k] = clean(v)
        elif k in _ELEMENT_TRACKED:
            v = bool(v) if k == "assumed" else clean(v)
            if e.get(k) != v:
                changed.append(f"{k}: '{e.get(k)}' \u2192 '{v}'")
                e[k] = v
    if changed:
        _bump(ws, rid, "; ".join(changed))
    return changed


def delete_element(ws, rid):
    e = find(elements(ws), rid)
    if not e:
        raise ValidationError(f"{rid} not found")
    gone_flows = [f["id"] for f in flows(ws) if rid in (f["source"], f["destination"])]
    affected = _dependents_of(ws, [rid] + gone_flows)
    ws["dfd"]["elements"] = [x for x in elements(ws) if x["id"] != rid]
    ws["dfd"]["flows"] = [f for f in flows(ws) if f["id"] not in gone_flows]
    for b in boundaries(ws):
        b["members"] = [m for m in b["members"] if m != rid]
    ws["deleted_ids"] += [rid] + gone_flows
    for fid in gone_flows:
        ws["crossing_reviews"] = {k: v for k, v in ws["crossing_reviews"].items() if not k.endswith("|" + fid)}
    _mark_stale(ws, affected, f"DFD element {rid} ('{e['name']}') was deleted" + (f" together with flows {gone_flows}" if gone_flows else ""), orphan=[rid] + gone_flows)
    log_change(ws, "dfd_delete", rid, f"Deleted '{e['name']}'" + (f" and flows {gone_flows}" if gone_flows else ""), _flat(affected))
    return gone_flows


def find_flow(ws, source, destination, data):
    for f in flows(ws):
        if f["source"] == source and f["destination"] == destination and norm(f["data"]) == norm(data):
            return f
    return None


def add_flow(ws, source, destination, data, protocol="", direction="one-way", classification="", authenticated="", notes="",
             origin="learner", token=None):
    prior = _once(ws, token)
    if prior:
        return prior
    errs = []
    if not find(elements(ws), source):
        errs.append("Source element does not exist.")
    if not find(elements(ws), destination):
        errs.append("Destination element does not exist.")
    if source == destination:
        errs.append("A flow cannot start and end at the same element (model it as a process boundary instead).")
    if not clean(data):
        errs.append("Describe the data carried by the flow.")
    if direction not in DIRECTIONS:
        errs.append(f"Direction must be one of {DIRECTIONS}.")
    if errs:
        raise ValidationError(errs)
    dup = find_flow(ws, source, destination, data)
    if dup:
        raise DuplicateError(f"This flow already exists as {dup['id']}.")
    rec = {"id": next_id(ws, "flow"), "source": source, "destination": destination, "data": clean(data),
           "protocol": clean(protocol), "direction": direction, "classification": classification if classification in CLASSIFICATIONS else "",
           "authenticated": clean(authenticated), "notes": clean(notes), "origin": origin, "rev": 1}
    flows(ws).append(rec)
    _remember(ws, token, rec["id"])
    log_change(ws, "dfd_add", rec["id"], f"Added flow {target_name(ws, rec['id'])}")
    return rec["id"]


_FLOW_TRACKED = ("source", "destination", "data", "protocol", "direction", "classification", "authenticated", "notes")


def update_flow(ws, rid, **fields):
    f = find(flows(ws), rid)
    if not f:
        raise ValidationError(f"{rid} not found")
    cand = {**f, **{k: (clean(v) if isinstance(v, str) else v) for k, v in fields.items() if k in _FLOW_TRACKED}}
    if not find(elements(ws), cand["source"]) or not find(elements(ws), cand["destination"]) or cand["source"] == cand["destination"]:
        raise ValidationError("Flow endpoints must be two different existing elements.")
    dup = find_flow(ws, cand["source"], cand["destination"], cand["data"])
    if dup and dup["id"] != rid:
        raise DuplicateError(f"This would duplicate flow {dup['id']}.")
    changed = []
    for k in _FLOW_TRACKED:
        if k in fields and f.get(k) != cand[k]:
            changed.append(f"{k}: '{f.get(k)}' \u2192 '{cand[k]}'")
            f[k] = cand[k]
    if changed:
        _bump(ws, rid, "; ".join(changed))
    return changed


def delete_flow(ws, rid):
    f = find(flows(ws), rid)
    if not f:
        raise ValidationError(f"{rid} not found")
    affected = _dependents_of(ws, [rid])
    name = target_name(ws, rid)
    ws["dfd"]["flows"] = [x for x in flows(ws) if x["id"] != rid]
    ws["deleted_ids"].append(rid)
    ws["crossing_reviews"] = {k: v for k, v in ws["crossing_reviews"].items() if not k.endswith("|" + rid)}
    _mark_stale(ws, affected, f"Flow {rid} ({name}) was deleted", orphan=[rid])
    log_change(ws, "dfd_delete", rid, f"Deleted flow {name}", _flat(affected))


def add_boundary(ws, name, description="", members=None, kind="", origin="learner", token=None):
    prior = _once(ws, token)
    if prior:
        return prior
    name = clean(name)
    if not name:
        raise ValidationError("A trust boundary needs a name.")
    if any(norm(b["name"]) == norm(name) for b in boundaries(ws)):
        raise DuplicateError(f"A boundary named '{name}' already exists.")
    members = list(dict.fromkeys(members or []))
    bad = [m for m in members if not find(elements(ws), m)]
    if bad:
        raise ValidationError(f"Unknown members: {bad}")
    rec = {"id": next_id(ws, "boundary"), "name": name, "description": clean(description), "members": members,
           "kind": clean(kind), "origin": origin, "rev": 1}
    boundaries(ws).append(rec)
    _remember(ws, token, rec["id"])
    log_change(ws, "dfd_add", rec["id"], f"Added trust boundary '{name}'")
    _flag_crossing_changes(ws, before=None, why=f"boundary {rec['id']} added")
    return rec["id"]


def update_boundary(ws, rid, **fields):
    b = find(boundaries(ws), rid)
    if not b:
        raise ValidationError(f"{rid} not found")
    before = crossing_signature(ws)
    changed = []
    if "name" in fields and clean(fields["name"]) != b["name"]:
        other = [x for x in boundaries(ws) if norm(x["name"]) == norm(fields["name"]) and x["id"] != rid]
        if other:
            raise DuplicateError("Another boundary has that name.")
        changed.append(f"name: '{b['name']}' \u2192 '{clean(fields['name'])}'")
        b["name"] = clean(fields["name"])
    if "description" in fields and clean(fields["description"]) != b["description"]:
        changed.append("description changed")
        b["description"] = clean(fields["description"])
    if "members" in fields:
        members = list(dict.fromkeys(fields["members"]))
        bad = [m for m in members if not find(elements(ws), m)]
        if bad:
            raise ValidationError(f"Unknown members: {bad}")
        if members != b["members"]:
            changed.append(f"members: {b['members']} \u2192 {members}")
            b["members"] = members
    if changed:
        b["rev"] += 1
        br = ws["boundary_reviews"].get(rid)
        if br:
            _stale_flag(br, "Boundary definition changed: " + "; ".join(changed))
        log_change(ws, "dfd_modify", rid, "; ".join(changed))
        _flag_crossing_changes(ws, before=before, why=f"boundary {rid} changed")
    return changed


def delete_boundary(ws, rid):
    b = find(boundaries(ws), rid)
    if not b:
        raise ValidationError(f"{rid} not found")
    before = crossing_signature(ws)
    ws["dfd"]["boundaries"] = [x for x in boundaries(ws) if x["id"] != rid]
    ws["deleted_ids"].append(rid)
    ws["boundary_reviews"].pop(rid, None)
    ws["crossing_reviews"] = {k: v for k, v in ws["crossing_reviews"].items() if not k.startswith(rid + "|")}
    log_change(ws, "dfd_delete", rid, f"Deleted trust boundary '{b['name']}'")
    _flag_crossing_changes(ws, before=before, why=f"boundary {rid} deleted")


def crossings(ws):
    """Flows that cross each boundary. Computed - never entered twice. A flow crosses boundary B
    when exactly one endpoint is a member of B."""
    out = []
    for b in boundaries(ws):
        mem = set(b["members"])
        for f in flows(ws):
            s, d = f["source"] in mem, f["destination"] in mem
            if s != d:
                out.append({"boundary_id": b["id"], "flow_id": f["id"], "direction": "inbound" if d else "outbound"})
    return out


def crossing_signature(ws):
    sig = {}
    for c in crossings(ws):
        sig.setdefault(c["flow_id"], set()).add(c["boundary_id"])
    return {k: sorted(v) for k, v in sig.items()}


def _flag_crossing_changes(ws, before, why):
    after = crossing_signature(ws)
    before = before if before is not None else {k: [] for k in after}
    for fid in set(before) | set(after):
        if before.get(fid, []) != after.get(fid, []) and find(flows(ws), fid):
            _bump(ws, fid, f"trust-boundary crossing changed ({why}): {before.get(fid, [])} \u2192 {after.get(fid, [])}", log=False)


# ── stale propagation ─────────────────────────────────────────────────────────────────
def _flat(affected):
    return [x for v in affected.values() for x in v]


def _dependents_of(ws, target_ids):
    ts = set(target_ids)
    thr = [t["id"] for t in ws["threats"] if ts & set(t["targets"])]
    return {"threats": thr,
            "mappings": [m["id"] for m in ws["mappings"] if m["threat_id"] in thr],
            "risks": [r["id"] for r in ws["risks"] if r["threat_id"] in thr],
            "controls": [c["id"] for c in ws["controls"] if set(c["threat_ids"]) & set(thr) or ts & set(c.get("targets", []))],
            "boundary_reviews": [k for k, v in ws["boundary_reviews"].items() if k in ts],
            "crossings": [k for k in ws["crossing_reviews"] if k.split("|")[1] in ts or k.split("|")[0] in ts]}


def _stale_flag(rec, reason):
    prev = rec.get("stale") or []
    if isinstance(prev, str):
        prev = [prev]
    rec["stale"] = prev + [{"reason": reason, "at": now()}]


def _mark_stale(ws, affected, reason, orphan=None):
    for coll, key in (("threats", "threats"), ("mappings", "mappings"), ("risks", "risks"), ("controls", "controls")):
        for rid in affected.get(key, []):
            rec = find(ws[coll], rid)
            if rec:
                _stale_flag(rec, reason)
    for rid in affected.get("crossings", []):
        if rid in ws["crossing_reviews"]:
            _stale_flag(ws["crossing_reviews"][rid], reason)
    for rid in affected.get("boundary_reviews", []):
        if rid in ws["boundary_reviews"]:
            _stale_flag(ws["boundary_reviews"][rid], reason)
    if orphan:
        for t in ws["threats"]:
            gone = [x for x in t["targets"] if x in orphan]
            if gone:
                t["orphaned_targets"] = sorted(set(t.get("orphaned_targets", [])) | set(gone))
                t["targets"] = [x for x in t["targets"] if x not in gone]


def _bump(ws, rid, summary, log=True):
    rec = get_target(ws, rid)
    rec["rev"] = rec.get("rev", 1) + 1
    affected = _dependents_of(ws, [rid])
    affected["crossings"] = [k for k in ws["crossing_reviews"] if k.endswith("|" + rid)]
    _mark_stale(ws, affected, f"{rid} changed: {summary}")
    if log:
        log_change(ws, "dfd_modify", rid, summary, _flat(affected))
    return affected


def impact_analysis(ws, rid):
    """Dry run: what would need revalidation if this DFD element/flow changed or were removed."""
    ids = [rid]
    if find(elements(ws), rid):
        ids += [f["id"] for f in flows(ws) if rid in (f["source"], f["destination"])]
    aff = _dependents_of(ws, ids)
    aff["flows"] = [i for i in ids if i != rid]
    aff["boundaries"] = [b["id"] for b in boundaries(ws) if rid in b["members"]]
    return aff


def stale_items(ws):
    out = []
    for coll, label in (("threats", "threat"), ("mappings", "mapping"), ("risks", "risk"), ("controls", "control")):
        for r in ws[coll]:
            if r.get("stale"):
                out.append({"kind": label, "id": r["id"], "reasons": [s["reason"] for s in r["stale"]]})
    for k, v in ws["crossing_reviews"].items():
        if v.get("stale"):
            out.append({"kind": "crossing", "id": k, "reasons": [s["reason"] for s in v["stale"]]})
    for k, v in ws["boundary_reviews"].items():
        if v.get("stale"):
            out.append({"kind": "boundary_review", "id": k, "reasons": [s["reason"] for s in v["stale"]]})
    return out


def revalidate(ws, kind, rid, note):
    note = clean(note)
    if len(note) < 10:
        raise ValidationError("Explain what you re-checked (at least a short sentence).")
    coll = {"threat": ws["threats"], "mapping": ws["mappings"], "risk": ws["risks"], "control": ws["controls"]}.get(kind)
    if coll is not None:
        rec = find(coll, rid)
    elif kind == "crossing":
        rec = ws["crossing_reviews"].get(rid)
    elif kind == "boundary_review":
        rec = ws["boundary_reviews"].get(rid)
    else:
        rec = None
    if not rec or not rec.get("stale"):
        raise ValidationError(f"{rid} is not flagged for revalidation.")
    rec["stale"] = []
    rec.setdefault("revalidations", []).append({"at": now(), "note": note})
    log_change(ws, "revalidated", rid, note)


def complete_remodel_exercise(ws, summary):
    summary = clean(summary)
    changes = [c for c in ws["changelog"] if c["kind"] in ("dfd_modify", "dfd_add", "dfd_delete")]
    errs = []
    if len(summary) < 30:
        errs.append("Summarise the change you made, which threats/mappings/risks/controls it affected and what you decided.")
    if not ws["versions"] or not any(v["kind"] == "dfd" for v in ws["versions"]):
        errs.append("Commit a DFD version (Step 2) before practising a change to it.")
    else:
        committed_at = max(v["at"] for v in ws["versions"] if v["kind"] == "dfd")
        if not [c for c in changes if c["at"] >= committed_at]:
            errs.append("Make a real change to a DFD element, flow or boundary after committing the DFD version.")
    pending = stale_items(ws)
    if pending:
        errs.append(f"{len(pending)} record(s) still need revalidation: " + ", ".join(p["id"] for p in pending[:8]))
    if errs:
        raise ValidationError(errs)
    ws["remodel"] = {"completed": True, "summary": summary, "completed_on": today()}
    log_change(ws, "remodel_exercise", "review", summary)


# ── DFD commit / reference loading ────────────────────────────────────────────────────
def _dfd_payload(ws):
    d = ws["dfd"]
    return {"elements": d["elements"], "flows": d["flows"], "boundaries": d["boundaries"], "assumptions": d["assumptions"],
            "no_boundary_rationale": d["no_boundary_rationale"]}


def dfd_changed_since_commit(ws):
    return canonical_hash(_dfd_payload(ws)) != ws["dfd"]["committed_hash"]


def commit_dfd(ws, note, author=""):
    note = clean(note)
    if not dfd_changed_since_commit(ws):
        return ws["dfd"]["version"]
    if not note:
        raise ValidationError("Describe what changed in this DFD version.")
    ws["dfd"]["version"] += 1
    ws["dfd"]["committed_hash"] = canonical_hash(_dfd_payload(ws))
    ws["versions"].append({"kind": "dfd", "version": ws["dfd"]["version"], "at": now(), "author": clean(author), "note": note,
                           "hash": ws["dfd"]["committed_hash"], "snapshot": copy.deepcopy(_dfd_payload(ws))})
    log_change(ws, "dfd_version", f"dfd v{ws['dfd']['version']}", note)
    return ws["dfd"]["version"]


def set_dfd_notes(ws, assumptions=None, no_boundary_rationale=None):
    if assumptions is not None:
        ws["dfd"]["assumptions"] = [clean(a) for a in assumptions if clean(a)]
    if no_boundary_rationale is not None:
        ws["dfd"]["no_boundary_rationale"] = clean(no_boundary_rationale)
    _touch_ws(ws)


def load_reference_dfd(ws, ref):
    """Load a reference payload obtained through assess.get_reference(). Existing names are skipped
    (never duplicated). Loaded records are marked origin='seeded'."""
    added = {"elements": 0, "flows": 0, "boundaries": 0}
    for e in ref.get("elements", []):
        if not element_by_name(ws, e["name"]):
            add_element(ws, e["type"], e["name"], e.get("description", ""), e.get("security_domain", ""), origin="seeded")
            added["elements"] += 1
    for f in ref.get("flows", []):
        a, b = element_by_name(ws, f["source"]), element_by_name(ws, f["destination"])
        if a and b and not find_flow(ws, a["id"], b["id"], f["data"]):
            add_flow(ws, a["id"], b["id"], f["data"], f.get("protocol", ""), origin="seeded")
            added["flows"] += 1
    for bd in ref.get("boundaries", []):
        mem = [element_by_name(ws, m)["id"] for m in bd["members"] if element_by_name(ws, m)]
        if mem and not any(norm(x["name"]) == norm(bd["name"]) for x in boundaries(ws)):
            add_boundary(ws, bd["name"], bd["description"], mem, origin="seeded")
            added["boundaries"] += 1
    return added


def dfd_issues(ws):
    """Validation view for Step 2."""
    out = []
    els, fls = elements(ws), flows(ws)
    if not els:
        out.append(issue("error", "dfd.empty", "No DFD elements yet.", step=2))
    linked = set()
    for f in fls:
        linked |= {f["source"], f["destination"]}
        miss = [k for k in ("protocol", "classification") if not f.get(k)]
        if miss:
            out.append(issue("error", "flow.incomplete", f"{f['id']} {target_name(ws, f['id'])}: missing {', '.join(miss)}.", f["id"], 2))
        sk, dk = target_kind(ws, f["source"]), target_kind(ws, f["destination"])
        if sk and dk and {sk, dk} <= {"external_entity", "datastore"}:
            out.append(issue("warning", "flow.no_process", f"{f['id']} connects {KIND_LABEL[sk].lower()} to {KIND_LABEL[dk].lower()} without a process - a process is probably missing.", f["id"], 2))
    for e in els:
        if e["id"] not in linked:
            out.append(issue("error", "element.disconnected", f"{e['id']} '{e['name']}' has no data flows (disconnected).", e["id"], 2))
        if e["type"] == "external_entity" and not (e["description"] or e["justification"]):
            out.append(issue("warning", "external.unexplained", f"External entity {e['id']} '{e['name']}' has no description or reason for the dependency.", e["id"], 2))
        if e["type"] == "datastore":
            if not any(f["destination"] == e["id"] for f in fls):
                out.append(issue("warning", "store.never_written", f"Data store {e['id']} '{e['name']}' is never written to by any flow - missing flow?", e["id"], 2))
            if not any(f["source"] == e["id"] for f in fls):
                out.append(issue("warning", "store.never_read", f"Data store {e['id']} '{e['name']}' is never read by any flow - missing flow?", e["id"], 2))
    if els and not any(e["type"] == "external_entity" for e in els):
        out.append(issue("warning", "dfd.no_external", "No external entity: who or what starts or consumes the data?", step=2))
    if els and not any(e["type"] == "process" for e in els):
        out.append(issue("error", "dfd.no_process", "No process: data cannot be stored or moved without one.", step=2))
    if els and not boundaries(ws) and not ws["dfd"]["no_boundary_rationale"]:
        out.append(issue("error", "dfd.no_boundary", "No trust boundary defined and no explanation why the system is a single trust domain.", step=2))
    for b in boundaries(ws):
        if not b["members"]:
            out.append(issue("error", "boundary.empty", f"Boundary {b['id']} '{b['name']}' contains no elements.", b["id"], 2))
    return out


# ═════════════════════════════════════════════════════════════════════════════════════
# Step 3 - STRIDE cells + threats
# ═════════════════════════════════════════════════════════════════════════════════════
def applicable_letters(kind):
    return APPLICABILITY.get(kind, "")


def applicable_cells(ws):
    cells = []
    for e in elements(ws):
        for L in applicable_letters(e["type"]):
            cells.append((e["id"], L))
    for f in flows(ws):
        for L in applicable_letters("flow"):
            cells.append((f["id"], L))
    return cells


def cell_key(tid, letter):
    return f"{tid}:{letter}"


def set_stride_cell(ws, target, letter, disposition, rationale=""):
    if not get_target(ws, target):
        raise ValidationError(f"Unknown target {target}")
    if letter not in STRIDE:
        raise ValidationError("Unknown STRIDE letter")
    if disposition not in CELL_DISPOSITIONS or disposition == "threat":
        raise ValidationError("Choose 'not applicable', 'mitigated by design' or 'deferred'. Threats are recorded through the threat builder.")
    rationale = clean(rationale)
    if disposition in ("not_applicable", "mitigated_by_design") and len(rationale) < 15:
        raise ValidationError("Explain why in at least a short sentence - 'N/A' on its own is not a reason.")
    ws["stride_cells"][cell_key(target, letter)] = {"disposition": disposition, "rationale": rationale, "at": now(),
                                                    "standard": letter in applicable_letters(target_kind(ws, target))}
    _touch_ws(ws)


def clear_stride_cell(ws, target, letter):
    ws["stride_cells"].pop(cell_key(target, letter), None)


def cell_status(ws, target, letter):
    thr = [t["id"] for t in ws["threats"] if target in t["targets"] and t["stride"] == letter]
    if thr:
        return {"status": "threat", "threat_ids": thr, "rationale": ""}
    c = ws["stride_cells"].get(cell_key(target, letter))
    if c and c["disposition"] in ("not_applicable", "mitigated_by_design"):
        return {"status": c["disposition"], "threat_ids": [], "rationale": c["rationale"]}
    if c and c["disposition"] == "deferred":
        return {"status": "deferred", "threat_ids": [], "rationale": c["rationale"]}
    return {"status": "unconsidered", "threat_ids": [], "rationale": ""}


def stride_coverage(ws):
    """Informational: how many applicability prompts have been dispositioned. This is a completeness
    check on the *reasoning*, not a count of threats - any number of threats (including zero for a
    cell) is acceptable when documented."""
    cells = applicable_cells(ws)
    st = {"threat": 0, "not_applicable": 0, "mitigated_by_design": 0, "deferred": 0, "unconsidered": 0}
    open_cells = []
    for tid, L in cells:
        s = cell_status(ws, tid, L)["status"]
        st[s] += 1
        if s in ("deferred", "unconsidered"):
            open_cells.append((tid, L))
    return {"total": len(cells), "by_status": st, "open": open_cells}


THREAT_TEXT = ("title", "source", "preconditions", "action", "impact", "security_property", "evidence", "rationale",
               "uncertainties", "departure_rationale", "statement_override", "confidence")
_MATERIAL = ("source", "preconditions", "action", "impact", "stride", "targets", "assets")


def _names_for(ws, ids):
    return "; ".join(target_name(ws, i) for i in ids) or "[DFD element or flow]"


def build_statement(ws, t):
    """AWS-style structured threat statement generated from the structured fields."""
    pre = clean(t.get("preconditions")) or "[preconditions]"
    src = clean(t.get("source")) or "[threat source]"
    act = clean(t.get("action")) or "[action]"
    imp = clean(t.get("impact")) or "[impact]"
    assets = ", ".join(t.get("assets", [])) or "[asset]"
    return f"Given {pre}, {src} could {act} against {_names_for(ws, t.get('targets', []))}, resulting in {imp} to {assets}."


def statement_text(ws, t):
    return clean(t.get("statement_override")) or build_statement(ws, t)


def threat_issues(ws, t):
    errs = []
    req = {"source": "threat source/actor", "preconditions": "preconditions", "action": "attack action or failure scenario",
           "impact": "business or technical impact", "rationale": "rationale"}
    for k, label in req.items():
        if len(clean(t.get(k))) < (10 if k != "source" else 3):
            errs.append(f"Describe the {label}.")
    if t.get("stride") not in STRIDE:
        errs.append("Choose a STRIDE category.")
    if not t.get("targets"):
        errs.append("Link the threat to at least one DFD element or flow ID.")
    for x in t.get("targets", []):
        if not get_target(ws, x):
            errs.append(f"Unknown DFD ID {x}.")
    if t.get("orphaned_targets"):
        errs.append(f"Referenced elements were deleted: {t['orphaned_targets']}.")
    if t.get("security_property") not in SECURITY_PROPERTIES:
        errs.append("Choose the security property affected.")
    if t.get("confidence") not in CONFIDENCE:
        errs.append("State your confidence (Low / Medium / High).")
    if not (clean(t.get("evidence")) or clean(t.get("uncertainties"))):
        errs.append("Give the evidence for this threat, or state what is uncertain.")
    if t.get("assets"):
        known = {norm(a["name"]) for a in ws["scope"]["assets"]}
        if known and any(norm(a) not in known for a in t["assets"]):
            errs.append("Asset(s) not defined in the Step 1 scope: " + ", ".join(a for a in t["assets"] if norm(a) not in known))
    else:
        errs.append("Name the asset affected.")
    ks = [target_kind(ws, x) for x in t.get("targets", []) if get_target(ws, x)]
    if t.get("stride") in STRIDE and ks and not any(t["stride"] in applicable_letters(k) for k in ks) and len(clean(t.get("departure_rationale"))) < 25:
        errs.append(f"{STRIDE[t['stride']]} is not a standard applicability prompt for {', '.join(sorted({KIND_LABEL[k] for k in ks}))}. "
                    "Explain why this scenario departs from the standard model (departure rationale).")
    return errs


def departs_from_standard(ws, t):
    ks = [target_kind(ws, x) for x in t.get("targets", []) if get_target(ws, x)]
    return bool(ks) and t.get("stride") in STRIDE and not any(t["stride"] in applicable_letters(k) for k in ks)


def add_threat(ws, token=None, origin="learner", validate=True, **f):
    prior = _once(ws, token)
    if prior:
        return prior
    t = {"id": None, "title": clean(f.get("title")), "stride": f.get("stride", ""), "source": clean(f.get("source")),
         "preconditions": clean(f.get("preconditions")), "assumption_ids": list(f.get("assumption_ids", [])),
         "action": clean(f.get("action")), "targets": list(dict.fromkeys(f.get("targets", []))),
         "security_property": f.get("security_property", ""), "impact": clean(f.get("impact")),
         "assets": [clean(a) for a in f.get("assets", []) if clean(a)], "evidence": clean(f.get("evidence")),
         "rationale": clean(f.get("rationale")), "confidence": f.get("confidence", ""),
         "uncertainties": clean(f.get("uncertainties")), "departure_rationale": clean(f.get("departure_rationale")),
         "statement_override": clean(f.get("statement_override")), "origin": origin, "created": now(), "updated": now(),
         "stale": [], "orphaned_targets": []}
    if validate:
        errs = threat_issues(ws, t)
        if errs:
            raise ValidationError(errs)
    dup = [x for x in ws["threats"] if x["stride"] == t["stride"] and sorted(x["targets"]) == sorted(t["targets"]) and norm(x["action"]) == norm(t["action"])]
    if dup:
        raise DuplicateError(f"This threat already exists as {dup[0]['id']}.")
    t["id"] = next_id(ws, "threat")
    if not t["title"]:
        t["title"] = f"{STRIDE.get(t['stride'], '?')} - {_names_for(ws, t['targets'])}"[:120]
    ws["threats"].append(t)
    _remember(ws, token, t["id"])
    log_change(ws, "threat_add", t["id"], t["title"])
    return t["id"]


def update_threat(ws, rid, **f):
    t = find(ws["threats"], rid)
    if not t:
        raise ValidationError(f"{rid} not found")
    cand = copy.deepcopy(t)
    for k, v in f.items():
        if k in THREAT_TEXT or k in ("stride",):
            cand[k] = clean(v) if isinstance(v, str) else v
        elif k in ("targets", "assets", "assumption_ids"):
            cand[k] = [clean(x) for x in dict.fromkeys(v)]
    cand["orphaned_targets"] = [x for x in cand.get("orphaned_targets", []) if x not in cand["targets"]]
    errs = threat_issues(ws, cand)
    if errs:
        raise ValidationError(errs)
    material = [k for k in _MATERIAL if cand.get(k) != t.get(k)]
    t.update(cand)
    t["updated"] = now()
    if material:
        aff = {"mappings": [m["id"] for m in ws["mappings"] if m["threat_id"] == rid],
               "risks": [r["id"] for r in ws["risks"] if r["threat_id"] == rid],
               "controls": [c["id"] for c in ws["controls"] if rid in c["threat_ids"]]}
        _mark_stale(ws, aff, f"{rid} changed ({', '.join(material)}); downstream analysis must be re-checked")
        log_change(ws, "threat_modify", rid, "changed " + ", ".join(material), _flat(aff))
    return material


def reset_statement(ws, rid):
    t = find(ws["threats"], rid)
    t["statement_override"] = ""


def delete_threat(ws, rid):
    if not find(ws["threats"], rid):
        raise ValidationError(f"{rid} not found")
    ws["threats"] = [t for t in ws["threats"] if t["id"] != rid]
    ws["mappings"] = [m for m in ws["mappings"] if m["threat_id"] != rid]
    ws["risks"] = [r for r in ws["risks"] if r["threat_id"] != rid]
    for c in ws["controls"]:
        if rid in c["threat_ids"]:
            c["threat_ids"] = [x for x in c["threat_ids"] if x != rid]
            _stale_flag(c, f"Linked threat {rid} was deleted")
    for q in ws["questions"]:
        q["related"] = [x for x in q["related"] if x != rid]
    ws["deleted_ids"].append(rid)
    log_change(ws, "threat_delete", rid, "Threat deleted with its mappings and risk record")


# ═════════════════════════════════════════════════════════════════════════════════════
# Step 4 - boundary validation (reviews are on top of Step 2 boundaries; nothing is re-mapped)
# ═════════════════════════════════════════════════════════════════════════════════════
BOUNDARY_FIELDS = ("why_exists", "trust_change", "controls_required", "evidence_needed")


def set_boundary_review(ws, bid, why_exists, trust_change, properties, controls_required, evidence_needed):
    if not find(boundaries(ws), bid):
        raise ValidationError(f"Unknown boundary {bid}")
    rec = {"why_exists": clean(why_exists), "trust_change": clean(trust_change),
           "properties": [p for p in properties if p in BOUNDARY_PROPERTIES],
           "controls_required": clean(controls_required), "evidence_needed": clean(evidence_needed),
           "stale": [], "at": now(), "boundary_rev": find(boundaries(ws), bid)["rev"]}
    errs = boundary_review_issues(rec)
    if errs:
        raise ValidationError(errs)
    old = ws["boundary_reviews"].get(bid, {})
    rec["revalidations"] = old.get("revalidations", [])
    ws["boundary_reviews"][bid] = rec
    _touch_ws(ws)


def boundary_review_issues(rec):
    errs = []
    for k, label in (("why_exists", "Why the boundary exists"), ("trust_change", "What trust assumption changes"),
                     ("controls_required", "Controls required at the crossing"), ("evidence_needed", "Evidence that would validate the assumptions")):
        if len(clean(rec.get(k))) < 15:
            errs.append(f"{label}: write at least a short sentence.")
    if not rec.get("properties"):
        errs.append("Select the properties that matter at this boundary (identity, authorisation, validation, integrity, confidentiality, availability).")
    return errs


def set_crossing_review(ws, bid, fid, assumption, control, evidence):
    if not any(c["boundary_id"] == bid and c["flow_id"] == fid for c in crossings(ws)):
        raise ValidationError(f"Flow {fid} does not cross boundary {bid}.")
    rec = {"assumption": clean(assumption), "control": clean(control), "evidence": clean(evidence), "stale": [], "at": now()}
    errs = [f"{lbl}: write at least a short sentence." for k, lbl in (("assumption", "Trust assumption at the crossing"), ("control", "Control at the crossing"), ("evidence", "Evidence"))
            if len(rec[k]) < 10]
    if errs:
        raise ValidationError(errs)
    old = ws["crossing_reviews"].get(f"{bid}|{fid}", {})
    rec["revalidations"] = old.get("revalidations", [])
    ws["crossing_reviews"][f"{bid}|{fid}"] = rec
    _touch_ws(ws)


def boundary_inventory(ws):
    inv = []
    cs = crossings(ws)
    for b in boundaries(ws):
        cr = [c for c in cs if c["boundary_id"] == b["id"]]
        br = ws["boundary_reviews"].get(b["id"])
        inv.append({"boundary": b, "crossings": [{**c, "flow": get_target(ws, c["flow_id"]),
                                                   "review": ws["crossing_reviews"].get(f"{b['id']}|{c['flow_id']}")} for c in cr],
                    "review": br, "validated": bool(br) and not br.get("stale") and all(
                        ws["crossing_reviews"].get(f"{b['id']}|{c['flow_id']}") and not ws["crossing_reviews"][f"{b['id']}|{c['flow_id']}"].get("stale") for c in cr)})
    return inv


# ═════════════════════════════════════════════════════════════════════════════════════
# Step 5 - mappings
# ═════════════════════════════════════════════════════════════════════════════════════
def _mapping_base(ws, threat_id, framework):
    if framework not in tm_catalog.FRAMEWORKS:
        raise ValidationError("Framework must be ATT&CK or CAPEC.")
    if not find(ws["threats"], threat_id):
        raise ValidationError(f"Unknown threat {threat_id}")


def add_mapping(ws, threat_id, framework, ref_id, behaviour, relationship, rationale, confidence, evidence="",
                learner_supplied_name="", token=None):
    prior = _once(ws, token)
    if prior:
        return prior
    _mapping_base(ws, threat_id, framework)
    ref_id = tm_catalog.normalise_id(framework, ref_id)
    errs = []
    if not tm_catalog.valid_id_syntax(framework, ref_id):
        errs.append(f"'{ref_id}' is not a valid {framework} identifier.")
    if relationship not in RELATIONSHIPS:
        errs.append("Choose how this mapping relates to the threat statement.")
    if confidence not in CONFIDENCE:
        errs.append("State your confidence.")
    behaviour, rationale, evidence = clean(behaviour), clean(rationale), clean(evidence)
    if len(behaviour) < 15:
        errs.append("Describe the specific adversary behaviour / attack pattern in this scenario.")
    if len(rationale) < 40:
        errs.append("Explain why this mapping fits THIS scenario's attack path (at least a couple of sentences).")
    entry = tm_catalog.lookup(framework, ref_id) if not errs else None
    if not errs and not entry:
        if len(clean(learner_supplied_name)) < 4:
            errs.append(f"{ref_id} is not in the local {framework} dataset. Look it up at the official source and enter its exact official name; "
                        "it will be recorded as 'unlisted - pending verification'.")
    if not errs and entry:
        hint = norm(entry.get("hint", entry.get("note", "")))
        if hint and norm(rationale) == hint:
            errs.append("The rationale repeats the catalogue description. Explain how it applies to this system.")
    if not errs and any(m["threat_id"] == threat_id and m["framework"] == framework and m["outcome"] == "mapped" and m["ref_id"] == ref_id for m in ws["mappings"]):
        errs.append(f"{ref_id} is already mapped to {threat_id}.")
    if not errs and any(m["threat_id"] == threat_id and m["framework"] == framework and m["outcome"] == "no_defensible_mapping" for m in ws["mappings"]):
        errs.append(f"{threat_id} is recorded as 'no defensible {framework} mapping'. Remove that decision first if you now want to map it.")
    if errs:
        raise ValidationError(errs)
    meta = tm_catalog.catalogue_meta()[framework]
    rec = {"id": next_id(ws, "mapping"), "threat_id": threat_id, "framework": framework, "outcome": "mapped", "ref_id": ref_id,
           "name": entry["name"] if entry else clean(learner_supplied_name),
           "url": tm_catalog.reference_url(framework, ref_id),
           "catalogue_status": meta["status"] if entry else "unlisted-pending-verification",
           "source_version": meta["declared_version"], "retrieved": meta.get("retrieved") or "", "verified_on": meta.get("verified_on") or "",
           "behaviour": behaviour, "relationship": relationship, "rationale": rationale, "confidence": confidence, "evidence": evidence,
           "origin": "learner", "stale": [], "created": now()}
    ws["mappings"].append(rec)
    _remember(ws, token, rec["id"])
    log_change(ws, "mapping_add", rec["id"], f"{framework} {ref_id} -> {threat_id}")
    return rec["id"]


def add_no_mapping(ws, threat_id, framework, rationale):
    _mapping_base(ws, threat_id, framework)
    rationale = clean(rationale)
    if len(rationale) < 30:
        raise ValidationError("'No defensible mapping' is a valid outcome, but it needs a reason (what in the scenario prevents a confident mapping?).")
    if any(m["threat_id"] == threat_id and m["framework"] == framework for m in ws["mappings"]):
        raise DuplicateError(f"{threat_id} already has a {framework} decision. Remove it first to change it.")
    meta = tm_catalog.catalogue_meta()[framework]
    rec = {"id": next_id(ws, "mapping"), "threat_id": threat_id, "framework": framework, "outcome": "no_defensible_mapping",
           "ref_id": "", "name": "", "url": "", "catalogue_status": meta["status"], "source_version": meta["declared_version"],
           "retrieved": meta.get("retrieved") or "", "verified_on": meta.get("verified_on") or "", "behaviour": "", "relationship": "",
           "rationale": rationale, "confidence": "", "evidence": "", "origin": "learner", "stale": [], "created": now()}
    ws["mappings"].append(rec)
    log_change(ws, "mapping_add", rec["id"], f"No defensible {framework} mapping for {threat_id}")
    return rec["id"]


def delete_mapping(ws, rid):
    ws["mappings"] = [m for m in ws["mappings"] if m["id"] != rid]
    ws["deleted_ids"].append(rid)
    _touch_ws(ws)


def mapping_decisions(ws, threat_id):
    """Per framework: 'mapped' | 'no_defensible_mapping' | 'undecided'."""
    out = {}
    for fw in tm_catalog.FRAMEWORKS:
        ms = [m for m in ws["mappings"] if m["threat_id"] == threat_id and m["framework"] == fw]
        out[fw] = "mapped" if any(m["outcome"] == "mapped" for m in ms) else "no_defensible_mapping" if ms else "undecided"
    return out


# ═════════════════════════════════════════════════════════════════════════════════════
# Step 6 - inherent risk (separate from residual)
# ═════════════════════════════════════════════════════════════════════════════════════
def risk_score(l, i):
    if not (isinstance(l, int) and isinstance(i, int) and 1 <= l <= 5 and 1 <= i <= 5):
        raise ValidationError("Likelihood and impact must each be an integer from 1 to 5.")
    return l * i


def risk_band(score, model=None):
    model = model or RISK_MODEL
    for lo, hi, name in model["bands"]:
        if lo <= score <= hi:
            return name
    raise ValidationError(f"Score {score} is outside the risk model.")


def risk_matrix(model=None):
    model = model or RISK_MODEL
    return [[(l * i, risk_band(l * i, model)) for i in range(1, 6)] for l in range(5, 0, -1)]


def get_risk(ws, threat_id):
    return next((r for r in ws["risks"] if r["threat_id"] == threat_id), None)


def _rating(l, i, lr, ir, ctx="", evidence="", uncertainty=""):
    errs = []
    try:
        s = risk_score(l, i)
    except ValidationError as e:
        errs += e.errors
        s = None
    if len(clean(lr)) < 15:
        errs.append("Give a rationale for the likelihood rating.")
    if len(clean(ir)) < 15:
        errs.append("Give a rationale for the impact rating.")
    if errs:
        raise ValidationError(errs)
    band = risk_band(s)
    pr = RISK_MODEL["priority"][band]
    return {"likelihood": l, "impact": i, "likelihood_rationale": clean(lr), "impact_rationale": clean(ir), "score": s, "band": band,
            "priority": pr[0], "urgency": pr[1], "business_context": clean(ctx), "evidence": clean(evidence),
            "uncertainty": clean(uncertainty), "rated_on": today(), "model_version": RISK_MODEL["version"]}


def set_inherent_risk(ws, threat_id, likelihood, likelihood_rationale, impact, impact_rationale,
                      business_context="", evidence="", uncertainty=""):
    if not find(ws["threats"], threat_id):
        raise ValidationError(f"Unknown threat {threat_id}")
    inh = _rating(likelihood, impact, likelihood_rationale, impact_rationale, business_context, evidence, uncertainty)
    if not (inh["business_context"]):
        raise ValidationError("State the business context that makes this rating reasonable.")
    if not (inh["evidence"] or inh["uncertainty"]):
        raise ValidationError("Give the evidence for this rating, or state what is uncertain.")
    r = get_risk(ws, threat_id)
    if not r:
        r = {"id": next_id(ws, "risk"), "threat_id": threat_id, "inherent": None, "residual": None, "treatment": None, "stale": []}
        ws["risks"].append(r)
    changed = r["inherent"] is not None and (r["inherent"]["score"] != inh["score"])
    r["inherent"] = inh
    if changed and r["residual"]:
        _stale_flag(r, "Inherent rating changed; residual assessment and treatment must be re-checked")
    log_change(ws, "risk_inherent", r["id"], f"{threat_id}: {inh['band']} ({inh['score']})")
    return r["id"]


def prioritised_register(ws):
    rows = [r for r in ws["risks"] if r["inherent"]]
    return sorted(rows, key=lambda r: (-r["inherent"]["score"], -r["inherent"]["impact"], r["threat_id"]))


# ═════════════════════════════════════════════════════════════════════════════════════
# Step 7 - controls (selection never changes risk)
# ═════════════════════════════════════════════════════════════════════════════════════
def add_control(ws, threat_ids, title, objective, implementation, function, owner="", status="proposed", rationale="",
                targets=None, references=None, limitations="", dependencies="", token=None):
    prior = _once(ws, token)
    if prior:
        return prior
    errs = []
    threat_ids = list(dict.fromkeys(threat_ids))
    if not threat_ids:
        errs.append("Link the control to at least one threat ID.")
    for t in threat_ids:
        if not find(ws["threats"], t):
            errs.append(f"Unknown threat {t}.")
    if len(clean(title)) < 5:
        errs.append("Give the control a short title.")
    if len(clean(objective)) < 15:
        errs.append("State the control objective (what trust assumption or property does it enforce?).")
    if len(clean(implementation)) < 15:
        errs.append("Describe the proposed implementation concretely.")
    if function not in CONTROL_FUNCTIONS:
        errs.append("Choose preventive, detective, responsive or recovery.")
    if status not in ("proposed", "planned"):
        errs.append("New controls start as 'proposed' or 'planned'. Implementation and verification are recorded later, with evidence.")
    if errs:
        raise ValidationError(errs)
    tg = list(dict.fromkeys(targets or [x for t in threat_ids for x in find(ws["threats"], t)["targets"]]))
    c = {"id": next_id(ws, "control"), "threat_ids": threat_ids, "targets": tg, "title": clean(title), "objective": clean(objective),
         "rationale": clean(rationale), "implementation": clean(implementation), "function": function, "owner": clean(owner),
         "status": status, "verification": None, "references": [clean(r) for r in (references or []) if clean(r)],
         "limitations": clean(limitations), "dependencies": clean(dependencies), "stale": [], "created": now(), "origin": "learner"}
    ws["controls"].append(c)
    _remember(ws, token, c["id"])
    log_change(ws, "control_add", c["id"], c["title"])
    return c["id"]


def update_control(ws, rid, **f):
    c = find(ws["controls"], rid)
    if not c:
        raise ValidationError(f"{rid} not found")
    for k in ("title", "objective", "rationale", "implementation", "owner", "limitations", "dependencies"):
        if k in f:
            c[k] = clean(f[k])
    if "function" in f:
        if f["function"] not in CONTROL_FUNCTIONS:
            raise ValidationError("Invalid control function")
        c["function"] = f["function"]
    if "threat_ids" in f:
        bad = [t for t in f["threat_ids"] if not find(ws["threats"], t)]
        if bad or not f["threat_ids"]:
            raise ValidationError(f"Invalid threat links: {bad or 'none given'}")
        c["threat_ids"] = list(dict.fromkeys(f["threat_ids"]))
    if "references" in f:
        c["references"] = [clean(r) for r in f["references"] if clean(r)]
    return c


def set_control_status(ws, rid, status):
    c = find(ws["controls"], rid)
    if not c:
        raise ValidationError(f"{rid} not found")
    if status not in CONTROL_STATUS:
        raise ValidationError("Invalid status")
    if status in ("verified", "verification_failed"):
        raise ValidationError("Use record_verification(): verification needs a method, evidence and a date.")
    if status == "implemented" and (not c["owner"] or len(c["implementation"]) < 15):
        raise ValidationError("An implemented control needs a named owner and an implementation description.")
    if status in ("planned",) and not c["owner"]:
        raise ValidationError("A planned control needs an accountable owner.")
    if c["status"] in ("verified",) and status in ("proposed", "planned", "rejected"):
        c["verification"] = None
    c["status"] = status
    log_change(ws, "control_status", rid, f"status -> {status}")


def record_verification(ws, rid, method, evidence, verified_on, result, verifier=""):
    c = find(ws["controls"], rid)
    if not c:
        raise ValidationError(f"{rid} not found")
    errs = []
    if c["status"] not in ("implemented", "verified", "verification_failed"):
        errs.append("Only an implemented control can be verified. Record implementation first.")
    if not c["owner"]:
        errs.append("The control needs an owner.")
    if len(clean(method)) < 10:
        errs.append("Describe the verification method (e.g. test, configuration review, log evidence).")
    if len(clean(evidence)) < 15:
        errs.append("Record the evidence (reference, result, ticket or artefact) - a control cannot be marked verified without it.")
    d = parse_date(verified_on)
    if not d:
        errs.append("Enter the verification date (YYYY-MM-DD).")
    elif d > date.today():
        errs.append("The verification date cannot be in the future.")
    if result not in ("pass", "fail"):
        errs.append("Record the result: pass or fail.")
    if errs:
        raise ValidationError(errs)
    c["verification"] = {"method": clean(method), "evidence": clean(evidence), "date": d.isoformat(), "result": result, "verifier": clean(verifier)}
    c["status"] = "verified" if result == "pass" else "verification_failed"
    log_change(ws, "control_verified" if result == "pass" else "control_verification_failed", rid, f"{result}: {clean(method)}")


def delete_control(ws, rid):
    ws["controls"] = [c for c in ws["controls"] if c["id"] != rid]
    ws["deleted_ids"].append(rid)
    for r in ws["risks"]:
        res = r.get("residual")
        if res and rid in res.get("basis_control_ids", []):
            res["basis_control_ids"] = [x for x in res["basis_control_ids"] if x != rid]
            _stale_flag(r, f"Control {rid} that supported the residual rating was deleted")


def controls_for(ws, threat_id):
    return [c for c in ws["controls"] if threat_id in c["threat_ids"]]


def control_state_counts(ws):
    out = {s: 0 for s in CONTROL_STATUS}
    for c in ws["controls"]:
        out[c["status"]] += 1
    return out


# ═════════════════════════════════════════════════════════════════════════════════════
# Step 8 - residual risk, treatment, questions
# ═════════════════════════════════════════════════════════════════════════════════════
def set_residual_risk(ws, threat_id, likelihood, likelihood_rationale, impact, impact_rationale, basis_control_ids=None,
                      remaining_attack_paths="", control_limitations="", reduction_basis="", evidence="", uncertainty=""):
    r = get_risk(ws, threat_id)
    if not r or not r["inherent"]:
        raise ValidationError("Rate the inherent risk (Step 6) before assessing residual risk.")
    res = _rating(likelihood, impact, likelihood_rationale, impact_rationale, "", evidence, uncertainty)
    inh = r["inherent"]
    basis = list(dict.fromkeys(basis_control_ids or []))
    errs = []
    for cid in basis:
        c = find(ws["controls"], cid)
        if not c:
            errs.append(f"Unknown control {cid}.")
        elif threat_id not in c["threat_ids"]:
            errs.append(f"Control {cid} is not linked to {threat_id}.")
    reduced = [d for d, (a, b) in {"likelihood": (likelihood, inh["likelihood"]), "impact": (impact, inh["impact"])}.items() if a < b]
    if reduced and not errs:
        verified = [cid for cid in basis if find(ws["controls"], cid)["status"] == "verified" and find(ws["controls"], cid).get("verification", {}).get("result") == "pass"]
        unverified = [cid for cid in basis if cid not in verified]
        if not verified:
            errs.append(f"Residual {' and '.join(reduced)} is lower than inherent, but no VERIFIED control supports it"
                        + (f" ({', '.join(unverified)} not verified)" if unverified else " (select the verified controls it relies on)")
                        + ". Verify the control with evidence in Step 7, or keep the inherent rating.")
        if len(clean(reduction_basis)) < 25:
            errs.append("Explain how the verified control(s) reduce the " + " and ".join(reduced) + ", and what they do not cover.")
    if len(clean(remaining_attack_paths)) < 10:
        errs.append("Describe the remaining attack paths (or why none remain).")
    if len(clean(control_limitations)) < 10:
        errs.append("Describe the limitations of the controls relied upon.")
    if errs:
        raise ValidationError(errs)
    res.update({"basis_control_ids": basis, "remaining_attack_paths": clean(remaining_attack_paths),
                "control_limitations": clean(control_limitations), "reduction_basis": clean(reduction_basis)})
    r["residual"] = res
    log_change(ws, "risk_residual", r["id"], f"{threat_id}: {res['band']} ({res['score']})")
    return r["id"]


def set_treatment(ws, threat_id, decision, owner, justification, decision_date="", acceptance_conditions="", escalation_to="", review_by=""):
    r = get_risk(ws, threat_id)
    if not r or not r.get("residual"):
        raise ValidationError("Assess the residual risk before recording a treatment decision.")
    errs = []
    if decision not in TREATMENTS:
        errs.append("Choose mitigate, transfer, avoid or accept.")
    if len(clean(owner)) < 3:
        errs.append("Every treatment decision needs an accountable risk owner (a named person or role).")
    if len(clean(justification)) < 25:
        errs.append("Write an explicit justification (what was weighed, and why this decision).")
    d = parse_date(decision_date or today())
    if not d:
        errs.append("Decision date must be YYYY-MM-DD.")
    band = r["residual"]["band"]
    if decision == "accept":
        if len(clean(acceptance_conditions)) < 10:
            errs.append("Accepted risk needs conditions (when must it be revisited? what would invalidate the acceptance?).")
        if band in ("High", "Critical") and len(clean(escalation_to)) < 3:
            errs.append(f"A {band} residual risk cannot be accepted by the owner alone: name who it is escalated to.")
        if not parse_date(review_by):
            errs.append("Accepted risk needs a review-by date (YYYY-MM-DD).")
    if decision == "mitigate" and not [c for c in controls_for(ws, threat_id) if c["status"] not in ("rejected",)]:
        errs.append("'Mitigate' requires at least one proposed or planned control linked to this threat.")
    if errs:
        raise ValidationError(errs)
    r["treatment"] = {"decision": decision, "owner": clean(owner), "justification": clean(justification), "decision_date": d.isoformat(),
                      "acceptance_conditions": clean(acceptance_conditions), "escalation_to": clean(escalation_to),
                      "escalation_required": band in ("High", "Critical") and decision == "accept", "review_by": clean(review_by)}
    log_change(ws, "treatment", r["id"], f"{threat_id}: {decision} by {clean(owner)}")


def add_question(ws, text, owner="", due="", related=None, blocking=False, token=None):
    prior = _once(ws, token)
    if prior:
        return prior
    text = clean(text)
    if len(text) < 10:
        raise ValidationError("Write the question as a full sentence.")
    if any(norm(q["text"]) == norm(text) and q["status"] == "open" for q in ws["questions"]):
        raise DuplicateError("That question is already open.")
    if due and not parse_date(due):
        raise ValidationError("Due date must be YYYY-MM-DD.")
    q = {"id": next_id(ws, "question"), "text": text, "owner": clean(owner), "due": due or "", "related": list(related or []),
         "blocking": bool(blocking), "status": "open", "answer": "", "created": now(), "origin": "learner"}
    ws["questions"].append(q)
    _remember(ws, token, q["id"])
    return q["id"]


def update_question(ws, rid, **f):
    q = find(ws["questions"], rid)
    if not q:
        raise ValidationError(f"{rid} not found")
    if "due" in f and f["due"] and not parse_date(f["due"]):
        raise ValidationError("Due date must be YYYY-MM-DD.")
    for k in ("owner", "due", "answer", "text"):
        if k in f:
            q[k] = clean(f[k])
    if "status" in f:
        if f["status"] == "closed" and len(q["answer"]) < 10:
            raise ValidationError("Record the answer before closing a question.")
        q["status"] = f["status"]
    return q


def delete_question(ws, rid):
    ws["questions"] = [q for q in ws["questions"] if q["id"] != rid]


# ═════════════════════════════════════════════════════════════════════════════════════
# Step 9 - review plan
# ═════════════════════════════════════════════════════════════════════════════════════
def set_review_plan(ws, **f):
    rp = ws["review"]
    for k in ("model_owner", "security_reviewer", "required_approval", "required_evidence", "approved_by"):
        if k in f:
            rp[k] = clean(f[k])
    if "cadence" in f:
        rp["cadence"] = f["cadence"] if f["cadence"] in CADENCES else ""
    if "next_review" in f:
        if f["next_review"] and not parse_date(f["next_review"]):
            raise ValidationError("Next review date must be YYYY-MM-DD.")
        rp["next_review"] = f["next_review"] or ""
    if "approved_on" in f:
        rp["approved_on"] = f["approved_on"] or ""
    for k in ("full_triggers", "change_triggers"):
        if k in f:
            rp[k] = [clean(x) for x in f[k] if clean(x)]
    _touch_ws(ws)


# ═════════════════════════════════════════════════════════════════════════════════════
# Persistence + migration
# ═════════════════════════════════════════════════════════════════════════════════════
def new_state():
    return {"state_version": STATE_VERSION, "completed_labs": [], "unlocked_labs": ["1"], "selected_lab": None,
            "current_step": 1, "workspaces": {}, "migration_notes": []}


def ensure_workspace(state, lab_id, learner="learner"):
    lab_id = str(lab_id)
    if lab_id not in state["workspaces"]:
        state["workspaces"][lab_id] = new_workspace(lab_id, learner)
    return state["workspaces"][lab_id]


def save_state(path, state):
    tmp = path + "." + uuid.uuid4().hex + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except (OSError, TypeError, ValueError):
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        raise


def load_state(path):
    """Load and migrate. Returns (state, notes). Corrupt files raise ValueError (caller decides)."""
    with open(path, encoding="utf-8") as f:
        payload = json.load(f)
    return migrate_state(payload)


def migrate_state(payload):
    notes = []
    if not isinstance(payload, dict):
        raise ValueError("Saved state is not an object")
    if payload.get("state_version", 0) >= 5 and "workspaces" in payload:
        st_ = new_state()
        st_.update({k: payload[k] for k in ("completed_labs", "unlocked_labs", "selected_lab", "current_step", "workspaces", "migration_notes") if k in payload})
        st_["unlocked_labs"] = sorted(set(st_["unlocked_labs"]) | {"1"})
        for lab, ws in list(st_["workspaces"].items()):
            st_["workspaces"][lab] = migrate_workspace(ws, notes)
        if st_.get("current_step") not in range(1, 10):
            st_["current_step"] = 1
        return st_, notes
    if payload.get("schema_version") is not None:  # legacy single-session payload (schema 1/2)
        return migrate_legacy(payload)
    raise ValueError("Unrecognised saved-state format")


def migrate_workspace(ws, notes=None):
    base = new_workspace(ws.get("lab_id", "1"), ws.get("learner", "learner"))
    for k, v in base.items():
        ws.setdefault(k, copy.deepcopy(v))
    for k, v in base["scope"].items():
        ws["scope"].setdefault(k, copy.deepcopy(v))
    for k, v in base["dfd"].items():
        ws["dfd"].setdefault(k, copy.deepcopy(v))
    for k, v in base["review"].items():
        ws["review"].setdefault(k, v)
    ws["workspace_version"] = WORKSPACE_VERSION
    return ws


_LEGACY_L = {1: 2, 2: 3, 3: 4}      # legacy 1-3 scale -> 5-point scale (documented in docs/ARCHITECTURE.md)
_LEGACY_LBL = {"Low": 2, "Medium": 3, "High": 4, "Critical": 5}


def migrate_legacy(p):
    """Best-effort import of the legacy (schema <= 2) single-workshop payload.

    Preserved: scope statement/goals/assumptions/exclusions, open questions, review plan and the
    selected workshop's threat records (as threats with origin='migrated'), CAPEC/ATT&CK picks
    (as unverified mappings), selected mitigations (as 'proposed' controls) and ratings.
    NOT preserved (documented): answer-key scores, zone labels, stride-rule answers, diagram annotations.
    Everything migrated is flagged for learner review; nothing is promoted to 'verified'."""
    notes = ["Legacy progress file migrated. Scores, zone scores and diagram annotations are not carried over; "
             "migrated threats, ratings and controls need review in the new nine-step flow."]
    st_ = new_state()
    st_["completed_labs"] = [str(x) for x in p.get("completed_workshops", [])]
    st_["unlocked_labs"] = sorted(set(str(x) for x in p.get("unlocked_workshops", ["1"])) | {"1"})
    sel = str(p["selected_workshop"]) if p.get("selected_workshop") else None
    st_["selected_lab"] = sel if sel in tm_labs.LAB_IDS else None
    labs = set(p.get("scope_models", {})) | set(p.get("open_questions", {})) | set(p.get("review_plans", {}))
    if st_["selected_lab"]:
        labs.add(st_["selected_lab"])
    for lab in sorted(l for l in labs if l in tm_labs.LAB_IDS):
        ws = ensure_workspace(st_, lab)
        ws["migrated_from"] = "legacy-schema-%s" % p.get("schema_version")
        sc = (p.get("scope_models") or {}).get(lab) or {}
        if sc.get("statement"):
            ws["scope"]["purpose"] = clean(sc["statement"])
        for g in sc.get("goals", []):
            if clean(g) and norm(g) not in [norm(x) for x in ws["scope"]["success_criteria"]]:
                ws["scope"]["success_criteria"].append(clean(g))
        for g in sc.get("must_do", []) + sc.get("must_never", []):
            if clean(g) and norm(g) not in [norm(x) for x in ws["scope"]["objectives"]]:
                ws["scope"]["objectives"].append(clean(g))
        for a in sc.get("assumptions", []):
            try:
                add_scope_item(ws, "assumptions", {"text": a, "status": "needs validation"}, origin="migrated", _quiet=True)
            except ValidationError:
                pass
        for x in sc.get("exclusions", []) + sc.get("oos_components", []):
            try:
                add_scope_item(ws, "exclusions", {"text": x, "reason": "migrated - add a reason"}, origin="migrated", _quiet=True)
            except ValidationError:
                pass
        oq = (p.get("open_questions") or {}).get(lab) or {}
        for q in oq.get("questions", []):
            try:
                add_question(ws, q if len(clean(q)) >= 10 else q + " (migrated)")
                ws["questions"][-1]["origin"] = "migrated"
            except ValidationError:
                pass
        rp = (p.get("review_plans") or {}).get(lab) or {}
        ws["review"].update({"model_owner": rp.get("owner", ""), "security_reviewer": rp.get("security_role", ""),
                             "next_review": rp.get("next_review", ""), "full_triggers": rp.get("full", []),
                             "change_triggers": rp.get("triggers", [])})
        if lab == st_["selected_lab"]:
            _migrate_threats(ws, p, notes)
        ws["migration_notes"] = list(notes)
    st_["current_step"] = 1
    st_["migration_notes"] = notes
    return st_, notes


def _migrate_threats(ws, p, notes):
    unresolved = 0
    for rec in p.get("user_answers", []) or []:
        comp = rec.get("component", "")
        targets = []
        if " \u2192 " in comp:
            a, b = [x.strip() for x in comp.split(" \u2192 ", 1)]
            for f in flows(ws):
                if target_name(ws, f["source"]) == a and target_name(ws, f["destination"]) == b:
                    targets.append(f["id"])
        else:
            e = element_by_name(ws, comp)
            if e:
                targets.append(e["id"])
        stride = tm_labs._letter(rec.get("stride", ""))
        t = {"id": next_id(ws, "threat"), "title": rec.get("threat_statement", "")[:120] or f"{rec.get('stride', '')} - {comp}",
             "stride": stride, "source": rec.get("threat_source", ""), "preconditions": rec.get("prerequisites", ""), "assumption_ids": [],
             "action": rec.get("threat_action", ""), "targets": targets, "security_property": PROPERTY_FOR_STRIDE.get(stride, ""),
             "impact": rec.get("threat_impact", ""), "assets": [a.strip() for a in str(rec.get("impacted_assets", "")).split(",") if a.strip()],
             "evidence": "", "rationale": rec.get("statement_rationale", ""), "confidence": "", "uncertainties": "migrated - review",
             "departure_rationale": "", "statement_override": rec.get("threat_statement", ""), "origin": "migrated",
             "created": now(), "updated": now(), "stale": [{"reason": "Migrated from legacy file - confirm targets, wording and rationale", "at": now()}],
             "orphaned_targets": [], "legacy_component": comp}
        if not targets:
            unresolved += 1
        ws["threats"].append(t)
        for cap in rec.get("capec", []) or []:
            if str(cap).startswith("No suitable"):
                continue
            m = re.match(r"^(CAPEC-\d+)", str(cap))
            if m and tm_catalog.lookup("CAPEC", m.group(1)):
                e = tm_catalog.lookup("CAPEC", m.group(1))
                meta = tm_catalog.catalogue_meta()["CAPEC"]
                ws["mappings"].append({"id": next_id(ws, "mapping"), "threat_id": t["id"], "framework": "CAPEC", "outcome": "mapped",
                                       "ref_id": e["id"], "name": e["name"], "url": tm_catalog.reference_url("CAPEC", e["id"]),
                                       "catalogue_status": meta["status"], "source_version": meta["declared_version"], "retrieved": "",
                                       "verified_on": "", "behaviour": "migrated", "relationship": RELATIONSHIPS[0],
                                       "rationale": clean(rec.get("capec_rationale", "")) or "migrated - add rationale", "confidence": "",
                                       "evidence": "", "origin": "migrated", "created": now(),
                                       "stale": [{"reason": "Migrated - confirm rationale", "at": now()}]})
        for tid in rec.get("mitre", []) or []:
            e = tm_catalog.lookup("ATT&CK", tid)
            if e:
                meta = tm_catalog.catalogue_meta()["ATT&CK"]
                ws["mappings"].append({"id": next_id(ws, "mapping"), "threat_id": t["id"], "framework": "ATT&CK", "outcome": "mapped",
                                       "ref_id": e["id"], "name": e["name"], "url": tm_catalog.reference_url("ATT&CK", e["id"]),
                                       "catalogue_status": meta["status"], "source_version": meta["declared_version"], "retrieved": "",
                                       "verified_on": "", "behaviour": "migrated", "relationship": RELATIONSHIPS[0],
                                       "rationale": "migrated - add rationale", "confidence": "", "evidence": "", "origin": "migrated",
                                       "created": now(), "stale": [{"reason": "Migrated - confirm rationale", "at": now()}]})
        ln, im = rec.get("likelihood_n"), rec.get("impact_n")
        if ln in _LEGACY_L and im in _LEGACY_L:
            inh = {"likelihood": _LEGACY_L[ln], "impact": _LEGACY_L[im], "likelihood_rationale": rec.get("likelihood_rationale", "") or "migrated",
                   "impact_rationale": rec.get("impact_rationale", "") or "migrated", "business_context": "", "evidence": "", "uncertainty": "migrated - rescore on the 5-point scale",
                   "rated_on": today(), "model_version": RISK_MODEL["version"]}
            inh["score"] = inh["likelihood"] * inh["impact"]
            inh["band"] = risk_band(inh["score"])
            inh["priority"], inh["urgency"] = RISK_MODEL["priority"][inh["band"]]
            ws["risks"].append({"id": next_id(ws, "risk"), "threat_id": t["id"], "inherent": inh, "residual": None, "treatment": None,
                                "stale": [{"reason": "Migrated from the legacy 1-3 scale; re-rate", "at": now()}]})
        for mit in rec.get("selected_mitigations", []) or []:
            ws["controls"].append({"id": next_id(ws, "control"), "threat_ids": [t["id"]], "targets": list(targets), "title": str(mit)[:80],
                                   "objective": "migrated - restate the objective", "rationale": "", "implementation": str(mit),
                                   "function": "preventive", "owner": "", "status": "proposed", "verification": None, "references": [],
                                   "limitations": "", "dependencies": "", "stale": [{"reason": "Migrated - confirm", "at": now()}],
                                   "created": now(), "origin": "migrated"})
    if unresolved:
        notes.append(f"{unresolved} migrated threat(s) could not be linked to DFD IDs because the DFD is new; link them in Step 3.")
