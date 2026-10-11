"""Shared Streamlit helpers. All business rules live in tm_model / tm_assess / tm_export."""
import json
import os
import re
import tempfile
import uuid
from datetime import date

import streamlit as st

import tm_assess as a
import tm_labs
import tm_model as m

S = st.session_state


# ── session / persistence ──────────────────────────────────────────────────────────────
def _sid():
    sid = S.get("_sid")
    if not sid:
        try:
            sid = st.query_params.get("sid")
            if isinstance(sid, list):
                sid = sid[0] if sid else None
            if not sid:
                sid = uuid.uuid4().hex[:16]
                st.query_params["sid"] = sid
        except Exception:
            sid = uuid.uuid4().hex[:16]
        sid = re.sub(r"[^A-Za-z0-9]", "", str(sid))[:32] or uuid.uuid4().hex[:16]
        S["_sid"] = sid
    return sid


def progress_path(version=5):
    return os.path.join(tempfile.gettempdir(), f"threat_progress_v{version}_{_sid()}.json")


def init_state():
    if "tm" not in S:
        S["tm"] = m.new_state()
    if "_loaded" in S:
        return
    S["_loaded"] = True
    for version in (5, 4):
        p = progress_path(version)
        if os.path.exists(p):
            try:
                state, notes = m.load_state(p)
                S["tm"] = state
                S["_notes"] = notes
                if version == 4:
                    save()
                break
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                S["_load_warning"] = f"Saved progress could not be read and was ignored ({exc}). Your file was left untouched."


def save():
    try:
        m.save_state(progress_path(5), S["tm"])
    except (OSError, TypeError, ValueError) as exc:
        st.warning(f"Progress could not be saved: {exc}. Download your exports before closing this session.")


def tm():
    return S["tm"]


def lab_id():
    return tm()["selected_lab"]


def ws():
    return m.ensure_workspace(tm(), lab_id(), learner=_sid())


def go(step):
    tm()["current_step"] = int(step)
    save()
    st.rerun()


def select_lab(lab):
    tm()["selected_lab"] = str(lab)
    m.ensure_workspace(tm(), lab, learner=_sid())
    tm()["current_step"] = 1
    save()


# ── key / token helpers (rerun-safe forms, no cross-lab widget leakage) ───────────────
def kv(w, *parts):
    return "_".join([w["lab_id"], *[str(p) for p in parts]])


def nonce(w, name):
    return S.setdefault("_nonce", {}).get(kv(w, name), 0)


def bump(w, name):
    S.setdefault("_nonce", {})[kv(w, name)] = nonce(w, name) + 1


def token(w, name):
    return f"{kv(w, name)}:{nonce(w, name)}"


def flash(msg, level="success"):
    S.setdefault("_flash", []).append((level, msg))


def show_flash():
    for level, msg in S.pop("_flash", []):
        {"success": st.success, "warning": st.warning, "info": st.info, "error": st.error}[level](msg)


def attempt(fn, *args, ok=None, rerun=True, **kw):
    """Run a core operation, surfacing validation problems visibly. Returns (success, result)."""
    try:
        res = fn(*args, **kw)
    except m.DuplicateError as exc:
        st.warning("Not added - " + "; ".join(exc.errors))
        return False, None
    except m.ValidationError as exc:
        for e in exc.errors:
            st.error(e)
        return False, None
    except m.RevealLocked as exc:
        st.info(str(exc))
        return False, None
    save()
    if ok:
        flash(ok)
    if rerun:
        st.rerun()
    return True, res


def label(w, rid):
    return f"{rid} \u00b7 {m.target_name(w, rid)}"


def target_options(w):
    return [e["id"] for e in m.elements(w)] + [f["id"] for f in m.flows(w)]


def element_options(w):
    return [e["id"] for e in m.elements(w)]


# ── page furniture ─────────────────────────────────────────────────────────────────────
def frame(step, learn, do, why, artefact, defensible):
    """The five questions every page must answer."""
    st.header(f"Step {step}: {a.STEP_TITLES[step]}")
    show_flash()
    with st.expander("What am I doing on this page?", expanded=True):
        st.markdown(f"**1. What am I learning?** {learn}\n\n**2. What do I need to do?** {do}\n\n"
                    f"**3. Why does this matter in a real architecture review?** {why}\n\n"
                    f"**4. What artefact must I produce?** {artefact}\n\n**5. How will I know my reasoning is defensible?** {defensible}")


def gate_panel(step):
    w = ws()
    sstat = a.step_status(w, step)
    icon = {"complete": "\u2705", "in_progress": "\U0001F7E1", "not_started": "\u26AA", "blocked": "\u26D4"}[sstat["state"]]
    with st.expander(f"{icon} Completion check - step {step} ({sstat['state'].replace('_', ' ')})", expanded=sstat["state"] == "in_progress"):
        if not sstat["blockers"] and not sstat["warnings"]:
            st.write("Nothing outstanding for this step.")
        for b in sstat["blockers"]:
            st.error(b["message"])
        for x in sstat["warnings"]:
            st.warning(x["message"])
        st.caption("Completion is judged on the quality and traceability of your records - not on how many you created.")


def nav(step):
    w = ws()
    c1, c2 = st.columns(2)
    if step > 1 and c1.button(f"\u2B05 Back: {a.STEP_TITLES[step - 1]}", key=kv(w, "back", step), use_container_width=True):
        go(step - 1)
    if step < 9:
        nxt = step + 1
        if c2.button(f"Next: {a.STEP_TITLES[nxt]} \u27A1", key=kv(w, "next", step), type="primary", use_container_width=True):
            pre = a.prerequisites(w, nxt)
            if pre:
                st.warning(pre[0])
            else:
                go(nxt)


def prerequisite_block(step):
    pre = a.prerequisites(ws(), step)
    if pre:
        st.warning(pre[0])
        return True
    return False


def discover_panel(w, hyp_key, prompt, kind, ref=None, show=None, label_btn="Show reference material"):
    """Discover-first: the hypothesis box is real - reference content is only obtained via
    a.get_reference(), which refuses until the learner's own work exists."""
    if w["settings"]["discover_first"]:
        cur = w["hypotheses"].get(str(hyp_key), {}).get("text", "")
        txt = st.text_area(prompt, value=cur, key=kv(w, "hyp", hyp_key, nonce(w, f"hyp{hyp_key}")), height=90)
        if st.button("Save my hypothesis", key=kv(w, "hypbtn", hyp_key)):
            attempt(a.set_hypothesis, w, hyp_key, txt, ok="Hypothesis saved.")
    ok, why = a.reveal_status(w, kind, ref)
    if not ok:
        st.info("\U0001F512 " + why)
        return
    if st.button(label_btn, key=kv(w, "reveal", kind, ref)):
        S[kv(w, "shown", kind, ref)] = True
    if S.get(kv(w, "shown", kind, ref)):
        try:
            data = a.get_reference(w, kind, ref)
        except m.RevealLocked as exc:
            st.info(str(exc))
            return
        save()
        show(data)


def scope_strings(w, listname, title, placeholder=""):
    st.markdown(f"**{title}**")
    for i, item in enumerate(w["scope"][listname]):
        c1, c2 = st.columns([8, 1])
        c1.write("\u2022 " + item)
        if c2.button("\u2716", key=kv(w, "rm", listname, i, item[:12]), help=f"Remove '{item}'"):
            m.remove_scope_string(w, listname, item)
            save()
            st.rerun()
    with st.form(kv(w, "frm", listname, nonce(w, listname)), clear_on_submit=True):
        txt = st.text_input("Add", placeholder=placeholder, key=kv(w, "in", listname, nonce(w, listname)))
        if st.form_submit_button("Add"):
            ok, _ = attempt(m.add_scope_string, w, listname, txt, rerun=False)
            if ok:
                bump(w, listname)
                st.rerun()


def scope_items(w, listname, title, fields):
    """fields: list of (key, label, options-or-None, kind) kind: text|select|bool."""
    st.markdown(f"**{title}**")
    for it in w["scope"][listname]:
        c1, c2 = st.columns([8, 1])
        c1.write(f"`{it['id']}` " + " \u00b7 ".join(str(it[k[0]]) for k in fields if it.get(k[0]) not in ("", None, False))
                 + (" \u00b7 *(from lab brief)*" if it.get("origin") == "seeded" else ""))
        if c2.button("\u2716", key=kv(w, "rm", listname, it["id"]), help=f"Remove {it['id']}"):
            m.remove_scope_item(w, listname, it["id"])
            save()
            st.rerun()
    n = nonce(w, listname)
    with st.form(kv(w, "frm", listname, n), clear_on_submit=True):
        vals = {}
        cols = st.columns(len(fields))
        for col, (k, lbl, opts, kind) in zip(cols, fields):
            key = kv(w, "in", listname, k, n)
            if kind == "select":
                vals[k] = col.selectbox(lbl, opts, key=key)
            elif kind == "bool":
                vals[k] = col.checkbox(lbl, key=key)
            else:
                vals[k] = col.text_input(lbl, key=key)
        if st.form_submit_button("Add"):
            ok, _ = attempt(m.add_scope_item, w, listname, vals, token=token(w, listname), rerun=False)
            if ok:
                bump(w, listname)
                st.rerun()
