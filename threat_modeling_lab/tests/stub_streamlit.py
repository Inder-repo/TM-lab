"""A minimal in-memory stand-in for Streamlit used ONLY for smoke-testing page code paths when the real
package is unavailable. It is NOT a substitute for browser testing: it does not render anything and
cannot detect layout, widget-state or rerun-semantics bugs of the real runtime."""
import sys
import types
from datetime import date


class Rerun(BaseException):
    pass


class Stop(BaseException):
    pass


class _State(dict):
    __getattr__ = dict.get

    def __setattr__(self, k, v):
        self[k] = v


class StreamlitAPIException(Exception):
    """Stand-in for the errors the real runtime raises for rule violations the stub can detect."""


class _Ctx:
    def __init__(self, st, kind=None): self.st, self.kind = st, kind
    def __enter__(self):
        if self.kind:
            self.st._stack.append(self.kind)
        return self.st
    def __exit__(self, *a):
        if self.kind:
            self.st._stack.pop()
        return False
    def __getattr__(self, n): return getattr(self.st, n)


def install(overrides=None, clicks=None):
    mod = types.ModuleType("streamlit")
    mod.session_state = _State()
    mod.query_params = {}
    mod._overrides = overrides if overrides is not None else {}
    mod._clicks = clicks if clicks is not None else set()
    mod._calls = []
    mod._messages = []
    mod._frames = []
    mod._stack = []
    mod._keys = set()

    def new_run():
        """Call before each page render: Streamlit forgets widget identities between script runs."""
        mod._keys.clear()
        mod._stack.clear()
    mod._new_run = new_run

    def reg(key, label=""):
        if key is None:
            return
        if key in mod._keys:
            raise StreamlitAPIException(f"DuplicateWidgetID: key '{key}' used twice in one run (label '{label}')")
        mod._keys.add(key)

    def widget(key, default, label=""):
        reg(key, label)
        if key is not None and key in mod._overrides:
            v = mod._overrides[key]
        elif key is not None and key in mod.session_state:
            v = mod.session_state[key]
        else:
            v = default
        if key is not None:
            mod.session_state[key] = v
        return v

    def msg(kind):
        def f(text="", *a, **k):
            mod._messages.append((kind, str(text)))
        return f
    for n in ("markdown", "header", "subheader", "caption", "write", "title", "code", "text"):
        setattr(mod, n, msg(n))
    for n in ("info", "warning", "error", "success"):
        setattr(mod, n, msg(n))
    mod.set_page_config = lambda **k: None
    mod.dataframe = lambda data=None, *a, **k: (mod._calls.append("dataframe"), mod._frames.append(repr(data)))
    mod.graphviz_chart = lambda dot=None, *a, **k: (mod._calls.append("graphviz"), mod._frames.append(str(dot)))
    mod.progress = lambda *a, **k: None
    mod.metric = lambda *a, **k: None
    def expander(*a, **k):
        if "expander" in mod._stack:
            raise StreamlitAPIException("Expanders may not be nested inside other expanders.")
        return _Ctx(mod, "expander")

    def form(*a, **k):
        if "form" in mod._stack:
            raise StreamlitAPIException("Forms cannot be nested in other forms.")
        return _Ctx(mod, "form")
    mod.expander = expander
    mod.form = form
    mod.spinner = lambda *a, **k: _Ctx(mod)
    mod.container = lambda *a, **k: _Ctx(mod)
    mod.sidebar = _Ctx(mod, None)
    mod.columns = lambda spec, **k: [_Ctx(mod) for _ in range(spec if isinstance(spec, int) else len(spec))]
    mod.tabs = lambda labels: [_Ctx(mod) for _ in labels]
    def button(label, key=None, **k):
        if "form" in mod._stack:
            raise StreamlitAPIException(f"st.button() cannot be used inside an st.form() (label '{label}'); use st.form_submit_button().")
        reg(key, label)
        return (key in mod._clicks or label in mod._clicks) and not k.get("disabled")

    def form_submit_button(label="Submit", **k):
        if "form" not in mod._stack:
            raise StreamlitAPIException("st.form_submit_button() must be inside an st.form().")
        return label in mod._clicks
    mod.button, mod.form_submit_button = button, form_submit_button
    mod.download_button = lambda label, data, key=None, **k: (reg(key, label), mod._calls.append(("download", label, len(data))))
    mod.text_input = lambda label, value="", key=None, **k: widget(key, value, label)
    mod.text_area = lambda label, value="", key=None, **k: widget(key, value, label)
    mod.selectbox = lambda label, options, index=0, key=None, **k: widget(key, list(options)[index] if len(list(options)) else None, label)
    mod.multiselect = lambda label, options, default=None, key=None, **k: widget(key, list(default or []), label)
    mod.checkbox = lambda label, value=False, key=None, **k: widget(key, value, label)
    mod.radio = lambda label, options, index=0, key=None, **k: widget(key, list(options)[index], label)
    mod.slider = lambda label, mn=0, mx=1, value=None, key=None, **k: widget(key, value if value is not None else mn, label)
    mod.select_slider = lambda label, options, value=None, key=None, **k: widget(key, value, label)
    mod.date_input = lambda label, value=None, key=None, **k: widget(key, value or date.today(), label)

    def rerun():
        raise Rerun()

    def stop():
        raise Stop()
    mod.rerun, mod.stop = rerun, stop
    sys.modules["streamlit"] = mod
    return mod
