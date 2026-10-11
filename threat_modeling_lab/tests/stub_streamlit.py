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


class _Ctx:
    def __init__(self, st): self.st = st
    def __enter__(self): return self.st
    def __exit__(self, *a): return False
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

    def widget(key, default):
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
    mod.download_button = lambda label, data, **k: mod._calls.append(("download", label, len(data)))
    mod.expander = lambda *a, **k: _Ctx(mod)
    mod.form = lambda *a, **k: _Ctx(mod)
    mod.spinner = lambda *a, **k: _Ctx(mod)
    mod.container = lambda *a, **k: _Ctx(mod)
    mod.sidebar = _Ctx(mod)
    mod.columns = lambda spec, **k: [_Ctx(mod) for _ in range(spec if isinstance(spec, int) else len(spec))]
    mod.tabs = lambda labels: [_Ctx(mod) for _ in labels]
    mod.button = lambda label, key=None, **k: (key in mod._clicks or label in mod._clicks) and not k.get("disabled")
    mod.form_submit_button = lambda label="Submit", **k: label in mod._clicks
    mod.text_input = lambda label, value="", key=None, **k: widget(key, value)
    mod.text_area = lambda label, value="", key=None, **k: widget(key, value)
    mod.selectbox = lambda label, options, index=0, key=None, **k: widget(key, list(options)[index] if len(list(options)) else None)
    mod.multiselect = lambda label, options, default=None, key=None, **k: widget(key, list(default or []))
    mod.checkbox = lambda label, value=False, key=None, **k: widget(key, value)
    mod.radio = lambda label, options, index=0, key=None, **k: widget(key, list(options)[index])
    mod.slider = lambda label, mn=0, mx=1, value=None, key=None, **k: widget(key, value if value is not None else mn)
    mod.select_slider = lambda label, options, value=None, key=None, **k: widget(key, value)
    mod.date_input = lambda label, value=None, key=None, **k: widget(key, value or date.today())

    def rerun():
        raise Rerun()

    def stop():
        raise Stop()
    mod.rerun, mod.stop = rerun, stop
    sys.modules["streamlit"] = mod
    return mod
