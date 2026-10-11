"""Real-runtime check using Streamlit's own AppTest harness. Skipped automatically when Streamlit is not
installed (as in the build sandbox). Run it on a machine with `pip install -r requirements.txt`."""
import os
import unittest

try:
    from streamlit.testing.v1 import AppTest
except Exception:           # pragma: no cover
    AppTest = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@unittest.skipIf(AppTest is None, "Streamlit not installed - real-runtime test skipped")
class RealRuntime(unittest.TestCase):
    def test_home_then_lab1_walkthrough(self):
        at = AppTest.from_file(os.path.join(ROOT, "workshop23.py"), default_timeout=60).run()
        self.assertFalse(at.exception, at.exception)
        start = [b for b in at.button if "Start Lab 1" in b.label][0]
        start.click()
        at.run()
        self.assertFalse(at.exception, at.exception)
        self.assertTrue([h for h in at.header if "Step 1" in h.value])
        for n in range(2, 10):          # navigate through the tracker buttons
            [b for b in at.sidebar.button if b.label.endswith(f"{n} \u00b7 " + ["", "", "DFD", "STRIDE", "Boundaries", "ATT&CK / CAPEC", "Inherent risk", "Controls", "Residual", "Review"][n])][0].click()
            at.run()
            self.assertFalse(at.exception, (n, at.exception))


if __name__ == "__main__":
    unittest.main()
