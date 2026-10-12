import json
import os
import tempfile
import unittest

import support as sp  # noqa: F401
import tm_catalog as c
from tools import verify_catalogues as vc


def stix(framework, entries, **extra):
    src = "mitre-attack" if framework == "ATT&CK" else "capec"
    objs = []
    for i, n, *rest in entries:
        o = {"type": "attack-pattern", "name": n, "external_references": [{"source_name": src, "external_id": i}]}
        o.update(rest[0] if rest else {})
        objs.append(o)
    return {"type": "bundle", "objects": objs}


class CatalogueProvenance(unittest.TestCase):
    """Fixtures here are SYNTHETIC bundles that exercise the verifier. They are not MITRE data."""

    def test_dataset_is_labelled_unverified_by_default(self):
        meta = c.catalogue_meta(path="/nonexistent")
        self.assertTrue(all(v["status"] == "curated-unverified" for v in meta.values()))

    def test_id_syntax_and_urls(self):
        self.assertTrue(c.valid_id_syntax("ATT&CK", "T1059.001"))
        self.assertFalse(c.valid_id_syntax("ATT&CK", "1059"))
        self.assertTrue(c.valid_id_syntax("CAPEC", "CAPEC-66"))
        self.assertEqual(c.normalise_id("CAPEC", "66"), "CAPEC-66")
        self.assertEqual(c.reference_url("CAPEC", "CAPEC-66"), "https://capec.mitre.org/data/definitions/66.html")
        self.assertEqual(c.reference_url("ATT&CK", "T1059.001"), "https://attack.mitre.org/techniques/T1059/001/")
        self.assertEqual(c.reference_url("ATT&CK", "nonsense"), "")

    def test_local_entries_are_well_formed_and_unique(self):
        ids = [t["id"] for t in c.ATTACK_TECHNIQUES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(c.valid_id_syntax("ATT&CK", i) for i in ids))
        self.assertTrue(all(c.valid_id_syntax("CAPEC", p["id"]) for p in c.CAPEC_PATTERNS))
        self.assertNotIn("No suitable", " ".join(p["name"] for p in c.CAPEC_PATTERNS))

    def test_verifier_passes_only_when_every_entry_matches(self):
        good = stix("ATT&CK", [(t["id"], t["name"]) for t in c.ATTACK_TECHNIQUES])
        self.assertEqual(c.verify_against_stix(good, "ATT&CK")["status"], "verified")
        bad = stix("ATT&CK", [(t["id"], t["name"]) for t in c.ATTACK_TECHNIQUES[1:]] + [(c.ATTACK_TECHNIQUES[0]["id"], "Renamed")])
        rep = c.verify_against_stix(bad, "ATT&CK")
        self.assertEqual(rep["status"], "problems-found")
        self.assertEqual(rep["problems"][0]["problem"], "name mismatch")
        revoked = stix("CAPEC", [(p["id"], p["name"], {"revoked": True}) for p in c.CAPEC_PATTERNS])
        self.assertEqual(c.verify_against_stix(revoked, "CAPEC")["status"], "problems-found")
        missing = stix("CAPEC", [])
        self.assertTrue(all(p["problem"] == "not found in official source" for p in c.verify_against_stix(missing, "CAPEC")["problems"]))

    def test_verification_stamp_changes_reported_status_only_when_clean(self):
        with tempfile.TemporaryDirectory() as d:
            ap, cp, out = (os.path.join(d, n) for n in ("a.json", "c.json", "out.json"))
            json.dump(stix("ATT&CK", [(t["id"], t["name"]) for t in c.ATTACK_TECHNIQUES]), open(ap, "w"))
            json.dump(stix("CAPEC", [(p["id"], p["name"]) for p in c.CAPEC_PATTERNS][:-1]), open(cp, "w"))
            rc = vc.main(["--attack", ap, "--attack-version", "ATT&CK vTEST", "--capec", cp, "--capec-version", "CAPEC vTEST", "--out", out])
            self.assertEqual(rc, 1)        # CAPEC had a missing entry
            meta = c.catalogue_meta(path=out)
            self.assertEqual(meta["ATT&CK"]["status"], "verified")
            self.assertEqual(meta["ATT&CK"]["declared_version"], "ATT&CK vTEST")
            self.assertEqual(meta["CAPEC"]["status"], "curated-unverified")

    def test_search_never_filters_by_stride(self):
        every = c.search("ATT&CK", limit=1000)
        aligned = c.search("ATT&CK", stride_letter="S", limit=1000)
        self.assertEqual({e["id"] for e in every}, {e["id"] for e in aligned})


if __name__ == "__main__":
    unittest.main()
