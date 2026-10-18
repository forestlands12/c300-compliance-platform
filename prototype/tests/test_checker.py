"""Run with: python -m unittest discover -s tests -v   (from the prototype folder)"""
import tempfile
import unittest
from pathlib import Path

from compliance_checker.checks import evaluate, run_checks
from compliance_checker.cli import main
from compliance_checker.collectors import collect_linux, collect_windows_secedit
from compliance_checker.loader import ControlFileError, load_controls
from compliance_checker.models import Control, Status

HERE = Path(__file__).resolve().parent.parent
BASELINE = HERE / "controls" / "baseline.yaml"
LINUX_SAMPLE = HERE / "samples" / "linux-web-01"
WIN_SAMPLE = HERE / "samples" / "win-ws-01" / "secpol.inf"


def ctl(op, expected, fact="x"):
    return Control(id="T-1", title="t", platforms=("linux",), fact=fact,
                   operator=op, expected=expected)


class EngineTests(unittest.TestCase):
    def test_operators(self):
        self.assertEqual(evaluate(ctl("gte", 14), {"x": 14}).status, Status.PASS)
        self.assertEqual(evaluate(ctl("gte", 14), {"x": 8}).status, Status.FAIL)
        self.assertEqual(evaluate(ctl("between", [1, 5]), {"x": 0}).status, Status.FAIL)
        self.assertEqual(evaluate(ctl("between", [1, 5]), {"x": 5}).status, Status.PASS)
        self.assertEqual(evaluate(ctl("in", ["a"]), {"x": "a"}).status, Status.PASS)

    def test_missing_fact_is_never_a_pass(self):
        self.assertEqual(evaluate(ctl("eq", 1), {}).status, Status.NOT_COLLECTED)
        self.assertEqual(evaluate(ctl("eq", 1), {"x": None}).status, Status.NOT_COLLECTED)

    def test_type_mismatch_is_error_not_crash(self):
        self.assertEqual(evaluate(ctl("gte", 14), {"x": "abc"}).status, Status.ERROR)

    def test_platform_filter(self):
        controls = load_controls(BASELINE)
        ids = {r.control.id for r in run_checks(controls, {}, "linux")}
        self.assertIn("SSH-01", ids)
        self.assertNotIn("PW-05", ids)


class LoaderTests(unittest.TestCase):
    def test_baseline_loads(self):
        self.assertGreaterEqual(len(load_controls(BASELINE)), 10)

    def test_rejects_unknown_operator(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.yaml"
            bad.write_text("controls:\n  - {id: A, title: a, platforms: [linux], "
                           "fact: x, operator: approx, expected: 1}\n")
            with self.assertRaises(ControlFileError):
                load_controls(bad)


class CollectorTests(unittest.TestCase):
    def test_linux_sample(self):
        f = collect_linux(LINUX_SAMPLE)
        self.assertEqual(f["password.min_length"], 9)  # pwquality overrides login.defs
        self.assertEqual(f["password.max_age_days"], 99999)
        self.assertEqual(f["lockout.duration_minutes"], 10)
        self.assertEqual(f["ssh.permit_root_login"], "yes")
        self.assertEqual(f["ssh.max_auth_tries"], 6)  # OpenSSH default when unset
        self.assertNotIn("file.etc_shadow.mode", f)

    def test_windows_sample(self):
        f = collect_windows_secedit(WIN_SAMPLE)
        self.assertEqual(f["password.min_length"], 8)
        self.assertIs(f["password.complexity_enabled"], True)
        self.assertEqual(f["lockout.threshold"], 0)
        self.assertIsNone(f["lockout.duration_minutes"])

    def test_windows_utf16_export(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "secpol.inf"
            p.write_bytes(WIN_SAMPLE.read_text().encode("utf-16"))  # adds BOM like secedit
            self.assertEqual(collect_windows_secedit(p)["password.min_length"], 8)


class CliTests(unittest.TestCase):
    def test_exit_code_is_1_when_controls_fail(self):
        self.assertEqual(main(["scan", "--platform", "windows", "--source", str(WIN_SAMPLE)]), 1)


if __name__ == "__main__":
    unittest.main()
