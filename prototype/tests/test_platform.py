"""Tests for the one-click platform: scan engine, drift, scoring, dashboard API, AI assistant.

Run with: python -m unittest discover -s tests -v   (from the prototype folder)
The dashboard tests need Flask and are skipped if it is not installed.
Nothing here touches data/ or a real machine: every test works in a temp folder.
"""
import json
import shutil
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from compliance_checker import demo
from compliance_checker.assistant import AIConfig, Assistant, build_messages, redact, self_test
from compliance_checker.engine import run_scan
from compliance_checker.inventory import load_inventory
from compliance_checker.loader import load_controls
from compliance_checker.scoring import build_summary, drift, posture
from compliance_checker.store import Store

HERE = Path(__file__).resolve().parent.parent
BASELINE = HERE / "controls" / "baseline.yaml"

try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False


# WHAT: A private copy of the demo playground (hosts + inventory + history db) in a temp folder.
class Playground:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cc-test-"))
        self.targets = self.tmp / "targets"
        shutil.copytree(demo.SAMPLES, self.targets, ignore=shutil.ignore_patterns("README.md"))
        inv = (HERE / "inventory" / "demo.yaml").read_text(encoding="utf-8")
        inv = inv.replace("../data/demo-targets", str(self.targets))
        self.inventory_path = self.tmp / "inventory.yaml"
        self.inventory_path.write_text(inv, encoding="utf-8")
        self.inventory = load_inventory(self.inventory_path)
        self.controls = load_controls(BASELINE)
        self.store = Store(self.tmp / "history.db")

    def scan(self, trigger="cli"):
        return run_scan(self.inventory, self.controls, self.store, trigger=trigger)

    def apply_drift(self):
        # WHY: demo.drift() edits demo.WORK; point it at our copy, never at data/.
        with mock.patch.object(demo, "WORK", self.targets):
            return demo.drift()

    def close(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class ScanAndDriftTests(unittest.TestCase):
    def setUp(self):
        self.pg = Playground()

    def tearDown(self):
        self.pg.close()

    def test_scan_all_hosts_and_auto_baseline(self):
        run_id = self.pg.scan()
        scans = self.pg.store.host_scans(run_id)
        self.assertEqual(len(scans), 4)
        self.assertTrue(all(hs["error"] is None for hs in scans), [hs["error"] for hs in scans])
        for hs in scans:
            # First good scan of each host becomes its baseline.
            self.assertEqual(self.pg.store.baseline(hs["host"])["id"], hs["id"])
            self.assertTrue(self.pg.store.results(hs["id"]))

    def test_deliberate_drift_is_caught(self):
        self.pg.scan()
        first = build_summary(self.pg.store)["score"]
        story = self.pg.apply_drift()
        self.pg.scan()
        s = build_summary(self.pg.store)
        self.assertLess(s["score"], first)
        self.assertLess(s["delta"], 0)
        worse = {(d["host"], d["control_id"]) for d in s["drift"] if d["direction"] == "worse"}
        # Every host named in the drift story must show at least one "worse" change.
        for host in {line.split(":")[0] for line in story}:
            self.assertTrue(any(h == host for h, _ in worse), f"no drift caught on {host}: {worse}")

    def test_fixing_drift_shows_as_better(self):
        self.pg.scan()
        self.pg.apply_drift()
        self.pg.scan()
        # Put the hosts back the way they were (as an admin would) and scan again.
        shutil.rmtree(self.pg.targets)
        shutil.copytree(demo.SAMPLES, self.pg.targets, ignore=shutil.ignore_patterns("README.md"))
        self.pg.scan()
        s = build_summary(self.pg.store)
        self.assertFalse([d for d in s["drift"] if d["direction"] == "worse"])

    def test_unreachable_host_is_an_error_not_a_pass(self):
        (self.pg.targets / "pos-win11-01.json").unlink()
        run_id = self.pg.scan()
        pos = next(hs for hs in self.pg.store.host_scans(run_id) if hs["host"] == "POS-WIN11-01")
        self.assertIsNotNone(pos["error"])
        s = build_summary(self.pg.store)
        self.assertEqual(len(s["hosts"]), 4)  # the other three still scanned
        self.assertIsNone(self.pg.store.baseline("POS-WIN11-01"))


class ScoringTests(unittest.TestCase):
    def r(self, cid, status, sev="medium", actual=None):
        return {"control_id": cid, "title": cid, "severity": sev, "status": status, "actual": actual}

    def test_weighted_score_ignores_not_collected(self):
        rs = [self.r("A", "PASS", "high"), self.r("B", "FAIL", "low"), self.r("C", "NOT_COLLECTED")]
        self.assertEqual(posture(rs), 75.0)  # 3 / (3 + 1)

    def test_no_assessed_results_has_no_score(self):
        self.assertIsNone(posture([self.r("C", "NOT_COLLECTED")]))

    def test_drift_directions(self):
        old = [self.r("A", "PASS", actual=1), self.r("B", "FAIL", actual=0), self.r("C", "PASS", actual=5)]
        new = [self.r("A", "FAIL", actual=0), self.r("B", "PASS", actual=1), self.r("C", "PASS", actual=6)]
        got = {d["control_id"]: d["direction"] for d in drift(old, new)}
        self.assertEqual(got, {"A": "worse", "B": "better", "C": "changed"})


# WHAT: A fake OpenAI-compatible server, so the AI path is tested with real HTTP.
class FakeAI(BaseHTTPRequestHandler):
    requests: list = []
    reply = "What this means\nTest answer."

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeAI.requests.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
        out = json.dumps({"choices": [{"message": {"role": "assistant", "content": FakeAI.reply}}]})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out.encode())

    def log_message(self, *a):
        pass


class AssistantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FakeAI)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/v1"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        FakeAI.requests = []
        self.row = {"control_id": "DB-01", "title": "Database does not listen on all interfaces",
                    "severity": "high", "operator": "ne", "expected": "0.0.0.0",
                    "actual": "0.0.0.0", "remediation": {"linux": "Set bind-address to 10.10.20.11."},
                    "rationale": "A database open to every network is easier to attack."}

    def test_offline_when_not_configured(self):
        a = Assistant(AIConfig()).explain(self.row, "linux", "Customer database (MariaDB)")
        self.assertEqual(a["source"], "offline")
        self.assertIn("on the customer database (MariaDB)", a["text"])  # B-07: keep the name's case
        self.assertIn("How to fix it", a["text"])
        self.assertIn("bind-address", a["text"])
        self.assertEqual(FakeAI.requests, [])

    def test_model_answer_and_cache(self):
        cfg = AIConfig(base_url=self.url, model="school-llm", api_key="k-123", timeout=5)
        asst = Assistant(cfg)
        a = asst.explain(self.row, "linux", "Customer database")
        self.assertEqual((a["source"], a["model"], a["text"]), ("model", "school-llm", FakeAI.reply))
        req = FakeAI.requests[0]
        self.assertEqual(req["path"], "/v1/chat/completions")
        self.assertEqual(req["auth"], "Bearer k-123")
        self.assertEqual(req["body"]["model"], "school-llm")
        self.assertTrue(asst.explain(self.row, "linux", "Customer database")["cached"])
        self.assertEqual(len(FakeAI.requests), 1)

    def test_falls_back_when_model_unreachable(self):
        cfg = AIConfig(base_url="http://127.0.0.1:9/v1", model="m", timeout=2)  # port 9: nothing there
        a = Assistant(cfg).explain(self.row, "linux")
        self.assertEqual(a["source"], "offline")
        self.assertIn("school wifi or the VPN", a["note"])

    def test_no_host_names_or_private_ips_sent(self):
        row = {**self.row, "actual": "bind 10.10.20.11 and 0.0.0.0", "host": "SHOP-DB-01"}
        sent = json.dumps(build_messages(row, "linux", "Customer database"))
        self.assertNotIn("10.10.20.11", sent)
        self.assertNotIn("SHOP-DB-01", sent)
        self.assertIn("0.0.0.0", sent)  # the finding itself is kept
        self.assertEqual(redact(["192.168.1.5", {"x": "127.0.0.1"}]), ["<ip-address>", {"x": "127.0.0.1"}])

    def test_self_test(self):
        ok, msg = self_test(AIConfig(base_url=self.url, model="school-llm"))
        self.assertTrue(ok, msg)
        ok, msg = self_test(AIConfig())
        self.assertFalse(ok)


@unittest.skipUnless(HAVE_FLASK, "Flask not installed")
class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        from compliance_checker.web import create_app
        self.pg = Playground()
        self.app = create_app(self.pg.inventory, self.pg.controls, self.pg.store, Assistant(AIConfig()))
        self.client = self.app.test_client()
        page = self.client.get("/").get_data(as_text=True)
        self.token = page.split("window.CC_TOKEN = ")[1].split(";")[0].strip('"')

    def tearDown(self):
        self.pg.close()

    def wait_for_scan(self):
        for _ in range(100):
            if not self.client.get("/api/scan/status").get_json()["running"]:
                return
            time.sleep(0.1)
        self.fail("scan did not finish")

    def test_empty_then_one_click_scan(self):
        self.assertFalse(self.client.get("/api/summary").get_json()["has_data"])
        self.assertEqual(self.client.post("/api/scan").status_code, 403)  # no token
        self.assertEqual(self.client.post("/api/scan", headers={"X-CC-Token": "wrong"}).status_code, 403)
        self.assertEqual(self.client.post("/api/scan", headers={"X-CC-Token": self.token}).status_code, 202)
        self.wait_for_scan()
        s = self.client.get("/api/summary").get_json()
        self.assertTrue(s["has_data"])
        self.assertEqual(len(s["hosts"]), 4)
        self.assertEqual(s["run"]["trigger"], "manual")

    def test_explain_endpoint(self):
        self.pg.scan()
        fail = build_summary(self.pg.store)["top_failures"][0]
        body = {"host_scan_id": fail["host_scan_id"], "control_id": fail["control_id"]}
        self.assertEqual(self.client.post("/api/explain", json=body).status_code, 403)
        r = self.client.post("/api/explain", json=body, headers={"X-CC-Token": self.token})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["source"], "offline")
        bad = self.client.post("/api/explain", json={"host_scan_id": 999, "control_id": "X"},
                               headers={"X-CC-Token": self.token})
        self.assertEqual(bad.status_code, 404)
        self.assertEqual(self.client.get("/api/assistant").get_json()["mode"], "offline")

    def test_baseline_and_evidence(self):
        run_id = self.pg.scan()
        h = {"X-CC-Token": self.token}
        self.assertEqual(self.client.post("/api/hosts/NOPE/baseline", headers=h).status_code, 404)
        self.assertEqual(self.client.post("/api/hosts/SHOP-WEB-01/baseline", headers=h).status_code, 200)
        ev = self.client.get(f"/api/runs/{run_id}/evidence.json")
        self.assertEqual(ev.status_code, 200)
        self.assertEqual(len(ev.get_json()["hosts"]), 4)


class HtmlReportTests(unittest.TestCase):
    def setUp(self):
        self.pg = Playground()
        self.addCleanup(self.pg.close)

    def test_report_after_drift_has_sections_and_org(self):
        from compliance_checker.html_report import render_report
        self.pg.scan()
        self.pg.apply_drift()
        self.pg.scan()
        html = render_report(self.pg.store, "SME Supermarket", "Demo")
        self.assertIn("SME Supermarket", html)
        self.assertIn("SHOP-WEB-01", html)
        self.assertIn("<!doctype html>", html.lower())

    def test_report_escapes_hostile_values(self):
        from compliance_checker.html_report import render_report
        self.pg.scan()
        html = render_report(self.pg.store, "<script>alert(1)</script>", "x")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_report_on_empty_store_does_not_crash(self):
        from compliance_checker.html_report import render_report
        html = render_report(self.pg.store, "Org", "Env")
        self.assertIn("Org", html)


# WHAT: A fake machine that pretends to run a scanner script, so the script path
# through the engine is tested without a VM (output below is real fyp-scan.sh output).
class FakeScriptTarget:
    description = "fake ssh target"

    def __init__(self, out="", err="", rc=0, fail_put=False):
        self.out, self.err, self.rc, self.fail_put = out, err, rc, fail_put
        self.uploaded, self.ran, self.cleaned = {}, [], []

    def put_text(self, path, text, *, mode=0o700, private_dir=None):
        if self.fail_put:
            from compliance_checker.targets import TargetError
            raise TargetError("could not copy the scan script")
        self.uploaded[path] = (text, mode, private_dir)

    def run_script(self, path, *, timeout=300):
        self.ran.append(path)
        return self.rc, self.out, self.err

    def run(self, command):
        self.cleaned.append(command)
        return ""

    def close(self):
        pass


SCRIPT_OUTPUT = """ubu-test|CIS-5.1.20|SSH root login disabled|no|yes|FAIL|2026-11-04T14:32:00+08:00
ubu-test|CIS-4.2.3|Firewall (ufw) active|active|active|PASS|2026-11-04T14:32:00+08:00
ubu-test|CIS-9.9.9|A rule Ace added today|yes|no|FAIL|2026-11-04T14:32:00+08:00
sudo: a password is required
ubu-test|SCORE|Compliance score|42 rules|15 passed|35%|2026-11-04T14:32:00+08:00
"""

BENCHMARK = HERE / "controls" / "cis-ubuntu-24.04.yaml"
SCANNER = HERE / "scripts" / "fyp-scan.sh"


class ScriptScanTests(unittest.TestCase):
    def setUp(self):
        from compliance_checker.script_scan import load_benchmark
        self.bench = load_benchmark(BENCHMARK)

    def test_catalogue_matches_the_script(self):
        # WHY: if Ace edits fyp-scan.sh and nobody updates the catalogue, the
        # dashboard would show rules with no agreed risk rating. Fail loudly here.
        from compliance_checker.script_scan import compare
        diff = compare(self.bench, SCANNER)
        self.assertEqual(diff["only_in_script"], [])
        self.assertEqual(diff["only_in_catalogue"], [])
        self.assertEqual(len(diff["both"]), 42)

    def test_every_rule_has_a_risk_rating_and_reason(self):
        for rule_id, control in self.bench.controls.items():
            self.assertIn(control.severity, ("low", "medium", "high", "critical"), rule_id)
            self.assertIn("Risk ", control.rationale, rule_id)
            self.assertTrue(control.remediation["linux"], rule_id)
            self.assertTrue(control.frameworks.get("cis_ubuntu_24_04"), rule_id)

    def test_parse_output_ignores_noise_and_reads_the_verdicts(self):
        from compliance_checker.script_scan import parse_output
        rows, score = parse_output(SCRIPT_OUTPUT)
        self.assertEqual([r.rule_id for r in rows], ["CIS-5.1.20", "CIS-4.2.3", "CIS-9.9.9"])
        self.assertEqual(rows[0].status, "FAIL")
        self.assertEqual(rows[0].actual, "yes")
        self.assertIn("15 passed", score)

    def test_scan_keeps_unknown_rules_and_marks_the_rest_not_collected(self):
        from compliance_checker.script_scan import run_script_scan
        target = FakeScriptTarget(out=SCRIPT_OUTPUT)
        results, error = run_script_scan(target, self.bench, SCANNER)
        self.assertIsNone(error)
        self.assertEqual(len(results), 42 + 1)  # catalogue + the rule only the script knows
        by_id = {r.control.id: r for r in results}
        self.assertEqual(by_id["CIS-5.1.20"].status.value, "FAIL")
        self.assertEqual(by_id["CIS-5.1.20"].control.severity, "critical")
        self.assertEqual(by_id["CIS-4.2.3"].status.value, "PASS")
        self.assertEqual(by_id["CIS-9.9.9"].control.severity, "medium")
        # a rule the script never reported is a gap, never a pass (D-04)
        self.assertEqual(by_id["CIS-7.2.2"].status.value, "NOT_COLLECTED")
        self.assertTrue(target.cleaned, "the uploaded script must be removed again")

    def test_sudo_refusal_is_explained_not_silent(self):
        from compliance_checker.script_scan import run_script_scan
        target = FakeScriptTarget(out="", err="sudo: a password is required", rc=1)
        results, error = run_script_scan(target, self.bench, SCANNER)
        self.assertEqual(results, [])
        self.assertIn("password for sudo", error)

    def test_installed_copy_is_not_uploaded(self):
        # SECURITY: with remote_script the root-owned copy is run as it is.
        from compliance_checker.script_scan import run_script_scan
        target = FakeScriptTarget(out=SCRIPT_OUTPUT)
        run_script_scan(target, self.bench, SCANNER, remote_script="/usr/local/sbin/fyp-scan.sh")
        self.assertEqual(target.uploaded, {})
        self.assertEqual(target.ran, ["/usr/local/sbin/fyp-scan.sh"])
        self.assertEqual(target.cleaned, [])

    def test_engine_scans_a_script_host_and_stores_it(self):
        from compliance_checker.engine import scan_host
        from compliance_checker.inventory import load_inventory
        tmp = Path(tempfile.mkdtemp(prefix="cc-script-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "inv.yaml").write_text(f"""organisation: SME Supermarket
environment: test
hosts:
  - name: UBU-WEB
    platform: linux
    transport: ssh
    address: 10.0.0.1
    username: ace
    scanner: script
    script: {SCANNER}
    benchmark: {BENCHMARK}
""", encoding="utf-8")
        host = load_inventory(tmp / "inv.yaml").hosts[0]
        with mock.patch.object(host, "open", return_value=FakeScriptTarget(out=SCRIPT_OUTPUT)):
            results, error = scan_host(host, [])
        self.assertIsNone(error)
        self.assertEqual(sum(1 for r in results if r["status"] == "FAIL"), 2)
        self.assertTrue(all(r["reference"] for r in results))

    def test_inventory_rejects_a_script_host_with_no_script(self):
        from compliance_checker.inventory import InventoryError, load_inventory
        tmp = Path(tempfile.mkdtemp(prefix="cc-script-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "bad.yaml").write_text("""organisation: x
environment: y
hosts:
  - name: UBU-WEB
    platform: linux
    transport: ssh
    scanner: script
""", encoding="utf-8")
        with self.assertRaises(InventoryError):
            load_inventory(tmp / "bad.yaml")


class CoverageWarningTests(unittest.TestCase):
    # FIX(B-08): a real VM scan showed 100% from a single check that could be read.
    def test_low_coverage_is_flagged(self):
        from compliance_checker.scoring import coverage
        results = [{"status": "PASS", "severity": "high"}] + \
                  [{"status": "NOT_COLLECTED", "severity": "high"}] * 12
        cov = coverage(results)
        self.assertTrue(cov["low"])
        self.assertEqual(cov["assessed"], 1)
        self.assertEqual(cov["total"], 13)

    def test_full_coverage_is_not_flagged(self):
        from compliance_checker.scoring import coverage
        results = [{"status": "PASS", "severity": "high"}] * 8 + \
                  [{"status": "FAIL", "severity": "low"}] * 2
        self.assertFalse(coverage(results)["low"])


if __name__ == "__main__":
    unittest.main()
