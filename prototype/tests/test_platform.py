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


if __name__ == "__main__":
    unittest.main()
