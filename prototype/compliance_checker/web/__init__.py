"""Local web dashboard with the one-click "Run scan" button.

Start it with:  python -m compliance_checker dashboard   (then open http://127.0.0.1:8300)

The page is static HTML + JavaScript; all numbers come from /api/summary, which
reads the same history store the CLI writes. Charts are drawn as inline SVG, so
the dashboard works in an offline lab with no internet (no CDN libraries).
"""
from __future__ import annotations

import secrets
import threading
from datetime import datetime, timezone
from typing import Any

from flask import Flask, abort, jsonify, render_template, request

from ..assistant import Assistant
from ..engine import run_scan
from ..inventory import Inventory, load_inventory
from ..models import Control
from ..scoring import build_summary
from ..store import Store


# WHAT: Tracks the one scan that may run at a time, for the progress display.
class ScanState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running = False
        self.started_at: str | None = None
        self.hosts: dict[str, str] = {}
        self.last_run_id: int | None = None
        self.error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"running": self.running, "started_at": self.started_at, "hosts": dict(self.hosts),
                "last_run_id": self.last_run_id, "error": self.error}


def create_app(inventory: Inventory, controls: list[Control], store: Store,
               assistant: Assistant | None = None) -> Flask:
    app = Flask(__name__)
    state = ScanState()
    assistant = assistant or Assistant()
    # SECURITY: any web page you visit could try to POST to localhost:8300 and start
    # scans (cross-site request forgery). Each POST must carry this random token,
    # which only our own page knows. A new token is made every time the server starts.
    token = secrets.token_urlsafe(24)

    def require_token() -> None:
        if not secrets.compare_digest(request.headers.get("X-CC-Token", ""), token):
            abort(403)

    def do_scan(trigger: str) -> None:
        try:
            # WHY: reload the inventory each time so a newly added VM is picked up
            # without restarting the dashboard.
            inv = load_inventory(inventory.path)
            state.last_run_id = run_scan(inv, controls, store, trigger=trigger,
                                         on_progress=lambda h, s: state.hosts.__setitem__(h, s))
        except Exception as exc:  # show it on the page instead of losing it in the console
            state.error = f"{type(exc).__name__}: {exc}"
        finally:
            state.running = False

    @app.get("/")
    def index():
        return render_template("index.html", token=token, organisation=inventory.organisation,
                               environment=inventory.environment)

    @app.get("/api/summary")
    def summary():
        inv = inventory
        data = build_summary(store, inv.organisation, inv.environment)
        data["inventory_hosts"] = [{"name": h.name, "role": h.role, "kind": h.kind,
                                    "platform": h.platform, "transport": h.transport}
                                   for h in inv.hosts]
        data["controls_total"] = len(controls)
        return jsonify(data)

    @app.post("/api/scan")
    def start_scan():
        require_token()
        with state.lock:
            if state.running:
                return jsonify({"started": False, "reason": "a scan is already running"}), 409
            state.running, state.error = True, None
            state.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            state.hosts = {h.name: "queued" for h in inventory.hosts}
        threading.Thread(target=do_scan, args=("manual",), daemon=True).start()
        return jsonify({"started": True}), 202

    @app.get("/api/scan/status")
    def scan_status():
        return jsonify(state.as_dict())

    @app.get("/api/host-scans/<int:host_scan_id>")
    def host_results(host_scan_id: int):
        return jsonify(store.results(host_scan_id))

    @app.post("/api/hosts/<name>/baseline")
    def set_baseline(name: str):
        require_token()
        hs = store.set_baseline(name)
        if hs is None:
            return jsonify({"ok": False, "reason": "no successful scan of this host yet"}), 404
        return jsonify({"ok": True, "host_scan_id": hs})

    @app.get("/api/assistant")
    def assistant_status():
        return jsonify(assistant.status())

    # WHAT: Explain one failed check in plain English (AI model if configured, else offline).
    # SECURITY: the browser sends only ids; the check itself is read from our own store,
    # so a page cannot make us send arbitrary text to the AI provider.
    @app.post("/api/explain")
    def explain():
        require_token()
        body = request.get_json(silent=True) or {}
        try:
            hs_id = int(body.get("host_scan_id"))
        except (TypeError, ValueError):
            abort(400)
        hs = store.host_scan(hs_id)
        row = next((r for r in store.results(hs_id) if r["control_id"] == body.get("control_id")),
                   None) if hs else None
        if row is None:
            abort(404)
        return jsonify(assistant.explain(row, hs["platform"], hs.get("role", "")))

    # WHAT: Full evidence of one run as JSON (for the report appendix).
    @app.get("/api/runs/<int:run_id>/evidence.json")
    def evidence(run_id: int):
        hosts = []
        for hs in store.host_scans(run_id):
            hosts.append({**hs, "results": store.results(hs["id"])})
        if not hosts:
            abort(404)
        resp = jsonify({"run_id": run_id, "hosts": hosts})
        resp.headers["Content-Disposition"] = f"attachment; filename=run-{run_id}-evidence.json"
        return resp

    return app


__all__ = ["create_app", "load_inventory"]
