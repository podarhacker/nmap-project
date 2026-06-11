"""
runner.py
=========
Bridges the API to the existing recon code (nmap/tools). Runs one scan to
completion in a background thread and persists the result.

Two modes:
  - "offline" : offline_recon.run_offline_recon  (no LLM, default — always works)
  - "llm"     : agent.run_agent                  (needs a provider API key)

Both produce a run object that report.py can render, so persistence is uniform.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

# Make the flat tool modules importable (they live in nmap/tools).
_TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

import report  # noqa: E402  (from nmap/tools)

from .db import SessionLocal, Scan, Finding


def _dig(d: dict, *keys):
    """Walk nested dict keys, returning the first value found or None."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def extract_findings(payload: dict) -> list[dict]:
    """Pull structured findings from a recon bundle payload (best-effort).

    Handles nuclei-style parsed entries (severity + name nested under 'info')
    and nmap host NSE script output. Tools without a severity are skipped.
    """
    out: list[dict] = []
    for r in payload.get("results", []):
        tool = r.get("tool", "")
        for item in (r.get("parsed") or []):
            if not isinstance(item, dict):
                continue
            sev = _dig(item, "severity") or _dig(item, "info", "severity")
            if not sev:
                continue
            name = (item.get("name") or _dig(item, "info", "name")
                    or item.get("template-id") or item.get("templateID") or tool)
            out.append({
                "tool": tool, "severity": str(sev).lower(),
                "name": str(name)[:255], "detail": json.dumps(item)[:2000],
            })
        # nmap host NSE scripts -> info-level findings.
        for host in (r.get("hosts") or []):
            for sid, output in (host.get("hostscripts") or {}).items():
                out.append({
                    "tool": "nmap", "severity": "info",
                    "name": str(sid)[:255], "detail": str(output)[:2000],
                })
            # per-port NSE scripts (the vuln scan attaches results here, not at
            # host level) -> info-level findings, labelled with the port.
            for port in (host.get("ports") or []):
                for sid, output in (port.get("scripts") or {}).items():
                    label = f"{port.get('port')}/{port.get('protocol', 'tcp')} {sid}"
                    out.append({
                        "tool": "nmap", "severity": "info",
                        "name": label[:255], "detail": str(output)[:2000],
                    })
    return out


_SEV_KEYS = ("critical", "high", "medium", "low", "info")


def _count_from_findings(findings: list[dict]) -> dict[str, int]:
    """Severity tally over the extracted findings, so the dashboard badges
    always match the Findings table exactly."""
    counts = {s: 0 for s in _SEV_KEYS}
    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _persist(scan_id: int, **fields) -> None:
    with SessionLocal() as s:
        row = s.get(Scan, scan_id)
        if row is None:
            return
        for k, v in fields.items():
            setattr(row, k, v)
        s.commit()


def run_scan(scan_id: int) -> None:
    """Execute the scan identified by `scan_id` and persist every outcome.

    Designed to run in a background thread/task. All errors are captured into
    the row (status='failed') — a crashing scan never takes down the server.
    """
    with SessionLocal() as s:
        row = s.get(Scan, scan_id)
        if row is None:
            return
        target = row.target
        mode = row.mode
        provider = row.provider or "anthropic"
        scope = json.loads(row.scope or "null")

    _persist(scan_id, status="running")

    try:
        if mode == "llm":
            import agent  # imported lazily: needs LLM client libs/keys
            run = agent.run_agent(
                target, provider=provider, allowed_scope=scope, verbose=False)
            bundle_json = json.dumps({
                "target": run.target, "provider": run.provider, "model": run.model,
                "steps": run.steps, "stopped_reason": run.stopped_reason,
                "tool_results": run.tool_results,
            }, indent=2)
            stopped = run.stopped_reason
            steps = run.steps
        else:  # offline (default)
            import offline_recon
            bundle = offline_recon.run_offline_recon(
                target, allowed_scope=scope, verbose=False)
            run = bundle
            bundle_json = json.dumps(offline_recon.bundle_to_payload(bundle), indent=2)
            stopped = bundle.stopped_reason
            steps = bundle.steps

        md = report.render_markdown(run)
        html = report.render_html(run)

        # Structured findings (offline bundle carries 'results' with parsed/hosts).
        try:
            findings = extract_findings(json.loads(bundle_json))
        except Exception:
            findings = []

        # Badges count the findings themselves so they always agree with the
        # Findings table. Fall back to scraping the report text only when no
        # structured findings were extracted.
        counts = _count_from_findings(findings) if findings else report.count_severities(md)

        _persist(
            scan_id,
            status="done",
            stopped_reason=stopped,
            steps=steps,
            report_md=md,
            report_html=html,
            bundle_json=bundle_json,
            sev_counts=json.dumps(counts),
            finished_at=datetime.now(timezone.utc),
        )
        if findings:
            with SessionLocal() as s:
                s.add_all([Finding(scan_id=scan_id, **f) for f in findings])
                s.commit()
    except Exception as exc:  # any failure -> failed row, server stays up
        _persist(
            scan_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            finished_at=datetime.now(timezone.utc),
        )
