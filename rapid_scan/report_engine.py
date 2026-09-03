"""Canonical scan result and report writers.

Reports consume structured test/finding data only. Missing CVSS or MITRE
evidence is represented explicitly instead of being guessed from prose.
"""

import html
import json
import os
import tempfile
from rapid_scan.cvss_engine import calculate_base_score
from rapid_scan.mitre_mapping import map_finding


def _atomic_text(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".report-", suffix=".tmp",
                                     dir=os.path.dirname(path), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def build_canonical_result(state):
    tests = state.get("tests", [])
    completed = sum(str(item.get("status", "")).lower() == "completed" for item in tests)
    failed = sum(str(item.get("status", "")).lower() == "failed" for item in tests)
    skipped = sum(str(item.get("status", "")).lower() == "skipped" for item in tests)
    findings = []
    for test in tests:
        for finding in test.get("findings", []):
            cvss = finding.get("cvss")
            vector = finding.get("cvss_vector")
            if vector:
                try:
                    cvss = {"vector": vector, "version": "3.1",
                            "base_score": calculate_base_score(vector)}
                except ValueError as error:
                    cvss = {"status": "Invalid Vector", "error": str(error)}
            findings.append({
                "id": f"{test.get('test_id', 'test')}-{len(findings) + 1}",
                "title": finding.get("title", "Unclassified scanner finding"),
                "finding_type": finding.get("finding_type", "unclassified"),
                "header": finding.get("header"),
                "category": finding.get("category", "Scanner finding"),
                "status": finding.get("finding_status", "Not Assessed"),
                "verified": bool(finding.get("verified", False)),
                "severity": finding.get("severity", "Unknown"),
                "confidence": finding.get("confidence", "Low"),
                "verification": finding.get("verification", {"status": "not_run"}),
                "cvss": cvss or {"status": "Not Assessed"},
                "evidence": finding.get("evidence", ""),
                "remediation": finding.get("remediation", "Review and remediate the reported condition; verify manually."),
                "mitre": map_finding(finding),
            })
    return {
        "schema_version": "1.0",
        "target": state.get("url"),
        "scan": {
            "scan_id": state.get("scan_id"),
            "mode": state.get("scan_mode", "UNKNOWN"),
            "mode_reason": state.get("mode_reason"),
            "status": state.get("status"),
            "started_at": state.get("started_at"),
            "updated_at": state.get("updated_at"),
            "completion": state.get("scan_completion", "UNKNOWN"),
        },
        "coverage": {"total": len(tests), "completed": completed,
                     "failed": failed, "skipped": skipped},
        "tests": tests,
        "findings": findings,
        "risk_summary": {status.lower().replace(" ", "_"): sum(f["status"] == status for f in findings)
                         for status in ("Confirmed", "Potential", "Inconclusive",
                                        "Not Detected", "Not Assessed")},
        "mitre": [{"finding_id": f["id"], "mappings": f["mitre"] or ["No direct mapping"]}
                  for f in findings],
        "limitations": (["RapidScan Docker backend unavailable"]
                        if state.get("scan_mode") != "FULL" else []) +
                       (["One or more RapidScan tests failed or were skipped"]
                        if state.get("scan_completion") == "PARTIAL" else []),
    }


def _pdf_escape(value):
    return str(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _write_simple_pdf(path, lines):
    # Dependency-free, text-only PDF for environments without a PDF package.
    # Keep every report line; callers may provide many findings.  The
    # dependency-free renderer is intentionally plain, but it must not drop
    # findings from the exported artifact.
    visible = [line[:110] for line in lines]
    stream = "BT /F1 9 Tf 40 760 Td " + " ".join(
        f"({_pdf_escape(line)}) Tj 0 -14 Td" for line in visible) + " ET"
    objects = [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        f"<< /Length {len(stream.encode('latin-1', 'replace'))} >>\nstream\n{stream}\nendstream",
    ]
    output = "%PDF-1.4\n"
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(output.encode("latin-1")))
        output += f"{number} 0 obj\n{obj}\nendobj\n"
    xref = len(output.encode("latin-1"))
    output += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n"
    output += "".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:])
    output += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    with open(path, "wb") as handle:
        handle.write(output.encode("latin-1", "replace"))


def write_canonical_reports(state, output_dir):
    result = build_canonical_result(state)
    scan_id = state.get("scan_id", "scan")
    json_path = os.path.join(output_dir, f"security_report_{scan_id}.json")
    html_path = os.path.join(output_dir, f"security_report_{scan_id}.html")
    pdf_path = os.path.join(output_dir, f"security_report_{scan_id}.pdf")
    mitre_path = os.path.join(output_dir, f"mitre_mapping_{scan_id}.json")
    _atomic_text(json_path, json.dumps(result, indent=2, ensure_ascii=False))
    _atomic_text(mitre_path, json.dumps({"scan_id": scan_id, "mappings": result["mitre"]},
                                        indent=2, ensure_ascii=False))
    report_rows = []
    for test in result["tests"]:
        test_findings = test.get("findings", []) or [{}]
        for finding in test_findings:
            report_rows.append(
                f"<tr><td>{html.escape(str(test.get('name', test.get('test_id', 'Unknown'))))}</td>"
                f"<td>{html.escape(str(test.get('status', 'Unknown')))}</td>"
                f"<td>{html.escape(str(finding.get('title', 'No finding')))}</td>"
                f"<td>{html.escape(str(finding.get('finding_status', 'Not Assessed')))}</td>"
                f"<td>{html.escape(str(finding.get('evidence', ''))[:500])}</td></tr>")
    rows = "".join(report_rows)
    html_doc = ("<!doctype html><meta charset='utf-8'><title>WebGuard report</title>"
                "<h1>WebGuard Security Report</h1>"
                f"<p><b>Target:</b> {html.escape(str(result['target']))}</p>"
                f"<p><b>Execution mode:</b> {html.escape(str(result['scan']['mode']))}</p>"
                f"<p><b>Completion:</b> {html.escape(str(result['scan']['completion']))}</p>"
                f"<p><b>Coverage:</b> {html.escape(json.dumps(result['coverage']))}</p>"
                "<table border='1' cellpadding='6'><tr><th>Test</th><th>Status</th>"
                f"<th>Finding</th><th>Finding status</th><th>Evidence</th></tr>{rows}</table>"
                "<h2>Findings</h2>"
                f"<pre>{html.escape(json.dumps(result['findings'], indent=2))}</pre>")
    _atomic_text(html_path, html_doc)
    pdf_lines = ["WebGuard Security Report", f"Target: {result['target']}",
                 f"Execution mode: {result['scan']['mode']}",
                 f"Completion: {result['scan']['completion']}",
                 f"Coverage: {result['coverage']}"]
    pdf_lines.extend(f"{t.get('name', t.get('test_id'))}: {t.get('status')}"
                     for t in result["tests"])
    pdf_lines.extend(f"Finding: {finding['title']} [{finding['status']}]"
                     for finding in result["findings"])
    _write_simple_pdf(pdf_path, pdf_lines)
    return {"json": json_path, "html": html_path, "pdf": pdf_path, "mitre": mitre_path}
