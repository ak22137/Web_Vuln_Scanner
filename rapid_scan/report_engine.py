"""Canonical scan result and report writers.

Reports consume structured test/finding data only. Missing CVSS or MITRE
evidence is represented explicitly instead of being guessed from prose.
"""

import html
import hashlib
import json
import os
import re
import tempfile
import textwrap
from rapid_scan.cvss_engine import calculate_base_score, vector_from_facts
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


def _public_value(value):
    """Remove local filesystem details from user-facing report artifacts."""
    if isinstance(value, dict):
        return {key: _public_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_public_value(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"[A-Za-z]:\\[^\s\"']+", "[local path redacted]", value)
        value = re.sub(r"(?<![A-Za-z0-9])/(?:tmp|var|home)/[^\s\"']+", "[local path redacted]", value)
    return value


def _finding_id(test, finding):
    """Stable identity across presentation ordering changes."""
    identity = "|".join(str(part or "") for part in (
        test.get("test_id"), finding.get("finding_type"),
        finding.get("header"), (finding.get("evidence") or {}).get("url")
        if isinstance(finding.get("evidence"), dict) else "",
        (finding.get("evidence") or {}).get("parameter")
        if isinstance(finding.get("evidence"), dict) else "",
    ))
    return f"{test.get('test_id', 'test')}-{hashlib.sha256(identity.encode()).hexdigest()[:12]}"


def _evidence_schema(evidence, verification):
    evidence = evidence if isinstance(evidence, dict) else {"response": {"body_excerpt": str(evidence)}}
    return {
        "url": evidence.get("url"), "method": evidence.get("method"),
        "parameter": evidence.get("parameter"), "status_code": evidence.get("status_code"),
        "request": evidence.get("request"), "response": evidence.get("response"),
        "payload": evidence.get("payload"), "source": evidence.get("source"),
        "verification_result": verification,
        **{key: value for key, value in evidence.items()
           if key not in {"url", "method", "parameter", "status_code", "request", "response", "payload", "source"}},
    }


def build_canonical_result(state):
    tests = _public_value(state.get("tests", []))
    for test in tests:
        if str(test.get("status", "")).lower() in {"failed", "skipped"}:
            error_text = "; ".join(error.get("message", str(error)) if isinstance(error, dict) else str(error)
                                   for error in test.get("errors", []))
            test.setdefault("assessment_reason", error_text or
                            "Test did not complete; findings were not assessed.")
        elif not test.get("findings"):
            test.setdefault("assessment_reason", "Test completed without a detected finding.")
    completed = sum(str(item.get("status", "")).lower() == "completed" for item in tests)
    failed = sum(str(item.get("status", "")).lower() == "failed" for item in tests)
    skipped = sum(str(item.get("status", "")).lower() == "skipped" for item in tests)
    findings = []
    for test in tests:
        for finding in test.get("findings", []):
            cvss = finding.get("cvss")
            vector = finding.get("cvss_vector")
            if not vector and finding.get("verified"):
                vector = vector_from_facts(finding.get("impact_facts"))
            if vector:
                try:
                    cvss = {"vector": vector, "version": "3.1",
                            "base_score": calculate_base_score(vector)}
                except ValueError as error:
                    cvss = {"status": "Invalid Vector", "error": str(error)}
            findings.append({
                "id": _finding_id(test, finding),
                "title": finding.get("title", "Unclassified scanner finding"),
                "finding_type": finding.get("finding_type", "unclassified"),
                "header": finding.get("header"),
                "category": finding.get("category", "Scanner finding"),
                "status": finding.get("finding_status", "Not Assessed"),
                "status_reason": finding.get("status_reason", "No status rationale was supplied."),
                "verified": bool(finding.get("verified", False)),
                "severity": finding.get("severity", "Unknown"),
                "confidence": finding.get("confidence", "Low"),
                "impact_facts": finding.get("impact_facts"),
                "verification": finding.get("verification", {"status": "not_run"}),
                "cvss": cvss or {"status": "Not Assessed"},
                "evidence": _evidence_schema(finding.get("evidence"), finding.get("verification", {})),
                "remediation": finding.get("remediation", "Review and remediate the reported condition; verify manually."),
                "references": finding.get("references", []),
                "mitre": map_finding(finding),
            })
    severity_rank = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    confirmed_severities = [finding["severity"] for finding in findings
                            if finding["status"] == "Confirmed" and finding["severity"] in severity_rank]
    overall_risk = (max(confirmed_severities, key=lambda value: severity_rank[value])
                    if confirmed_severities else "No Confirmed Findings")
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
                     "failed": failed, "skipped": skipped,
                     "not_assessed": sum(f["status"] == "Not Assessed" for f in findings)},
        "tests": tests,
        "findings": findings,
        "risk_summary": {status.lower().replace(" ", "_"): sum(f["status"] == status for f in findings)
                         for status in ("Confirmed", "Potential", "Inconclusive",
                                        "Not Detected", "Not Assessed")},
        "executive_risk_summary": {"overall_risk": overall_risk,
                                    "basis": "Confirmed findings only"},
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
    """Write a paginated, dependency-free text PDF without dropping evidence."""
    visible = [wrapped for line in lines for wrapped in textwrap.wrap(str(line), width=90) or [""]]
    pages = [visible[index:index + 48] for index in range(0, len(visible), 48)] or [[""]]
    objects = ["<< /Type /Catalog /Pages 2 0 R >>", None]
    page_numbers = []
    for page_lines in pages:
        page_number = len(objects) + 1
        content_number = page_number + 1
        page_numbers.append(page_number)
        stream = "BT /F1 9 Tf 40 760 Td " + " ".join(
            f"({_pdf_escape(line)}) Tj 0 -14 Td" for line in page_lines) + " ET"
        objects.extend([None, f"<< /Length {len(stream.encode('latin-1', 'replace'))} >>\nstream\n{stream}\nendstream"])
    font_number = len(objects) + 1
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects[1] = (f"<< /Type /Pages /Kids [{' '.join(f'{number} 0 R' for number in page_numbers)}] "
                  f"/Count {len(page_numbers)} >>")
    for page_number in page_numbers:
        objects[page_number - 1] = ("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                                    f"/Resources << /Font << /F1 {font_number} 0 R >> >> "
                                    f"/Contents {page_number + 1} 0 R >>")
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
    txt_path = os.path.join(output_dir, f"security_report_{scan_id}.txt")
    mitre_path = os.path.join(output_dir, f"mitre_mapping_{scan_id}.json")
    _atomic_text(json_path, json.dumps(result, indent=2, ensure_ascii=False))
    _atomic_text(mitre_path, json.dumps({"scan_id": scan_id, "mappings": result["mitre"]},
                                        indent=2, ensure_ascii=False))
    text_lines = ["WebGuard Security Report", f"Target: {result['target']}",
                  f"Execution Mode: {result['scan']['mode']}",
                  f"Completion: {result['scan']['completion']}",
                  f"Coverage: {json.dumps(result['coverage'])}", ""]
    text_lines.extend([f"Overall Risk: {result['executive_risk_summary']['overall_risk']}",
                       f"Risk Basis: {result['executive_risk_summary']['basis']}", ""])
    for finding in result["findings"]:
        text_lines.extend([f"Finding Type: {finding['finding_type']}",
                           f"Title: {finding['title']}",
                           f"Status: {finding['status']}",
                           f"Severity: {finding['severity']}",
                           f"Confidence: {finding['confidence']}",
                           f"CVSS: {json.dumps(finding['cvss'])}",
                           f"Remediation: {finding['remediation']}",
                           f"Evidence: {json.dumps(finding['evidence'], ensure_ascii=False)}", ""])
    _atomic_text(txt_path, "\n".join(text_lines))
    report_rows = []
    for test in result["tests"]:
        test_findings = test.get("findings", []) or [{}]
        for finding in test_findings:
            report_rows.append(
                f"<tr><td>{html.escape(str(test.get('name', test.get('test_id', 'Unknown'))))}</td>"
                f"<td>{html.escape(str(test.get('status', 'Unknown')))}</td>"
                f"<td>{html.escape(str(finding.get('title', 'No finding')))}</td>"
                f"<td>{html.escape(str(finding.get('finding_status', 'Not Assessed')))}</td>"
                f"<td>{html.escape(str(finding.get('evidence', ''))[:500])}</td>"
                f"<td>{html.escape(str(test.get('assessment_reason', '')))}</td></tr>")
    rows = "".join(report_rows)
    html_doc = ("<!doctype html><meta charset='utf-8'><title>WebGuard report</title>"
                "<h1>WebGuard Security Report</h1>"
                f"<p><b>Target:</b> {html.escape(str(result['target']))}</p>"
                f"<p><b>Execution mode:</b> {html.escape(str(result['scan']['mode']))}</p>"
                f"<p><b>Completion:</b> {html.escape(str(result['scan']['completion']))}</p>"
                f"<p><b>Coverage:</b> {html.escape(json.dumps(result['coverage']))}</p>"
                f"<p><b>Overall risk:</b> {html.escape(result['executive_risk_summary']['overall_risk'])} "
                f"({html.escape(result['executive_risk_summary']['basis'])})</p>"
                "<table border='1' cellpadding='6'><tr><th>Test</th><th>Status</th>"
                f"<th>Finding</th><th>Finding status</th><th>Evidence</th><th>Assessment</th></tr>{rows}</table>"
                "<h2>Findings</h2>"
                f"<pre>{html.escape(json.dumps(result['findings'], indent=2))}</pre>")
    _atomic_text(html_path, html_doc)
    pdf_lines = ["WebGuard Security Report", f"Target: {result['target']}",
                 f"Execution mode: {result['scan']['mode']}",
                 f"Completion: {result['scan']['completion']}",
                 f"Coverage: {result['coverage']}",
                 f"Overall Risk: {result['executive_risk_summary']['overall_risk']}"]
    pdf_lines.extend(f"{t.get('name', t.get('test_id'))}: {t.get('status')}"
                     for t in result["tests"])
    for finding in result["findings"]:
        pdf_lines.extend(["", f"Finding: {finding['title']} [{finding['status']}]",
                          f"Type: {finding['finding_type']}", f"Severity: {finding['severity']}",
                          f"Confidence: {finding['confidence']}", f"CVSS: {json.dumps(finding['cvss'])}",
                          f"Remediation: {finding['remediation']}",
                          f"References: {json.dumps(finding['references'])}",
                          f"Evidence: {json.dumps(finding['evidence'], ensure_ascii=False)}"])
    _write_simple_pdf(pdf_path, pdf_lines)
    return {"json": json_path, "html": html_path, "pdf": pdf_path,
            "txt": txt_path, "mitre": mitre_path}
