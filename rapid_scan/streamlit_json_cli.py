import re
import subprocess
import streamlit as st
import threading
import queue
import pandas as pd
import os
import json
import tempfile
import shutil
import sys
from datetime import datetime, timezone
from rapid_scan.report_engine import write_canonical_reports

PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
SCAN_RESULTS_DIR = os.path.join(PROJECT_ROOT, 'scan_results')
SCAN_HISTORY_FILE = os.path.join(SCAN_RESULTS_DIR, 'scan_history.json')

# A queue to handle real-time output
output_queue = queue.Queue()

# Add highest_threat_level as a global variable at the top of the file
highest_threat_level = ""
# Function to clean ANSI escape sequences from the logs
def clean_ansi_codes(log_line):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', log_line)


def _text_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value or '')

def _write_json_atomic(path, data):
    """Write scan state atomically so a Streamlit rerun never reads half JSON."""
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix='.scan-', suffix='.tmp', dir=directory, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def _persist_scan_state(state):
    _write_json_atomic(os.path.join(SCAN_RESULTS_DIR, f"scan_{state['scan_id']}.json"), state)
    history = []
    if os.path.exists(SCAN_HISTORY_FILE):
        try:
            with open(SCAN_HISTORY_FILE, encoding='utf-8') as handle:
                history = json.load(handle)
        except (OSError, ValueError, TypeError):
            history = []
    record = {key: state.get(key) for key in
              ('scan_id', 'url', 'status', 'stage', 'started_at', 'updated_at',
               'highest_threat_level', 'scan_mode', 'mode_reason', 'scan_completion', 'error')}
    record['result_file'] = os.path.basename(state['result_file']) if state.get('result_file') else None
    record['raw_log_file'] = os.path.basename(state['raw_log_file']) if state.get('raw_log_file') else None
    record['rapidscan_result_file'] = (os.path.basename(state['rapidscan_result_file'])
                                      if state.get('rapidscan_result_file') else None)
    history = [item for item in history if item.get('scan_id') != record['scan_id']]
    history.append(record)
    history.sort(key=lambda item: item.get('updated_at') or '', reverse=True)
    _write_json_atomic(SCAN_HISTORY_FILE, history)


def load_scan_history(limit=50):
    """Return historical scan metadata independently of deletable run artifacts."""
    if not os.path.exists(SCAN_HISTORY_FILE):
        return []
    try:
        with open(SCAN_HISTORY_FILE, encoding='utf-8') as handle:
            history = json.load(handle)
        return history[:limit] if isinstance(history, list) else []
    except (OSError, ValueError, TypeError):
        return []


def create_scan_state(url):
    """Create a durable scan record before long-running pre-scan work."""
    now = datetime.now(timezone.utc).isoformat()
    state = {"scan_id": datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'),
             "url": url, "status": "Running", "stage": "Preparing scan",
             "started_at": now, "updated_at": now, "highest_threat_level": "",
             "results": [], "tests": [], "scan_mode": "UNKNOWN",
             "mode_reason": None, "error": None}
    _persist_scan_state(state)
    return state


def update_scan_stage(scan_id, stage, status=None, error=None):
    """Persist a workflow stage without disturbing scan results."""
    path = os.path.join(SCAN_RESULTS_DIR, f"scan_{scan_id}.json")
    try:
        with open(path, encoding='utf-8') as handle:
            state = json.load(handle)
    except (OSError, ValueError):
        return
    state["stage"] = stage
    if status:
        state["status"] = status
    if error:
        state["error"] = error
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    _persist_scan_state(state)


def load_latest_scan_state():
    """Return the newest persisted scan, including scans that are still running."""
    if not os.path.isdir(SCAN_RESULTS_DIR):
        return None
    paths = [os.path.join(SCAN_RESULTS_DIR, name) for name in os.listdir(SCAN_RESULTS_DIR)
             if name.startswith('scan_') and name.endswith('.json')
             and name != os.path.basename(SCAN_HISTORY_FILE)]
    newest = None
    for path in paths:
        try:
            with open(path, encoding='utf-8') as handle:
                state = json.load(handle)
            if not isinstance(state, dict) or not state.get('scan_id'):
                continue
            # Older snapshots recorded only Failed/error=null. Recover a useful
            # diagnostic from their raw log so the UI is not misleading.
            if state.get('status') == 'Failed' and not state.get('error'):
                raw_log = state.get('raw_log_file')
                if raw_log and os.path.exists(raw_log):
                    with open(raw_log, encoding='utf-8', errors='replace') as log_handle:
                        tail = log_handle.read()[-2000:].strip()
                    state['error'] = tail or 'Scanner failed without diagnostic output.'
            if newest is None or state.get('updated_at', '') > newest.get('updated_at', ''):
                newest = state
        except (OSError, ValueError, TypeError):
            continue
    return newest


def write_vulnerability_info_to_file(url, scan_results, timestamp=None, raw_output=''):
    scan_results_dir = SCAN_RESULTS_DIR
    os.makedirs(scan_results_dir, exist_ok=True)

    timestamp = timestamp or datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    filename = os.path.join(scan_results_dir, f'vulnerability_scan_{timestamp}.txt')
    
    mitre_dir = os.path.join(PROJECT_ROOT, 'Mitre-Att&ck', 'src', 'ScenarioBank')
    os.makedirs(mitre_dir, exist_ok=True)
    mitre_filename = os.path.join(mitre_dir, f'vulnerability_details_{timestamp}.txt')

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"Vulnerability Scan Results for {url}\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
        
        for result in scan_results:
            f.write(f"Test: {result.get('Test Name', 'Unknown')}\n")
            f.write(f"Status: {result.get('Status', 'Unknown')}\n")
            f.write(f"Finding Status: {result.get('Finding Status', 'Not Assessed')}\n")
            f.write(f"Threat Level: {result.get('Threat Level', 'Unknown')}\n")
            if result.get('Definition'):
                # Clean ANSI codes and [0m from the definition
                clean_definition = clean_ansi_codes(_text_value(result['Definition'])).replace('[0m', '')
                f.write(f"Vulnerability Definition: {clean_definition}\n")
            if result.get('Remediation'):
                # Clean ANSI codes and [0m from the remediation
                clean_remediation = clean_ansi_codes(_text_value(result['Remediation'])).replace('[0m', '')
                f.write(f"Vulnerability Remediation: {clean_remediation}\n")
            f.write("\n" + "-"*50 + "\n\n")
    
    with open(mitre_filename, 'w', encoding='utf-8') as f:
        f.write(f"Detailed Vulnerability Information for {url}\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
        f.write("The scenario is as follows:\n")
        for result in scan_results:
            if _text_value(result.get('Definition')).strip() and _text_value(result.get('Remediation')).strip():
                f.write(f"Test: {result.get('Test Name', 'Unknown')}\n")
                clean_definition = clean_ansi_codes(_text_value(result['Definition'])).replace('[0m', '')
                clean_remediation = clean_ansi_codes(_text_value(result['Remediation'])).replace('[0m', '')
                f.write(f"Vulnerability Definition: {clean_definition}\n")
                f.write(f"Vulnerability Remediation: {clean_remediation}\n")
                f.write("\n" + "-"*50 + "\n\n")
    
    
    raw_filename = os.path.join(scan_results_dir, f'vulnerability_scan_{timestamp}.log')
    with open(raw_filename, 'w', encoding='utf-8') as f:
        f.write(raw_output)

    return filename, mitre_filename, raw_filename

# Function to run the scanner in a separate thread
def run_scan_real_time(url, output_queue):
    """Run the full Docker RapidScan backend; never substitute a partial scan."""
    mode = os.environ.get("WEBGUARD_SCANNER_MODE", "auto").lower()
    docker_available = shutil.which("docker") is not None
    if mode == "local":
        output_queue.put({"type": "ERROR", "message": "Local scanner mode is disabled; full Docker RapidScan is required.", "return_code": -1})
        return
    if not docker_available:
        output_queue.put({"type": "ERROR", "message": "Docker executable was not found; full RapidScan cannot run.", "return_code": -1})
        return

    try:
        docker_info = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, text=True, timeout=10)
        image_info = subprocess.run(["docker", "image", "inspect", "rapidscan"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    text=True, timeout=10)
        docker_ready = docker_info.returncode == 0
        image_ready = image_info.returncode == 0
        docker_error = (docker_info.stderr.strip() if not docker_ready else
                        image_info.stderr.strip() if not image_ready else "")
    except (OSError, subprocess.SubprocessError) as exc:
        docker_ready = False
        image_ready = False
        docker_error = str(exc)
    else:
        docker_error = docker_error or "Docker RapidScan preflight failed."

    if not docker_ready or not image_ready:
        output_queue.put({"type": "ERROR", "message": docker_error, "return_code": -1})
        return

    output_directory = tempfile.mkdtemp(prefix="webguard-rapidscan-")
    structured_path = os.path.join(output_directory, "result.json")
    command = ["docker", "run", "--rm", "-v", f"{output_directory}:/output",
               "rapidscan", url, "--nospinner", "--json-output", "/output/result.json"]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, bufsize=1)
        for line in process.stdout:
            output_queue.put(line.rstrip('\r\n'))
        return_code = process.wait()
        if os.path.exists(structured_path):
            try:
                with open(structured_path, encoding="utf-8") as result_file:
                    output_queue.put({"type": "STRUCTURED_RESULT", "data": json.load(result_file)})
            except (OSError, ValueError) as exc:
                output_queue.put({"type": "ERROR", "message": f"Invalid RapidScan JSON output: {exc}", "return_code": -1})
        output_queue.put({"type": "DONE", "return_code": return_code})
    except Exception as exc:
        output_queue.put({"type": "ERROR", "message": str(exc), "return_code": -1})
    finally:
        shutil.rmtree(output_directory, ignore_errors=True)

def perform_vulnerability_scan(url, scan_id=None):
    """
    Performs vulnerability scan on given URL and returns results and highest threat level
    """
    output_queue = queue.Queue()
    scan_results = []
    highest_threat_level = ""
    if scan_id:
        state_path = os.path.join(SCAN_RESULTS_DIR, f"scan_{scan_id}.json")
        try:
            with open(state_path, encoding='utf-8') as handle:
                state = json.load(handle)
        except (OSError, ValueError):
            state = create_scan_state(url)
    else:
        state = create_scan_state(url)
    scan_id = state["scan_id"]
    state["stage"] = "Vulnerability scan"
    _persist_scan_state(state)
    raw_lines = []
    structured_payload = None
    _persist_scan_state(state)
    table_placeholder = st.empty()

    def save_state(status=None, error=None):
        state["status"] = status or state["status"]
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        state["highest_threat_level"] = highest_threat_level or "Not Assessed"
        state["results"] = scan_results
        state["tests"] = structured_payload.get("tests", []) if structured_payload else [{
            "test_id": re.sub(r"[^a-z0-9]+", "_", item.get("Test Name", "unknown").lower()).strip("_"),
            "name": item.get("Test Name", "Unknown"),
            "status": item.get("Status", "Unknown"),
            "duration": item.get("Time Taken"),
            "finding_status": "Not Assessed"
        } for item in scan_results]
        if structured_payload:
            statuses = {str(test.get("status", "")).lower() for test in state["tests"]}
            state["scan_completion"] = (
                "PARTIAL" if statuses.intersection({"failed", "skipped"}) else "COMPLETE"
            )
        elif status == "Completed":
            state["scan_completion"] = "PARTIAL"
        else:
            state["scan_completion"] = "FAILED"
        state["error"] = error
        _persist_scan_state(state)

    def update_logs():
        nonlocal highest_threat_level, structured_payload
        threat_levels = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        valid_threat_levels = ["Low", "Medium", "High", "Critical"]
        
        while True:
            item = output_queue.get()
            if isinstance(item, dict) and item.get("type") == "STRUCTURED_RESULT":
                structured_payload = item.get("data")
                continue
            if isinstance(item, dict) and item.get("type") in {"DONE", "ERROR"}:
                process_succeeded = item.get("type") == "DONE" and item.get("return_code") == 0
                if structured_payload and not scan_results:
                    severity_rank = {"Informational": 0, "Low": 1, "Medium": 2,
                                     "High": 3, "Critical": 4}
                    for test in structured_payload.get("tests", []):
                        findings = test.get("findings", [])
                        finding = findings[0] if findings else {}
                        severity = finding.get("severity", "Unknown")
                        scan_results.append({
                            "Test Name": test.get("name", test.get("test_id", "Unknown")),
                            "Status": test.get("status", "unknown").capitalize(),
                            "Test Status": test.get("status", "unknown").capitalize(),
                            "Finding Status": finding.get("finding_status", "Not Detected"),
                            "Time Taken": f"{test.get('duration_ms', 0)}ms" if test.get("duration_ms") is not None else "Unknown",
                            "Expected Time": "Unknown",
                            "Threat Level": severity,
                            "Definition": finding.get("evidence", ""),
                            "Remediation": finding.get("remediation", "Review and remediate the reported condition; verify manually."),
                            "Evidence": finding.get("evidence", ""),
                            "Verified": finding.get("verified", False)
                        })
                        if severity_rank.get(severity, 0) > severity_rank.get(highest_threat_level, 0):
                            highest_threat_level = severity
                # Tests without a finding are not equivalent to a verified safe result.
                for test in scan_results:
                    if not test["Threat Level"]:
                        test["Threat Level"] = "Unknown"
                    if test.get("Status") == "Running":
                        test["Status"] = "Completed" if process_succeeded else "Failed"
                        test["Test Status"] = test["Status"]
                        test["Time Taken"] = "Unknown"
                        test["Finding Status"] = "Not Detected" if process_succeeded else "Not Assessed"
                if not highest_threat_level or highest_threat_level not in valid_threat_levels:
                    highest_threat_level = "Not Assessed"
                
                df = pd.DataFrame(scan_results)
                df = df.sort_index()
                table_placeholder.table(df)
                if item.get("type") == "ERROR":
                    state["scan_mode"] = "FAILED"
                    state["mode_reason"] = "RapidScan Docker execution failed"
                    raw_lines.append("ERROR: " + item["message"])
                    scan_results.append({"Test Name": "Scanner error", "Status": "Failed",
                                         "Time Taken": "N/A", "Expected Time": "N/A",
                                         "Threat Level": "Unknown", "Definition": item["message"],
                                         "Remediation": "Check Docker and scanner configuration."})
                    save_state("Failed", item["message"])
                else:
                    status = "Completed" if item.get("return_code") == 0 else "Failed"
                    if status == "Completed":
                        state["scan_mode"] = "FULL"
                        state["mode_reason"] = "RapidScan Docker backend"
                    else:
                        state["scan_mode"] = "FAILED"
                    error = None if status == "Completed" else (
                        f"Scanner exited with code {item.get('return_code')}. "
                        f"See {state.get('raw_log_file', 'the raw log')} for details.")
                    save_state(status, error)
                break

            raw_lines.append(item)
            # Terminal lines are diagnostics only. Results arrive via the
            # structured JSON payload handled above and are never regex-parsed.
            state["live_log_tail"] = "\n".join(raw_lines)[-12000:]
            state["updated_at"] = datetime.now(timezone.utc).isoformat()
            _persist_scan_state(state)
            continue

        return highest_threat_level

    # Run the scan in a separate thread
    scan_thread = threading.Thread(target=run_scan_real_time, args=(url, output_queue))
    scan_thread.start()

    # Update logs and get highest threat level
    highest_threat_level = update_logs()
    
    if highest_threat_level == "":
        highest_threat_level = "Not Assessed"

    # Save results to file
    results_file, mitre_file, raw_file = write_vulnerability_info_to_file(
        url, scan_results, timestamp=scan_id, raw_output='\n'.join(raw_lines))
    state["result_file"] = results_file
    state["mitre_file"] = mitre_file
    state["raw_log_file"] = raw_file
    if structured_payload:
        state["rapidscan_result_file"] = os.path.join(
            SCAN_RESULTS_DIR, f"rapidscan_result_{scan_id}.json")
        _write_json_atomic(state["rapidscan_result_file"], structured_payload)
    state["canonical_reports"] = write_canonical_reports(state, SCAN_RESULTS_DIR)
    save_state(state["status"], state.get("error"))
    st.success(f"Scan results have been saved to: {results_file}")

    return scan_results, highest_threat_level
