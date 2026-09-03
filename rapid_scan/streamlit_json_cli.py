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
import urllib.error
import urllib.request
from datetime import datetime, timezone

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
               'highest_threat_level', 'error')}
    record['result_file'] = os.path.basename(state['result_file']) if state.get('result_file') else None
    record['raw_log_file'] = os.path.basename(state['raw_log_file']) if state.get('raw_log_file') else None
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
             "results": [], "error": None}
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
            f.write(f"Threat Level: {result.get('Threat Level', 'Unknown')}\n")
            if result.get('Definition'):
                # Clean ANSI codes and [0m from the definition
                clean_definition = clean_ansi_codes(result['Definition']).replace('[0m', '')
                f.write(f"Vulnerability Definition: {clean_definition}\n")
            if result.get('Remediation'):
                # Clean ANSI codes and [0m from the remediation
                clean_remediation = clean_ansi_codes(result['Remediation']).replace('[0m', '')
                f.write(f"Vulnerability Remediation: {clean_remediation}\n")
            f.write("\n" + "-"*50 + "\n\n")
    
    with open(mitre_filename, 'w', encoding='utf-8') as f:
        f.write(f"Detailed Vulnerability Information for {url}\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
        f.write("The scenario is as follows:\n")
        for result in scan_results:
            if result.get('Definition', '').strip() and result.get('Remediation', '').strip():
                f.write(f"Test: {result.get('Test Name', 'Unknown')}\n")
                clean_definition = clean_ansi_codes(result['Definition']).replace('[0m', '')
                clean_remediation = clean_ansi_codes(result['Remediation']).replace('[0m', '')
                f.write(f"Vulnerability Definition: {clean_definition}\n")
                f.write(f"Vulnerability Remediation: {clean_remediation}\n")
                f.write("\n" + "-"*50 + "\n\n")
    
    
    raw_filename = os.path.join(scan_results_dir, f'vulnerability_scan_{timestamp}.log')
    with open(raw_filename, 'w', encoding='utf-8') as f:
        f.write(raw_output)

    return filename, mitre_filename, raw_filename

# Function to run the scanner in a separate thread
def _run_basic_local_scan(url, output_queue):
    """Small dependency-free fallback for development machines without Docker."""
    output_queue.put("Local scanner selected: Docker RapidScan is unavailable.")
    output_queue.put("Deploying < 1s | HTTP security headers")
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "WebGuard/1.0"}, method="GET")
        with urllib.request.urlopen(request, timeout=15) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            missing = [name for name in ("content-security-policy", "x-content-type-options",
                                         "strict-transport-security", "x-frame-options")
                       if name not in headers]
            level = "Medium" if len(missing) >= 3 else "Low" if missing else "Safe"
            output_queue.put("Vulnerability Threat Level")
            output_queue.put(level)
            output_queue.put("Vulnerability Definition")
            output_queue.put(f"HTTP {response.status}; missing security headers: {', '.join(missing) or 'none'}.")
            output_queue.put("Vulnerability Remediation")
            output_queue.put("Configure the missing HTTP security headers at the web server or reverse proxy.")
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        output_queue.put("Vulnerability Threat Level")
        output_queue.put("Unknown")
        output_queue.put("Vulnerability Definition")
        output_queue.put(f"HTTP check failed: {exc}")
        output_queue.put("Vulnerability Remediation")
        output_queue.put("Verify the URL, DNS, network access, and TLS certificate.")
    output_queue.put("Scan Completed in 1s")
    output_queue.put({"type": "DONE", "return_code": 0, "backend": "local-basic"})


def run_scan_real_time(url, output_queue):
    """Run Docker RapidScan when available, otherwise use the local fallback."""
    mode = os.environ.get("WEBGUARD_SCANNER_MODE", "auto").lower()
    docker_available = shutil.which("docker") is not None
    if mode == "local" or not docker_available:
        return _run_basic_local_scan(url, output_queue)

    try:
        docker_ready = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, text=True, timeout=10).returncode == 0
        image_ready = subprocess.run(["docker", "image", "inspect", "rapidscan"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                     text=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        docker_ready = False
        image_ready = False
        docker_error = str(exc)
    else:
        docker_error = "Docker daemon is not running or the 'rapidscan' image is not built."

    if not docker_ready or not image_ready:
        output_queue.put(f"Docker RapidScan unavailable: {docker_error}")
        return _run_basic_local_scan(url, output_queue)

    command = ["docker", "run", "--rm", "rapidscan", url]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, bufsize=1)
        for line in process.stdout:
            output_queue.put(line.rstrip('\r\n'))
        return_code = process.wait()
        output_queue.put({"type": "DONE", "return_code": return_code})
    except Exception as exc:
        output_queue.put({"type": "ERROR", "message": str(exc), "return_code": -1})

# Function to parse scan results from each line
def parse_scan_line(line, next_line=None, scan_results=None):
    # Check for vulnerability threat level first
    if "Vulnerability Threat Level" in line and next_line:
        print(f"Found threat level line: {line}")
        print(f"Next line: {next_line}")
        threat_match = re.search(r'(low|medium|high|critical)', next_line.lower())
        if threat_match:
            threat_level = threat_match.group(1).capitalize()
            print(f"Found threat level: {threat_level}")
            return {
                "type": "threat_level_update",
                "Threat Level": threat_level,
                "Test Name": scan_results[-1]["Test Name"] if scan_results else "Unknown"
            }

    # Check for vulnerability definition
    if "Vulnerability Definition" in line and next_line:
        if scan_results and scan_results[-1]:
            scan_results[-1]["Definition"] = next_line.strip()
        return None

    # Check for vulnerability remediation
    if "Vulnerability Remediation" in line and next_line:
        if scan_results and scan_results[-1]:
            scan_results[-1]["Remediation"] = next_line.strip()
        return None

    # Check if line contains deployment information
    if "Deploying" in line and "|" in line:
        parts = line.split("|")
        if len(parts) >= 2:
            test_info = clean_ansi_codes(parts[1].strip())
            time_match = re.search(r'<\s*(\d+[ms])', parts[0])
            expected_time = time_match.group(1) if time_match else "Unknown"
            
            return {
                "type": "new_test",
                "data": {
                    "Test Name": test_info,
                    "Status": "Running",
                    "Time Taken": "In progress",
                    "Expected Time": expected_time,
                    "Threat Level": "",
                    "Definition": "",
                    "Remediation": ""
                }
            }
    
    # Check if scan completion is reported
    if "Scan Completed in" in line:
        time_taken = re.search(r'Completed in (\d+[ms])', line)
        if time_taken:
            return {"type": "completion", "time_taken": time_taken.group(1)}
    
    return None

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
    _persist_scan_state(state)
    table_placeholder = st.empty()

    def save_state(status=None, error=None):
        state["status"] = status or state["status"]
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        state["highest_threat_level"] = highest_threat_level or "Safe"
        state["results"] = scan_results
        state["error"] = error
        _persist_scan_state(state)

    def update_logs():
        previous_line = None
        last_test_index = -1
        nonlocal highest_threat_level
        threat_levels = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        valid_threat_levels = ["Low", "Medium", "High", "Critical"]
        
        while True:
            item = output_queue.get()
            if isinstance(item, dict) and item.get("type") in {"DONE", "ERROR"}:
                # Set remaining tests to "Safe"
                for test in scan_results:
                    if not test["Threat Level"]:
                        test["Threat Level"] = "Safe"
                if not highest_threat_level or highest_threat_level not in valid_threat_levels:
                    highest_threat_level = "Safe"
                
                df = pd.DataFrame(scan_results)
                df = df.sort_index()
                table_placeholder.table(df)
                if item.get("type") == "ERROR":
                    raw_lines.append("ERROR: " + item["message"])
                    scan_results.append({"Test Name": "Scanner error", "Status": "Failed",
                                         "Time Taken": "N/A", "Expected Time": "N/A",
                                         "Threat Level": "Unknown", "Definition": item["message"],
                                         "Remediation": "Check Docker and scanner configuration."})
                    save_state("Failed", item["message"])
                else:
                    status = "Completed" if item.get("return_code") == 0 else "Failed"
                    error = None if status == "Completed" else (
                        f"Scanner exited with code {item.get('return_code')}. "
                        f"See {state.get('raw_log_file', 'the raw log')} for details.")
                    save_state(status, error)
                break

            raw_lines.append(item)
            result = parse_scan_line(previous_line, item, scan_results) if previous_line else None
            previous_line = item

            if result:
                if result.get("type") == "new_test":
                    current_test = result["data"]
                    current_test["Threat Level"] = "Safe"
                    scan_results.append(current_test)
                    last_test_index = len(scan_results) - 1
                    
                elif result.get("type") == "completion" and last_test_index >= 0:
                    scan_results[last_test_index]["Status"] = "Completed"
                    scan_results[last_test_index]["Time Taken"] = result["time_taken"]
                    if not scan_results[last_test_index]["Threat Level"]:
                        scan_results[last_test_index]["Threat Level"] = "Safe"
                    
                elif result.get("type") == "threat_level_update":
                    for test in scan_results:
                        if test["Test Name"] == result["Test Name"]:
                            new_threat = result["Threat Level"]
                            if new_threat in valid_threat_levels:
                                test["Threat Level"] = new_threat
                                current_level = threat_levels.get(new_threat.lower(), 0)
                                highest_level = threat_levels.get(highest_threat_level.lower(), 0)
                                if current_level > highest_level:
                                    highest_threat_level = new_threat
                            break
            
                df = pd.DataFrame(scan_results)
                df = df.sort_index()
                table_placeholder.table(df)
                save_state()

        return highest_threat_level

    # Run the scan in a separate thread
    scan_thread = threading.Thread(target=run_scan_real_time, args=(url, output_queue))
    scan_thread.start()

    # Update logs and get highest threat level
    highest_threat_level = update_logs()
    
    if highest_threat_level == "":
        highest_threat_level = "Safe"

    # Save results to file
    results_file, mitre_file, raw_file = write_vulnerability_info_to_file(
        url, scan_results, timestamp=scan_id, raw_output='\n'.join(raw_lines))
    state["result_file"] = results_file
    state["mitre_file"] = mitre_file
    state["raw_log_file"] = raw_file
    save_state(state["status"], state.get("error"))
    st.success(f"Scan results have been saved to: {results_file}")

    return scan_results, highest_threat_level
