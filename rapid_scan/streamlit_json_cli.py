import re
import subprocess
import streamlit as st
import threading
import queue
import pandas as pd
import os
from datetime import datetime

# A queue to handle real-time output
output_queue = queue.Queue()

# Add highest_threat_level as a global variable at the top of the file
highest_threat_level = ""
# Function to clean ANSI escape sequences from the logs
def clean_ansi_codes(log_line):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', log_line)

def write_vulnerability_info_to_file(url, scan_results):
    os.makedirs('scan_results', exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'scan_results/vulnerability_scan_{timestamp}.txt'
    
    mitre_dir = '/Users/apple/Desktop/Web-Vulnerability-Scanner/Mitre-Att&ck/src/ScenarioBank'
    os.makedirs(mitre_dir, exist_ok=True)
    mitre_filename = f'{mitre_dir}/vulnerability_details_{timestamp}.txt'

    with open(filename, 'w') as f:
        f.write(f"Vulnerability Scan Results for {url}\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
        
        for result in scan_results:
            f.write(f"Test: {result['Test Name']}\n")
            # if result.get('Threat Level'):
            #     f.write(f"Threat Level: {result['Threat Level'].lower()}\n")
            if 'Definition' in result:
                # Clean ANSI codes and [0m from the definition
                clean_definition = clean_ansi_codes(result['Definition']).replace('[0m', '')
                f.write(f"Vulnerability Definition: {clean_definition}\n")
            if 'Remediation' in result:
                # Clean ANSI codes and [0m from the remediation
                clean_remediation = clean_ansi_codes(result['Remediation']).replace('[0m', '')
                f.write(f"Vulnerability Remediation: {clean_remediation}\n")
            f.write("\n" + "-"*50 + "\n\n")
    
    with open(mitre_filename, 'w') as f:
        f.write(f"Detailed Vulnerability Information for {url}\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*50 + "\n\n")
        f.write("The scenario is as follows:\n")
        for result in scan_results:
            if 'Definition' in result and 'Remediation' in result and result['Definition'].strip() and result['Remediation'].strip():
                f.write(f"Test: {result['Test Name']}\n")
                clean_definition = clean_ansi_codes(result['Definition']).replace('[0m', '')
                clean_remediation = clean_ansi_codes(result['Remediation']).replace('[0m', '')
                f.write(f"Vulnerability Definition: {clean_definition}\n")
                f.write(f"Vulnerability Remediation: {clean_remediation}\n")
                f.write("\n" + "-"*50 + "\n\n")
    
    
    return filename

# Function to run the scanner in a separate thread
def run_scan_real_time(url, output_queue):
    command = ["docker", "run", "rapidscan", url]
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    for line in process.stdout:
        output_queue.put(line.strip())  # Push each line to the queue

    process.wait()
    output_queue.put("DONE")  # Sentinel to indicate completion

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

def perform_vulnerability_scan(url):
    """
    Performs vulnerability scan on given URL and returns results and highest threat level
    """
    output_queue = queue.Queue()
    scan_results = []
    highest_threat_level = ""
    table_placeholder = st.empty()

    def update_logs():
        previous_line = None
        last_test_index = -1
        nonlocal highest_threat_level
        threat_levels = {"safe": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        valid_threat_levels = ["Low", "Medium", "High", "Critical"]
        
        while True:
            item = output_queue.get()
            if item == "DONE":
                # Set remaining tests to "Safe"
                for test in scan_results:
                    if not test["Threat Level"] or test["Threat Level"] not in valid_threat_levels:
                        test["Threat Level"] = "Safe"
                if not highest_threat_level or highest_threat_level not in valid_threat_levels:
                    highest_threat_level = "Safe"
                
                df = pd.DataFrame(scan_results)
                df = df.sort_index()
                table_placeholder.table(df)
                break

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

        return highest_threat_level

    # Run the scan in a separate thread
    scan_thread = threading.Thread(target=run_scan_real_time, args=(url, output_queue))
    scan_thread.start()

    # Update logs and get highest threat level
    highest_threat_level = update_logs()
    
    if highest_threat_level == "":
        highest_threat_level = "Safe"

    # Save results to file
    results_file = write_vulnerability_info_to_file(url, scan_results)
    st.success(f"Scan results have been saved to: {results_file}")

    return scan_results, highest_threat_level
