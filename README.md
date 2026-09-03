
## A Comprehensive Web Application Fuzzer

It is a comprehensive fuzzer designed to enhance the security of web applications by automating the discovery and testing of hidden vulnerabilities. It identifies potential weaknesses in components such as directories, virtual hosts, API endpoints, URL parameters, and subdomains. By proactively uncovering security flaws, it empowers developers and security teams to remediate vulnerabilities and secure their applications effectively.

## Tools Used:

 1. Directories and Files:

   * dirb
   * uniscan_filebrute
   * uniscan_dirbrute

 2. Virtual Hosts (VHosts):

   * lbd
   * dnsrecon

 3. API Endpoints:

    * wapiti
    * uniscan_rfi
    * whatweb

 4. Parameters:

    * xsser
    * wapiti
 5. Custom Test Cases:

    * whatweb

 6. Subdomains:

    * amass
    * dnsmap_brute
    * theHarvester
    * dnsenum_zone_transfer

## Installation 

1. Clone the repository

```
git clone https://github.com/amrishacodes/Web-Vulnerability-Scanner.git
cd Web-Vulnerability-Scanner

```
2. To install requirements

```
python -m pip install --no-cache-dir -r requirements.txt

```
3. To run on streamlit

```
streamlit run main_v2.py

```

Docker is optional. The full RapidScan tool runs through Docker when the
Docker daemon is running and the `rapidscan` image exists. Build it once with:

```bash
docker build -t rapidscan -f rapid_scan/Dockerfile.txt rapid_scan
```

Without Docker, WebGuard automatically runs a local HTTP security-header
check so the scan still produces persistent results and logs. Set
`WEBGUARD_SCANNER_MODE=local` to force that fallback.
