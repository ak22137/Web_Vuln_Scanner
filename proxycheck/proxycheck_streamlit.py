import subprocess
import re

def check_ip(ip_address):
    """
    Checks an IP address using proxycheck.py and returns cleaned results as text.
    
    Args:
        ip_address (str): The IP address to check
        
    Returns:
        str: Formatted IP information
    """
    # Run the proxycheck script and capture output
    result = subprocess.run(['python', 'proxycheck.py', ip_address], 
                          capture_output=True, 
                          text=True)
    
    # Get the output text
    output = result.stdout
    
    # Define patterns to extract information
    patterns = {
        'IP Details': r'IP Details: ([\d\.]+)',
        'ASN': r'ASN: (AS\d+)',
        'Range': r'Range: ([\d\./]+)',
        'Provider': r'Provider: (.+)',
        'Organisation': r'Organisation: (.+)',
        'Continent': r'Continent: (.+)',
        'Country': r'Country: (.+)',
        'Region': r'Region: (.+)',
        'City': r'City: (.+)',
        'Postal Code': r'Postal Code: (.+)',
        'Latitude': r'Latitude: ([\d\.-]+)',
        'Longitude': r'Longitude: ([\d\.-]+)',
        'Proxy': r'Proxy: (.+)',
        'Type': r'Type: (.+)'
    }
    
    # Build formatted output string
    formatted_output = []
    for label, pattern in patterns.items():
        match = re.search(pattern, output)
        if match:
            formatted_output.append(f"{label}: {match.group(1).strip()}")
    
    # Join all lines with newlines
    return "\n".join(formatted_output)

