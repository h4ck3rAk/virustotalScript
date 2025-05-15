import os
import requests
import pandas as pd
from tabulate import tabulate
from datetime import datetime

# Replace with your VirusTotal API key
API_KEY = "ENTER_YOUR_API_KEY"

# Path to the file containing IOCs (one IOC per line)
IOCS_FILE_PATH = r"C:\Users\FILEPATH\FILE.TXT"
  # change this to the appropriate file path

# Check if the file exists
if not os.path.exists(IOCS_FILE_PATH):
    raise FileNotFoundError(f"{IOCS_FILE_PATH} not found. Please provide a valid file path.")

# Read IOCs from the file
with open(IOCS_FILE_PATH, "r") as file:
    IOC_LIST = [line.strip() for line in file if line.strip()]

def format_analysis_date(timestamp):
    """Convert Unix epoch timestamp to human-readable format."""
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"

def check_ioc(ioc, ioc_type):
    url = f"https://www.virustotal.com/api/v3/{ioc_type}/{ioc}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    # Initialize a result dictionary with basic fields
    result = {"IOC": ioc}
    
    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        result["Malicious"] = stats.get("malicious", 0)
        result["Suspicious"] = stats.get("suspicious", 0)
        result["Harmless"] = stats.get("harmless", 0)
        result["Undetected"] = stats.get("undetected", 0)
        result["Timeout"] = stats.get("timeout", 0)
        
        # Format last analysis time if available
        last_analysis = attributes.get("last_analysis_date")
        result["Last Analysis Date"] = format_analysis_date(last_analysis) if last_analysis else "N/A"
        
        # Add reputation if provided
        result["Reputation"] = attributes.get("reputation", "N/A")
    else:
        result["Malicious"] = "Error"
        result["Suspicious"] = "Error"
        result["Harmless"] = "Error"
        result["Undetected"] = "Error"
        result["Timeout"] = "Error"
        result["Last Analysis Date"] = "Error"
        result["Reputation"] = "Error"
        
    return result

# Collect results
results = []

for ioc in IOC_LIST:
    # Determine IOC type. Here we use a simple rule: if it contains a dot and non-digit characters, treat it as a domain
    if "." in ioc and not ioc.replace(".", "").isdigit():
        ioc_type = "domains"
    elif ioc.replace(".", "").isdigit():
        ioc_type = "ip_addresses"
    else:
        ioc_type = "files"
    
    print(f"Checking IOC: {ioc} as {ioc_type}...")
    result = check_ioc(ioc, ioc_type)
    results.append(result)

# Create a DataFrame with the results
df = pd.DataFrame(results)

# Save results to CSV; update the path if necessary.
output_path = "results.csv"
df.to_csv(output_path, index=False)

# Print the results in a structured table
print(f"\n✅ Reputation Check Completed! Results saved to {output_path}\n")
print(tabulate(df, headers="keys", tablefmt="grid"))
