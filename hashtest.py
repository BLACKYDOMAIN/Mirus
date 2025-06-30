import requests

# Replace with your actual API key
API_KEY = open("apikey.txt",'r').read()
HASH = "3c4a47ded906805022b10d663e9532c7f36d76612ea72e85f8040b84d395c27d"  # Example MD5 (EICAR test file)

# API endpoint for file reports
url = f"https://www.virustotal.com/api/v3/files/{HASH}"

headers = {
    "x-apikey": API_KEY
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    data = response.json()
    
    # Basic details
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)
    suspicious = stats.get("suspicious", 0)

    print("== VirusTotal Analysis ==")
    print(f"Malicious: {malicious}")
    print(f"Harmless: {harmless}")
    print(f"Suspicious: {suspicious}")
    print(f"Scan Date: {attributes.get('last_analysis_date')}")
    print(f"Permalink: https://www.virustotal.com/gui/file/{HASH}")
else:
    print(f"Error: {response.status_code}")
    print(response.text)
