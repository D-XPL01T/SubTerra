import urllib.request
import urllib.error
import json
from typing import List, Optional, Tuple

# ==========================================
# 1. PASTE YOUR VIRUSTOTAL API KEY HERE
# Get a free API key at: https://www.virustotal.com/gui/join-us
# ==========================================
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
# ==========================================

def is_subdomain_or_domain(hostname: str, domain: str) -> bool:
    """Checks if the hostname is exactly the domain or a subdomain of it."""
    hostname = hostname.strip().lower()
    domain = domain.strip().lower()
    
    if hostname == domain:
        return True
    if hostname.endswith("." + domain):
        return True
    return False

def normalize_subdomain(text: str) -> str:
    """Normalizes the subdomain string (lowercase, strips, removes wildcards/emails/trailing dots)."""
    text = text.strip().lower()
    if not text:
        return ""
    if text.startswith("*."):
        return ""
    if "@" in text:
        return ""
    if text.endswith("."):
        text = text[:-1]
    if "." not in text:
        return ""
    return text

def fetch_subdomains_virustotal(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches subdomains for a given domain from the VirusTotal v3 API.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    # Check if the API key has been set
    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return [], Exception("VT_API_KEY is not set. Please add your VirusTotal API key to virustotal.py")

    # Use the official VirusTotal v3 API endpoint
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=1000"
    
    # 1. Make HTTP GET request with the API key in the header
    try:
        req = urllib.request.Request(url)
        req.add_header("x-apikey", VT_API_KEY)
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        
        with urllib.request.urlopen(req) as response:
            body = response.read().decode('utf-8')
            
    except urllib.error.HTTPError as e:
        return [], Exception(f"request failed with status: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        return [], e
    except Exception as e:
        return [], e

    # 2. Unmarshal JSON
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        return [], e

    # 3. Use a set to track unique filtered subdomains
    subdomain_set = set()
    
    # 4. Safely extract the data list
    # VT v3 API returns: {"data": [{"id": "sub.example.com", "type": "domain", ...}, ...]}
    vt_data = data.get("data", [])
    
    if not isinstance(vt_data, list):
        return [], Exception("unexpected JSON response format: expected a list for 'data'")

    # 5. Iterate over the data
    for item in vt_data:
        if not isinstance(item, dict):
            continue
            
        # Extract the ID field (which contains the subdomain in VT v3 API)
        subdomain_id = item.get("id", "")
        
        if subdomain_id and is_subdomain_or_domain(subdomain_id, domain):
            normalized = normalize_subdomain(subdomain_id)
            if normalized:
                subdomain_set.add(normalized)

    # 6. Convert set to list
    subdomains = list(subdomain_set)
    
    return subdomains, None