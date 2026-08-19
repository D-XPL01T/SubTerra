import time
  # ... inside the function, right before the try block:
time.sleep(1.5) 
import urllib.request
import urllib.error
import json
from typing import List, Optional, Tuple

def is_subdomain_or_domain(hostname: str, domain: str) -> bool:
    """
    Checks if the hostname is exactly the domain or a subdomain of it.
    (Equivalent to the missing isSubdomainOrDomain function in the Go snippet).
    """
    hostname = hostname.strip().lower()
    domain = domain.strip().lower()
    
    if hostname == domain:
        return True
    if hostname.endswith("." + domain):
        return True
    return False

def normalize_subdomain(text: str) -> str:
    """
    Normalizes the subdomain string.
    (Matches the robust normalization logic discussed previously).
    """
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

def fetch_subdomains_alienvault(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches subdomains for a given domain from the AlienVault OTX API.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    
    # 1. Make HTTP GET request (equivalent to http.Get)
    try:
        # Adding a basic User-Agent is often recommended for OTX to avoid default blocks
        req = urllib.request.Request(url, headers={'User-Agent': 'SubTerra'})
        with urllib.request.urlopen(req) as response:
            # 2. Read response body (equivalent to ioutil.ReadAll)
            body = response.read().decode('utf-8')
    except urllib.error.URLError as e:
        return [], e
    except Exception as e:
        return [], e

    # 3. Unmarshal JSON (equivalent to json.Unmarshal)
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        return [], e

    # 4. Use a set to track unique filtered subdomains (equivalent to map[string]bool)
    subdomain_set = set()
    
    # Safely get the passive_dns list, defaulting to empty list if key is missing
    passive_dns = data.get("passive_dns", [])
    
    for record in passive_dns:
        hostname = record.get("hostname", "")
        
        # 5. Check if it's a valid subdomain/domain
        if is_subdomain_or_domain(hostname, domain):
            # 6. Normalize and add to set if not empty
            normalized = normalize_subdomain(hostname)
            if normalized:
                subdomain_set.add(normalized)

    # 7. Convert set to list (equivalent to converting map to slice)
    subdomains = list(subdomain_set)
    
    return subdomains, None