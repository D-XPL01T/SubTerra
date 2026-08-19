import urllib.request
import urllib.error
import json
from typing import List, Optional, Tuple

# ==========================================
# 1. YOUR SHODAN API KEY IS SET HERE
# ==========================================
SHODAN_API_KEY = "dCb3cFyxQ3N6lB9kdw8L5Cn117NYpn9S"
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

def fetch_subdomains_shodan(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches subdomains for a given domain from the Shodan API.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    # Append the API key directly to the URL
    url = f"https://api.shodan.io/dns/domain/{domain}?key={SHODAN_API_KEY}"
    
    # Make HTTP GET request with a standard browser User-Agent to avoid 403 blocks
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req) as response:
            body = response.read().decode('utf-8')
            
    except urllib.error.HTTPError as e:
        return [], Exception(f"request failed with status: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        return [], e
    except Exception as e:
        return [], e

    # Unmarshal JSON
    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        return [], e

    # Use a set to track unique filtered subdomains
    subdomain_set = set()
    
    # Safely extract the subdomains list
    raw_subdomains = data.get("subdomains", [])
    
    # Iterate over the partial subdomains
    for sub in raw_subdomains:
        if not isinstance(sub, str):
            continue
            
        # Shodan returns partial subdomains, so we concatenate them with the root domain
        full_subdomain = f"{sub}.{domain}"
        
        if is_subdomain_or_domain(full_subdomain, domain):
            normalized = normalize_subdomain(full_subdomain)
            if normalized:
                subdomain_set.add(normalized)

    # Convert set to list
    full_subdomains = list(subdomain_set)
    
    return full_subdomains, None