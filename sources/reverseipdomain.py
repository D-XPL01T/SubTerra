import urllib.request
import urllib.error
import json
from typing import List, Optional, Tuple

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

def fetch_subdomains_reverseipdomain(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches subdomains for a given domain from the Reverse IP Domain API.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    url = f"https://sub-scan-api.reverseipdomain.com/?domain={domain}"
    
    # 1. Make HTTP GET request
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SubTerra'})
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

    # 3. Use a set to track unique filtered subdomains (equivalent to map[string]bool)
    subdomain_set = set()
    
    # 4. Safely extract the nested domains list
    # Go struct: response.Result.Domains -> Python dict: data["result"]["domains"]
    result_data = data.get("result", {})
    
    # Ensure result_data is a dictionary before trying to get "domains"
    if isinstance(result_data, dict):
        domains_list = result_data.get("domains", [])
    else:
        domains_list = []

    # 5. Iterate over the domains
    for domain_name in domains_list:
        # Defensive check to ensure the item is a string
        if not isinstance(domain_name, str):
            continue
            
        if is_subdomain_or_domain(domain_name, domain):
            normalized = normalize_subdomain(domain_name)
            if normalized:
                subdomain_set.add(normalized)

    # 6. Convert set to list (equivalent to converting map to slice)
    filtered_domains = list(subdomain_set)
    
    return filtered_domains, None