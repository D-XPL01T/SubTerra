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

def fetch_subdomains_urlscan(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches subdomains for a given domain from the URLScan API.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    
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
    
    # 4. Safely extract the results list
    results = data.get("results", [])
    if not isinstance(results, list):
        return [], Exception("unexpected JSON response format: expected a list for 'results'")

    # 5. Iterate over the results
    for result in results:
        if not isinstance(result, dict):
            continue
            
        # Check Task.Domain (skip ApexDomain as it often contains unrelated domains)
        task_domain = result.get("task", {}).get("domain", "")
        if task_domain and is_subdomain_or_domain(task_domain, domain):
            normalized = normalize_subdomain(task_domain)
            if normalized:
                subdomain_set.add(normalized)
                
        # Check Page.Domain (skip ApexDomain as it often contains unrelated domains)
        page_domain = result.get("page", {}).get("domain", "")
        if page_domain and is_subdomain_or_domain(page_domain, domain):
            normalized = normalize_subdomain(page_domain)
            if normalized:
                subdomain_set.add(normalized)

    # 6. Convert set to list (equivalent to converting map to slice)
    subdomains = list(subdomain_set)
    
    return subdomains, None