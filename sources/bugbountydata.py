import urllib.request
import urllib.error
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

def fetch_subdomains_bugbounty_data(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches subdomains for a given domain from the BugBountyData GitHub repository.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    url = f"https://raw.githubusercontent.com/rix4uni/BugBountyData/refs/heads/main/data/{domain}.txt"
    
    # 1. Make HTTP GET request
    try:
        # Adding a User-Agent is highly recommended for GitHub raw content to avoid 403 Forbidden
        req = urllib.request.Request(url, headers={'User-Agent': 'SubTerra'})
        with urllib.request.urlopen(req) as response:
            # 2. Check if the request was successful (equivalent to resp.StatusCode != http.StatusOK)
            if response.status != 200:
                # Go's resp.Status is a string like "404 Not Found". We replicate that here.
                return [], Exception(f"request failed with status: {response.status} {response.reason}")
            
            # 3. Read response body (equivalent to ioutil.ReadAll)
            body = response.read().decode('utf-8')
            
    except urllib.error.HTTPError as e:
        # Catch HTTP errors (like 404) explicitly to match Go's behavior cleanly
        return [], Exception(f"request failed with status: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        return [], e
    except Exception as e:
        return [], e

    # 4. Parse the response body as plain text (split by newlines, equivalent to strings.Split)
    lines = body.split('\n')

    # 5. Use a set to track unique filtered subdomains (equivalent to map[string]bool)
    subdomain_set = set()
    
    for line in lines:
        subdomain = line.strip() # equivalent to strings.TrimSpace
        
        # 6. Check conditions
        if subdomain and is_subdomain_or_domain(subdomain, domain):
            normalized = normalize_subdomain(subdomain)
            if normalized:
                subdomain_set.add(normalized)

    # 7. Convert set to list (equivalent to converting map to slice)
    subdomains = list(subdomain_set)
    
    return subdomains, None