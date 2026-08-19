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

def fetch_hostnames_trickest(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches hostnames for a given domain from the Trickest API.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    # 1. Fetch the Trickest targets JSON file
    index_url = "https://raw.githubusercontent.com/rix4uni/targets-filter/refs/heads/main/trickest-targets.json"
    
    try:
        req1 = urllib.request.Request(index_url, headers={'User-Agent': 'SubTerra'})
        with urllib.request.urlopen(req1) as response:
            body1 = response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return [], Exception(f"request failed with status: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        return [], e
    except Exception as e:
        return [], e

    # 2. Unmarshal the JSON data
    try:
        targets = json.loads(body1)
        if not isinstance(targets, list):
            return [], Exception("unexpected JSON response format: expected a list of targets")
    except json.JSONDecodeError as e:
        return [], e

    hostnames_raw = []
    
    # 3. Find the matching domain and fetch its hostnames
    for target in targets:
        # Defensive check to ensure target is a dict and has required keys
        if not isinstance(target, dict):
            continue
            
        target_domain = target.get("domain", "")
        
        # Equivalent to strings.EqualFold(target.Domain, domain)
        if target_domain.lower() == domain.lower():
            hostnames_url = target.get("hostnames", "")
            if not hostnames_url:
                break
                
            # Fetch hostnames from the specific URL
            try:
                req2 = urllib.request.Request(hostnames_url, headers={'User-Agent': 'SubTerra'})
                with urllib.request.urlopen(req2) as response:
                    body2 = response.read().decode('utf-8')
            except urllib.error.HTTPError as e:
                # Replicating Go's specific error message for this step
                return [], Exception(f"error fetching hostnames from Trickest: request failed with status {e.code} {e.reason}")
            except urllib.error.URLError as e:
                return [], Exception(f"error fetching hostnames from Trickest: {e}")
            except Exception as e:
                return [], Exception(f"error fetching hostnames from Trickest: {e}")

            # 4. Split the response into individual hostnames
            lines = body2.split('\n')
            for line in lines:
                line = line.strip()
                if line:
                    hostnames_raw.append(line)
            
            # Equivalent to Go's break (No need to continue after finding the correct domain)
            break

    # 5. Use a set to track unique filtered subdomains (equivalent to map[string]bool)
    subdomain_set = set()
    
    for hostname in hostnames_raw:
        if is_subdomain_or_domain(hostname, domain):
            normalized = normalize_subdomain(hostname)
            if normalized:
                subdomain_set.add(normalized)

    # 6. Convert set to list (equivalent to converting map to slice)
    filtered_hostnames = list(subdomain_set)
    
    return filtered_hostnames, None