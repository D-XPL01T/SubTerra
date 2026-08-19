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

def fetch_subdomains_crtsh(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches subdomains for a given domain from the crt.sh API.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    url = f"https://crt.sh/?q={domain}&output=json"
    
    # 1. Make HTTP GET request
    try:
        # crt.sh is known to block default Python User-Agents, so we set a custom one
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (SubTerra)'})
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
        # crt.sh returns a list of certificate objects
        certs = json.loads(body)
        if not isinstance(certs, list):
            return [], Exception("unexpected JSON response format: expected a list")
    except json.JSONDecodeError as e:
        return [], e

    # 3. Use a set to track unique filtered subdomains (equivalent to map[string]bool)
    subdomain_set = set()

    # Helper function to process a name string (can contain multiple subdomains)
    # Exactly replicates Go's processNameString logic
    def process_name_string(name_str: str) -> None:
        if not name_str:
            return
        
        # Split by newlines first
        for line in name_str.split('\n'):
            # Then by commas
            for comma_part in line.split(','):
                # Then by spaces. 
                # Note: Python's split() without arguments behaves exactly like Go's strings.Fields():
                # it splits by any whitespace and automatically ignores empty strings.
                for name in comma_part.split():
                    trimmed_name = name.strip()
                    if trimmed_name and is_subdomain_or_domain(trimmed_name, domain):
                        normalized = normalize_subdomain(trimmed_name)
                        if normalized:
                            subdomain_set.add(normalized)

    # 4. Iterate over certificates
    for cert in certs:
        # Process CommonName field
        common_name = cert.get("common_name", "")
        if common_name:
            trimmed_cn = common_name.strip()
            if trimmed_cn and is_subdomain_or_domain(trimmed_cn, domain):
                normalized = normalize_subdomain(trimmed_cn)
                if normalized:
                    subdomain_set.add(normalized)
        
        # Process NameValue field (can contain multiple subdomains)
        name_value = cert.get("name_value", "")
        process_name_string(name_value)

    # 5. Convert set to list (equivalent to converting map to slice)
    results = list(subdomain_set)
    
    return results, None