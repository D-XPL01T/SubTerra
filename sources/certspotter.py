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

def fetch_dnsnames_certspotter(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches DNS names for a given domain from the Certspotter API.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    # 1. Construct URL (equivalent to fmt.Sprintf)
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    
    # 2. Make HTTP GET request
    try:
        # Adding a User-Agent is recommended for Certspotter API to avoid rate limiting/blocks
        req = urllib.request.Request(url, headers={'User-Agent': 'SubTerra'})
        with urllib.request.urlopen(req) as response:
            # 3. Read response body (equivalent to ioutil.ReadAll)
            body = response.read().decode('utf-8')
            
    except urllib.error.HTTPError as e:
        return [], Exception(f"request failed with status: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        return [], e
    except Exception as e:
        return [], e

    # 4. Unmarshal JSON (equivalent to json.Unmarshal)
    try:
        # CertspotterResponse in Go is []struct{ DNSNames []string }
        # In Python, json.loads naturally parses this as a list of dictionaries.
        data = json.loads(body)
    except json.JSONDecodeError as e:
        return [], e
    except TypeError:
        # Handle cases where the API might return a non-list (e.g., an error object)
        return [], Exception("unexpected JSON response format")

    # 5. Use a set to track unique filtered subdomains (equivalent to map[string]bool)
    subdomain_set = set()
    
    # Ensure data is a list before iterating
    if isinstance(data, list):
        for issuance in data:
            # Safely get the dns_names list, defaulting to empty list if key is missing
            dns_names = issuance.get("dns_names", [])
            
            for dns_name in dns_names:
                # 6. Check if it's a valid subdomain/domain
                if is_subdomain_or_domain(dns_name, domain):
                    # 7. Normalize and add to set if not empty
                    normalized = normalize_subdomain(dns_name)
                    if normalized:
                        subdomain_set.add(normalized)

    # 8. Convert set to list (equivalent to converting map to slice)
    dns_names_list = list(subdomain_set)
    
    return dns_names_list, None