import urllib.request
import urllib.error
import csv
import io
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

def fetch_subdomains_hackertarget(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches subdomains for a given domain from the HackerTarget API.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    
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

    # 2. Parse the CSV response (equivalent to csv.NewReader)
    try:
        # csv.reader expects an iterable of strings, so we split by newlines
        # io.StringIO is the Python equivalent of strings.NewReader
        reader = csv.reader(io.StringIO(body))
        records = list(reader)
    except csv.Error as e:
        return [], Exception(f"error parsing CSV: {e}")

    # 3. Use a set to track unique filtered subdomains (equivalent to map[string]bool)
    subdomain_set = set()
    
    # 4. Iterate over CSV records
    for record in records:
        # First column contains the subdomain (equivalent to record[0])
        if len(record) > 0:
            subdomain = record[0].strip()
            
            if subdomain and is_subdomain_or_domain(subdomain, domain):
                normalized = normalize_subdomain(subdomain)
                if normalized:
                    subdomain_set.add(normalized)

    # 5. Convert set to list (equivalent to converting map to slice)
    subdomains = list(subdomain_set)
    
    return subdomains, None