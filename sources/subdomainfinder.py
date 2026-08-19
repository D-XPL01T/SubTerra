import urllib.request
import urllib.error
import re
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

def fetch_subdomains_subdomain_finder(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches subdomains for a given domain from the SubdomainFinder (c99.nl) API.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    url = "https://subdomainfinder.c99.nl/"
    
    # 1. Prepare the exact POST payload (equivalent to fmt.Sprintf)
    payload = f"CSRF9843433218797932=pirate107704869&is_admin=false&jn=JS+aan%2C+T+aangeroepen%2C+CSRF+aangepast&domain={domain}&lol-stop-reverse-engineering-my-source-and-buy-an-api-key=cf917529992fd6f916e2b4ef8b37c6d97f040eba&scan_subdomains="
    encoded_data = payload.encode('utf-8')
    
    # 2. Create request with specific headers
    req = urllib.request.Request(url, data=encoded_data, method='POST')
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    
    # 3. Send request and read response
    try:
        with urllib.request.urlopen(req) as response:
            # Explicitly check status code (equivalent to resp.StatusCode != http.StatusOK)
            if response.status != 200:
                return [], Exception(f"request failed with status: {response.status} {response.reason}")
            
            body = response.read().decode('utf-8')
            
    except urllib.error.HTTPError as e:
        # Catch HTTP errors (like 403/404) explicitly to match Go's behavior cleanly
        return [], Exception(f"request failed with status: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        return [], e
    except Exception as e:
        return [], e

    # 4. Regex to match the subdomain entries
    # Equivalent to: regexp.MustCompile(`href='//([^']+)'`)
    pattern = re.compile(r"href='//([^']+)'")
    
    # findall returns a list of the captured groups (the subdomains)
    matches = pattern.findall(body)
    
    # 5. Use a set to track unique filtered subdomains (equivalent to map[string]bool)
    subdomain_set = set()
    
    for subdomain in matches:
        subdomain = subdomain.strip()
        if subdomain and is_subdomain_or_domain(subdomain, domain):
            normalized = normalize_subdomain(subdomain)
            if normalized:
                subdomain_set.add(normalized)

    # 6. Convert set to list (equivalent to converting map to slice)
    unique_subdomains = list(subdomain_set)
    
    return unique_subdomains, None