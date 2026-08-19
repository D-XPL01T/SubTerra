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

def fetch_domains_merklemap(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches subdomains for a given domain from the MerkleMap API (streaming).
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    url = f"https://api.merklemap.com/search?query={domain}&stream=true"
    
    # 1. Make HTTP GET request
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SubTerra'})
        response = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        return [], Exception(f"request failed with status: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        return [], e
    except Exception as e:
        return [], e

    # 2. Use a set to track unique filtered subdomains (equivalent to map[string]bool)
    subdomain_set = set()

    # 3. Stream line-by-line (equivalent to bufio.NewScanner(resp.Body) + scanner.Scan())
    try:
        for raw_line in response:
            # Equivalent to strings.TrimSpace(scanner.Text())
            line = raw_line.decode('utf-8').strip()
            
            # Equivalent to strings.HasPrefix(line, "data: ")
            if line.startswith("data: "):
                # Equivalent to strings.TrimPrefix(line, "data: ")
                line = line[6:]  # len("data: ") == 6
                
                # Equivalent to strings.Contains(line, `"domain"`)
                if '"domain"' in line:
                    # Equivalent to:
                    #   domainStart := strings.Index(line, `"domain":"`) + 10
                    #   domainEnd := strings.Index(line[domainStart:], `"`) + domainStart
                    #   domainName := line[domainStart:domainEnd]
                    search_str = '"domain":"'
                    start_idx = line.find(search_str)
                    
                    if start_idx != -1:
                        domain_start = start_idx + len(search_str)  # +10 in Go
                        # Find the closing quote after domain_start
                        end_offset = line[domain_start:].find('"')
                        
                        if end_offset != -1:
                            domain_end = domain_start + end_offset
                            domain_name = line[domain_start:domain_end]
                            
                            # 4. Check if it's a valid subdomain/domain
                            if is_subdomain_or_domain(domain_name, domain):
                                # 5. Normalize and add to set if not empty
                                normalized = normalize_subdomain(domain_name)
                                if normalized:
                                    subdomain_set.add(normalized)

    except Exception as e:
        # Equivalent to: if err := scanner.Err(); err != nil { return nil, err }
        response.close()
        return [], e
    finally:
        # Equivalent to: defer resp.Body.Close()
        response.close()

    # 6. Convert set to list (equivalent to converting map to slice)
    subdomains = list(subdomain_set)
    
    return subdomains, None