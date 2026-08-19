import urllib.request
import urllib.parse
import urllib.error
import re
import http.cookiejar
from typing import List, Optional, Tuple

def is_subdomain_or_domain(hostname: str, domain: str) -> bool:
    hostname = hostname.strip().lower()
    domain = domain.strip().lower()
    if hostname == domain: return True
    return hostname.endswith("." + domain)

def normalize_subdomain(text: str) -> str:
    text = text.strip().lower()
    if not text or text.startswith("*.") or "@" in text: return ""
    if text.endswith("."): text = text[:-1]
    return text if "." in text else ""

def fetch_subdomains_dnsdumpster(domain: str) -> Tuple[List[str], Optional[Exception]]:
    url = "https://dnsdumpster.com/"
    
    # 1. Create a cookie jar to handle session cookies automatically
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    
    try:
        # 2. GET request to fetch the page and extract the dynamic CSRF token
        req_get = urllib.request.Request(url, headers=headers)
        with opener.open(req_get) as response:
            html = response.read().decode('utf-8')
            
        # Extract csrfmiddlewaretoken from the HTML form
        match = re.search(r"name=['\"]csrfmiddlewaretoken['\"] value=['\"]([^'\"]+)['\"]", html)
        if not match:
            return [], Exception("Could not find dynamic CSRF token in DNSDumpster HTML")
            
        csrf_token = match.group(1)
        
        # 3. POST request with the dynamic token
        form_data = {"csrfmiddlewaretoken": csrf_token, "targetip": domain, "user": "free"}
        encoded_data = urllib.parse.urlencode(form_data).encode('utf-8')
        
        req_post = urllib.request.Request(url, data=encoded_data, headers=headers, method='POST')
        req_post.add_header("Referer", url)
        
        with opener.open(req_post) as response:
            body = response.read().decode('utf-8')
            
    except urllib.error.HTTPError as e:
        return [], Exception(f"request failed with status: {e.code} {e.reason}")
    except Exception as e:
        return [], e

    # 4. Regex to match the subdomain entries
    pattern = re.compile(r'<tr><td class="col-md-4">(.*?)<br</td>')
    matches = pattern.findall(body)
    
    subdomain_set = set()
    for subdomain in matches:
        subdomain = subdomain.strip()
        if subdomain and is_subdomain_or_domain(subdomain, domain):
            normalized = normalize_subdomain(subdomain)
            if normalized:
                subdomain_set.add(normalized)

    return list(subdomain_set), None