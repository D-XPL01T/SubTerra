def is_subdomain_or_domain(domain: str, target_domain: str) -> bool:
    """
    Checks if a domain is either the target domain itself or a subdomain of it.
    It matches the pattern ^(.*.)?target.domain$ (e.g., "dell.com" or "admin.dell.com").
    """
    # Equivalent to: if domain == "" || targetDomain == ""
    if not domain or not target_domain:
        return False
    
    # Exact match
    if domain == target_domain:
        return True
    
    # Subdomain match: domain ends with "." + targetDomain
    # Equivalent to: strings.HasSuffix(domain, "."+targetDomain)
    return domain.endswith("." + target_domain)


def normalize_subdomain(subdomain: str) -> str:
    """
    Filters out email addresses (strings containing "@") and 
    wildcard subdomains (starting with "*.").
    Returns an empty string if the input contains "@" or starts with "*.", 
    otherwise returns the lowercase version.
    """
    # Equivalent to: strings.Contains(subdomain, "@")
    if "@" in subdomain:
        return ""
    
    # Equivalent to: strings.HasPrefix(subdomain, "*.")
    if subdomain.startswith("*."):
        return ""
    
    # Equivalent to: strings.ToLower(subdomain)
    return subdomain.lower()