import subprocess
from typing import List, Optional, Tuple

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

def fetch_subdomains_subfinder(domain: str) -> Tuple[List[str], Optional[Exception]]:
    """
    Fetches subdomains using the external subfinder tool.
    Returns a tuple of (list_of_subdomains, error). 
    If successful, error is None. If failed, list is empty and error contains the Exception.
    """
    try:
        # Equivalent to exec.Command("subfinder", "-duc", "-silent", "-all", "-d", domain).Output()
        # capture_output=True captures stdout and stderr
        # text=True returns strings instead of bytes
        # check=True raises an exception if the command exits with a non-zero status
        result = subprocess.run(
            ["subfinder", "-duc", "-silent", "-all", "-d", domain],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout
        
    except FileNotFoundError:
        # Equivalent to Go returning an error if the executable is not found in PATH
        return [], Exception("error running subfinder: executable not found")
    except subprocess.CalledProcessError as e:
        # Equivalent to Go's cmd.Output() returning an error on non-zero exit code
        return [], Exception(f"error running subfinder: {e}")
    except Exception as e:
        return [], Exception(f"error running subfinder: {e}")

    # Note: Unlike the API fetchers, the Go code does NOT use a map[string]bool here.
    # It simply appends to a slice, relying on the main script's writeOutput() to handle global deduplication.
    # We replicate this exact behavior using a list.
    subdomains = []
    
    # Parse the output line by line (equivalent to bufio.NewScanner + scanner.Scan())
    # output.splitlines() cleanly handles \n and \r\n without leaving empty trailing elements.
    for line in output.splitlines():
        line = line.strip()  # equivalent to strings.TrimSpace
        
        if line:
            normalized = normalize_subdomain(line)
            if normalized:
                subdomains.append(normalized)
                
    return subdomains, None