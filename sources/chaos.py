import urllib.request
import urllib.error
import json
import io
import zipfile
import sys
from typing import Any

def normalize_subdomain(text: str) -> str:
    text = text.strip().lower()
    if not text: return ""
    if text.startswith("*."): return ""
    if "@" in text: return ""
    if text.endswith("."): text = text[:-1]
    if "." not in text: return ""
    return text

def process_domain_chaos(domain: str, writer: Any) -> int:
    if writer is None:
        writer = sys.stdout

    # 1. Fetch bugbounty list (Updated URL for ProjectDiscovery's new repo structure)
    url1 = "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/dist/data.json"
    try:
        req1 = urllib.request.Request(url1, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req1) as resp:
            if resp.status != 200: raise Exception(f"status {resp.status}")
            body1 = resp.read().decode('utf-8')
    except Exception as e:
        raise Exception(f"error fetching bugbounty list: {e}")

    try:
        root = json.loads(body1)
    except json.JSONDecodeError as e:
        raise Exception(f"error unmarshaling bugbounty json: {e}")

    program_name = ""
    for p in root.get("programs", []):
        if domain in p.get("domains", []):
            program_name = p.get("name", "")
            break

    if not program_name:
        return 0

    # 2. Fetch chaos data index
    url2 = "https://chaos-data.projectdiscovery.io/index.json"
    try:
        req2 = urllib.request.Request(url2, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req2) as resp:
            if resp.status != 200: raise Exception(f"status {resp.status}")
            body2 = resp.read().decode('utf-8')
    except Exception as e:
        raise Exception(f"error fetching chaos data index: {e}")

    try:
        chaos_data = json.loads(body2)
    except json.JSONDecodeError as e:
        raise Exception(f"error unmarshaling chaos index json: {e}")

    count_added = 0
    for data in chaos_data:
        if data.get("name") == program_name:
            # FIX: The API returns "URL" (uppercase), but we check both just in case
            download_url = data.get("URL") or data.get("url")
            if not download_url:
                continue

            try:
                req3 = urllib.request.Request(download_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
                with urllib.request.urlopen(req3) as resp:
                    if resp.status != 200: raise Exception(f"status {resp.status}")
                    zip_bytes = resp.read()
            except Exception as e:
                raise Exception(f"error downloading data: {e}")

            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                    target_file = f"{domain}.txt"
                    if target_file in zf.namelist():
                        with zf.open(target_file) as f:
                            for line in f:
                                text = line.decode('utf-8').strip()
                                if text:
                                    normalized = normalize_subdomain(text)
                                    if normalized:
                                        result = writer.write(normalized)
                                        if result == 1:
                                            count_added += 1
                                        elif result > 1 and not hasattr(writer, 'seen_stdout'):
                                            count_added += 1
            except Exception as e:
                raise Exception(f"error processing zip file: {e}")
                
    return count_added