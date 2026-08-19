# SubTerra
```

SubTerra is a powerful subdomain enumeration tool written in pure Python that aggregates data from multiple sources to create comprehensive lists of root subdomains.

SubTerra aggregates subdomains from **17+ passive sources**, deduplicates results in real time, and presents a beautiful per-source summary table — all with nothing but the Python standard library.

> *Made with jealousy by XPL01T* 🐍

---

## ✨ Features

- 17+ Data Sources** — Certificate Transparency logs, security APIs, OSINT datasets, and public bug-bounty archives
- Parallel Processing** — Scan all sources simultaneously with `--parallel`
- Real-Time Deduplication** — Thread-safe, cross-source duplicate removal for both stdout and file output
- Smart Normalization** — Automatically filters wildcard entries (`*.example.com`), email addresses, and invalid hostnames
- Verbose Summary Table** — Per-source counts, timings, and status in a clean box-drawing table
- File + Terminal Output** — Save results with `-o` while still streaming to the terminal
- Flexible Source Control** — Run a single source, or exclude the ones you don't want
- External Tool Support** — Integrates [subfinder](https://github.com/projectdiscovery/subfinder) via the `--all` flag
- Zero pip Dependencies** — Built entirely on the Python standard library (`urllib`, `json`, `re`, `csv`, `zipfile`, `threading`)

---

## 📦 Installation

**Requirements:** Python 3.8+ · *(optional)* [subfinder](https://github.com/projectdiscovery/subfinder) in your `PATH` for `--all`

```bash
git clone https://github.com/D-XPL01T/SubTerra.git
cd SubTerra
python3 main.py --help
```

Optional: install it as a system command:

```bash
pip install -e .
echo "example.com" | subterra --verbose
```

---

## 🔑 API Keys (Optional but Recommended)

SubTerra works out of the box with free sources. For maximum coverage, add your keys directly in the source files:

| Service | File | Constant | Get a key |
|---|---|---|---|
| VirusTotal | `sources/virustotal.py` | `VT_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/join-us) (free) |
| Shodan | `sources/shodan.py` | `SHODAN_API_KEY` | [developer.shodan.io](https://developer.shodan.io) (DNS endpoint requires membership) |
| AlienVault OTX | `sources/alienvault.py` | `OTX_API_KEY` *(optional)* | [otx.alienvault.com](https://otx.alienvault.com) (free, avoids 429s) |

> ⚠️ **Security note:** Never commit your API keys. Keep them local or replace the constants with placeholders before sharing your code.

---

## 🚀 Usage

```
echo "example.com" | python3 main.py [flags]
cat domains.txt   | python3 main.py [flags]
```

| Flag | Description |
|---|---|
| `-s, --source` | Choose a specific source, or `all` (default: `all`) |
| `-e, --exclude-source` | Comma-separated list of sources to exclude |
| `-l, --list-sources` | List all available sources and exit |
| `-p, --parallel` | Run all sources in parallel |
| `-o, --output` | Save results to a file |
| `-a, --all` | Include external tools (subfinder) |
| `--verbose` | Show the detailed summary table |
| `--silent` | Silent mode (subdomains only) |
| `--version` | Print version and exit |

### Examples

```bash
# Basic scan
echo "example.com" | python3 main.py

# Fast parallel scan with summary table
echo "example.com" | python3 main.py --parallel --verbose

# Save to file
echo "example.com" | python3 main.py -o subs.txt

# Single source only
echo "example.com" | python3 main.py -s crtsh

# Exclude noisy sources
echo "example.com" | python3 main.py -e shodan,dnsdumpster

# Everything, everywhere, all at once
cat targets.txt | python3 main.py --all --parallel --verbose -o results.txt
```

---

## 🗂️ Available Sources

| Source | Type | Notes |
|---|---|---|
| `subdomaincenter` | API | Free, no key |
| `jldc` | API | Frequently rate-limited (403) |
| `virustotal` | API | Requires free `VT_API_KEY` |
| `alienvault` | API | Anonymous OK; rate-limited (429) |
| `urlscan` | API | Free, no key |
| `certspotter` | CT Log | Free, no key |
| `hackertarget` | API | Free, no key |
| `crtsh` | CT Log | Free, can be slow |
| `trickest` | GitHub | Free, no key |
| `subdomainfinder` | Scraping | Free (c99.nl) |
| `chaos` | Dataset | ProjectDiscovery public bug-bounty data |
| `merklemap` | API | Free, no key |
| `shodan` | API | Key required; DNS endpoint = paid tier |
| `reverseipdomain` | API | Free, no key |
| `dnsdumpster` | Scraping | Cloudflare-protected (often 403) |
| `bugbountydata` | GitHub | Free, no key |
| `subfinder` | External | Requires binary + `--all` flag |

> **Note:** Third-party OSINT APIs change often. A `403/429/404` in the summary table simply means that source is rate-limited or has no data for your target — SubTerra handles all failures gracefully and continues scanning.

---

## 📊 Sample Output (`--verbose`)

```
╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║Subdomain Enumeration Summary - hackerone.com                                                         ║
╠═══════════════════╦═════════╦═══════════╦════════════════════════════════════════════════════════════╣
║ Source            ║ Count   ║ Time      ║ Status                                                     ║
╠═══════════════════╬═════════╬═══════════╬════════════════════════════════════════════════════════════╣
║ subdomaincenter   ║ 512     ║ 1.456s    ║ ✓ Success                                                  ║
║ virustotal        ║ 87      ║ 0.972s    ║ ✓ Success                                                  ║
║ chaos             ║ 24      ║ 1.001s    ║ ✓ Success                                                  ║
║ crtsh             ║ 6       ║ 9.538s    ║ ✓ Success                                                  ║
║ shodan            ║ 0       ║ 0.824s    ║ ✗ Requires membership or higher to access                  ║
╠═══════════════════╬═════════╬═══════════╬════════════════════════════════════════════════════════════╣
║ TOTAL             ║ 629     ║ 12.791s   ║                                                            ║
╚═══════════════════╩═════════╩═══════════╩════════════════════════════════════════════════════════════╝
```

---

## 🗃️ Project Structure

```
SubTerra/
├── main.py              # CLI entry point, concurrency & summary table
├── banner.py            # ASCII banner & version info
├── pyproject.toml       # Optional pip installation
├── README.md
└── sources/             # Enumeration modules (pure stdlib)
    ├── __init__.py      # Exposes all fetchers to main.py
    ├── utils.py         # normalize_subdomain / is_subdomain_or_domain
    ├── alienvault.py
    ├── bugbountydata.py
    ├── certspotter.py
    ├── chaos.py
    ├── crtsh.py
    ├── dnsdumpster.py
    ├── hackertarget.py
    ├── jldc.py
    ├── merklemap.py
    ├── reverseipdomain.py
    ├── shodan.py
    ├── subdomaincenter.py
    ├── subdomainfinder.py
    ├── subfinder.py
    ├── trickest.py
    ├── urlscan.py
    └── virustotal.py
```

---

## ⚖️ Disclaimer

SubTerra is intended for **authorized security testing, bug bounty research, and educational purposes only**. You are responsible for complying with each data source's terms of service and for obtaining proper authorization before scanning any domain.

---

## 🙏 Credits
- Data sources: ProjectDiscovery (Chaos), crt.sh, CertSpotter, URLScan.io, HackerTarget, AlienVault OTX, VirusTotal, Shodan, Trickest, MerkleMap, DNSDumpster, and the bug-bounty community.
