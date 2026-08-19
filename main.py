import sys
import argparse
import time
import threading
import os
from typing import List, Dict, Callable, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

# Import the translated modules (ensure sources/ package and banner.py are in the same directory)
import sources
import banner

AVAILABLE_SOURCES = [
    "subdomaincenter",
    "jldc",
    "virustotal",
    "alienvault",
    "urlscan",
    "certspotter",
    "hackertarget",
    "crtsh",
    "trickest",
    "subdomainfinder",
    "chaos",
    "merklemap",
    "shodan",
    "reverseipdomain",
    "dnsdumpster",
    "bugbountydata",
    "subfinder",
]

def format_number(n: int) -> str:
    s = str(n)
    if n < 1000:
        return s
    result = []
    for i, r in enumerate(s):
        if i > 0 and (len(s) - i) % 3 == 0:
            result.append(",")
        result.append(r)
    return "".join(result)

def format_duration(seconds: float) -> str:
    return f"{seconds:.3f}s"

def print_summary(stats: List[Dict], total_duration: float, domain: str):
    # ==========================================
    # COLUMN WIDTHS - Change these to resize any column!
    # (Status expanded from 14 -> 60 so errors are fully visible)
    # ==========================================
    SRC_W, CNT_W, TIME_W, STAT_W = 17, 7, 9, 60

    inner_w = (SRC_W + 2) + 1 + (CNT_W + 2) + 1 + (TIME_W + 2) + 1 + (STAT_W + 2)

    def hline(left, mid, right):
        return (left + "═" * (SRC_W + 2) + mid + "═" * (CNT_W + 2) + mid +
                "═" * (TIME_W + 2) + mid + "═" * (STAT_W + 2) + right)

    print()
    print("╔" + "═" * inner_w + "╗")

    title_prefix = "Subdomain Enumeration Summary - "
    max_domain_len = inner_w - len(title_prefix)
    domain_display = domain
    if len(domain_display) > max_domain_len:
        domain_display = domain_display[:max_domain_len - 3] + "..."
    title = (title_prefix + domain_display).ljust(inner_w)
    print(f"║{title}║")

    print(hline("╠", "", "╣"))
    print(f"║ {'Source':<{SRC_W}} ║ {'Count':<{CNT_W}} ║ {'Time':<{TIME_W}} ║ {'Status':<{STAT_W}} ║")
    print(hline("╠", "", "╣"))

    total_count = 0
    for stat in stats:
        total_count += stat["count"]
        duration_str = format_duration(stat["duration"])

        source_name = stat["name"]
        if len(source_name) > SRC_W:
            source_name = source_name[:SRC_W - 3] + "..."

        count_str = format_number(stat["count"])
        if len(count_str) > CNT_W:
            count_str = count_str[:CNT_W - 3] + "..."

        if len(duration_str) > TIME_W:
            duration_str = duration_str[:TIME_W - 3] + "..."

        status = "✓ Success"
        if stat["error"] is not None:
            error_msg = stat["error_msg"]
            max_err = STAT_W - 2  # room for the "✗ " prefix
            if len(error_msg) > max_err:
                error_msg = error_msg[:max_err - 3] + "..."
            status = f"✗ {error_msg}"
        if len(status) > STAT_W:
            status = status[:STAT_W - 3] + "..."

        print(f"║ {source_name:<{SRC_W}} ║ {count_str:<{CNT_W}} ║ {duration_str:<{TIME_W}} ║ {status:<{STAT_W}} ║")

    print(hline("╠", "╬", "╣"))

    total_count_str = format_number(total_count)
    if len(total_count_str) > CNT_W:
        total_count_str = total_count_str[:CNT_W - 3] + "..."
    total_duration_str = format_duration(total_duration)
    if len(total_duration_str) > TIME_W:
        total_duration_str = total_duration_str[:TIME_W - 3] + "..."

    print(f"║ {'TOTAL':<{SRC_W}} ║ {total_count_str:<{CNT_W}} ║ {total_duration_str:<{TIME_W}} ║ {'':<{STAT_W}} ║")
    print(hline("╚", "", "╝"))
    print()

class UniqueFileWriter:
    def __init__(self, file, seen_subdomains: Dict[str, bool], written_to_file: Dict[str, bool], mutex: threading.Lock):
        self.file = file
        self.seen_subdomains = seen_subdomains
        self.written_to_file = written_to_file
        self.mutex = mutex

    def write(self, p) -> int:
        # Handle both bytes and str to mimic Go's []byte to string conversion
        if isinstance(p, bytes):
            text = p.decode('utf-8', errors='ignore').strip()
        else:
            text = str(p).strip()

        if not text:
            return len(p) if isinstance(p, (str, bytes)) else 0

        normalized = sources.normalize_subdomain(text)
        if not normalized:
            return len(p) if isinstance(p, (str, bytes)) else 0

        with self.mutex:
            if normalized not in self.seen_subdomains:
                print(normalized)
                self.seen_subdomains[normalized] = True

            if self.file is not None and normalized not in self.written_to_file:
                self.written_to_file[normalized] = True
                try:
                    self.file.write(normalized + "\n")
                except Exception as e:
                    self.written_to_file[normalized] = False
                    raise e

        return len(p) if isinstance(p, (str, bytes)) else 0

def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    parser.add_argument("-s", "--source", default="all", help="Choose source(s) to use, or 'all' for all sources. Use --list-sources to see available sources")
    parser.add_argument("-e", "--exclude-source", default="", help="Comma-separated list of sources to exclude when using --source all")
    parser.add_argument("-l", "--list-sources", action="store_true", help="List all available sources and exit")
    parser.add_argument("-p", "--parallel", action="store_true", help="Run all sources in parallel to speed up scanning")
    parser.add_argument("--silent", action="store_true", help="Silent mode.")
    parser.add_argument("--version", action="store_true", help="Print the version of the tool and exit.")
    parser.add_argument("--verbose", action="store_true", help="enable verbose mode")
    parser.add_argument("-o", "--output", default="", help="Save subdomain results to a file")
    parser.add_argument("-a", "--all", action="store_true", help="Run all sources including external tools (subfinder)")

    args = parser.parse_args()

    if args.list_sources:
        print("Available sources:")
        for source in AVAILABLE_SOURCES:
            if source == "subfinder":
                print(f"  - {source} (requires --all flag)")
            else:
                print(f"  - {source}")
        print("\nUse 'all' to run all sources")
        print("Use --all flag to include external tools (subfinder)")
        return

    excluded_map = {}
    if args.exclude_source:
        excluded = args.exclude_source.split(",")
        for e in excluded:
            excluded_map[e.strip()] = True

    def should_run(source_name: str) -> bool:
        if args.source == source_name:
            return source_name not in excluded_map
        if args.source == "all":
            return source_name not in excluded_map
        return False

    def should_run_subfinder() -> bool:
        return args.all and "subfinder" not in excluded_map

    if args.version:
        banner.print_banner()
        banner.print_version()
        return

    if not args.silent:
        banner.print_banner()

    file_obj = None
    if args.output:
        try:
            file_obj = open(args.output, "w", encoding="utf-8")
        except Exception as e:
            print(f"Error creating output file: {e}", file=sys.stderr)
            return

    output_mutex = threading.Lock()
    seen_subdomains = {}
    written_to_file = {}

    unique_writer = UniqueFileWriter(
        file=file_obj,
        seen_subdomains=seen_subdomains,
        written_to_file=written_to_file,
        mutex=output_mutex
    )

    def write_output(text: str):
        normalized = sources.normalize_subdomain(text)
        if not normalized:
            return
        with output_mutex:
            if normalized not in seen_subdomains:
                print(normalized)
                seen_subdomains[normalized] = True
            if file_obj is not None and normalized not in written_to_file:
                written_to_file[normalized] = True
                file_obj.write(normalized + "\n")

    # Read from stdin line by line (mimics bufio.Scanner)
    for line in sys.stdin:
        domain = line.strip()
        if not domain:
            continue

        stats = []
        stats_mutex = threading.Lock()
        domain_start_time = time.time()

        def process_source(source_name: str, domain: str, fetch_func: Callable[[str], Tuple[List[str], Optional[Exception]]]):
            if not should_run(source_name):
                return

            start_time = time.time()
            if args.verbose:
                with output_mutex:
                    print(f"Fetching from {source_name} for {domain}")

            results, err = fetch_func(domain)
            duration = time.time() - start_time

            if err is not None:
                if args.verbose:
                    with output_mutex:
                        print(f"Error fetching subdomains from {source_name} for {domain}: {err}")
                with stats_mutex:
                    stats.append({
                        "name": source_name,
                        "count": 0,
                        "duration": duration,
                        "error": err,
                        "error_msg": str(err)
                    })
                return

            with output_mutex:
                count_before = len(seen_subdomains)

            for result in results:
                write_output(result)

            with output_mutex:
                count_after = len(seen_subdomains)
                count = count_after - count_before

            with stats_mutex:
                stats.append({
                    "name": source_name,
                    "count": count,
                    "duration": duration,
                    "error": None,
                    "error_msg": ""
                })

        # ============================================================
        # FIX #1 (Parallel Chaos): removed leftover dead code that
        # referenced undefined `count_before` (NameError crash) and
        # appended a duplicate stats entry. Stats appends are now
        # protected by stats_mutex.
        # ============================================================
        def process_chaos_source(domain: str):
            if not should_run("chaos"):
                return

            start_time = time.time()
            if args.verbose:
                with output_mutex:
                    print(f"Fetching from Chaos for {domain}")

            try:
                # process_domain_chaos returns the count of added subdomains,
                # or raises an Exception on failure
                chaos_count = sources.process_domain_chaos(domain, unique_writer)
                duration = time.time() - start_time
                with stats_mutex:
                    stats.append({
                        "name": "chaos",
                        "count": chaos_count,
                        "duration": duration,
                        "error": None,
                        "error_msg": ""
                    })
            except Exception as e:
                duration = time.time() - start_time
                if args.verbose:
                    with output_mutex:
                        print(f"Error fetching subdomains from Chaos for {domain}: {e}")
                with stats_mutex:
                    stats.append({
                        "name": "chaos",
                        "count": 0,
                        "duration": duration,
                        "error": e,
                        "error_msg": str(e)
                    })

        if args.parallel:
            # Run all sources in parallel (mimics sync.WaitGroup)
            with ThreadPoolExecutor() as executor:
                futures = []
                futures.append(executor.submit(process_source, "subdomaincenter", domain, sources.fetch_subdomains_subdomaincenter))
                futures.append(executor.submit(process_source, "jldc", domain, sources.fetch_subdomains_jldc))
                futures.append(executor.submit(process_source, "virustotal", domain, sources.fetch_subdomains_virustotal))
                futures.append(executor.submit(process_source, "alienvault", domain, sources.fetch_subdomains_alienvault))
                futures.append(executor.submit(process_source, "urlscan", domain, sources.fetch_subdomains_urlscan))
                futures.append(executor.submit(process_source, "certspotter", domain, sources.fetch_dnsnames_certspotter))
                futures.append(executor.submit(process_source, "hackertarget", domain, sources.fetch_subdomains_hackertarget))
                futures.append(executor.submit(process_source, "crtsh", domain, sources.fetch_subdomains_crtsh))
                futures.append(executor.submit(process_source, "trickest", domain, sources.fetch_hostnames_trickest))
                futures.append(executor.submit(process_source, "subdomainfinder", domain, sources.fetch_subdomains_subdomain_finder))
                futures.append(executor.submit(process_chaos_source, domain))
                futures.append(executor.submit(process_source, "merklemap", domain, sources.fetch_domains_merklemap))
                futures.append(executor.submit(process_source, "shodan", domain, sources.fetch_subdomains_shodan))
                futures.append(executor.submit(process_source, "reverseipdomain", domain, sources.fetch_subdomains_reverseipdomain))
                futures.append(executor.submit(process_source, "dnsdumpster", domain, sources.fetch_subdomains_dnsdumpster))
                futures.append(executor.submit(process_source, "bugbountydata", domain, sources.fetch_subdomains_bugbounty_data))

                if should_run_subfinder():
                    futures.append(executor.submit(process_source, "subfinder", domain, sources.fetch_subdomains_subfinder))

                # Wait for all to complete (mimics wg.Wait())
                for f in futures:
                    f.result()

            if args.verbose:
                total_duration = time.time() - domain_start_time
                print_summary(stats, total_duration, domain)
        else:
            # Sequential execution
            def process_sequential_source(source_name: str, fetch_func: Callable[[str], Tuple[List[str], Optional[Exception]]]):
                if not should_run(source_name):
                    return

                start_time = time.time()
                if args.verbose:
                    print(f"Fetching from {source_name} for {domain}")

                subdomains, err = fetch_func(domain)
                duration = time.time() - start_time

                if err is not None:
                    if args.verbose:
                        print(f"Error fetching subdomains from {source_name} for {domain}: {err}")
                    stats.append({
                        "name": source_name,
                        "count": 0,
                        "duration": duration,
                        "error": err,
                        "error_msg": str(err)
                    })
                    return

                with output_mutex:
                    count_before = len(seen_subdomains)

                for subdomain in subdomains:
                    write_output(subdomain)

                with output_mutex:
                    count_after = len(seen_subdomains)
                    count = count_after - count_before

                stats.append({
                    "name": source_name,
                    "count": count,
                    "duration": duration,
                    "error": None,
                    "error_msg": ""
                })

            process_sequential_source("subdomaincenter", sources.fetch_subdomains_subdomaincenter)
            process_sequential_source("jldc", sources.fetch_subdomains_jldc)
            process_sequential_source("virustotal", sources.fetch_subdomains_virustotal)
            process_sequential_source("alienvault", sources.fetch_subdomains_alienvault)
            process_sequential_source("urlscan", sources.fetch_subdomains_urlscan)
            process_sequential_source("certspotter", sources.fetch_dnsnames_certspotter)
            process_sequential_source("hackertarget", sources.fetch_subdomains_hackertarget)
            process_sequential_source("crtsh", sources.fetch_subdomains_crtsh)
            process_sequential_source("trickest", sources.fetch_hostnames_trickest)
            process_sequential_source("subdomainfinder", sources.fetch_subdomains_subdomain_finder)

            # ============================================================
            # FIX #2 (Sequential Chaos): replaced the broken
            # `err = ... / if err is not None:` pattern (fake "✗ 24")
            # with try/except using the returned count.
            # ============================================================
            if should_run("chaos"):
                start_time = time.time()
                if args.verbose:
                    print(f"Fetching from Chaos for {domain}")

                try:
                    chaos_count = sources.process_domain_chaos(domain, unique_writer)
                    duration = time.time() - start_time
                    stats.append({
                        "name": "chaos",
                        "count": chaos_count,
                        "duration": duration,
                        "error": None,
                        "error_msg": ""
                    })
                except Exception as e:
                    duration = time.time() - start_time
                    if args.verbose:
                        print(f"Error fetching subdomains from Chaos for {domain}: {e}")
                    stats.append({
                        "name": "chaos",
                        "count": 0,
                        "duration": duration,
                        "error": e,
                        "error_msg": str(e)
                    })

            process_sequential_source("merklemap", sources.fetch_domains_merklemap)
            process_sequential_source("shodan", sources.fetch_subdomains_shodan)
            process_sequential_source("reverseipdomain", sources.fetch_subdomains_reverseipdomain)
            process_sequential_source("dnsdumpster", sources.fetch_subdomains_dnsdumpster)
            process_sequential_source("bugbountydata", sources.fetch_subdomains_bugbounty_data)

            if should_run_subfinder():
                process_sequential_source("subfinder", sources.fetch_subdomains_subfinder)

            if args.verbose:
                total_duration = time.time() - domain_start_time
                print_summary(stats, total_duration, domain)

    # Clean up file
    if file_obj is not None:
        try:
            file_obj.flush()
            os.fsync(file_obj.fileno())  # Mimics Go's file.Sync()
        except OSError:
            pass
        finally:
            file_obj.close()

if __name__ == "__main__":
    main()