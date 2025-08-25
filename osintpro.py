from __future__ import annotations

import argparse
import configparser
import csv
import json
import os
import random
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

# ---------------------------
# Global console & banner
# ---------------------------
console = Console()

BANNER = "[bold cyan]=== OSINT Compass Pro ===[/bold cyan]"

# ---------------------------
# Network session with retries
# ---------------------------

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

@dataclass
class NetConfig:
    timeout: int = 20
    retries: int = 3
    backoff: float = 0.7
    jitter: float = 0.3
    proxy: Optional[str] = None


def build_session(cfg: NetConfig) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=cfg.retries,
        read=cfg.retries,
        connect=cfg.retries,
        backoff_factor=cfg.backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "HEAD"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    if cfg.proxy:
        session.proxies = {"http": cfg.proxy, "https": cfg.proxy}
    return session


# ---------------------------
# Config helpers
# ---------------------------

def load_config(path: str = "config.ini") -> configparser.ConfigParser:
    c = configparser.ConfigParser()
    if os.path.exists(path):
        try:
            c.read(path)
        except Exception as e:
            console.print(f"[red]Failed to parse config.ini: {e}[/red]")
    return c


def get_api_key(cfg: configparser.ConfigParser, service: str) -> str:
    # Try config.ini first, then environment variable, then fallback
    try:
        key = cfg.get("api_keys", service, fallback=None)
        if key:
            return key.strip()
    except Exception:
        pass
    # Try environment variable
    if service == "virustotal":
        env_key = os.getenv("VT_API_KEY")
        if env_key:
            return env_key.strip()
        # Fallback hardcoded key (not recommended for production)
        return "8eff611570568176b065351cf8ac051e44c5deb2b7deeb6032329c2bc4091e01"
    return ""


# ---------------------------
# Utility
# ---------------------------

def jitter_sleep(base: float) -> None:
    time.sleep(base + random.random() * 0.25)


def normalize_name(name: str) -> str:
    name = name.strip().lower()
    if name.startswith("*."):
        name = name[2:]
    return name


def valid_for_domain(name: str, domain: str) -> bool:
    n = name.lower()
    d = domain.lower()
    return n == d or n.endswith("." + d)


# ---------------------------
# Passive Sources (JSON-friendly)
# ---------------------------

class Source:
    """Base class for sources; each returns (subdomains, urls)."""

    def fetch(self, session: requests.Session, domain: str, net: NetConfig, api_keys: Dict[str, str]) -> Tuple[Set[str], List[str]]:
        raise NotImplementedError


class CRTSh(Source):
    def fetch(self, session: requests.Session, domain: str, net: NetConfig, api_keys: Dict[str, str]) -> Tuple[Set[str], List[str]]:
        subs: Set[str] = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            r = session.get(url, headers=headers, timeout=net.timeout)
            if r.status_code == 200:
                try:
                    data = r.json()
                except json.JSONDecodeError:
                    console.print("[yellow]CRT.sh returned non-JSON (likely rate limit/WAF). Skipping.[/yellow]")
                    return subs, []
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for line in name_value.split("\n"):
                        nm = normalize_name(line)
                        if nm and valid_for_domain(nm, domain) and "*" not in nm:
                            subs.add(nm)
            elif r.status_code == 429:
                console.print("[yellow]CRT.sh rate-limited (429).[/yellow]")
            else:
                console.print(f"[yellow]CRT.sh HTTP {r.status_code}; continuing.[/yellow]")
        except requests.RequestException as e:
            console.print(f"[red]CRT.sh error: {e}[/red]")
        return subs, []


class SonarOmnisint(Source):
    """https://sonar.omnisint.io/subdomains/{domain} -> [list]"""

    def fetch(self, session: requests.Session, domain: str, net: NetConfig, api_keys: Dict[str, str]) -> Tuple[Set[str], List[str]]:
        subs: Set[str] = set()
        url = f"https://sonar.omnisint.io/subdomains/{domain}"
        try:
            r = session.get(url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=net.timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    for s in data:
                        nm = normalize_name(str(s))
                        if nm and valid_for_domain(nm, domain):
                            subs.add(nm)
            else:
                console.print(f"[yellow]Sonar HTTP {r.status_code}[/yellow]")
        except requests.RequestException as e:
            console.print(f"[red]Sonar error: {e}[/red]")
        return subs, []


class AnubisDB(Source):
    """https://jldc.me/anubis/subdomains/{domain} -> [list]"""

    def fetch(self, session: requests.Session, domain: str, net: NetConfig, api_keys: Dict[str, str]) -> Tuple[Set[str], List[str]]:
        subs: Set[str] = set()
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        try:
            r = session.get(url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=net.timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    for s in data:
                        nm = normalize_name(str(s))
                        if nm and valid_for_domain(nm, domain):
                            subs.add(nm)
            else:
                console.print(f"[yellow]Anubis HTTP {r.status_code}[/yellow]")
        except requests.RequestException as e:
            console.print(f"[red]Anubis error: {e}[/red]")
        return subs, []


class OTXPassiveDNS(Source):
    """AlienVault OTX passive DNS: https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"""

    def fetch(self, session: requests.Session, domain: str, net: NetConfig, api_keys: Dict[str, str]) -> Tuple[Set[str], List[str]]:
        subs: Set[str] = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        try:
            r = session.get(url, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=net.timeout)
            if r.status_code == 200:
                data = r.json()
                for rec in data.get("passive_dns", []) or []:
                    nm = normalize_name(str(rec.get("hostname", "")))
                    if nm and valid_for_domain(nm, domain):
                        subs.add(nm)
            elif r.status_code == 429:
                console.print("[yellow]OTX rate-limited (429).[/yellow]")
            else:
                console.print(f"[yellow]OTX HTTP {r.status_code}[/yellow]")
        except requests.RequestException as e:
            console.print(f"[red]OTX error: {e}[/red]")
        return subs, []


class WaybackCDX(Source):
    """Wayback Machine CDX API -> historical URLs for *.domain"""

    def fetch(self, session: requests.Session, domain: str, net: NetConfig, api_keys: Dict[str, str]) -> Tuple[Set[str], List[str]]:
        urls: List[str] = []
        # Collapse on urlkey to deduplicate, only need original URLs
        url = "http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
        }
        try:
            r = session.get(url, params=params, headers={"User-Agent": random.choice(USER_AGENTS)}, timeout=net.timeout)
            if r.status_code == 200:
                data = r.json()
                # data[0] is header when output=json; subsequent are [url]
                for row in data[1:]:
                    if row and isinstance(row, list) and row[0]:
                        urls.append(row[0])
            else:
                console.print(f"[yellow]Wayback HTTP {r.status_code}[/yellow]")
        except requests.RequestException as e:
            console.print(f"[red]Wayback error: {e}[/red]")
        # Not returning subdomains here; we could parse hosts from URLs later.
        return set(), urls


class VirusTotal(Source):
    """VT v3 domains/{domain}/subdomains?limit=1000 (paged); requires API key."""

    def fetch(self, session: requests.Session, domain: str, net: NetConfig, api_keys: Dict[str, str]) -> Tuple[Set[str], List[str]]:
        subs: Set[str] = set()
        api_key = api_keys.get("virustotal", "")
        if not api_key:
            console.print("[yellow]VirusTotal API key not found; skipping VT.[/yellow]")
            return subs, []
        headers = {"x-apikey": api_key, "User-Agent": random.choice(USER_AGENTS)}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        params = {"limit": 1000}
        try:
            while True:
                r = session.get(url, headers=headers, params=params, timeout=net.timeout)
                if r.status_code == 401:
                    console.print("[red]VirusTotal unauthorized; check API key.[/red]")
                    break
                if r.status_code == 429:
                    console.print("[yellow]VirusTotal rate-limited (429). Backing off...[/yellow]")
                    jitter_sleep(1.5)
                    continue
                if r.status_code != 200:
                    console.print(f"[yellow]VirusTotal HTTP {r.status_code}[/yellow]")
                    break
                data = r.json()
                for it in data.get("data", []) or []:
                    nm = normalize_name(str(it.get("id", "")))
                    if nm and valid_for_domain(nm, domain):
                        subs.add(nm)
                nxt = data.get("links", {}).get("next")
                if not nxt:
                    break
                url = nxt
                params = None  # next has query embedded
                jitter_sleep(0.2)
        except requests.RequestException as e:
            console.print(f"[red]VirusTotal error: {e}[/red]")
        return subs, []


class CertSpotter(Source):
    """https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names
    Free tier requires API token; we page with 'Link' header.
    """

    def fetch(self, session: requests.Session, domain: str, net: NetConfig, api_keys: Dict[str, str]) -> Tuple[Set[str], List[str]]:
        subs: Set[str] = set()
        api_key = api_keys.get("certspotter", "")
        if not api_key:
            # Silent skip if not provided
            return subs, []
        headers = {"Authorization": f"Bearer {api_key}", "User-Agent": random.choice(USER_AGENTS)}
        url = "https://api.certspotter.com/v1/issuances"
        params = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
        try:
            while True:
                r = session.get(url, headers=headers, params=params, timeout=net.timeout)
                if r.status_code == 429:
                    console.print("[yellow]CertSpotter rate-limited (429). Backing off...[/yellow]")
                    jitter_sleep(1.2)
                    continue
                if r.status_code != 200:
                    console.print(f"[yellow]CertSpotter HTTP {r.status_code}[/yellow]")
                    break
                data = r.json()
                for cert in data or []:
                    for nm in cert.get("dns_names", []) or []:
                        nm = normalize_name(str(nm))
                        if nm and valid_for_domain(nm, domain):
                            subs.add(nm)
                # Pagination via Link header
                link = r.headers.get("Link", "")
                next_url = None
                for part in link.split(","):
                    if "rel=\"next\"" in part:
                        seg = part.split(";")[0].strip()
                        next_url = seg.strip("<>")
                        break
                if not next_url:
                    break
                url = next_url
                params = None
                jitter_sleep(0.2)
        except requests.RequestException as e:
            console.print(f"[red]CertSpotter error: {e}[/red]")
        return subs, []


# ---------------------------
# Orchestrator
# ---------------------------

SOURCES: List[Source] = [
    CRTSh(),
    SonarOmnisint(),
    AnubisDB(),
    OTXPassiveDNS(),
    WaybackCDX(),  # yields URLs only
    VirusTotal(),  # optional with key
    CertSpotter(), # optional with key
]


@dataclass
class RunOptions:
    domain: str
    resolve: bool = False
    concurrency: int = 16
    timeout: int = 20
    retries: int = 3
    backoff: float = 0.7
    jitter: float = 0.3
    proxy: Optional[str] = None


class Cache:
    """In-memory cache for this run to de-duplicate HTTP calls per URL+params."""
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._store: Dict[str, Tuple[int, object]] = {}

    def get(self, key: str) -> Optional[Tuple[int, object]]:
        with self._lock:
            return self._store.get(key)

    def set(self, key: str, value: Tuple[int, object]) -> None:
        with self._lock:
            self._store[key] = value


# (Currently unused, but can be integrated if we add per-request caching.)
CACHE = Cache()


def run_sources(opts: RunOptions, api_keys: Dict[str, str]) -> Tuple[Set[str], List[str]]:
    net = NetConfig(timeout=opts.timeout, retries=opts.retries, backoff=opts.backoff, jitter=opts.jitter, proxy=opts.proxy)
    session = build_session(net)

    all_subs: Set[str] = set()
    all_urls: List[str] = []

    # Parallelize with threads; sources count is small, so threads suffice.
    results: List[Tuple[Set[str], List[str]]] = []
    errors: List[str] = []

    def worker(src: Source) -> None:
        try:
            s, u = src.fetch(session, opts.domain, net, api_keys)
            results.append((s, u))
        except Exception as e:  # isolation: one source never kills the run
            errors.append(f"{src.__class__.__name__}: {e}")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True, console=console) as progress:
        task = progress.add_task("Enumerating via passive sources...", total=len(SOURCES))
        threads: List[threading.Thread] = []
        for src in SOURCES:
            t = threading.Thread(target=lambda s=src: (worker(s), progress.update(task, advance=1)))
            t.daemon = True
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    for s, u in results:
        all_subs.update(s)
        all_urls.extend(u)

    # Expand subdomains from historical URLs too (optional heuristic)
    for u in set(all_urls):
        host = None
        try:
            # crude parse without urlparse to avoid pulling scheme issues; still okay
            if "://" in u:
                host = u.split("://", 1)[1].split("/", 1)[0]
            else:
                host = u.split("/", 1)[0]
        except Exception:
            host = None
        if host:
            nm = normalize_name(host)
            if nm and valid_for_domain(nm, opts.domain):
                all_subs.add(nm)

    return all_subs, all_urls


# ---------------------------
# DNS Resolution (optional)
# ---------------------------

def resolve_alive(subs: Iterable[str], concurrency: int = 32, timeout: float = 2.0) -> Tuple[Set[str], Dict[str, List[str]]]:
    """Use socket.getaddrinfo to check DNS resolution and collect IPs.
    No external deps. Fast and best-effort only.
    """
    subs_list = list(set(subs))
    alive: Set[str] = set()
    ipmap: Dict[str, List[str]] = {}

    lock = threading.Lock()

    def res_worker(batch: List[str]) -> None:
        for host in batch:
            try:
                addrs = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
                ips = sorted({item[4][0] for item in addrs})
                with lock:
                    alive.add(host)
                    ipmap[host] = ips
            except socket.gaierror:
                # unresolved; ignore
                pass
            except Exception:
                pass

    if not subs_list:
        return alive, ipmap

    # chunk work
    n = max(1, concurrency)
    size = max(1, len(subs_list) // n)
    threads: List[threading.Thread] = []
    for i in range(0, len(subs_list), size):
        t = threading.Thread(target=res_worker, args=(subs_list[i:i+size],))
        t.daemon = True
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout)
    return alive, ipmap


# ---------------------------
# Rendering & Output
# ---------------------------

def render_subdomains(title: str, subs: Iterable[str]) -> None:
    subs = sorted(set(subs))
    table = Table(title=title, title_style="bold green", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("No.", style="cyan", justify="right")
    table.add_column("Subdomain", style="white", overflow="fold")
    for i, s in enumerate(subs, 1):
        table.add_row(str(i), s)
    if subs:
        console.print(table)
    else:
        console.print(Panel.fit("No subdomains found.", style="dim"))


def render_urls(title: str, urls: Iterable[str]) -> None:
    urls = sorted(set(urls))
    table = Table(title=title, title_style="bold magenta", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("No.", style="cyan", justify="right")
    table.add_column("URL", style="white", overflow="fold")
    for i, u in enumerate(urls, 1):
        table.add_row(str(i), u)
    if urls:
        console.print(table)
    else:
        console.print(Panel.fit("No historical URLs found.", style="dim"))


def print_summary(unique_subs: Set[str], urls: List[str], resolved: Optional[Set[str]] = None) -> None:
    msg = Text.assemble(
        ("Scan complete. ", "bold green"),
        ("Found ", "white"),
        (f"{len(unique_subs)}", "bold cyan"),
        (" unique subdomains and ", "white"),
        (f"{len(set(urls))}", "bold magenta"),
        (" historical URLs.", "white"),
    )
    if resolved is not None:
        msg.append_text(Text.assemble(("  Resolvable: ", "white"), (f"{len(resolved)}", "bold yellow")))
    console.print(Panel.fit(msg, title="Summary", title_align="left", border_style="green", box=box.ROUNDED))


# ---------------------------
# Persistence
# ---------------------------

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def save_txt(path: Path, items: Iterable[str]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for it in sorted(set(items)):
            f.write(it + "\n")


def save_json(path: Path, data: dict) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def save_csv(path: Path, rows: Iterable[Tuple[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["type", "value"])
        for t, v in rows:
            w.writerow([t, v])


# ---------------------------
# CLI
# ---------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="OSINT Compass Pro",
        description="Master-grade passive enumerator for subdomains & historical URLs.",
    )
    p.add_argument("-d", "--domain", required=True, help="Target domain, e.g., example.com")
    p.add_argument("--resolve", action="store_true", help="Attempt DNS resolution to filter alive subdomains")
    p.add_argument("--concurrency", type=int, default=16, help="Thread concurrency (for resolvers & source fanout)")
    p.add_argument("--timeout", type=int, default=20, help="Per-request timeout in seconds")
    p.add_argument("--retries", type=int, default=3, help="Total HTTP retries (with backoff)")
    p.add_argument("--backoff", type=float, default=0.7, help="Exponential backoff factor")
    p.add_argument("--proxy", type=str, default=None, help="Proxy like http://127.0.0.1:8080")
    p.add_argument("-o", "--out", default=None, help="Output directory (created if missing)")
    p.add_argument("--formats", nargs="+", default=["txt"], choices=["txt", "json", "csv"], help="Output formats")
    return p.parse_args()


def main() -> None:
    console.print(BANNER)
    args = parse_args()

    domain = args.domain.strip().lower()
    if not domain or "." not in domain:
        console.print("[red]Provide a valid domain (e.g., example.com).[/red]")
        sys.exit(2)

    console.print(Panel.fit(f"Target: [bold white]{domain}[/bold white]", border_style="cyan", box=box.ROUNDED))

    cfg = load_config()
    api_keys = {
        "virustotal": get_api_key(cfg, "virustotal"),
        "certspotter": get_api_key(cfg, "certspotter"),
    }

    opts = RunOptions(
        domain=domain,
        resolve=bool(args.resolve),
        concurrency=max(1, int(args.concurrency)),
        timeout=int(args.timeout),
        retries=int(args.retries),
        backoff=float(args.backoff),
        proxy=args.proxy,
    )

    subs, urls = run_sources(opts, api_keys)

    alive_subs: Optional[Set[str]] = None
    ipmap: Dict[str, List[str]] = {}
    if opts.resolve and subs:
        console.print("[blue]Resolving discovered subdomains...[/blue]")
        alive_subs, ipmap = resolve_alive(subs, concurrency=opts.concurrency)

    # Render
    render_subdomains("[+] Aggregated Subdomains", alive_subs if alive_subs is not None else subs)
    render_urls("[+] Historical URLs (Wayback & others)", urls)
    print_summary(subs, urls, resolved=alive_subs)

    # Persist
    if args.out:
        out_dir = Path(args.out)
        ensure_dir(out_dir)
        if "txt" in args.formats:
            save_txt(out_dir / "subdomains.txt", alive_subs or subs)
            save_txt(out_dir / "urls.txt", urls)
        if "json" in args.formats:
            payload = {
                "domain": domain,
                "subdomains": sorted(set(alive_subs or subs)),
                "urls": sorted(set(urls)),
                "resolved_ips": ipmap,
            }
            save_json(out_dir / "results.json", payload)
        if "csv" in args.formats:
            rows: List[Tuple[str, str]] = [("subdomain", s) for s in sorted(set(alive_subs or subs))]
            rows += [("url", u) for u in sorted(set(urls))]
            save_csv(out_dir / "results.csv", rows)
        console.print(Panel.fit(f"Saved outputs to [bold]{out_dir.resolve()}[/bold]", border_style="green"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
        sys.exit(130)
