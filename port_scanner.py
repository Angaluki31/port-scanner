#!/usr/bin/env python3
"""
port_scanner.py - Multithreaded TCP port scanner.

Features: banner grabbing, multiple hosts / CIDR ranges, hosts from a file,
common-port preset, JSON/CSV export, optional progress bar (tqdm).

"""
import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime

try:
    from tqdm import tqdm
except ImportError:  # progress bar is optional
    tqdm = None

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 3306, 3389, 5432, 5900, 8000, 8080, 8443,
]
HTTP_PORTS = {80, 8000, 8080, 8443}
MAX_CIDR_HOSTS = 1024


@dataclass
class PortResult:
    host: str
    ip: str
    port: int
    service: str
    banner: str


def get_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(sock: socket.socket, host: str, port: int) -> str:
    """Try to read a short banner from an already-connected socket."""
    try:
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = sock.recv(1024).decode(errors="ignore").strip()
        if not data:
            return ""
        lines = data.splitlines()
        for line in lines:  # prefer the HTTP Server header when present
            if line.lower().startswith("server:"):
                return line[:100]
        return lines[0][:100]
    except OSError:
        return ""


def scan_port(host: str, ip: str, port: int, timeout: float, banners: bool):
    """Return a PortResult if the port is open, else None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            return None
        banner = grab_banner(s, host, port) if banners else ""
        return PortResult(host, ip, port, get_service(port), banner)


def parse_ports(spec: str) -> list[int]:
    """Parse '1-1024', '22,80,443', 'common', or a mix like '22,80,8000-8100'."""
    if spec.lower() == "common":
        return COMMON_PORTS
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def expand_targets(targets: list[str]) -> list[str]:
    """Expand CIDR notation (e.g. 192.168.1.0/24) into individual hosts."""
    hosts = []
    for t in targets:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            ips = [str(ip) for ip in net.hosts()]
            if len(ips) > MAX_CIDR_HOSTS:
                raise ValueError(f"{t} has too many hosts (max {MAX_CIDR_HOSTS})")
            hosts.extend(ips)
        else:
            hosts.append(t)
    return hosts


def load_targets(args) -> list[str]:
    targets = list(args.targets)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            targets += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    return expand_targets(targets)


def save_json(results, path, meta):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "results": [asdict(r) for r in results]}, f, indent=2)


def save_csv(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["host", "ip", "port", "service", "banner"])
        writer.writeheader()
        writer.writerows(asdict(r) for r in results)


def build_parser():
    p = argparse.ArgumentParser(description="Multithreaded TCP port scanner")
    p.add_argument("targets", nargs="*", help="Hosts, IPs or CIDR ranges")
    p.add_argument("-f", "--file", help="File with one target per line")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="Ports: '1-1024', '22,80,443' or 'common' (default 1-1024)")
    p.add_argument("-t", "--timeout", type=float, default=0.5, help="Timeout in seconds")
    p.add_argument("-w", "--workers", type=int, default=100, help="Thread count")
    p.add_argument("-b", "--banners", action="store_true", help="Grab service banners")
    p.add_argument("--json", metavar="FILE", help="Save results as JSON")
    p.add_argument("--csv", metavar="FILE", help="Save results as CSV")
    p.add_argument("--no-progress", action="store_true", help="Disable progress bar")
    return p


def main():
    args = build_parser().parse_args()
    if not args.targets and not args.file:
        build_parser().error("provide at least one target or --file")

    try:
        ports = parse_ports(args.ports)
        targets = load_targets(args)
    except (ValueError, OSError) as e:
        sys.exit(f"Error: {e}")

    # Resolve hostnames once up front
    resolved = {}
    for host in targets:
        try:
            resolved[host] = socket.gethostbyname(host)
        except socket.gaierror:
            print(f"[!] Could not resolve {host}, skipping")

    if not resolved:
        sys.exit("No valid targets.")

    total = len(resolved) * len(ports)
    print(f"Scanning {len(resolved)} host(s), {len(ports)} port(s) each...\n")
    start = time.time()
    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(scan_port, host, ip, port, args.timeout, args.banners)
            for host, ip in resolved.items()
            for port in ports
        ]
        iterator = as_completed(futures)
        if tqdm and not args.no_progress:
            iterator = tqdm(iterator, total=total, unit="port", leave=False)
        for fut in iterator:
            res = fut.result()
            if res:
                results.append(res)

    results.sort(key=lambda r: (r.ip, r.port))
    elapsed = time.time() - start

    if results:
        print(f"{'HOST':<20}{'PORT':<8}{'SERVICE':<14}BANNER")
        for r in results:
            print(f"{r.ip:<20}{r.port:<8}{r.service:<14}{r.banner}")
    else:
        print("No open ports found.")
    print(f"\nDone: {len(results)} open port(s) in {elapsed:.2f}s")

    meta = {
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "targets": list(resolved),
        "ports_scanned": len(ports),
        "duration_seconds": round(elapsed, 2),
    }
    if args.json:
        save_json(results, args.json, meta)
        print(f"Saved JSON -> {args.json}")
    if args.csv:
        save_csv(results, args.csv)
        print(f"Saved CSV  -> {args.csv}")


if __name__ == "__main__":
    main()