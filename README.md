<<<<<<< HEAD
# Python Port Scanner

A fast, multithreaded TCP port scanner written in Python. Built to learn how
networking, sockets and concurrency work.

## Features
- Multithreaded scanning with `ThreadPoolExecutor`
- Banner grabbing to identify services (`-b`)
- Multiple targets, CIDR ranges (`192.168.1.0/30`) and target files
- Flexible port specs: ranges, lists, or the `common` preset
- Export results to JSON or CSV
- Optional progress bar via `tqdm`

## Install
Requires Python 3.10+. The progress bar is optional:

    pip install -r requirements.txt

## Usage

    python port_scanner.py 127.0.0.1 -p 1-1024
    python port_scanner.py localhost -p common -b
    python port_scanner.py 192.168.1.0/28 -p 22,80,443 --json results.json
    python port_scanner.py -f targets.txt --csv results.csv

| Flag | Description |
|------|-------------|
| `-p, --ports` | `1-1024`, `22,80,443`, or `common` |
| `-f, --file` | File with one target per line |
| `-t, --timeout` | Connection timeout in seconds (default 0.5) |
| `-w, --workers` | Thread count (default 100) |
| `-b, --banners` | Grab service banners |
| `--json / --csv` | Export results |

## How it works
Each worker thread opens a TCP socket and calls `connect_ex`. A return value
of `0` means the port accepted the connection (open). For open ports the
scanner optionally reads a banner and looks up the standard service name.

## Disclaimer
Only scan systems you own or have written permission to test. Unauthorised
scanning may be illegal.

## Roadmap
- UDP scanning
- Async version with `asyncio`
- Simple GUI
=======
# port-scanner
>>>>>>> d8a4f43257bf5985add00d234bec0d36f1d57358
