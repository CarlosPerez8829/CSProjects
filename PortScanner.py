import argparse
import asyncio  # For asynchronous operations
import socket   # For network connections
import json
import csv
from pathlib import Path
from datetime import datetime  # For timing the scan


# --- CLI handling ---
parser = argparse.ArgumentParser(description='Simple async port scanner with service-name output')
parser.add_argument('-H', '--host', help='Host to scan (name or IP). If omitted, you will be prompted or stdin is used).')
parser.add_argument('-m', '--max-port', type=int, help='Maximum port to scan (1..N). Defaults to 4999.')
parser.add_argument('-c', '--concurrency', type=int, default=300, help='Max concurrent connections (default: 300)')
parser.add_argument('-t', '--timeout', type=float, default=0.35, help='Connect timeout in seconds (default: 0.35)')
parser.add_argument('-o', '--output', help='Output file path to save results (json or csv). If omitted, results are not saved.')
parser.add_argument('-f', '--format', choices=['json', 'csv'], help='Output format (json or csv). If omitted, inferred from filename extension or defaults to json.')
args = parser.parse_args()

# Determine host: CLI > stdin/piped > interactive input
import sys
host = None
if args.host:
    host = args.host.strip()
else:
    # If data was piped into stdin, read one line
    if not sys.stdin.isatty():
        try:
            line = sys.stdin.readline().strip()
            if line:
                host = line
        except Exception:
            host = None
    if not host:
        host = input("Enter a host to scan: ").strip()

try:
    targetIP = socket.gethostbyname(host)
except socket.gaierror:
    print("Could not resolve host.")
    raise SystemExit(1)

max_port = args.max_port if args.max_port and args.max_port > 0 else 4999
PORTS = list(range(1, max_port + 1))      # Ports to scan, inclusive
CONCURRENCY = args.concurrency
CONNECT_TIMEOUT = args.timeout


# Common port name overrides (if system lookup doesn't know them)
COMMON_PORTS = {
    20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    53: 'dns', 67: 'dhcp', 68: 'dhcp', 69: 'tftp', 80: 'http',
    110: 'pop3', 123: 'ntp', 143: 'imap', 161: 'snmp', 194: 'irc',
    443: 'https', 445: 'microsoft-ds', 587: 'smtp-alt', 631: 'ipp',
    993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle',
    2049: 'nfs', 3306: 'mysql', 3389: 'rdp', 5900: 'vnc', 6379: 'redis',
    8080: 'http-alt'
}


def get_service_name(port, protocol='tcp'):
    """Return a human-friendly service name for a port.

    Tries system lookup via socket.getservbyport, falls back to COMMON_PORTS,
    otherwise returns 'unknown'.
    """
    try:
        name = socket.getservbyport(port, protocol)
        if name:
            return name
    except OSError:
        pass
    return COMMON_PORTS.get(port, 'unknown')

async def scan_port(host, port, timeout):
    """
    Attempt to connect to a specific port on the host.
    Returns (port, True) if open, (port, False) otherwise.
    """
    try:
        coro = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return port, True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False
    except Exception:
        return port, False

async def run():
    """
    Run the port scan using a semaphore to limit concurrency.
    Prints open ports as they are found.
    Returns a list of open ports.
    """
    sem = asyncio.Semaphore(CONCURRENCY)
    async def worker(p):
        async with sem:
            return await scan_port(targetIP, p, CONNECT_TIMEOUT)
    tasks = [asyncio.create_task(worker(p)) for p in PORTS]
    open_ports = []
    for fut in asyncio.as_completed(tasks):
        port, is_open = await fut
        if is_open:
            name = get_service_name(port)
            print(f"Port {port:5d}    OPEN    {name}")
            open_ports.append((port, name))
    return open_ports

start = datetime.now()  # Record start time
open_ports = asyncio.run(run())  # Run the scan
end = datetime.now()    # Record end time
# Format final output: show port/name list
formatted = [f"{p}/{n}" for (p, n) in open_ports]
print(f"\nScan finished in {end - start}. Open ports: {formatted}")  # Print results

# Save results to file if requested
if args.output:
    out_path = Path(args.output)
    fmt = args.format
    if not fmt:
        suf = out_path.suffix.lower()
        if suf == '.csv':
            fmt = 'csv'
        else:
            fmt = 'json'
    try:
        if fmt == 'json':
            data = [{'port': p, 'service': n} for (p, n) in open_ports]
            out_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        else:
            with out_path.open('w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['port', 'service'])
                for p, n in open_ports:
                    writer.writerow([p, n])
        print(f"Results saved to {out_path} (format: {fmt})")
    except Exception as e:
        print(f"Failed to save results to {out_path}: {e}")
