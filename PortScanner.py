import asyncio  # For asynchronous operations
import socket   # For network connections
from datetime import datetime  # For timing the scan

target = input("Enter a host to scan: ").strip()  # Get target host from user
try:
    targetIP = socket.gethostbyname(target)  # Resolve host to IP address
except socket.gaierror:
    print("Could not resolve host.")
    raise SystemExit(1)

PORTS = list(range(1, 5000))      # Ports to scan
CONCURRENCY = 300                 # Number of concurrent scans
CONNECT_TIMEOUT = 0.35            # Timeout for each connection attempt

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
            print(f"Port {port:5d}    OPEN")
            open_ports.append(port)
    return open_ports

start = datetime.now()  # Record start time
open_ports = asyncio.run(run())  # Run the scan
end = datetime.now()    # Record end time
print(f"\nScan finished in {end - start}. Open ports: {open_ports}")  # Print results
