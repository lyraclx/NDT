import re
import sys
import time
import yaml
import json
import socket
import ctypes
import socket
import zipfile
import platform
import threading
import itertools
import subprocess
from pathlib import Path
from urllib.request import urlopen
from colorama import Fore, Style, init
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# Initialize colorama
init(autoreset=True)

# Color shortcuts
GREEN = Fore.GREEN
CYAN = Fore.CYAN
RED = Fore.RED
RESET = Style.RESET_ALL

def fetch_regions() -> Dict[str, List[str]]:
    url = "https://raw.githubusercontent.com/lyraclx/NDT/refs/heads/main/get_VIPS.txt"
    try:
        with urlopen(url) as response:
            content = response.read().decode("utf-8")
            namespace = {}
            exec(content, {}, namespace)
            return namespace.get("regions", {})
    except Exception as e:
        print(f"{RED}[x]{RESET} Failed to fetch VIP regions: {e}")
        return {}


def get_default_gateway() -> Optional[str]:
    class MIB_IPFORWARDROW(ctypes.Structure):
        _fields_ = [
            ("dwForwardDest", ctypes.c_ulong),
            ("dwForwardMask", ctypes.c_ulong),
            ("dwForwardPolicy", ctypes.c_ulong),
            ("dwForwardNextHop", ctypes.c_ulong),
            ("dwForwardIfIndex", ctypes.c_ulong),
            ("dwForwardType", ctypes.c_ulong),
            ("dwForwardProto", ctypes.c_ulong),
            ("dwForwardAge", ctypes.c_ulong),
            ("dwForwardNextHopAS", ctypes.c_ulong),
            ("dwForwardMetric1", ctypes.c_ulong),
            ("dwForwardMetric2", ctypes.c_ulong),
            ("dwForwardMetric3", ctypes.c_ulong),
            ("dwForwardMetric4", ctypes.c_ulong),
            ("dwForwardMetric5", ctypes.c_ulong),
        ]

    class MIB_IPFORWARDTABLE(ctypes.Structure):
        _fields_ = [
            ("dwNumEntries", ctypes.c_ulong),
            ("table", MIB_IPFORWARDROW * 256),
        ]

    GetIpForwardTable = ctypes.windll.iphlpapi.GetIpForwardTable
    GetIpForwardTable.argtypes = [ctypes.POINTER(MIB_IPFORWARDTABLE), ctypes.POINTER(ctypes.c_ulong), ctypes.c_bool]
    GetIpForwardTable.restype = ctypes.c_ulong

    table = MIB_IPFORWARDTABLE()
    size = ctypes.c_ulong(ctypes.sizeof(table))

    result = GetIpForwardTable(ctypes.byref(table), ctypes.byref(size), False)
    if result != 0:
        return None

    for i in range(table.dwNumEntries):
        row = table.table[i]
        if row.dwForwardDest == 0:
            ip_bytes = row.dwForwardNextHop.to_bytes(4, 'little')
            return socket.inet_ntoa(ip_bytes)

    return None


def get_isp_info() -> Dict[str, Optional[str]]:
    try:
        with urlopen("https://ipinfo.io/json") as response:
            data = json.load(response)
            return {
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "org": data.get("org"),
                "timezone": data.get("timezone"),
            }
    except Exception as e:
        print(f"{RED}[x]{RESET} Failed to fetch ISP info: {e}")
        return {
            "city": None,
            "region": None,
            "country": None,
            "org": None,
            "timezone": None,
        }


def run_ping(address: str, count: int = 4) -> str:
    system = platform.system()
    cmd = (
        ["ping", address, "-n", str(count)]
        if system == "Windows"
        else ["ping", "-c", str(count), address]
    )
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        return e.output


def parse_ping_output(output: str) -> List[Dict[str, Any]]:
    results = []
    for line in output.splitlines():
        if "Reply from" in line or "bytes from" in line:
            timestamp = datetime.now(timezone.utc).isoformat()
            try:
                time_match = re.search(r"time[=<]([\d\.]+)ms", line)
                ttl_match = re.search(r"TTL=(\d+)", line, re.IGNORECASE)
                rtt = int(float(time_match.group(1))) if time_match else None
                ttl = int(ttl_match.group(1)) if ttl_match else None
                results.append(
                    {
                        "timestamp": timestamp,
                        "rtt_ms": max(1, rtt) if rtt is not None else None,
                        "ttl": ttl,
                    }
                )
            except Exception:
                continue
        elif any(err in line for err in ["Request timed out", "Destination Host Unreachable", "timed out"]):
            results.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "rtt_ms": None,
                    "ttl": None,
                    "dropped": True,
                }
            )
    return results


def run_traceroute(address: str) -> str:
    system = platform.system()
    cmd = ["tracert", address] if system == "Windows" else ["traceroute", address]
    try:
        return subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        return e.output


def extract_ip(host_part: str) -> Optional[str]:
    match = re.search(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", host_part)
    return match.group(1) if match else None


def parse_traceroute_output(output: str) -> List[Dict[str, Any]]:
    hops = []
    for line in output.splitlines():
        parts = line.strip().split()
        if not parts or not parts[0].isdigit():
            continue

        hop_num = int(parts[0])
        if "*" in parts:
            hops.append({"hop": hop_num, "timeout": True})
            continue

        hop_ip = next((extract_ip(p) for p in parts[1:] if extract_ip(p)), None)

        rtts = []
        for part in parts:
            if "ms" in part:
                try:
                    rtts.append(float(part.replace("ms", "").strip()))
                except ValueError:
                    pass

        hops.append({"hop": hop_num, "ip": hop_ip, "rtts": rtts})

    return hops


def analyze_ping(address: str, count: int, delay: float = 0, threaded: bool = False) -> Dict[str, Any]:
    results = []

    def ping_worker():
        output = run_ping(address, count=1)
        parsed = parse_ping_output(output)
        if parsed:
            results.extend(parsed)

    if threaded and delay > 0:
        threads = []
        for _ in range(count):
            t = threading.Thread(target=ping_worker)
            t.start()
            threads.append(t)
            time.sleep(delay)
        for t in threads:
            t.join()
    else:
        output = run_ping(address, count)
        results = parse_ping_output(output)

    rtts = [r["rtt_ms"] for r in results if r["rtt_ms"] is not None]
    jitter = (max(rtts) - min(rtts)) if rtts else None
    total_received = len(rtts)

    return {
        "ip": address,
        "total_sent": count,
        "received": total_received,
        "packet_loss": ((count - total_received) / count) * 100 if count else 100.0,
        "min_rtt": min(rtts) if rtts else None,
        "max_rtt": max(rtts) if rtts else None,
        "avg_rtt": sum(rtts) / total_received if total_received else None,
        "jitter": jitter,
    }


def animated_spinner(message: str, stop_event: threading.Event) -> None:
    spinner = itertools.cycle(["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"])
    while not stop_event.is_set():
        sys.stdout.write(f"\r{CYAN}{next(spinner)}{RESET} {message}")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * (len(message) + 4) + "\r")
    sys.stdout.flush()

def save_raw_traceroute(label: str, ip: str, raw_output: str) -> None:
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_label = label.replace(" ", "_").replace("(", "").replace(")", "")
    filename = Path(f"traceroute_{safe_label}_{timestamp_str}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"Traceroute to {ip} ({label}) at {timestamp_str}\n\n")
        f.write(raw_output)
    print(f"{GREEN}[+]{RESET} Raw traceroute saved to: {filename}")

def analyze_ping_sequential(address: str, count: int, delay: float = 1) -> Dict[str, Any]:
    """Ping an address sequentially 'count' times with 'delay' between pings."""
    results = []
    for _ in range(count):
        output = run_ping(address, count=1)
        parsed = parse_ping_output(output)
        if parsed:
            results.extend(parsed)
        time.sleep(delay)
    rtts = [r["rtt_ms"] for r in results if r["rtt_ms"] is not None]
    jitter = (max(rtts) - min(rtts)) if rtts else None
    total_received = len(rtts)
    return {
        "ip": address,
        "total_sent": count,
        "received": total_received,
        "packet_loss": ((count - total_received) / count) * 100 if count else 100.0,
        "min_rtt": min(rtts) if rtts else None,
        "max_rtt": max(rtts) if rtts else None,
        "avg_rtt": sum(rtts) / total_received if total_received else None,
        "jitter": jitter,
    }

def main() -> None:
    regions = fetch_regions()
    if not regions:
        print(f"{RED}[x]{RESET} No regions available.")
        return

    print(f"\n{GREEN}[+]{RESET} Available regions:")
    for i, region in enumerate(regions, 1):
        print(f"{i}. {region}")

    try:
        selected_index = int(input(f"{CYAN}[?]{RESET} Select region number: ")) - 1
        region_name = list(regions.keys())[selected_index]
    except (IndexError, ValueError):
        print(f"{RED}[x]{RESET} Invalid region selected.")
        return

    region_ips = regions[region_name]
    print(f"\n{GREEN}[+]{RESET} Selected region: {region_name}")
    print(f"{CYAN}[~]{RESET} This will take a minute, so grab a coffee...\n")

    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=animated_spinner, args=("Running network diagnostics", stop_event))
    spinner_thread.start()

    try:
        diagnostics = {
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "platform": platform.system(),
                "isp_info": get_isp_info(),
            },
            "default_gateway_analysis": {},
            "traceroutes": {},
        }

        raw_traceroutes: Dict[str, str] = {}

        gateway = get_default_gateway()
        if not gateway:
            raise RuntimeError("Default gateway not found.")

        diagnostics["default_gateway_analysis"] = analyze_ping(gateway, count=120, threaded=False)

        for idx, ip in enumerate(region_ips):
            label = f"{region_name}-{chr(97 + idx)}" if len(region_ips) > 1 else region_name
            tr_output = run_traceroute(ip)
            raw_traceroutes[label] = tr_output

            hops = parse_traceroute_output(tr_output)

            def ping_hop_worker(hop):
                if hop.get("timeout"):
                    hop["ping_stats"] = None
                else:
                    hop_ip = hop.get("ip")
                    if hop_ip:
                        hop["ping_stats"] = analyze_ping_sequential(hop_ip, count=60, delay=1)
                    else:
                        hop["ping_stats"] = None

            threads = []
            for hop in hops:
                t = threading.Thread(target=ping_hop_worker, args=(hop,))
                t.start()
                threads.append(t)

            for t in threads:
                t.join()

            diagnostics["traceroutes"][f"{label} ({ip})"] = hops

    finally:
        stop_event.set()
        spinner_thread.join()

    zip_filename = Path(f"diagnostics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
    with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
        for label, tr_output in raw_traceroutes.items():
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            raw_tr_filename = f"traceroute_{label}_{timestamp_str}.txt"
            zipf.writestr(raw_tr_filename, f"Traceroute to {label} at {timestamp_str}\n\n{tr_output}")

        diagnostics_yaml = yaml.dump(diagnostics, sort_keys=False, allow_unicode=True)
        zipf.writestr("diagnostics.yaml", diagnostics_yaml)

    print(f"\n{GREEN}[+]{RESET} Diagnostics completed and saved to {zip_filename}")

if __name__ == "__main__":
    main()
