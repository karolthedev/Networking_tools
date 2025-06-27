import netifaces
import ipaddress
import subprocess
import platform
import threading
import time
import re
from scapy.all import ARP, Ether, srp


def get_local_subnet():
    gateways = netifaces.gateways()
    iface = gateways['default'][netifaces.AF_INET][1]
    iface_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
    ip = iface_info['addr']
    netmask = iface_info['netmask']
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return str(iface), network

def ping_host(ip):
    system = platform.system().lower()

    if system == "windows":
        # Windows: -n for count, -w for timeout in milliseconds
        cmd = ['ping', '-n', '1', '-w', '1000', ip]
    else:
        # Linux/macOS: -c for count, -W for timeout in seconds
        cmd = ['ping', '-c', '1', '-W', '1', ip]

    # Use subprocess.DEVNULL to suppress output (cross-platform)
    return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def async_ping_sweep(ip_list, timeout=2):
    online_hosts = []
    lock = threading.Lock()

    def ping_and_store(ip):
        if ping_host(ip):
            with lock:
                online_hosts.append(ip)

    threads = []
    for ip in ip_list:
        t = threading.Thread(target=ping_and_store, args=(str(ip),))
        t.start()
        threads.append(t)

    # Wait for timeout duration, then terminate stragglers
    t0 = time.time()
    while time.time() - t0 < timeout:
        if all(not t.is_alive() for t in threads):
            break
        time.sleep(0.1)

    return online_hosts

def get_mac_from_arp(ip, timeout=1):
    """
    Send a single ARP request to `ip` and return its MAC in uppercase, no-colon form.
    Returns None if nobody answers.
    """
    # build Ethernet/ARP packet
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    # srp: send & receive at layer 2
    answered, _ = srp(pkt, timeout=timeout, verbose=False)
    
    for _, reply in answered:
        # reply is an Ether/ARP object; .src on the Ether layer is the MAC
        mac = reply.src
        # format: strip separators, uppercase
        return mac.replace(":", "").replace("-", "").upper()
    return None


def scan_local():
    iface, network = get_local_subnet()
    print(f"\nPerforming ping sweep on local subnet: {network}")

    # Grab all usable IPs in the subnet
    ip_list = list(network.hosts())  # excludes network and broadcast addresses

    # Use your multithreaded ping sweep
    live_hosts = async_ping_sweep(ip_list, timeout=2)

    # Sort IPs numerically (not lexically)
    live_hosts.sort(key=lambda ip: ipaddress.IPv4Address(ip))

    print(f"\n{'IP':<16}    {'MAC':<10}")
    print("-" * 30)
    for ip in live_hosts:
        mac = get_mac_from_arp(str(ip))
        print(f"{ip:<16}    {mac or 'N/A':<18}")


def scan_remote(start_ip, end_ip):
    # Build IPv4Address list
    start = ipaddress.IPv4Address(start_ip)
    end   = ipaddress.IPv4Address(end_ip)
    ip_list = [ipaddress.IPv4Address(i) for i in range(int(start), int(end) + 1)]

    print(f"\nPinging hosts from {start_ip} to {end_ip}...\nPlease wait...")
    live_hosts = set(async_ping_sweep([str(ip) for ip in ip_list], timeout=2))

    # Prepare a list of (ip_str, status) tuples
    results = []
    for ip in ip_list:
        ip_str = str(ip)
        status = "Online" if ip_str in live_hosts else "Offline"
        results.append((ip_str, status))

    # Sort so Online come first, then Offline; within each group sort by IP
    results.sort(
        key=lambda item: (
            item[1] != "Online",               # False (Online) < True (Offline)
            ipaddress.IPv4Address(item[0])     # numeric IP sort
        )
    )

    # Print
    print(f"\n{'IP':<16}    {'Status':<10}")
    print("-" * 30)
    for ip_str, status in results:
        print(f"{ip_str:<16}    {status:<10}")



# Main
print("Ping Sweep Utility")
print("1. Local Network Scan")
print("2. Remote Range Scan")
choice = input("Choose an option [1/2]: ").strip()

if choice == '1':
    scan_local()
elif choice == '2':
    ip_range = input("Enter IP range (e.g., 8.8.4.4 - 8.8.8.8): ").strip()
    match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s*-\s*(\d+\.\d+\.\d+\.\d+)", ip_range)
    if match:
        start_ip, end_ip = match.groups()
        scan_remote(start_ip, end_ip)
    else:
        print("Invalid range format. Use format like 192.168.1.10 - 192.168.1.50")
else:
    print("Invalid choice.")
