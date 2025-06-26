import netifaces
import ipaddress
from scapy.all import ARP, Ether, srp

# Step 1: Get default interface
default_iface = netifaces.gateways()['default'][netifaces.AF_INET][1]

# Step 2: Get IP and netmask
iface_info = netifaces.ifaddresses(default_iface)[netifaces.AF_INET][0]
ip = iface_info['addr']
netmask = iface_info['netmask']

# Step 3: Build network/subnet
network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
print(f"[+] Scanning network: {network}")

# Step 4: Craft ARP request
arp = ARP(pdst=str(network))
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether / arp

# Step 5: Send and receive responses
result = srp(packet, timeout=2, iface=default_iface, verbose=0)[0]

# Step 6: Display discovered devices
print(f"\n     {'IP':<16}   {'MAC':<18}")
print("-" * 35)
for sent, received in result:
    print(f"{received.psrc:<16} {received.hwsrc:<18}")
