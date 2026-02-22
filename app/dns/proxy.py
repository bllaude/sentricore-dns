import socket
from dnslib import DNSRecord, DNSHeader, RR, A, RCODE
from datetime import datetime, timezone

UPSTREAM_DNS = ("1.1.1.1", 53)
LISTEN_ADDRESS = ("0.0.0.0", 5300)
BLOCKLIST_PATH = "blocklists/malware.txt"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(LISTEN_ADDRESS)

print("Sentricore DNS Proxy running on port 5353...")

#blocklist loader
def load_blocklist():
    try:
        with open(BLOCKLIST_PATH, "r") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()

BLOCKLIST = load_blocklist()
print(f"Loaded {len(BLOCKLIST)} blocked domains.")
#end blocklist loader

while True:
    try:
        data, addr = sock.recvfrom(512)

        request = DNSRecord.parse(data)
        domain = str(request.q.qname).rstrip('.').lower() #block logic

        print(f"[{datetime.now(timezone.utc)}] {addr[0]} → {domain}") 
"""
        if domain in BLOCKLIST:
            print(f"[BLOCKED] {addr[0]} → {domain}")

            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN

            sock.sendto(reply.pack(), addr)
            continue
"""
        #suffix-based blocking
        if is_blocked(domain):
           for blocked in BLOCKLIST:
               if domain == blocked or domain.endswith("." + blocked):
                   return True
           return False
        #end suffix-based blocking

        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_sock.settimeout(3)
        upstream_sock.sendto(data, UPSTREAM_DNS)

        response, _ = upstream_sock.recvfrom(512)
        sock.sendto(response, addr)

    except Exception as e:
        print("Error:", e)




