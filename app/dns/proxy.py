import socket
from dnslib import DNSRecord
from datetime import datetime

UPSTREAM_DNS = ("1.1.1.1", 53)
LISTEN_ADDRESS = ("0.0.0.0", 53)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(LISTEN_ADDRESS)

print("Sentricore DNS Proxy running...")

while True:
    data, addr = sock.recvfrom(512)

    request = DNSRecord.parse(data)
    domain = str(request.q.qname)

    print(f"[{datetime.utcnow()}] {addr[0]} → {domain}")

    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream_sock.sendto(data, UPSTREAM_DNS)
    response, _ = upstream_sock.recvfrom(512)

    sock.sendto(response, addr)
