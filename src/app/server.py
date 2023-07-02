"""ICMP Server."""
from scapy.all import sniff, send, Raw
from scapy.layers.inet import ICMP, IP
from app.contansts import TTL
from app.model import Message
from scapy.config import conf


# Tunning scapy
# Disable verbose mode
conf.verb = 0

def sniffer(fucntion: callable):
    """Sniff for ICMP packets, for each packet call the function."""
    sniff(iface="lo0", prn=fucntion, filter="icmp", store="0")


def simple_echo_respose(packet: IP) -> bool:
    """Respond to ICMP echo requests."""
    print(f"[+] Request from {packet[IP].src}: {packet.summary()}")
    if packet[ICMP].type == 8:
        payload: bytes = packet[Raw].load
        packet: IP = (
            IP(dst=packet[IP].src, ttl=TTL) / ICMP(type=0, code=0) / Raw(payload)
        )
        send(packet, verbose=0)
        print(f"[+] Response to {packet[IP].dst}: {packet.summary()}")
        return True
    return False


def receiving_echo_respose(packet: IP) -> bool:
    """Respond to ICMP echo requests."""
    if str(packet[Raw].load[0]) == Message.SYN.value:
        print(f"[+] Request from {packet[IP].src}: {packet.summary()}")
        if str(packet[Raw].load[0]).startswith("0/TRANSMIT/"):
            print(f"[+] Request from {packet[IP].src}: {packet.summary()}")
            print(f"[+] Payload: {packet[Raw].load}")
            return True
    print(str(packet[Raw].load))
    return False


if __name__ == "__main__":
    sniffer(receiving_echo_respose)
