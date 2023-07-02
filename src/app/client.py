"""ICMP CLient."""
import logging

from scapy.all import Raw, sr1, sr # type: ignore
from scapy.layers.inet import ICMP, IP  # type: ignore

from app.contansts import LOG_LEVEL, PAYLOAD, TIMEOUT, TTL
from app.model import Message
from scapy.config import conf


# Tunning scapy
# Disable verbose mode
conf.verb = 0

# Adust logging level
logging.getLogger("scapy.runtime").setLevel(LOG_LEVEL)


def simple_echo_request(
    destination: str,
    payload: bytes = PAYLOAD,
) -> bool:
    """Send a simple ICMP echo request packet."""
    packet: IP = (
        IP(dst=destination, ttl=TTL) / ICMP(type=8, code=0) / Raw(payload)
    )
    awnser: IP | None = sr1(packet, timeout=TIMEOUT, verbose=0)
    if awnser:
        print(f"[+] Response from {destination}: {awnser.summary()}")
        print(f"[+] Payload: {awnser[Raw].load}")
        return True
    print(f"[-] No response from {destination}")
    return False


def simple_echo_request_loop(
    destination: str,
    count: int = 4,
) -> bool:
    """Send a count number of simple ICMP echo request packet."""
    if count < 1:
        print("[!]Error: count must be greater than 0")
        return False
    try:  # type: ignore
        while count > 0:
            simple_echo_request(destination)
            count -= 1
        return True
    except KeyboardInterrupt as error:
        print(f"[!]Error: {error}")
        return False


def send_echo_request_and_confirm_response(destination: str,
    payload: bytes = PAYLOAD,
) -> bool:
    """Send a simple ICMP echo request packet and confirm response with a Message.ACK."""
    packet: IP = (
        IP(dst=destination, ttl=TTL) / ICMP(type=8, code=0) / Raw(payload)
    )
    awnser: IP | None = sr(packet, timeout=TIMEOUT, verbose=0)
    if awnser:
        print(f"[+] Response from {destination}: {awnser.summary()}")
        print(f"[+] Payload: {awnser[Raw].load}")
        return True
    print(f"[-] No response from {destination}")
    return False




def send_file(file: str):
    """Send a file."""
    total = len(file)
    couter = 0
    while couter <= total:
        if couter == 0:
            payload = Message.SYN.value + "/" + "TRANSMIT" + "/" + str(total) + "/botelho.txt"
        else:
            payload = Message.SYN.value + "/" + str(couter) + "/" + file[couter - 1]
        simple_echo_request("34.172.143.22", payload.encode())
        couter += 1
        print("[+] Send:" + str(payload))

if __name__ == "__main__":
    send_file("1234567890")
