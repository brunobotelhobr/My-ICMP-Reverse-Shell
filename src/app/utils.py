"""Utils Module."""
import platform

from scapy.all import Raw  # type: ignore
from scapy.layers.inet import IP  # type: ignore

from app.model import Client, Message, Session

# Session Database
sessions: list[Session] = []

# Logs
logs: list[str] = []


def whoami() -> Client:
    """Return hostname and system."""
    return Client(
        hostname=platform.node(),
        system=platform.system(),
        release=platform.release(),
    )


def parcer(payload: bytes) -> tuple[Message, bytes]:
    """Parce payload."""
    # Exract first byte, return the apropiate message
    message: Message = Message(payload[0])
    return message, payload[1:]


def process(package: IP) -> bool:
    """Process message."""
    # Extract payload
    source: str = package[IP].src
    try:
        message: Message
        payload: bytes
        (message, payload) = parcer(package[Raw].load)
    except IndexError:
        logs.append("Invalid payload from {}".format(source))
        return True
    if message == Message.WHOAMI:
        sessions.append(Session(client=whoami(), address=source))
        return True
    else:
        print("Not implemented yet")
        return False
