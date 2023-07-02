"""Models for the application."""
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


@dataclass
class Client:
    """Client model."""

    hostname: str
    system: str
    release: str
    address: str | None = None


@dataclass
class Session:
    """Session model."""

    client: Client
    identification: int | None = None
    timestamp: datetime | None = None


class Message(Enum):
    """Commands."""

    SYN = "0"
    WHOAMI = "1"
    ACK = "8"


# Session Manager Singleton
class SessionManager:
    """Session Manager Singleton."""

    _instance = None

    def __new__(cls):
        """Create new instance."""
        if cls._instance is None:
            cls._instance = super(SessionManager, cls).__new__(cls)
            cls._instance.sessions = []
        return cls._instance

    def __init__(self) -> None:
        """Init."""
        self.sessions: list[Session] = []

    def process(self, client: Client) -> None:
        """Process client."""
        session: Session | None = self.get(client)
        if session:
            # Update timestamp
            session.timestamp = datetime.now()
        else:
            # Create new session
            self.sessions.append(
                Session(
                    client=client,
                    timestamp=datetime.now(),
                    identification=len(self.sessions) + 1,
                )
            )

    def remove(self, client: Client) -> None:
        """Remove session."""
        session: Session | None = self.get(client)
        if session:
            self.sessions.remove(session)

    def get(self, client: Client) -> Session | None:
        """Get session by client."""
        for session in self.sessions:
            if session.client == client:
                return session
        return None
