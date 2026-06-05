from dataclasses import dataclass

@dataclass
class SecurityEvent:
    id: int
    timestamp: str
    endpoint: str
    event_type: str
    severity: str
    source_ip: str
    description: str