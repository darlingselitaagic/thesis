from models.security_event import SecurityEvent

class EventService:

    @staticmethod
    def get_events():

        return [
            SecurityEvent(
                id=1,
                timestamp="2026-06-04 20:15:00",
                endpoint="WORKSTATION-01",
                event_type="PowerShell Execution",
                severity="High",
                source_ip="192.168.1.15",
                description="Encoded PowerShell command detected"
            ),

            SecurityEvent(
                id=2,
                timestamp="2026-06-04 20:18:00",
                endpoint="SERVER-01",
                event_type="Failed Login Attempts",
                severity="Medium",
                source_ip="192.168.1.50",
                description="10 failed login attempts detected"
            ),

            SecurityEvent(
                id=3,
                timestamp="2026-06-04 20:20:00",
                endpoint= "WORKSTATION-01",
                event_type= "Suspicious Network Connection",
                severity= "Medium",
                source_ip= "185.220.101.12",
                description= "Outbound connection to suspicious external IP detected"
            )
        ]