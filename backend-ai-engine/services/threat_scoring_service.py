from models.security_event import SecurityEvent


class ThreatScoringService:

    @staticmethod
    def calculate_score(event: SecurityEvent):

        score = 0

        if event.severity == "Critical":
            score += 80
        elif event.severity == "High":
            score += 60
        elif event.severity == "Medium":
            score += 35
        elif event.severity == "Low":
            score += 10

        text = f"{event.event_type} {event.description}".lower()

        if "powershell" in text:
            score += 30

        if "logon failure" in text or "failed login" in text or "bad password" in text:
            score += 25

        if "malware" in text:
            score += 35

        if "executable file dropped" in text:
            score += 30

        if "network" in text or "connection" in text:
            score += 15

        if "discovery" in text:
            score += 20

        return min(score, 100)