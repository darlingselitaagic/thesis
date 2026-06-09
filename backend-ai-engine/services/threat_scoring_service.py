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
            score += 5

        text = f"{event.event_type} {event.description}".lower()

        if "powershell" in text:
            score += 35

        if "failed login" in text or "logon failure" in text or "bad password" in text:
            score += 30

        if "account discovery" in text or "discovery activity" in text or "net.exe" in text:
            score += 35

        if "successful sudo" in text or "sudo to root" in text:
            return 15

        if "privilege escalation" in text:
            score += 25

        if "suspicious file drop" in text or "executable file dropped" in text:
            score += 40

        if "malware" in text:
            score += 35

        if "suspicious network connection" in text:
            score += 30

        if "successful login" in text:
            score += 5

        if "login session opened" in text or "login session closed" in text:
            score += 5

        return min(score, 100)