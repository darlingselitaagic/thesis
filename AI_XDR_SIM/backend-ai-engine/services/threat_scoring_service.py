from models.security_event import SecurityEvent

class ThreatScoringService:

    @staticmethod
    def calculate_score(event: SecurityEvent):

        score = 0

        if event.severity == "High":
            score += 50

        elif event.severity == "Medium":
            score += 25

        if "PowerShell" in event.event_type:
            score += 30

        if "Failed Login" in event.event_type:
            score += 20

        return min(score, 100)