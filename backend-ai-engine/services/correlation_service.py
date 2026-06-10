from datetime import datetime
from models.security_event import SecurityEvent


class CorrelationService:

    TIME_WINDOW_MINUTES = 30

    @staticmethod
    def parse_timestamp(timestamp):
        try:
            return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
        except Exception:
            return None

    @staticmethod
    def has_sequence(events, sequence):
        event_types = [event.event_type for event in events]

        position = 0

        for event_type in event_types:
            if event_type == sequence[position]:
                position += 1

                if position == len(sequence):
                    return True

        return False

    @staticmethod
    def correlate(events: list[SecurityEvent]):

        correlated_results = []
        events_by_endpoint = {}

        for event in events:
            events_by_endpoint.setdefault(event.endpoint, []).append(event)

        for endpoint, endpoint_events in events_by_endpoint.items():

            endpoint_events = sorted(
                endpoint_events,
                key=lambda event: CorrelationService.parse_timestamp(event.timestamp)
                or datetime.min
            )

            event_types = [event.event_type for event in endpoint_events]

            correlation_score = 0
            detected_patterns = []
            attack_chain = []
            mitre_mapping = []
            possible_attack_stage = "General Monitoring"

            if "Failed Login Attempts" in event_types:
                correlation_score += 25
                detected_patterns.append("Authentication anomaly")
                attack_chain.append("Credential Access")
                mitre_mapping.append({
                    "technique_id": "T1110",
                    "technique": "Brute Force"
                })

            if "Successful Login" in event_types and "Failed Login Attempts" in event_types:
                correlation_score += 20
                detected_patterns.append("Successful login after failed attempts")
                attack_chain.append("Valid Account Usage")
                mitre_mapping.append({
                    "technique_id": "T1078",
                    "technique": "Valid Accounts"
                })

            if "Account Discovery" in event_types:
                correlation_score += 30
                detected_patterns.append("Account discovery activity")
                attack_chain.append("Discovery")
                mitre_mapping.append({
                    "technique_id": "T1087",
                    "technique": "Account Discovery"
                })

            if "PowerShell Execution" in event_types:
                correlation_score += 35
                detected_patterns.append("Suspicious command execution")
                attack_chain.append("Execution")
                mitre_mapping.append({
                    "technique_id": "T1059.001",
                    "technique": "PowerShell"
                })

            if "Privilege Escalation" in event_types:
                correlation_score += 20
                detected_patterns.append("Privilege elevation activity")
                attack_chain.append("Privilege Escalation")
                mitre_mapping.append({
                    "technique_id": "T1548",
                    "technique": "Abuse Elevation Control Mechanism"
                })

            if "Suspicious Network Connection" in event_types:
                correlation_score += 30
                detected_patterns.append("External suspicious communication")
                attack_chain.append("Command and Control")
                mitre_mapping.append({
                    "technique_id": "T1071",
                    "technique": "Application Layer Protocol"
                })

            if "Suspicious File Drop" in event_types:
                correlation_score += 45
                detected_patterns.append("Suspicious executable file drop")
                attack_chain.append("Malware Staging")
                mitre_mapping.append({
                    "technique_id": "T1105",
                    "technique": "Ingress Tool Transfer"
                })

            if (
                "Failed Login Attempts" in event_types
                and "Successful Login" in event_types
                and "Account Discovery" in event_types
            ):
                correlation_score += 35
                detected_patterns.append("Possible compromise followed by discovery")
                possible_attack_stage = "Initial Compromise and Discovery"

            if (
                "PowerShell Execution" in event_types
                and "Suspicious File Drop" in event_types
            ):
                correlation_score += 40
                detected_patterns.append("Possible malware execution chain")
                possible_attack_stage = "Execution and Malware Staging"

            if (
                "Account Discovery" in event_types
                and "Privilege Escalation" in event_types
            ):
                correlation_score += 30
                detected_patterns.append("Discovery followed by privilege escalation")
                possible_attack_stage = "Post-Exploitation"

            if (
                "PowerShell Execution" in event_types
                and "Suspicious Network Connection" in event_types
            ):
                correlation_score += 35
                detected_patterns.append("Possible command-and-control activity")
                possible_attack_stage = "Command and Control"

            if CorrelationService.has_sequence(
                endpoint_events,
                [
                    "Failed Login Attempts",
                    "Successful Login",
                    "Account Discovery"
                ]
            ):
                correlation_score += 40
                detected_patterns.append("Sequential authentication compromise pattern")
                possible_attack_stage = "Credential Compromise"

            if CorrelationService.has_sequence(
                endpoint_events,
                [
                    "PowerShell Execution",
                    "Suspicious File Drop"
                ]
            ):
                correlation_score += 35
                detected_patterns.append("Sequential execution-to-file-drop pattern")
                possible_attack_stage = "Malware Execution"

            unique_mitre = []
            seen_mitre = set()

            for item in mitre_mapping:
                key = item["technique_id"]

                if key not in seen_mitre:
                    seen_mitre.add(key)
                    unique_mitre.append(item)

            correlated_results.append({
                "endpoint": endpoint,
                "correlation_score": min(correlation_score, 100),
                "detected_patterns": detected_patterns,
                "attack_chain": attack_chain,
                "possible_attack_stage": possible_attack_stage,
                "mitre_mapping": unique_mitre,
                "related_events": [
                    event.id for event in endpoint_events
                ],
                "related_event_count": len(endpoint_events)
            })

        return correlated_results