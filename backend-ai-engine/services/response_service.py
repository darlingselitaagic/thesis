from datetime import datetime


class ResponseService:

    @staticmethod
    def simulate(action, endpoint, context=None):

        context = context or {}

        correlation_score = context.get("correlation_score", 0)
        detected_patterns = context.get("detected_patterns", [])
        threat_score = context.get("threat_score", 0)
        event_type = context.get("event_type", "Unknown")
        description = context.get("description", "No description available")

        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "endpoint": endpoint,
            "action": action,
            "status": "Simulated",
            "risk_level": ResponseService.get_risk_level(
                correlation_score,
                threat_score
            ),
            "confidence": ResponseService.get_confidence(
                correlation_score,
                detected_patterns
            ),
            "summary": ResponseService.build_summary(
                action,
                endpoint,
                event_type,
                description
            ),
            "response_reason": ResponseService.build_reason(
                action,
                correlation_score,
                detected_patterns
            ),
            "recommended_next_steps": ResponseService.get_next_steps(
                action,
                detected_patterns
            )
        }

    @staticmethod
    def get_risk_level(correlation_score, threat_score):

        score = max(correlation_score, threat_score)

        if score >= 85:
            return "Critical"

        if score >= 60:
            return "High"

        if score >= 30:
            return "Medium"

        return "Low"

    @staticmethod
    def get_confidence(correlation_score, detected_patterns):

        if correlation_score >= 85 and len(detected_patterns) >= 3:
            return "High"

        if correlation_score >= 60:
            return "Medium"

        return "Low"

    @staticmethod
    def build_summary(action, endpoint, event_type, description):

        return (
            f"The system selected '{action}' for endpoint '{endpoint}' "
            f"based on event type '{event_type}'. "
            f"Original alert: {description}."
        )

    @staticmethod
    def build_reason(action, correlation_score, detected_patterns):

        if detected_patterns:
            patterns = ", ".join(detected_patterns)
        else:
            patterns = "No strong correlated pattern was detected"

        return (
            f"The response action '{action}' was selected because the "
            f"correlation score reached {correlation_score}. "
            f"Detected patterns: {patterns}."
        )

    @staticmethod
    def get_next_steps(action, detected_patterns):

        steps = [
            "Review the original Wazuh alert details",
            "Inspect the affected endpoint",
            "Validate whether the activity is legitimate or malicious"
        ]

        if "Suspicious executable file drop" in detected_patterns:
            steps.extend([
                "Check the dropped executable path",
                "Calculate and verify the file hash",
                "Review the parent process that created the file"
            ])

        if "Suspicious command execution" in detected_patterns:
            steps.extend([
                "Inspect the executed command line",
                "Check PowerShell history and script block logs"
            ])

        if "Authentication anomaly" in detected_patterns:
            steps.extend([
                "Review failed login source IP addresses",
                "Check whether the account was later successfully accessed"
            ])

        if action == "Simulate Endpoint Isolation":
            steps.append(
                "Simulate removing the endpoint from the network"
            )

        if action == "Escalate Incident":
            steps.append(
                "Escalate the incident for analyst validation"
            )

        return steps