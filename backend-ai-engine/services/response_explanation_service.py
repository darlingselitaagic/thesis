class ResponseExplanationService:

    @staticmethod
    def generate(action, endpoint, correlation_score, detected_patterns, related_events):

        risk_level = ResponseExplanationService.get_risk_level(correlation_score)
        confidence = ResponseExplanationService.get_confidence(correlation_score, detected_patterns)
        mitre_mapping = ResponseExplanationService.map_mitre(detected_patterns)
        next_steps = ResponseExplanationService.get_next_steps(action, detected_patterns)

        return {
            "action": action,
            "endpoint": endpoint,
            "risk_level": risk_level,
            "confidence": confidence,
            "why_this_action": ResponseExplanationService.build_reason(
                action,
                endpoint,
                correlation_score,
                detected_patterns
            ),
            "possible_attack_stage": ResponseExplanationService.get_attack_stage(
                detected_patterns
            ),
            "mitre_mapping": mitre_mapping,
            "evidence": detected_patterns,
            "related_events": related_events,
            "recommended_next_steps": next_steps
        }

    @staticmethod
    def get_risk_level(score):

        if score >= 85:
            return "Critical"

        if score >= 60:
            return "High"

        if score >= 30:
            return "Medium"

        return "Low"

    @staticmethod
    def get_confidence(score, patterns):

        if score >= 85 and len(patterns) >= 3:
            return "High"

        if score >= 60 and len(patterns) >= 2:
            return "Medium"

        return "Low"

    @staticmethod
    def build_reason(action, endpoint, score, patterns):

        if patterns:
            pattern_text = ", ".join(patterns)
        else:
            pattern_text = "no strong correlated attack pattern"

        return (
            f"The action '{action}' was selected for endpoint '{endpoint}' "
            f"because the correlation score reached {score}. "
            f"The detected evidence includes: {pattern_text}."
        )

    @staticmethod
    def get_attack_stage(patterns):

        if "Possible malware execution chain" in patterns:
            return "Execution / Malware Activity"

        if "Possible malware staging activity" in patterns:
            return "Malware Staging"

        if "Possible credential compromise" in patterns:
            return "Credential Access"

        if "Possible post-exploitation activity" in patterns:
            return "Post-Exploitation"

        if "Authentication anomaly" in patterns:
            return "Initial Access Attempt"

        return "General Monitoring"

    @staticmethod
    def map_mitre(patterns):

        mappings = []

        if "Suspicious command execution" in patterns:
            mappings.append({
                "technique_id": "T1059",
                "technique": "Command and Scripting Interpreter"
            })

        if "Suspicious executable file drop" in patterns:
            mappings.append({
                "technique_id": "T1105",
                "technique": "Ingress Tool Transfer"
            })

        if "Possible malware staging activity" in patterns:
            mappings.append({
                "technique_id": "T1204",
                "technique": "User Execution"
            })

        if "Authentication anomaly" in patterns:
            mappings.append({
                "technique_id": "T1110",
                "technique": "Brute Force"
            })

        if "External suspicious communication" in patterns:
            mappings.append({
                "technique_id": "T1071",
                "technique": "Application Layer Protocol"
            })

        return mappings

    @staticmethod
    def get_next_steps(action, patterns):

        steps = [
            "Review the original Wazuh alert details",
            "Validate whether the activity is expected or malicious",
            "Document the incident evidence"
        ]

        if "Suspicious executable file drop" in patterns:
            steps.extend([
                "Identify the dropped executable path",
                "Calculate and verify the file hash",
                "Check the parent process that created the file"
            ])

        if "Suspicious command execution" in patterns:
            steps.extend([
                "Review the executed command line",
                "Inspect PowerShell or CMD activity",
                "Check whether the command was launched by a user or process"
            ])

        if "Authentication anomaly" in patterns:
            steps.extend([
                "Review failed login attempts",
                "Check source IP addresses",
                "Verify whether a successful login followed the failures"
            ])

        if action == "Simulate Endpoint Isolation":
            steps.append("Simulate isolating the endpoint from the network")

        if action == "Escalate Incident":
            steps.append("Escalate the case to a security analyst for validation")

        return steps