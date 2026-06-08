from models.security_event import SecurityEvent


class WazuhAlertTransformer:

    @staticmethod
    def transform(alerts):

        events = []
        seen = set()

        for alert in alerts:

            rule = alert.get("rule", {})
            agent = alert.get("agent", {})
            data = alert.get("data", {})
            win = data.get("win", {})
            system = win.get("system", {})

            timestamp = alert.get("timestamp", "")
            endpoint = agent.get("name", "Unknown")
            description = rule.get("description", "Unknown alert")
            level = rule.get("level", 0)

            dedupe_key = (
                timestamp,
                endpoint,
                description
            )

            if dedupe_key in seen:
                continue

            seen.add(dedupe_key)

            event_type = WazuhAlertTransformer.get_event_type(description)
            severity = WazuhAlertTransformer.map_severity(level)

            source_ip = (
                data.get("srcip")
                or data.get("src_ip")
                or system.get("computer", "N/A")
            )

            event_id = len(events) + 1

            events.append(
                SecurityEvent(
                    id=event_id,
                    timestamp=timestamp,
                    endpoint=endpoint,
                    event_type=event_type,
                    severity=severity,
                    source_ip=source_ip,
                    description=description
                )
            )

        return events

    @staticmethod
    def map_severity(level):

        if level >= 12:
            return "Critical"

        if level >= 8:
            return "High"

        if level >= 5:
            return "Medium"

        return "Low"

    @staticmethod
    def get_event_type(description):

        desc = description.lower()

        if "powershell" in desc:
            return "PowerShell Execution"

        if "logon failure" in desc or "failed" in desc or "bad password" in desc:
            return "Failed Login Attempts"

        if "network" in desc or "connection" in desc:
            return "Suspicious Network Connection"

        if "process" in desc:
            return "Process Execution"

        if "executable file dropped" in desc:
            return "Suspicious File Drop"

        return "Generic Security Event"