from models.security_event import SecurityEvent


class CorrelationService:

    @staticmethod
    def correlate(events: list[SecurityEvent]):
        
        correlated_results = []

        events_by_endpoint = {}

        for event in events:
            events_by_endpoint.setdefault(
                event.endpoint,
                []
            ).append(event)

        for endpoint, endpoint_events in events_by_endpoint.items():

            event_types = [
                event.event_type
                for event in endpoint_events
            ]

            correlation_score = 0
            detected_patterns = []

            if "Failed Login Attempts" in event_types:
                correlation_score += 25
                detected_patterns.append('Authentication anomaly')
            
            if "PowerShell Execution" in event_types:
                correlation_score += 35
                detected_patterns.append('Suspicious command execution')

            if "Suspicious Network Connection" in event_types:
                correlation_score += 30
                detected_patterns.append('External suspicious communication')
            
            if(
                'PowerShell Execution' in event_types
                and 'Suspicious Network Connection' in event_types
            ):
                correlation_score += 25
                detected_patterns.append('Possible post-exploitation activity')


            correlated_results.append({
                "endpoint": endpoint,
                "correlation_score": min(correlation_score, 100),
                "detected_patterns": detected_patterns,
                "related_events": [
                    event.id for event in endpoint_events
                ]
            })

        return correlated_results