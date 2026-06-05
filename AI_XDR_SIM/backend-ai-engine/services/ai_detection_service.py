import pandas as pd
from sklearn.ensemble import IsolationForest


class AIDetectionService:

    @staticmethod

    def build_dataset(events):

        rows = []

        for event in events:
            rows.append({
                "severity_score": AIDetectionService.severity_to_number(event.severity),
                "is_powershell": 1 if "PowerShell" in event.event_type else 0,
                "is_failed_login": 1 if "Failed Login" in event.event_type else 0,
                "is_network": 1 if "Network" in event.event_type else 0
            })
        
        return pd.DataFrame(rows)
    
    @staticmethod
    def detect_anomalies(events):

        dataset = AIDetectionService.build_dataset(events)

        model = IsolationForest(
            contamination=0.25,
            random_state=42
        )

        predictions = model.fit_predict(dataset)
        anomaly_scores = model.decision_function(dataset)

        results = []

        for index, event in enumerate(events):
            is_anomaly = predictions[index] == -1

            results.append({
                "event_id": event.id,
                "endpoint": event.endpoint,
                "event_type": event.event_type,
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": round(float(abs(anomaly_scores[index])), 4)
            })

        return results

    @staticmethod
    def severity_to_number(severity):

        values = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }

        return values.get(severity, 1)