import joblib
import pandas as pd


class AIDetectionService:

    MODEL_PATH = "models/isolation_forest_model.pkl"

    FEATURES = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Fwd Packet Length Mean",
        "Bwd Packet Length Mean",
        "Packet Length Mean"
    ]

    model = joblib.load(MODEL_PATH)

    @staticmethod
    def build_dataset(events):

        rows = []

        for event in events:
            rows.append(
                AIDetectionService.map_event_to_features(event)
            )

        return pd.DataFrame(rows, columns=AIDetectionService.FEATURES)

    @staticmethod
    def map_event_to_features(event):

        event_type = event.event_type.lower()
        severity = event.severity.lower()

        base = {
            "Flow Duration": 1000,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 1,
            "Flow Bytes/s": 500,
            "Flow Packets/s": 2,
            "Fwd Packet Length Mean": 100,
            "Bwd Packet Length Mean": 100,
            "Packet Length Mean": 100
        }

        if "powershell" in event_type:
            base["Flow Duration"] = 5000
            base["Total Fwd Packets"] = 8
            base["Total Backward Packets"] = 3
            base["Flow Bytes/s"] = 2500
            base["Flow Packets/s"] = 12
            base["Fwd Packet Length Mean"] = 350
            base["Bwd Packet Length Mean"] = 150
            base["Packet Length Mean"] = 250

        if "failed login" in event_type:
            base["Flow Duration"] = 3000
            base["Total Fwd Packets"] = 5
            base["Total Backward Packets"] = 1
            base["Flow Bytes/s"] = 800
            base["Flow Packets/s"] = 6
            base["Fwd Packet Length Mean"] = 120
            base["Bwd Packet Length Mean"] = 60
            base["Packet Length Mean"] = 90

        if "network" in event_type:
            base["Flow Duration"] = 10000
            base["Total Fwd Packets"] = 20
            base["Total Backward Packets"] = 15
            base["Flow Bytes/s"] = 6000
            base["Flow Packets/s"] = 30
            base["Fwd Packet Length Mean"] = 500
            base["Bwd Packet Length Mean"] = 400
            base["Packet Length Mean"] = 450

        if severity == "high":
            base["Flow Bytes/s"] *= 1.5
            base["Flow Packets/s"] *= 1.5

        if severity == "critical":
            base["Flow Bytes/s"] *= 2
            base["Flow Packets/s"] *= 2

        return base

    @staticmethod
    def detect_anomalies(events):

        dataset = AIDetectionService.build_dataset(events)

        predictions = AIDetectionService.model.predict(dataset)
        anomaly_scores = AIDetectionService.model.decision_function(dataset)

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