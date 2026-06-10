import joblib
import pandas as pd


class AIDetectionService:

    NETWORK_MODEL_PATH = "models/isolation_forest_model.pkl"
    LOG_MODEL_PATH = "models/log_event_model.pkl"

    SEVERITY_ENCODER_PATH = "models/severity_encoder.pkl"
    EVENT_TYPE_ENCODER_PATH = "models/event_type_encoder.pkl"
    ENDPOINT_ENCODER_PATH = "models/endpoint_encoder.pkl"

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

    network_model = joblib.load(NETWORK_MODEL_PATH)
    log_model = joblib.load(LOG_MODEL_PATH)

    severity_encoder = joblib.load(SEVERITY_ENCODER_PATH)
    event_type_encoder = joblib.load(EVENT_TYPE_ENCODER_PATH)
    endpoint_encoder = joblib.load(ENDPOINT_ENCODER_PATH)

    @staticmethod
    def safe_encode(encoder, value):
        value = str(value)

        if value in encoder.classes_:
            return encoder.transform([value])[0]

        return -1

    @staticmethod
    def build_dataset(events):
        rows = []

        for event in events:
            rows.append(AIDetectionService.map_event_to_features(event))

        return pd.DataFrame(rows, columns=AIDetectionService.FEATURES)

    @staticmethod
    def build_log_dataset(events):
        rows = []

        for event in events:
            rows.append({
                "severity_encoded": AIDetectionService.safe_encode(
                    AIDetectionService.severity_encoder,
                    event.severity
                ),
                "threat_score": AIDetectionService.local_threat_score(event),
                "event_type_encoded": AIDetectionService.safe_encode(
                    AIDetectionService.event_type_encoder,
                    event.event_type
                ),
                "endpoint_encoded": AIDetectionService.safe_encode(
                    AIDetectionService.endpoint_encoder,
                    event.endpoint
                )
            })

        return pd.DataFrame(rows)

    @staticmethod
    def local_threat_score(event):
        text = f"{event.event_type} {event.description}".lower()

        if "suspicious file drop" in text:
            return 100

        if "failed login" in text or "bad password" in text:
            return 65

        if "account discovery" in text or "net.exe" in text:
            return 45

        if "powershell" in text:
            return 80

        if "suspicious network connection" in text:
            return 75

        if "successful sudo" in text or "sudo to root" in text:
            return 15

        if "successful login" in text:
            return 10

        if "login session opened" in text or "login session closed" in text:
            return 10

        if event.severity == "Critical":
            return 80

        if event.severity == "High":
            return 60

        if event.severity == "Medium":
            return 35
        
        if "successful sudo" in text:
            return 50

        return 10

    @staticmethod
    def map_event_to_features(event):
        event_type = event.event_type.lower()
        severity = event.severity.lower()
        description = event.description.lower()

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

        if "successful login" in event_type or "login session" in event_type:
            base.update({
                "Flow Duration": 700,
                "Total Fwd Packets": 1,
                "Total Backward Packets": 1,
                "Flow Bytes/s": 250,
                "Flow Packets/s": 1.5,
                "Fwd Packet Length Mean": 80,
                "Bwd Packet Length Mean": 80,
                "Packet Length Mean": 80
            })

        if "failed login" in event_type:
            base.update({
                "Flow Duration": 3000,
                "Total Fwd Packets": 7,
                "Total Backward Packets": 1,
                "Flow Bytes/s": 900,
                "Flow Packets/s": 8,
                "Fwd Packet Length Mean": 140,
                "Bwd Packet Length Mean": 60,
                "Packet Length Mean": 100
            })

        if "account discovery" in event_type or "net.exe" in description:
            base.update({
                "Flow Duration": 4500,
                "Total Fwd Packets": 10,
                "Total Backward Packets": 2,
                "Flow Bytes/s": 1800,
                "Flow Packets/s": 14,
                "Fwd Packet Length Mean": 260,
                "Bwd Packet Length Mean": 90,
                "Packet Length Mean": 180
            })

        if "powershell" in event_type:
            base.update({
                "Flow Duration": 8000,
                "Total Fwd Packets": 15,
                "Total Backward Packets": 4,
                "Flow Bytes/s": 3500,
                "Flow Packets/s": 20,
                "Fwd Packet Length Mean": 420,
                "Bwd Packet Length Mean": 180,
                "Packet Length Mean": 300
            })

        if "suspicious file drop" in event_type or "executable file dropped" in description:
            base.update({
                "Flow Duration": 9000,
                "Total Fwd Packets": 18,
                "Total Backward Packets": 5,
                "Flow Bytes/s": 4200,
                "Flow Packets/s": 24,
                "Fwd Packet Length Mean": 500,
                "Bwd Packet Length Mean": 220,
                "Packet Length Mean": 360
            })

        if "suspicious network connection" in event_type:
            base.update({
                "Flow Duration": 12000,
                "Total Fwd Packets": 30,
                "Total Backward Packets": 20,
                "Flow Bytes/s": 7000,
                "Flow Packets/s": 40,
                "Fwd Packet Length Mean": 600,
                "Bwd Packet Length Mean": 450,
                "Packet Length Mean": 520
            })

        if severity == "medium":
            base["Flow Bytes/s"] *= 1.2
            base["Flow Packets/s"] *= 1.2

        if severity == "high":
            base["Flow Bytes/s"] *= 1.5
            base["Flow Packets/s"] *= 1.5

        if severity == "critical":
            base["Flow Bytes/s"] *= 2
            base["Flow Packets/s"] *= 2

        return base

    @staticmethod
    def rule_based_anomaly(event):
        text = f"{event.event_type} {event.description}".lower()

        if "suspicious file drop" in text:
            return True

        if "powershell" in text and "encoded" in text:
            return True

        if "failed login" in text or "bad password" in text:
            return True

        if "suspicious network connection" in text:
            return True

        if "account discovery" in text or "net.exe" in text:
            return True
        
        if "successful sudo" in text:
            return True

        if "sudo to root" in text:
            return True

        return False

    @staticmethod
    def detect_anomalies(events):
        network_dataset = AIDetectionService.build_dataset(events)
        log_dataset = AIDetectionService.build_log_dataset(events)

        network_predictions = AIDetectionService.network_model.predict(network_dataset)
        network_scores = AIDetectionService.network_model.decision_function(network_dataset)

        log_predictions = AIDetectionService.log_model.predict(log_dataset)

        results = []

        for index, event in enumerate(events):
            network_anomaly = network_predictions[index] == -1
            log_anomaly = log_predictions[index] == 1
            rule_anomaly = AIDetectionService.rule_based_anomaly(event)

            is_anomaly = network_anomaly or log_anomaly or rule_anomaly

            if rule_anomaly:
                detection_method = "Rule Override"
            elif log_anomaly:
                detection_method = "Log Event Model"
            elif network_anomaly:
                detection_method = "Network Isolation Forest"
            else:
                detection_method = "Normal"

            results.append({
                "event_id": event.id,
                "endpoint": event.endpoint,
                "event_type": event.event_type,
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": round(float(abs(network_scores[index])), 4),
                "network_model_anomaly": bool(network_anomaly),
                "log_model_anomaly": bool(log_anomaly),
                "rule_anomaly": bool(rule_anomaly),
                "detection_method": detection_method
            })

        return results