import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv("dataset/log_training_data_labeled.csv")

print(f"Loaded {len(df)} records")

severity_encoder = LabelEncoder()
event_type_encoder = LabelEncoder()
endpoint_encoder = LabelEncoder()

df["severity_encoded"] = severity_encoder.fit_transform(df["severity"])
df["event_type_encoded"] = event_type_encoder.fit_transform(df["event_type"])
df["endpoint_encoded"] = endpoint_encoder.fit_transform(df["endpoint"])

X = df[
    [
        "severity_encoded",
        "threat_score",
        "event_type_encoded",
        "endpoint_encoded"
    ]
]

y = df["is_anomaly"]

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)

model.fit(X, y)

print("Saving model...")

joblib.dump(model, "models/log_event_model.pkl")
joblib.dump(severity_encoder, "models/severity_encoder.pkl")
joblib.dump(event_type_encoder, "models/event_type_encoder.pkl")
joblib.dump(endpoint_encoder, "models/endpoint_encoder.pkl")

print("Training completed successfully.")
print(f"Samples used: {len(df)}")
print(f"Normal events: {(y == 0).sum()}")
print(f"Anomalous events: {(y == 1).sum()}")