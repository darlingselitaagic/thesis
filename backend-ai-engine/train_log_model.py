import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

# Load dataset
df = pd.read_csv("../dataset/log_training_data_labeled.csv")

print(f"Loaded {len(df)} records")

# Normalize column names (IMPORTANT ✅)
df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")

# Drop rows without labels
df = df.dropna(subset=["is_anomaly"])
df["is_anomaly"] = df["is_anomaly"].astype(int)

# Initialize encoders
severity_encoder = LabelEncoder()
event_type_encoder = LabelEncoder()
endpoint_encoder = LabelEncoder()

# Encode categorical features
df["severity_encoded"] = severity_encoder.fit_transform(df["severity"])
df["event_type_encoded"] = event_type_encoder.fit_transform(df["event_type"])
df["endpoint_encoded"] = endpoint_encoder.fit_transform(df["endpoint"])

# Features and target
X = df[
    [
        "severity_encoded",
        "threat_score",
        "event_type_encoded",
        "endpoint_encoded"
    ]
]

y = df["is_anomaly"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Model
model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)

# Train model
model.fit(X_train, y_train)

# Predictions
predictions = model.predict(X_test)

# Evaluation
print("Accuracy:", accuracy_score(y_test, predictions))
print("Precision:", precision_score(y_test, predictions))
print("Recall:", recall_score(y_test, predictions))
print("F1:", f1_score(y_test, predictions))

print("Confusion Matrix:")
print(confusion_matrix(y_test, predictions))

# Train on full dataset before saving
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