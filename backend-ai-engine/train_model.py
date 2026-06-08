import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
import joblib

DATASET_PATH = Path("../dataset/CICIDS2017")

csv_files = list(DATASET_PATH.glob("*.csv"))

monday_file = DATASET_PATH / "Monday-WorkingHours.pcap_ISCX.csv"

df = pd.read_csv(monday_file)
df.columns = df.columns.str.strip()

features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Packet Length Mean"
]

X = df[features]

model = IsolationForest(
    contamination=0.01,
    random_state=42
)

model.fit(X)

print("Model trained successfully")

joblib.dump(model, "models/isolation_forest_model.pkl")

print("Model saved to models/isolation_forest_model.pkl")