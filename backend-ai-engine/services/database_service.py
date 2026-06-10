import sqlite3

DB_NAME = "filtered_logs.db"

class DatabaseService:

    @staticmethod
    def get_connection():
        return sqlite3.connect(DB_NAME)

    @staticmethod
    def initialize():

        conn = DatabaseService.get_connection()

        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            endpoint TEXT,
            source_ip TEXT,
            severity TEXT,
            event_type TEXT,
            description TEXT,
            threat_score INTEGER,
            classification TEXT,
            recommended_action TEXT,
            anomaly_score REAL,
            is_anomaly INTEGER,
            UNIQUE(timestamp, endpoint, description, event_type)
        )
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_timestamp
        ON security_events(timestamp)
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_endpoint
        ON security_events(endpoint)
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_event_type
        ON security_events(event_type)
        """)

        cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_classification
        ON security_events(classification)
        """)

        conn.commit()
        conn.close()

    @staticmethod
    def save_event(event_data):

        conn = DatabaseService.get_connection()

        cursor = conn.cursor()

        cursor.execute("""
        INSERT OR IGNORE INTO security_events(
            timestamp,
            endpoint,
            source_ip,
            severity,
            event_type,
            description,
            threat_score,
            classification,
            recommended_action,
            anomaly_score,
            is_anomaly
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_data["timestamp"],
            event_data["endpoint"],
            event_data["source_ip"],
            event_data["severity"],
            event_data["event_type"],
            event_data["description"],
            event_data["threat_score"],
            event_data["classification"],
            event_data["recommended_action"],
            event_data["anomaly_score"],
            int(event_data["is_anomaly"])
        ))
        inserted = cursor.rowcount
        conn.commit()
        conn.close()
        return inserted