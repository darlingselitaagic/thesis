from dataclasses import asdict
from flask import Flask, jsonify
from flask_cors import CORS
from services.decision_service import DecisionService
from services.threat_scoring_service import ThreatScoringService
from services.correlation_service import CorrelationService
from services.response_service import ResponseService
from services.ai_detection_service import AIDetectionService
from services.wazuh_connector import WazuhConnector
from services.wazuh_alert_file_reader import WazuhAlertFileReader
from dataclasses import asdict
from services.event_service import EventService
from services.wazuh_alert_file_reader import WazuhAlertFileReader
from services.wazuh_alert_transformer import WazuhAlertTransformer
from services.response_service import ResponseService
from services.response_explanation_service import ResponseExplanationService
from services.database_service import DatabaseService

app = Flask(__name__)
CORS(app)
DatabaseService.initialize()

@app.route("/")
def home():
    return jsonify({
        "message": "AI-XDR Backend Running"
    })

@app.route("/api/alerts")
def get_alerts():

    events = EventService.get_events()

    ai_results = AIDetectionService.detect_anomalies(events)

    ai_results_by_id = {
        result["event_id"]: result
        for result in ai_results
    }

    response = []

    for event in events:

        event_data = asdict(event)

        score = ThreatScoringService.calculate_score(event)

        classification = DecisionService.classify(score)

        ai_result = ai_results_by_id.get(event.id, {})

        is_anomaly = ai_result.get("is_anomaly", False)
        anomaly_score = ai_result.get("anomaly_score", 0)

        action = DecisionService.recommend_ai_action(
            score,
            is_anomaly,
            anomaly_score
        )

        event_data["threat_score"] = score
        event_data["classification"] = classification
        event_data["recommended_action"] = action
        event_data["is_anomaly"] = is_anomaly
        event_data["anomaly_score"] = anomaly_score

        response.append(event_data)

    return jsonify(response)

@app.route("/api/correlations")

def get_correlation():

    events = EventService.get_events()

    correlations = CorrelationService.correlate(events)

    response = []

    for correlation in correlations:

        correlation_score = correlation['correlation_score']

        action = DecisionService.recommend_correlation_action(correlation_score)

        correlation["recommended_action"] = action

        response.append(correlation)
    
    return jsonify(response)


@app.route("/api/responses")
def get_responses():

    events = EventService.get_events()

    ai_results = AIDetectionService.detect_anomalies(events)

    ai_results_by_id = {
        result["event_id"]: result
        for result in ai_results
    }

    responses = []

    for event in events:

        score = ThreatScoringService.calculate_score(event)

        ai_result = ai_results_by_id.get(event.id, {})

        is_anomaly = ai_result.get("is_anomaly", False)
        anomaly_score = ai_result.get("anomaly_score", 0)

        action = DecisionService.recommend_ai_action(
            score,
            is_anomaly,
            anomaly_score
        )

        response = ResponseService.simulate(
            action,
            event.endpoint
        )

        response["event_id"] = event.id
        response["event_type"] = event.event_type
        response["threat_score"] = score
        response["is_anomaly"] = is_anomaly
        response["anomaly_score"] = anomaly_score

        responses.append(response)

    return jsonify(responses)


@app.route("/api/ai-detection")
def get_ai_detection():

    events = EventService.get_events()

    results = AIDetectionService.detect_anomalies(events)

    return jsonify(results)

@app.route("/api/wazuh/agents")
def get_wazuh_agents():

    connector = WazuhConnector()

    agents = connector.get_agents()

    return jsonify(agents)

@app.route("/api/wazuh/alerts")
def get_wazuh_alerts():

    connector = WazuhConnector()

    alerts = connector.get_alerts()

    return jsonify(alerts)

@app.route("/api/wazuh/file-alerts")
def get_wazuh_file_alerts():

    reader = WazuhAlertFileReader()

    alerts = reader.get_recent_alerts(limit=10)

    return jsonify(alerts)

@app.route("/api/xdr/wazuh-alerts")
def get_xdr_wazuh_alerts():

    reader = WazuhAlertFileReader()

    raw_alerts = reader.get_recent_alerts(limit=20)

    events = WazuhAlertTransformer.transform(raw_alerts)

    ai_results = AIDetectionService.detect_anomalies(events)

    ai_results_by_id = {
        result["event_id"]: result
        for result in ai_results
    }

    response = []

    for event in events:

        event_data = asdict(event)

        score = ThreatScoringService.calculate_score(event)

        classification = DecisionService.classify(score)

        ai_result = ai_results_by_id.get(event.id, {})

        is_anomaly = ai_result.get("is_anomaly", False)
        anomaly_score = ai_result.get("anomaly_score", 0)

        action = DecisionService.recommend_ai_action(
            score,
            is_anomaly,
            anomaly_score
        )

        event_data["threat_score"] = score
        event_data["classification"] = classification
        event_data["recommended_action"] = action
        event_data["is_anomaly"] = is_anomaly
        event_data["anomaly_score"] = anomaly_score
        event_data["detection_method"] = ai_result.get("detection_method", "Unknown")
        event_data["network_model_anomaly"] = ai_result.get("network_model_anomaly", False)
        event_data["log_model_anomaly"] = ai_result.get("log_model_anomaly", False)
        event_data["rule_anomaly"] = ai_result.get("rule_anomaly", False)

        DatabaseService.save_event(event_data)
        response.append(event_data)

    return jsonify(response)

@app.route("/api/xdr/wazuh-correlations")
def get_xdr_wazuh_correlations():

    reader = WazuhAlertFileReader()

    raw_alerts = reader.get_recent_alerts(limit=50)

    events = WazuhAlertTransformer.transform(raw_alerts)

    correlations = CorrelationService.correlate(events)

    response = []

    for correlation in correlations:

        correlation_score = correlation["correlation_score"]

        action = DecisionService.recommend_correlation_action(
            correlation_score
        )

        correlation["recommended_action"] = action

        response.append(correlation)

    return jsonify(response)

@app.route("/api/xdr/wazuh-responses")
def get_xdr_wazuh_responses():

    reader = WazuhAlertFileReader()

    raw_alerts = reader.get_recent_alerts(limit=50)

    events = WazuhAlertTransformer.transform(raw_alerts)

    correlations = CorrelationService.correlate(events)

    responses = []

    for correlation in correlations:

        correlation_score = correlation["correlation_score"]

        action = DecisionService.recommend_correlation_action(
            correlation_score
        )

        response = ResponseService.simulate(
            action,
            correlation["endpoint"],
            context={
                "correlation_score": correlation_score,
                "detected_patterns": correlation["detected_patterns"]
            }
        )

        explanation = ResponseExplanationService.generate(
            action=action,
            endpoint=correlation["endpoint"],
            correlation_score=correlation_score,
            detected_patterns=correlation["detected_patterns"],
            related_events=correlation["related_events"]
        )

        response["correlation_score"] = correlation_score
        response["detected_patterns"] = correlation["detected_patterns"]
        response["related_events"] = correlation["related_events"]
        response["explanation"] = explanation

        responses.append(response)

    return jsonify(responses)

@app.route("/api/log-history")
def get_log_history():

    conn = DatabaseService.get_connection()

    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM security_events
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    results = []

    for row in rows:

        results.append({
            "id": row[0],
            "timestamp": row[1],
            "endpoint": row[2],
            "source_ip": row[3],
            "severity": row[4],
            "event_type": row[5],
            "description": row[6],
            "threat_score": row[7],
            "classification": row[8],
            "recommended_action": row[9],
            "anomaly_score": row[10],
            "is_anomaly": bool(row[11])
        })

    return jsonify(results)

@app.route("/api/sync-wazuh-logs")
def sync_wazuh_logs():

    reader = WazuhAlertFileReader()
    raw_alerts = reader.get_recent_alerts(limit=200)

    events = WazuhAlertTransformer.transform(raw_alerts)

    ai_results = AIDetectionService.detect_anomalies(events)

    ai_results_by_id = {
        result["event_id"]: result
        for result in ai_results
    }

    saved_count = 0

    for event in events:

        event_data = asdict(event)

        score = ThreatScoringService.calculate_score(event)
        classification = DecisionService.classify(score)

        ai_result = ai_results_by_id.get(event.id, {})

        event_data["threat_score"] = score
        event_data["classification"] = classification
        event_data["recommended_action"] = DecisionService.recommend_ai_action(
            score,
            ai_result.get("is_anomaly", False),
            ai_result.get("anomaly_score", 0)
        )
        event_data["is_anomaly"] = ai_result.get("is_anomaly", False)
        event_data["anomaly_score"] = ai_result.get("anomaly_score", 0)

        inserted = DatabaseService.save_event(event_data)
        saved_count += inserted

    return jsonify({
    "message": "Wazuh logs synced into SQLite",
    "processed": len(events),
    "inserted": saved_count,
    "ignored": len(events) - saved_count
    })

if __name__ == "__main__":
    app.run(debug=True)