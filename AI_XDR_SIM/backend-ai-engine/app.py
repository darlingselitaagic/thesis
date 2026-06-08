from dataclasses import asdict
from services.event_service import EventService
from flask import Flask, jsonify
from flask_cors import CORS
from services.decision_service import DecisionService
from services.threat_scoring_service import ThreatScoringService
from services.correlation_service import CorrelationService
from services.response_service import ResponseService
from services.ai_detection_service import AIDetectionService

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return jsonify({
        "message": "AI-XDR Backend Running"
    })

@app.route("/api/alerts")
def get_alerts():
    events = EventService.get_events()

    response = []

    for event in events:
        event_data = asdict(event)

        score = (
            ThreatScoringService.calculate_score(event)
        )

        classification = (
            DecisionService.classify(score)
        )

        ai_result = ai_results_by_id.get(event.id, {})

        is_anomaly = ai_result.get("is_anomaly", False)
        anomaly_score = ai_result.get("anomaly_score", 0)

        action = DecisionService.recommend_ai_action(
            score,
            is_anomaly,
            anomaly_score
        )

        event_data['threat_score'] = score
        event_data['classification'] = classification
        event_data['recommended_action'] = action

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

if __name__ == "__main__":
    app.run(debug=True)