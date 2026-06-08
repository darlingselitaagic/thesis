class DecisionService:

    @staticmethod
    def classify(score):
        
        if score >= 80:
            return 'Critical'
        
        if score >= 60:
            return 'High'
        
        if score >= 30:
            return 'Medium'
        
        return 'Low'
    
    @staticmethod
    def recommend_ai_action(threat_score, is_anomaly, anomaly_score):

        if threat_score >= 80 and is_anomaly:
            return "Simulate Endpoint Isolation"

        if threat_score >= 80:
            return "Escalate Incident"

        if threat_score >= 60 and is_anomaly:
            return "Escalate Incident"

        if threat_score >= 60:
            return "Investigate Immediately"

        if threat_score >= 30 and is_anomaly:
            return "Generate Alert"

        if threat_score >= 30:
            return "Monitor Closely"

        if is_anomaly:
            return "Generate Alert"

        return "Continue Monitoring"
    
    @staticmethod
    
    def recommend_correlation_action(correlation_score):

        if correlation_score >= 85:
            return 'Simulate Endpoint Isolation'
        
        if correlation_score >= 60:
            return 'Escalate Incident'
        
        if correlation_score >= 30:
            return 'Generate Alert'
        
        return 'Continue Monitoring'