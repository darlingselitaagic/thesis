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

        if is_anomaly and threat_score >= 70:
            return "Simulate Endpoint Isolation"

        if is_anomaly and threat_score >= 50:
            return "Escalate Incident"

        if is_anomaly:
            return "Generate Alert"

        if threat_score >= 60:
            return "Investigate Immediately"

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