from datetime import datetime

class ResponseService:

    @staticmethod

    def simulate(action, endpoint):

        return {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'endpoint': endpoint,
            'action': action,
            'status': "Simulated",
            'message': f"{action} executed on {endpoint}"
        }
        