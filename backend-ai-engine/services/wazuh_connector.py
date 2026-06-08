import os
import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

load_dotenv()


class WazuhConnector:

    def get_alerts(self, limit=50):

        token = self.get_token()

        url = f"{self.host}:55000/alerts"

        headers = {
            "Authorization": f"Bearer {token}"
        }

        response = requests.get(
            url,
            headers=headers,
            params={"limit": limit},
            verify=False
        )

        response.raise_for_status()

        return response.json()

    def __init__(self):
        self.host = os.getenv("WAZUH_HOST")
        self.user = os.getenv("WAZUH_USER")
        self.password = os.getenv("WAZUH_PASSWORD")

    def get_token(self):
        url = f"{self.host}:55000/security/user/authenticate"

        response = requests.post(
            url,
            auth=HTTPBasicAuth(self.user, self.password),
            verify=False
        )

        response.raise_for_status()

        return response.json()["data"]["token"]

    def get_agents(self):
        token = self.get_token()

        url = f"{self.host}:55000/agents"

        headers = {
            "Authorization": f"Bearer {token}"
        }

        response = requests.get(
            url,
            headers=headers,
            verify=False
        )

        response.raise_for_status()

        return response.json()