import os
import json
import paramiko
from dotenv import load_dotenv

load_dotenv()


class WazuhAlertFileReader:

    def __init__(self):
        self.host = os.getenv("WAZUH_SSH_HOST")
        self.user = os.getenv("WAZUH_SSH_USER")
        self.password = os.getenv("WAZUH_SSH_PASSWORD")
        self.alerts_path = "/var/ossec/logs/alerts/alerts.json"

    def get_recent_alerts(self, limit=10):

        command = f"sudo tail -n {limit} {self.alerts_path}"

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh.connect(
            hostname=self.host,
            username=self.user,
            password=self.password
        )

        stdin, stdout, stderr = ssh.exec_command(
            command,
            get_pty=True
        )

        stdin.write(self.password + "\n")
        stdin.flush()

        output = stdout.read().decode("utf-8")
        ssh.close()

        alerts = []

        for line in output.splitlines():
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return alerts