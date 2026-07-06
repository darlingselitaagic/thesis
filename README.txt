AI-XDR-Simulate Solution

Overview
--------
This repository contains two main components:
- backend-ai-engine: Flask-based backend API, local SQLite persistence, Wazuh integration, AI detection and correlation logic.
- dashboard: React + TypeScript + Vite frontend UI that connects to the backend at http://127.0.0.1:5000.

Requirements
------------
- Python 3.11+ (recommended) or any Python 3.10+ runtime compatible with the listed packages.
- Node.js 20+ and npm (or yarn/pnpm) for the dashboard.
- Wazuh server access configured through environment variables.

Backend Setup (backend-ai-engine)
---------------------------------
1. Open a terminal in `backend-ai-engine`.
2. Create and activate a Python virtual environment:
   - Windows PowerShell:
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
   - Windows CMD:
     python -m venv .venv
     .\.venv\Scripts\activate.bat
3. Install backend Python dependencies:
   pip install -r requirements.txt
4. Create a `.env` file in `backend-ai-engine` with the following required values:
   WAZUH_SSH_HOST=<wazuh ssh host>
   WAZUH_SSH_USER=<wazuh ssh user>
   WAZUH_SSH_PASSWORD=<wazuh ssh password>
   WAZUH_HOST=<wazuh api host, e.g. https://wazuh-server>
   WAZUH_USER=<wazuh api username>
   WAZUH_PASSWORD=<wazuh api password>

   Notes:
   - `WAZUH_SSH_HOST` is used by `WazuhAlertFileReader` to fetch the alerts JSON file via SSH.
   - `WAZUH_HOST` is used by `WazuhConnector` to access the Wazuh API on port 55000.
   - The backend reads `alerts.json` from `/var/ossec/logs/alerts/alerts.json` on the remote Wazuh host.

5. Start the backend API server:
   python app.py

6. The backend will run at:
   http://127.0.0.1:5000

Backend dependencies (from requirements.txt)
------------------------------------------
bcrypt==5.0.0
blinker==1.9.0
certifi==2026.5.20
cffi==2.0.0
charset-normalizer==3.4.7
click==8.4.1
colorama==0.4.6
cryptography==48.0.0
Flask==3.1.3
flask-cors==6.0.2
idna==3.18
invoke==3.0.3
itsdangerous==2.2.0
Jinja2==3.1.6
joblib==1.5.3
MarkupSafe==3.0.3
narwhals==2.22.1
numpy==2.4.6
pandas==3.0.3
paramiko==5.0.0
pycparser==3.0
PyNaCl==1.6.2
python-dateutil==2.9.0.post0
python-dotenv==1.2.2
requests==2.34.2
scikit-learn==1.9.0
scipy==1.17.1
six==1.17.0
threadpoolctl==3.6.0
tzdata==2026.2
urllib3==2.7.0
Werkzeug==3.1.8

Frontend Setup (dashboard)
--------------------------
1. Open a terminal in `dashboard`.
2. Install dependencies:
   npm install
3. Start the development server:
   npm run dev
4. Open the local Vite address shown in the terminal, typically:
   http://127.0.0.1:5173

Frontend dependencies (from package.json)
----------------------------------------
Dependencies:
- axios ^1.17.0
- lucide-react ^1.17.0
- react ^19.2.6
- react-dom ^19.2.6
- react-router-dom ^7.17.0
- recharts ^3.8.1

DevDependencies:
- @eslint/js ^10.0.1
- @types/node ^24.12.3
- @types/react ^19.2.14
- @types/react-dom ^19.2.3
- @vitejs/plugin-react ^6.0.1
- eslint ^10.3.0
- eslint-plugin-react-hooks ^7.1.1
- eslint-plugin-react-refresh ^0.5.2
- globals ^17.6.0
- typescript ~6.0.2
- typescript-eslint ^8.59.2
- vite ^8.0.12

Important notes
---------------
- The frontend is configured to call the backend at `http://127.0.0.1:5000` in `dashboard/src/services/api.ts`.
- Start the backend before launching the dashboard.
- The backend creates and uses `backend-ai-engine/filtered_logs.db` automatically.
- The backend currently disables SSL verification for Wazuh API calls (`verify=False`), so it is best used in development or trusted network environments.

Ubuntu Wazuh Agent and Dashboard Setup
--------------------------------------
These commands are intended for an Ubuntu machine linked to this solution.

1. Add the Wazuh repository and install packages:
   sudo apt-get update
   curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmour -o /usr/share/keyrings/wazuh-archive-keyring.gpg
   echo "deb [signed-by=/usr/share/keyrings/wazuh-archive-keyring.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
   sudo apt-get update
   sudo apt-get install wazuh-manager wazuh-api wazuh-dashboard wazuh-agent

2. Enable and start the Wazuh services:
   sudo systemctl daemon-reload
   sudo systemctl enable --now wazuh-manager wazuh-api wazuh-dashboard wazuh-agent
   sudo systemctl status wazuh-manager wazuh-api wazuh-dashboard wazuh-agent

3. Configure the Wazuh manager and agent:
   - On the manager machine, verify `/var/ossec/etc/ossec.conf` and `/etc/wazuh-dashboard/wazuh-dashboard.yml` if needed.
   - On the agent machine, set manager address and register the agent:
     sudo /var/ossec/bin/agent-auth -m <MANAGER_IP>
     sudo systemctl restart wazuh-agent
   - Validate with:
     sudo systemctl status wazuh-agent
     sudo tail -n 50 /var/ossec/logs/ossec.log

4. Access the Wazuh dashboard in a browser:
   - Use `https://<MANAGER_IP>:5601` or the port configured for the Wazuh dashboard.
   - If needed, adjust firewall rules to allow the dashboard port.

Windows Sysmon Installation
---------------------------
Use these steps on your Windows machine to install Sysmon from Microsoft Sysinternals.

1. Download Sysmon:
   - Visit https://learn.microsoft.com/sysinternals/downloads/sysmon
   - Or use PowerShell:
     curl -L -o sysmon.zip https://download.sysinternals.com/files/Sysmon.zip

2. Extract and install Sysmon as administrator:
   Expand-Archive .\sysmon.zip -DestinationPath .\sysmon
   Set-Location .\sysmon
   .\Sysmon64.exe -accepteula -i

3. Verify Sysmon is running:
   .\Sysmon64.exe -c
   Get-Service -Name Sysmon

4. Optional: install with a config file for better event capture:
   .\Sysmon64.exe -accepteula -i sysmon-config.xml
   (Use a community or custom Sysmon config file.)

How to use
----------
1. Start the backend: `python app.py` from `backend-ai-engine`.
2. Start the frontend: `npm run dev` from `dashboard`.
3. Open the Vite URL shown in the dashboard terminal.
4. Use the dashboard to fetch alerts, correlations, responses, and log history from the backend.

Troubleshooting
---------------
- If the dashboard cannot connect, confirm the backend is running on port 5000 and that CORS is enabled.
- If Wazuh endpoints fail, verify the `.env` variables and remote SSH/API connectivity.
- If packages fail to install, upgrade pip (`python -m pip install --upgrade pip`) and ensure Node.js is installed.
