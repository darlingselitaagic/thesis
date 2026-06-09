import { useEffect, useState } from "react"
import { Activity, AlertTriangle, Server, Shield } from "lucide-react"
import PageHeader from "../components/PageHeader"
import MetricCard from "../components/MetricCards"
import {
  getWazuhAgents,
  getLogHistory,
  getXdrResponses,
  syncWazuhLogs,
  type WazuhAgent,
  type XdrAlert,
  type XdrResponse
} from "../services/api"

export default function OverviewPage() {
  const [alerts, setAlerts] = useState<XdrAlert[]>([])
  const [responses, setResponses] = useState<XdrResponse[]>([])
  const [agents, setAgents] = useState<WazuhAgent[]>([])

useEffect(() => {
  syncWazuhLogs().then(() => {
    Promise.all([getLogHistory(), getXdrResponses(), getWazuhAgents()])
      .then(([alertsData, responsesData, agentsData]) => {
        setAlerts(alertsData)
        setResponses(responsesData)
        setAgents(agentsData)
      })
  })
}, [])

  const critical = alerts.filter(a => a.classification === "Critical").length
  const activeAgents = agents.filter(a => a.status === "active").length
  const recentAlerts = alerts.slice(0, 6)
  const recentResponses = responses.slice(0, 4)

  return (
    <>
      <PageHeader
        title="Dashboard Overview"
        subtitle="Centralized overview of Wazuh alerts, active agents, correlated incidents and simulated responses."
      />

      <section className="metric-grid">
        <MetricCard title="Total Alerts" value={alerts.length} label="WAZUH EVENTS" icon={<Activity />} />
        <MetricCard title="Critical Alerts" value={critical} label="ACTION REQUIRED" icon={<AlertTriangle />} danger />
        <MetricCard title="Active Agents" value={activeAgents} label="CONNECTED" icon={<Server />} />
        <MetricCard title="Responses" value={responses.length} label="SIMULATED" icon={<Shield />} />
      </section>

      <section className="overview-grid">
        <div className="dashboard-panel">
          <div className="panel-header">
            <h2>Recent Threats</h2>
            <span>{recentAlerts.length} events</span>
          </div>

          <div className="mini-list">
            {recentAlerts.map(alert => (
              <div className="mini-row" key={alert.id}>
                <div>
                  <strong>{alert.endpoint}</strong>
                  <p>{alert.description}</p>
                </div>

                <span className={`risk-pill ${alert.classification.toLowerCase()}`}>
                  {alert.classification}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="dashboard-panel">
          <div className="panel-header">
            <h2>Response Decisions</h2>
            <span>{recentResponses.length} actions</span>
          </div>

          <div className="mini-list">
            {recentResponses.map((response, index) => (
              <div className="mini-row" key={index}>
                <div>
                  <strong>{response.endpoint}</strong>
                  <p>{response.action}</p>
                </div>

                <span className={`risk-pill ${(response.explanation?.risk_level ?? response.risk_level).toLowerCase()}`}>
                  {response.explanation?.risk_level ?? response.risk_level}
                </span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="dashboard-panel">
        <div className="panel-header">
          <h2>Latest Wazuh Events</h2>
          <span>Transformed AI-XDR security events</span>
        </div>

        <div className="compact-table">
          <table>
            <thead>
              <tr>
                <th>Endpoint</th>
                <th>Event Type</th>
                <th>Threat Score</th>
                <th>Action</th>
              </tr>
            </thead>

            <tbody>
              {recentAlerts.map(alert => (
                <tr key={alert.id}>
                  <td>{alert.endpoint}</td>
                  <td>{alert.event_type}</td>
                  <td>{alert.threat_score}/100</td>
                  <td>{alert.recommended_action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  )
}