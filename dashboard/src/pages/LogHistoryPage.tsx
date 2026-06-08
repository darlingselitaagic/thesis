import { useEffect, useState } from "react"
import PageHeader from "../components/PageHeader"
import { getXdrAlerts, type XdrAlert } from "../services/api"

export default function LogHistoryPage() {
  const [alerts, setAlerts] = useState<XdrAlert[]>([])
  const [selectedAlert, setSelectedAlert] = useState<XdrAlert | null>(null)

  useEffect(() => {
    getXdrAlerts().then(setAlerts)
  }, [])

  return (
    <>
      <PageHeader
        title="Log History"
        subtitle="Complete Wazuh alert history transformed into AI-XDR security events."
      />

      <div className="table-card">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Endpoint</th>
              <th>Severity</th>
              <th>Event Type</th>
              <th>Threat Score</th>
              <th>Action</th>
            </tr>
          </thead>

          <tbody>
            {alerts.map(alert => (
              <tr
                key={alert.id}
                className="clickable-row"
                onClick={() => setSelectedAlert(alert)}
              >
                <td>{alert.timestamp}</td>
                <td>{alert.endpoint}</td>
                <td>
                  <span className={`risk-pill ${alert.classification.toLowerCase()}`}>
                    {alert.classification}
                  </span>
                </td>
                <td>{alert.event_type}</td>
                <td>{alert.threat_score}/100</td>
                <td>{alert.recommended_action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selectedAlert && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div className="modal-card" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h2>Alert Details</h2>
                <p>{selectedAlert.endpoint}</p>
              </div>

              <button onClick={() => setSelectedAlert(null)}>×</button>
            </div>

            <div className="modal-grid">
              <div>
                <span>Timestamp</span>
                <strong>{selectedAlert.timestamp}</strong>
              </div>

              <div>
                <span>Endpoint</span>
                <strong>{selectedAlert.endpoint}</strong>
              </div>

              <div>
                <span>Event Type</span>
                <strong>{selectedAlert.event_type}</strong>
              </div>

              <div>
                <span>Severity</span>
                <strong>{selectedAlert.severity}</strong>
              </div>

              <div>
                <span>Classification</span>
                <strong>{selectedAlert.classification}</strong>
              </div>

              <div>
                <span>Threat Score</span>
                <strong>{selectedAlert.threat_score}/100</strong>
              </div>

              <div>
                <span>AI Anomaly</span>
                <strong>{selectedAlert.is_anomaly ? "Yes" : "No"}</strong>
              </div>

              <div>
                <span>Anomaly Score</span>
                <strong>{selectedAlert.anomaly_score}</strong>
              </div>

              <div>
                <span>Source IP / Host</span>
                <strong>{selectedAlert.source_ip}</strong>
              </div>

              <div>
                <span>Recommended Action</span>
                <strong>{selectedAlert.recommended_action}</strong>
              </div>
            </div>

            <div className="modal-section">
              <span>Description</span>
              <p>{selectedAlert.description}</p>
            </div>
          </div>
        </div>
      )}
    </>
  )
}