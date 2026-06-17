import { useEffect, useState } from "react"
import PageHeader from "../components/PageHeader"
import { ArrowLeft, ArrowRight, Sheet } from "lucide-react"
import type { XdrAlert } from "../types"
import { useLogHistory } from "../hooks/useLogHistory"

export default function LogHistoryPage() {

  const [selectedAlert, setSelectedAlert] = useState<XdrAlert | null>(null)
  const { formatTimestamp, setAlertsPage,
    alerts, classifications, eventTypes, endpoints, setSearch, 
    setEndpoint, setClassification, setEventType, setCurrentPage, setRowsPerPage,
    search, filteredAlerts, selectedInfo, totalPages, currentPage, exportCsv,
    rowsPerPage, paginatedAlerts, endpoint, eventType, classification } = useLogHistory()

  useEffect(() => {
    setAlertsPage()
    }, [setAlertsPage])

  return (
    <>
      <PageHeader
        title="Log History"
        subtitle="Complete database-backed Wazuh alert history transformed into AI-XDR security events."
      />

      <div className="filter-bar">
        <input
          value={search}
          onChange={e => {
            setSearch(e.target.value)
            setCurrentPage(1)
          }}
          placeholder="Search logs..."
        />

        <select
          value={endpoint}
          onChange={e => {
            setEndpoint(e.target.value)
            setCurrentPage(1)
          }}
        >
          <option value="All">All endpoints</option>
          {endpoints.map(item => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>

        <select
          value={classification}
          onChange={e => {
            setClassification(e.target.value)
            setCurrentPage(1)
          }}
        >
          <option value="All">All classifications</option>
          {classifications.map(item => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>

        <select
          value={eventType}
          onChange={e => {
            setEventType(e.target.value)
            setCurrentPage(1)
          }}
        >
          <option value="All">All event types</option>
          {eventTypes.map(item => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>
      </div>


      <div className="panel-header">
        <h2>Stored Events</h2>
        <span>{filteredAlerts.length} of {alerts.length} logs</span>
      </div>

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
            {paginatedAlerts.map(alert => (
              <tr
                key={alert.id}
                className="clickable-row"
                onClick={() => setSelectedAlert(alert)}
              >
                <td>{formatTimestamp(alert.timestamp)}</td>
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
      <div className="pagination-bar">
        <span>
          Page {currentPage} of {totalPages || 1}
        </span>

        <div className="export-section">
          <button
          className="export-btn"
          onClick={exportCsv}
        >
         < Sheet size={15} />
          </button>
        </div>    

        <select
          value={rowsPerPage}
          onChange={e => {
            setRowsPerPage(Number(e.target.value))
            setCurrentPage(1)
          }}
        >
          <option value={10}>10</option>
          <option value={20}>20</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
        </select>

        <button
          disabled={currentPage === 1}
          onClick={() => setCurrentPage(page => page - 1)}
        >
          <ArrowLeft size={15} /> 
        </button>

        <button
          disabled={currentPage >= totalPages}
          onClick={() => setCurrentPage(page => page + 1)}
        >
          <ArrowRight size={15} />
        </button>
      </div>

      {selectedAlert && selectedInfo && (
        <div className="modal-overlay" onClick={() => setSelectedAlert(null)}>
          <div className="modal-card investigation-modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h2>Alert Investigation</h2>
                <p>{selectedAlert.endpoint}</p>
              </div>

              <button onClick={() => setSelectedAlert(null)}>×</button>
            </div>

            <div className="modal-grid">
              <div><span>Timestamp</span><strong>{formatTimestamp(selectedAlert.timestamp)}</strong></div>
              <div><span>Endpoint</span><strong>{selectedAlert.endpoint}</strong></div>
              <div><span>Event Type</span><strong>{selectedAlert.event_type}</strong></div>
              <div><span>Severity</span><strong>{selectedAlert.severity}</strong></div>
              <div><span>Classification</span><strong>{selectedAlert.classification}</strong></div>
              <div><span>Threat Score</span><strong>{selectedAlert.threat_score}/100</strong></div>
              <div><span>AI Anomaly</span><strong>{selectedAlert.is_anomaly ? "Yes" : "No"}</strong></div>
              <div><span>Anomaly Score</span><strong>{selectedAlert.anomaly_score}</strong></div>
              <div><span>Source IP / Host</span><strong>{selectedAlert.source_ip}</strong></div>
              <div><span>Recommended Action</span><strong>{selectedAlert.recommended_action}</strong></div>
            </div>

            <div className="modal-section">
              <span>Description</span>
              <p>{selectedAlert.description}</p>
            </div>

            <div className="investigation-grid">
              <div className="modal-section">
                <span>Attack Stage</span>
                <p>{selectedInfo.attackStage}</p>
              </div>

              <div className="modal-section">
                <span>Response Reason</span>
                <p>{selectedInfo.responseReason}</p>
              </div>
            </div>

            <div className="modal-section">
              <span>MITRE ATT&CK Mapping</span>
              {selectedInfo.mitre.length > 0 ? (
                <div className="mitre-list">
                  {selectedInfo.mitre.map(item => (
                    <strong key={item}>{item}</strong>
                  ))}
                </div>
              ) : (
                <p>No MITRE mapping available for this event type.</p>
              )}
            </div>

            <div className="modal-section">
              <span>Recommended Analyst Actions</span>
              <ul className="action-list">
                {selectedInfo.nextSteps.map(step => (
                  <li key={step}>{step}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </>
  )
}