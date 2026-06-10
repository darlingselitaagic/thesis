import { useEffect, useMemo, useState } from "react"
import PageHeader from "../components/PageHeader"
import { getLogHistory, syncWazuhLogs, type XdrAlert } from "../services/api"
import { ArrowLeft, ArrowRight, Sheet } from "lucide-react"

type InvestigationInfo = {
  attackStage: string
  responseReason: string
  mitre: string[]
  nextSteps: string[]
}

function formatTimestamp(timestamp: string) {
  const date = new Date(timestamp)

  if (Number.isNaN(date.getTime())) {
    return timestamp
  }

  return date.toLocaleString()
}

function getInvestigationInfo(alert: XdrAlert): InvestigationInfo {
  const text = `${alert.event_type} ${alert.description}`.toLowerCase()

  if (text.includes("suspicious file drop") || text.includes("executable file dropped")) {
    return {
      attackStage: "Malware Staging",
      responseReason:
        "An executable file was created in a location commonly abused by malware, which can indicate payload staging or preparation for execution.",
      mitre: [
        "T1105 - Ingress Tool Transfer",
        "T1204 - User Execution"
      ],
      nextSteps: [
        "Identify the dropped executable path",
        "Calculate and verify the file hash",
        "Check the parent process that created the file",
        "Review whether the executable was launched",
        "Escalate the incident for analyst validation"
      ]
    }
  }

  if (text.includes("failed login") || text.includes("logon failure") || text.includes("bad password")) {
    return {
      attackStage: "Credential Access",
      responseReason:
        "Authentication failures may indicate brute-force activity, password guessing, or attempted access using invalid credentials.",
      mitre: [
        "T1110 - Brute Force",
        "T1078 - Valid Accounts"
      ],
      nextSteps: [
        "Review the source host or IP address",
        "Check whether repeated failures occurred in a short time window",
        "Verify whether a successful login followed the failures",
        "Confirm whether the targeted account exists",
        "Consider temporary account lockout if attempts continue"
      ]
    }
  }

  if (text.includes("account discovery") || text.includes("net.exe") || text.includes("discovery")) {
    return {
      attackStage: "Discovery",
      responseReason:
        "Account discovery commands are commonly used by attackers after gaining access to enumerate users, groups, and privileges.",
      mitre: [
        "T1087 - Account Discovery",
        "T1059 - Command and Scripting Interpreter"
      ],
      nextSteps: [
        "Review the executed command line",
        "Identify the user or process that launched the command",
        "Check for additional discovery commands nearby",
        "Review process ancestry",
        "Monitor the endpoint for follow-up lateral movement"
      ]
    }
  }

  if (text.includes("privilege escalation") || text.includes("sudo")) {
    return {
      attackStage: "Privilege Escalation",
      responseReason:
        "Successful sudo activity indicates elevated privilege usage and should be reviewed to confirm it was expected and authorized.",
      mitre: [
        "T1548 - Abuse Elevation Control Mechanism"
      ],
      nextSteps: [
        "Identify the user who executed sudo",
        "Review the command executed with elevated privileges",
        "Confirm whether the action was administrative and expected",
        "Check authentication logs around the same time",
        "Review sudoers configuration if activity is unexpected"
      ]
    }
  }

  if (text.includes("successful login") || text.includes("authentication success")) {
    return {
      attackStage: "Access Validation",
      responseReason:
        "A successful login is normally low risk, but it provides useful context when correlated with failed logins or suspicious activity.",
      mitre: [
        "T1078 - Valid Accounts"
      ],
      nextSteps: [
        "Confirm the login source is expected",
        "Check whether the login occurred after failed attempts",
        "Review user activity after authentication"
      ]
    }
  }

  return {
    attackStage: "General Monitoring",
    responseReason:
      "The event does not match a high-confidence suspicious pattern, but it is retained for historical analysis and correlation.",
    mitre: [],
    nextSteps: [
      "Review the original event description",
      "Validate whether the activity is expected",
      "Keep the event available for future correlation"
    ]
  }
}

export default function LogHistoryPage() {
  const [alerts, setAlerts] = useState<XdrAlert[]>([])
  const [selectedAlert, setSelectedAlert] = useState<XdrAlert | null>(null)

  const [search, setSearch] = useState("")
  const [endpoint, setEndpoint] = useState("All")
  const [classification, setClassification] = useState("All")
  const [eventType, setEventType] = useState("All")
  const [currentPage, setCurrentPage] = useState(1)
  const [rowsPerPage, setRowsPerPage] = useState(10)

useEffect(() => {
  syncWazuhLogs().then(() => {
    getLogHistory().then(setAlerts)
  })
}, [])

  const endpoints = [...new Set(alerts.map(a => a.endpoint))]
  const classifications = [...new Set(alerts.map(a => a.classification))]
  const eventTypes = [...new Set(alerts.map(a => a.event_type))]

  const filteredAlerts = useMemo(() => {
    return alerts.filter(alert => {
      const text = `${alert.endpoint} ${alert.event_type} ${alert.description} ${alert.recommended_action}`.toLowerCase()

      return (
        text.includes(search.toLowerCase()) &&
        (endpoint === "All" || alert.endpoint === endpoint) &&
        (classification === "All" || alert.classification === classification) &&
        (eventType === "All" || alert.event_type === eventType)
      )
    })
  }, [alerts, search, endpoint, classification, eventType])

  const totalPages = Math.ceil(filteredAlerts.length / rowsPerPage)
  const paginatedAlerts = filteredAlerts.slice(
    (currentPage - 1) * rowsPerPage,
    currentPage * rowsPerPage
  )

  const selectedInfo = selectedAlert ? getInvestigationInfo(selectedAlert) : null

    useEffect(() => {
    setCurrentPage(1)
  }, [search, endpoint, classification, eventType])

  const exportCsv = () => {
  const headers = [
    "Timestamp",
    "Endpoint",
    "Event Type",
    "Severity",
    "Classification",
    "Threat Score",
    "Source IP",
    "Recommended Action",
    "Description"
  ]

  const rows = paginatedAlerts.map(alert => [
    alert.timestamp,
    alert.endpoint,
    alert.event_type,
    alert.severity,
    alert.classification,
    alert.threat_score,
    alert.source_ip,
    alert.recommended_action,
    `"${alert.description.replace(/"/g, '""')}"`
  ])

  const csv = [
    headers.join(","),
    ...rows.map(row => row.join(","))
  ].join("\n")

  const blob = new Blob([csv], {
    type: "text/csv;charset=utf-8;"
  })

  const url = URL.createObjectURL(blob)

  const link = document.createElement("a")
  link.href = url

  link.download = `xdr_logs_${new Date()
    .toISOString()
    .replace(/[:.]/g, "-")}.csv`

  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)

  URL.revokeObjectURL(url)
}

  return (
    <>
      <PageHeader
        title="Log History"
        subtitle="Complete database-backed Wazuh alert history transformed into AI-XDR security events."
      />

      <div className="filter-bar">
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search logs..."
        />

        <select value={endpoint} onChange={e => setEndpoint(e.target.value)}>
          <option value="All">All endpoints</option>
          {endpoints.map(item => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>

        <select value={classification} onChange={e => setClassification(e.target.value)}>
          <option value="All">All classifications</option>
          {classifications.map(item => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>

        <select value={eventType} onChange={e => setEventType(e.target.value)}>
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