import { useMemo, useState } from "react"
import type { InvestigationInfo, XdrAlert } from "../types"
import { getLogHistory, syncWazuhLogs } from "../services/api"


export const useLogHistory = () => {

const [alerts, setAlerts] = useState<XdrAlert[]>([])
  const [selectedAlert, setSelectedAlert] = useState<XdrAlert | null>(null)
  const [search, setSearch] = useState("")
  const [endpoint, setEndpoint] = useState("All")
  const [classification, setClassification] = useState("All")
  const [eventType, setEventType] = useState("All")
  const [currentPage, setCurrentPage] = useState(1)
  const [rowsPerPage, setRowsPerPage] = useState(10)

const setAlertsPage = () => {
    syncWazuhLogs().then(() => {
      getLogHistory().then(setAlerts)
    })
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

  if (text.includes("powershell") || text.includes("encodedcommand") || text.includes("base64")) {
  return {
    attackStage: "Execution",
    responseReason:
      "PowerShell executed a potentially suspicious command. Encoded PowerShell commands are frequently used by attackers to hide malicious activity and evade detection mechanisms.",

    mitre: [
      "T1059.001 - PowerShell"
    ],

    nextSteps: [
      "Review the executed PowerShell command",
      "Determine whether the command was encoded",
      "Inspect PowerShell Script Block logs",
      "Identify the parent process that launched PowerShell",
      "Validate whether the activity was authorized"
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

return { formatTimestamp, alerts, setAlerts, 
    setAlertsPage, endpoints, classifications, eventTypes, setSearch, 
    setEndpoint, setSelectedAlert, setClassification, setEventType,
    setCurrentPage, setRowsPerPage, search, totalPages, selectedInfo,
    rowsPerPage, exportCsv, filteredAlerts, currentPage, paginatedAlerts, endpoint, eventType, classification, selectedAlert }
}