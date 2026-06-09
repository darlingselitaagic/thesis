import { useEffect, useMemo, useState } from "react"
import PageHeader from "../components/PageHeader"
import { getLogHistory, type XdrAlert } from "../services/api"

type IncidentGroup = {
  endpoint: string
  events: XdrAlert[]
  highestScore: number
  highestClassification: string
  action: string
  patterns: string[]
  mitre: string[]
  attackStage: string
}

function getRiskRank(classification: string) {
  const ranks: Record<string, number> = {
    Low: 1,
    Medium: 2,
    High: 3,
    Critical: 4
  }

  return ranks[classification] ?? 0
}

function getMitreMapping(eventType: string) {
  if (eventType === "Suspicious File Drop") {
    return ["T1105 — Ingress Tool Transfer", "T1204 — User Execution"]
  }

  if (eventType === "Failed Login Attempts") {
    return ["T1110 — Brute Force", "T1078 — Valid Accounts"]
  }

  if (eventType === "Account Discovery") {
    return ["T1087 — Account Discovery", "T1059 — Command and Scripting Interpreter"]
  }

  if (eventType === "Privilege Escalation") {
    return ["T1548 — Abuse Elevation Control Mechanism"]
  }

  if (eventType === "Successful Login") {
    return ["T1078 — Valid Accounts"]
  }

  return []
}

function getAttackStage(patterns: string[]) {
  if (patterns.includes("Suspicious File Drop")) return "Malware Staging"
  if (patterns.includes("Failed Login Attempts")) return "Credential Access"
  if (patterns.includes("Account Discovery")) return "Discovery"
  if (patterns.includes("Privilege Escalation")) return "Privilege Escalation"
  return "General Monitoring"
}

export default function ThreatAnalysisPage() {
  const [alerts, setAlerts] = useState<XdrAlert[]>([])

  useEffect(() => {
    getLogHistory().then(setAlerts)
  }, [])

  const incidents = useMemo<IncidentGroup[]>(() => {
    const grouped: Record<string, XdrAlert[]> = {}

    alerts.forEach(alert => {
      grouped[alert.endpoint] ??= []
      grouped[alert.endpoint].push(alert)
    })

    return Object.entries(grouped)
      .map(([endpoint, events]) => {
        const highest = [...events].sort(
          (a, b) => b.threat_score - a.threat_score
        )[0]

        const highestClassification = [...events].sort(
          (a, b) => getRiskRank(b.classification) - getRiskRank(a.classification)
        )[0]?.classification ?? "Low"

        const patterns = [...new Set(events.map(e => e.event_type))]

        const mitre = [
          ...new Set(patterns.flatMap(pattern => getMitreMapping(pattern)))
        ]

        const action =
          highest.threat_score >= 85
            ? "Simulate Endpoint Isolation"
            : highest.threat_score >= 60
              ? "Escalate Incident"
              : highest.threat_score >= 30
                ? "Monitor Closely"
                : "Continue Monitoring"

        return {
          endpoint,
          events,
          highestScore: highest.threat_score,
          highestClassification,
          action,
          patterns,
          mitre,
          attackStage: getAttackStage(patterns)
        }
      })
      .sort((a, b) => b.highestScore - a.highestScore)
  }, [alerts])

  return (
    <>
      <PageHeader
        title="Threat Analysis & Incidents"
        subtitle="Database-backed correlated incidents grouped by endpoint, risk, MITRE mapping and analyst next steps."
      />

      <section className="threat-grid">
        {incidents.map(incident => (
          <article className="threat-card" key={incident.endpoint}>
            <div className="threat-card-header">
              <div>
                <h3>{incident.endpoint}</h3>
                <p>{incident.attackStage}</p>
              </div>

              <span className={`risk-pill ${incident.highestClassification.toLowerCase()}`}>
                {incident.highestClassification}
              </span>
            </div>

            <div className="threat-meta">
              <span>Action: {incident.action}</span>
              <span>Score: {incident.highestScore}</span>
              <span>Related Events: {incident.events.length}</span>
            </div>

            <h4>Detected Patterns</h4>
            <ul>
              {incident.patterns.map(pattern => (
                <li key={pattern}>{pattern}</li>
              ))}
            </ul>

            <h4>MITRE ATT&CK</h4>
            <div className="mitre-list">
              {incident.mitre.length ? (
                incident.mitre.map(item => (
                  <span key={item}>{item}</span>
                ))
              ) : (
                <span>No mapping available</span>
              )}
            </div>

            <details>
              <summary>Investigation Details</summary>

              <p>
                This incident group contains {incident.events.length} stored
                security events from endpoint <b>{incident.endpoint}</b>. The
                highest observed threat score is <b>{incident.highestScore}/100</b>,
                producing a <b>{incident.highestClassification}</b> classification.
              </p>

              <h4>Recommended Next Steps</h4>
              <ul>
                <li>Review the highest-scoring events first</li>
                <li>Validate whether the activity is expected or malicious</li>
                <li>Check related events from the same endpoint</li>
                <li>Escalate if activity is confirmed suspicious</li>
              </ul>
            </details>
          </article>
        ))}
      </section>
    </>
  )
}