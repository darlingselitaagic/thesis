import { useEffect, useState } from "react"
import PageHeader from "../components/PageHeader"
import { getXdrCorrelations, type XdrCorrelation } from "../services/api"

function getRiskLabel(score: number) {
  if (score >= 85) return "Critical"
  if (score >= 60) return "High"
  if (score >= 30) return "Medium"
  return "Low"
}

export default function ThreatAnalysisPage() {
  const [correlations, setCorrelations] = useState<XdrCorrelation[]>([])

  useEffect(() => {
    getXdrCorrelations().then(setCorrelations)
  }, [])

  return (
    <>
      <PageHeader
        title="Threat Analysis & Incidents"
        subtitle="Correlated attack chains, MITRE mapping, risk scoring and response recommendations."
      />

      <section className="threat-grid">
        {correlations.map(item => {
          const risk = getRiskLabel(item.correlation_score)

          return (
            <article className="threat-card" key={item.endpoint}>
              <div className="threat-card-header">
                <div>
                  <h3>{item.endpoint}</h3>
                  <p>{item.possible_attack_stage}</p>
                </div>

                <span className={`risk-pill ${risk.toLowerCase()}`}>
                  {risk}
                </span>
              </div>

              <div className="threat-meta">
                <span>Action: {item.recommended_action}</span>
                <span>Score: {item.correlation_score}/100</span>
                <span>Related Events: {item.related_event_count}</span>
              </div>

              <h4>Detected Patterns</h4>
              <ul>
                {item.detected_patterns.map(pattern => (
                  <li key={pattern}>{pattern}</li>
                ))}
              </ul>

              <h4>Attack Chain</h4>
              <div className="mitre-list">
                {item.attack_chain.length ? (
                  item.attack_chain.map(stage => (
                    <span key={stage}>{stage}</span>
                  ))
                ) : (
                  <span>No attack chain detected</span>
                )}
              </div>

              <h4>MITRE ATT&CK</h4>
              <div className="mitre-list">
                {item.mitre_mapping.length ? (
                  item.mitre_mapping.map(mitre => (
                    <span key={mitre.technique_id}>
                      {mitre.technique_id} — {mitre.technique}
                    </span>
                  ))
                ) : (
                  <span>No mapping available</span>
                )}
              </div>

              <details>
                <summary>Investigation Details</summary>

                <p>
                  This incident contains <b>{item.related_event_count}</b> related
                  events from endpoint <b>{item.endpoint}</b>. The correlation engine
                  assigned a score of <b>{item.correlation_score}/100</b> and recommended:
                  <b> {item.recommended_action}</b>.
                </p>

                <h4>Recommended Next Steps</h4>
                <ul>
                  <li>Review related event IDs: {item.related_events.join(", ")}</li>
                  <li>Validate whether the detected sequence is expected or suspicious</li>
                  <li>Check process activity and user activity around the same time</li>
                  <li>Escalate if the attack chain is confirmed malicious</li>
                </ul>
              </details>
            </article>
          )
        })}
      </section>
    </>
  )
}