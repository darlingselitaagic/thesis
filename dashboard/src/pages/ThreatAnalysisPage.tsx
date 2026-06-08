import { useEffect, useState } from "react"
import PageHeader from "../components/PageHeader"
import { getXdrResponses, type XdrResponse } from "../services/api"

export default function ThreatAnalysisPage() {
  const [responses, setResponses] = useState<XdrResponse[]>([])

  useEffect(() => {
    getXdrResponses().then(setResponses)
  }, [])

  return (
    <>
      <PageHeader
        title="Threat Analysis & Incidents"
        subtitle="Correlated threats, response decisions, MITRE mapping and analyst next steps."
      />

      <section className="threat-grid">
        {responses.map((item, index) => (
          <article className="threat-card" key={index}>
            <div className="threat-card-header">
              <div>
                <h3>{item.endpoint}</h3>
                <p>{item.explanation?.possible_attack_stage ?? "General Monitoring"}</p>
              </div>

              <span className={`risk-pill ${(item.explanation?.risk_level ?? item.risk_level).toLowerCase()}`}>
                {item.explanation?.risk_level ?? item.risk_level}
              </span>
            </div>

            <div className="threat-meta">
              <span>Action: {item.action}</span>
              <span>Score: {item.correlation_score}</span>
              <span>Confidence: {item.explanation?.confidence ?? item.confidence}</span>
            </div>

            <h4>Detected Patterns</h4>
            <ul>
              {item.detected_patterns.map((pattern, i) => (
                <li key={i}>{pattern}</li>
              ))}
            </ul>

            <h4>MITRE ATT&CK</h4>
            <div className="mitre-list">
              {item.explanation?.mitre_mapping?.length ? (
                item.explanation.mitre_mapping.map((m, i) => (
                  <span key={i}>{m.technique_id} — {m.technique}</span>
                ))
              ) : (
                <span>No mapping available</span>
              )}
            </div>

            <details>
              <summary>Investigation Details</summary>
              <p>{item.explanation?.why_this_action}</p>

              <h4>Recommended Next Steps</h4>
              <ul>
                {item.explanation?.recommended_next_steps.map((step, i) => (
                  <li key={i}>{step}</li>
                ))}
              </ul>
            </details>
          </article>
        ))}
      </section>
    </>
  )
}