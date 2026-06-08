import { useEffect, useState } from "react"
import PageHeader from "../components/PageHeader"
import StatusCard from "../components/StatusCard"
import { getWazuhAgents, type WazuhAgent } from "../services/api"

export default function SystemStatusPage() {
  const [agents, setAgents] = useState<WazuhAgent[]>([])

  useEffect(() => {
    getWazuhAgents().then(setAgents)
  }, [])

  return (
    <>
      <PageHeader
        title="System Status Monitoring"
        subtitle="Health status of Wazuh integrations, endpoint agents and internal XDR engines."
      />

      <section className="status-grid">
        <StatusCard title="AI Detection Engine" status="Running" description="Isolation Forest model loaded" />
        <StatusCard title="Correlation Engine" status="Running" description="Correlation rules active" />
        <StatusCard title="Response Engine" status="Running" description="Response simulation enabled" />

        {agents.map(agent => (
          <StatusCard
            key={agent.id}
            title={agent.name}
            status={agent.status === "active" ? "Connected" : "Disconnected"}
            description={`${agent.os?.name ?? "Unknown OS"} — ${agent.ip}`}
          />
        ))}
      </section>
    </>
  )
}