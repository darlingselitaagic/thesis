import type { StatusProps } from "../types"


export default function StatusCard({ title, status, description }: StatusProps) {
  const good = status === "Running" || status === "Connected"

  return (
    <div className="status-card">
      <div>
        <h3>{title}</h3>
        <p>{description}</p>
      </div>

      <span className={good ? "status-good" : "status-bad"}>
        {status}
      </span>
    </div>
  )
}