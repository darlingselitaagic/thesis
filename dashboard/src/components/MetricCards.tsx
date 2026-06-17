import type { MetricCardsProps } from "../types"


export default function MetricCard({ title, value, label, icon, danger }: MetricCardsProps) {
  return (
    <div className={`metric-card ${danger ? "danger" : ""}`}>
      <div className="metric-icon">{icon}</div>
      <span>{title}</span>
      <strong>{value}</strong>
      <small>{label}</small>
    </div>
  )
}