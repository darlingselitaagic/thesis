import type { ReactNode } from "react"

type Props = {
  title: string
  value: string | number
  label: string
  icon: ReactNode
  danger?: boolean
}

export default function MetricCard({ title, value, label, icon, danger }: Props) {
  return (
    <div className={`metric-card ${danger ? "danger" : ""}`}>
      <div className="metric-icon">{icon}</div>
      <span>{title}</span>
      <strong>{value}</strong>
      <small>{label}</small>
    </div>
  )
}