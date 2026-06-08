import type { ReactNode } from "react"

type StatsCardProps = {
  title: string
  value: number | string
  icon?: ReactNode
}

export default function StatsCard({ title, value, icon }: StatsCardProps) {
  return (
    <div className="stats-card">
      <div className="stats-icon">{icon}</div>
      <span>{title}</span>
      <strong>{value}</strong>
    </div>
  )
}