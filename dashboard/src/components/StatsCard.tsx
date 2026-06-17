import type { StatsCardProps } from "../types";

export default function StatsCard({ title, value, icon }: StatsCardProps) {
  return (
    <div className="stats-card">
      <div className="stats-icon">{icon}</div>
      <span>{title}</span>
      <strong>{value}</strong>
    </div>
  )
}