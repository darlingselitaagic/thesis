import { Activity, History, LayoutDashboard, Server, Shield } from "lucide-react"
import type { PageName } from "../App"

type Props = {
  activePage: PageName
  onNavigate: (page: PageName) => void
}

export default function SideNav({ activePage, onNavigate }: Props) {
  return (
    <aside className="side-nav">
      <div className="brand">
        <h1>Vigilant AI-XDR</h1>
        <span>Command Center</span>
      </div>

      <nav className="nav-links">
        <button className={activePage === "overview" ? "active" : ""} onClick={() => onNavigate("overview")}>
          <LayoutDashboard size={20} /> Overview
        </button>

        <button className={activePage === "threats" ? "active" : ""} onClick={() => onNavigate("threats")}>
          <Shield size={20} /> Threat Analysis
        </button>

        <button className={activePage === "logs" ? "active" : ""} onClick={() => onNavigate("logs")}>
          <History size={20} /> Log History
        </button>

        <button className={activePage === "status" ? "active" : ""} onClick={() => onNavigate("status")}>
          <Server size={20} /> System Status
        </button>
      </nav>

      <div className="nav-footer">
        <Activity size={16} />
        <span>System Online</span>
      </div>
    </aside>
  )
}