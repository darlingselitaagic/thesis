import {History, LayoutDashboard, Server, Shield } from "lucide-react"
import type { SideNavProps } from "../types"


export default function SideNav({ activePage, onNavigate }: SideNavProps) {
  return (
    <aside className="side-nav">
      <div className="brand">
        <h1> AI-driven XDR System</h1>
        <span>Analyst Dashboard</span>
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
    </aside>
  )
}