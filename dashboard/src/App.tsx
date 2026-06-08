import { useState } from "react"
import SideNav from "./components/SideNav"
import TopBar from "./components/TopBar"
import OverviewPage from "./pages/OverviewPage"
import ThreatAnalysisPage from "./pages/ThreatAnalysisPage"
import LogHistoryPage from "./pages/LogHistoryPage"
import SystemStatusPage from "./pages/StatusPage"
import "./App.css"

export type PageName = "overview" | "threats" | "logs" | "status"

export default function App() {
  const [activePage, setActivePage] = useState<PageName>("overview")

  return (
    <div className="app-shell">
      <SideNav activePage={activePage} onNavigate={setActivePage} />

      <div className="main-shell">
        <TopBar />

        <main className="main-content">
          {activePage === "overview" && <OverviewPage />}
          {activePage === "threats" && <ThreatAnalysisPage />}
          {activePage === "logs" && <LogHistoryPage />}
          {activePage === "status" && <SystemStatusPage />}
        </main>
      </div>
    </div>
  )
}