import { Search } from "lucide-react"

export default function TopBar() {
  return (
    <header className="top-bar">
      <h2>Security Operations</h2>

      <div className="search-box">
        <Search size={18} />
        <input placeholder="Search incidents, endpoints or logs..." />
      </div>

      <div className="online-pill">
        <span />
        SYSTEM ONLINE
      </div>
    </header>
  )
}