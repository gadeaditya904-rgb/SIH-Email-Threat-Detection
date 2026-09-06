import { Search, Bell, Settings, Menu } from "lucide-react"

interface TopbarProps {
  onMenuClick: () => void
}

export default function Topbar({ onMenuClick }: TopbarProps) {
  return (
    <header className="topbar">
      <button
        className="icon-btn menu-toggle"
        onClick={onMenuClick}
        aria-label="Open navigation menu"
      >
        <Menu size={20} />
      </button>

      <div className="search-box">
        <Search size={16} />
        <input
          type="search"
          placeholder="Search cases, senders, IPs, domains…"
          aria-label="Search"
        />
        <span className="search-kbd">⌘K</span>
      </div>

      <div className="topbar-actions">
        <button className="icon-btn" aria-label="Notifications">
          <Bell size={19} />
          <span className="notif-dot" aria-hidden="true" />
        </button>
        <button className="icon-btn" aria-label="Settings">
          <Settings size={19} />
        </button>
        <button className="profile-chip" aria-label="User profile">
          <span className="avatar" aria-hidden="true">
            AC
          </span>
          <span className="profile-meta">
            <span className="pm-name">A. Chen</span>
            <span className="pm-role">Tier 2 Analyst</span>
          </span>
        </button>
      </div>
    </header>
  )
}
