import { NavLink } from "react-router-dom"
import { ShieldHalf, Activity } from "lucide-react"
import { navItems } from "../data/navigation"

interface SidebarProps {
  open: boolean
  onNavigate: () => void
}

export default function Sidebar({ open, onNavigate }: SidebarProps) {
  return (
    <aside className={`sidebar${open ? " open" : ""}`} aria-label="Primary">
      <div className="sidebar-brand">
        <div className="brand-mark" aria-hidden="true">
          <ShieldHalf size={22} strokeWidth={2.2} />
        </div>
        <div>
          <div className="brand-name">Sentinel SOC</div>
          <div className="brand-tag">Threat Intelligence</div>
        </div>
      </div>

      <div className="nav-group-label">Operations</div>
      <ul className="nav-list">
        {navItems.map((item) => {
          const Icon = item.icon
          return (
            <li key={item.path}>
              <NavLink
                to={item.path}
                end={item.path === "/"}
                onClick={onNavigate}
                className={({ isActive }) =>
                  `nav-item${isActive ? " active" : ""}`
                }
              >
                <Icon size={18} strokeWidth={2} />
                <span>{item.label}</span>
                {item.count !== undefined && (
                  <span className="nav-count">{item.count}</span>
                )}
              </NavLink>
            </li>
          )
        })}
      </ul>

      <div className="sidebar-footer">
        <div className="threat-level-card">
          <div className="tl-head">
            <Activity size={14} />
            <span>Global Threat Level</span>
          </div>
          <div className="threat-level-value">ELEVATED</div>
          <div className="tl-bar" aria-hidden="true">
            <span />
          </div>
        </div>
      </div>
    </aside>
  )
}
