import { AlertTriangle, ShieldAlert, Paperclip, MapPin, TrendingUp } from "lucide-react"
import { alerts, severityColor, type Severity } from "../data/mockData"

const alertIcon = [ShieldAlert, AlertTriangle, Paperclip, MapPin, TrendingUp]

export default function AlertsPanel() {
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <h3>Live Alert Feed</h3>
          <span className="ch-sub">Automated detections</span>
        </div>
        <span className="live-badge">
          <span className="pulse-dot" aria-hidden="true" />
          Live
        </span>
      </div>

      <div className="alert-list">
        {alerts.map((a, i) => {
          const Icon = alertIcon[i % alertIcon.length]
          const color = severityColor[a.severity as Severity]
          return (
            <div className="alert-item" key={a.id}>
              <div
                className="alert-icon"
                style={{
                  background: `color-mix(in srgb, ${color} 14%, transparent)`,
                  color,
                }}
              >
                <Icon size={17} />
              </div>
              <div className="alert-body">
                <div className="alert-title">{a.title}</div>
                <div className="alert-desc">{a.description}</div>
                <div className="alert-time">{a.time}</div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
