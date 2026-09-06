import { threatOverview, severityColor } from "../data/mockData"

export default function ThreatOverview() {
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <h3>Threat Distribution</h3>
          <span className="ch-sub">Active cases by severity</span>
        </div>
      </div>

      <div className="threat-overview-grid">
        {threatOverview.map((t) => {
          const color = severityColor[t.key]
          return (
            <div className="threat-pill" key={t.key}>
              <div className="tp-top">
                <span className="tp-label">
                  <span className="tp-dot" style={{ background: color }} />
                  {t.label}
                </span>
              </div>
              <div className="tp-value" style={{ color }}>
                {t.value}
              </div>
              <div className="tp-bar" aria-hidden="true">
                <span style={{ width: `${t.pct}%`, background: color }} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
