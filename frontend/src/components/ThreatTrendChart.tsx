import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts"
import { trendData } from "../data/mockData"

export default function ThreatTrendChart() {
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <h3>Threat Detection Trend</h3>
          <span className="ch-sub">Detections over the last 7 days</span>
        </div>
      </div>

      <div className="chart-legend" style={{ marginBottom: 12 }}>
        <span className="legend-item">
          <span className="legend-swatch" style={{ background: "var(--critical)" }} />
          Total threats
        </span>
        <span className="legend-item">
          <span className="legend-swatch" style={{ background: "var(--high)" }} />
          Phishing
        </span>
        <span className="legend-item">
          <span className="legend-swatch" style={{ background: "var(--brand)" }} />
          Malware
        </span>
      </div>

      <div style={{ width: "100%", height: 260 }}>
        <ResponsiveContainer>
          <AreaChart data={trendData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id="gThreats" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--critical)" stopOpacity={0.35} />
                <stop offset="95%" stopColor="var(--critical)" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gPhishing" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--high)" stopOpacity={0.3} />
                <stop offset="95%" stopColor="var(--high)" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gMalware" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--brand)" stopOpacity={0.3} />
                <stop offset="95%" stopColor="var(--brand)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
            <XAxis
              dataKey="day"
              stroke="var(--text-muted)"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              stroke="var(--text-muted)"
              fontSize={12}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              contentStyle={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: 10,
                color: "var(--text-primary)",
                fontSize: 12,
              }}
              cursor={{ stroke: "var(--border)" }}
            />
            <Area
              type="monotone"
              dataKey="threats"
              stroke="var(--critical)"
              strokeWidth={2}
              fill="url(#gThreats)"
            />
            <Area
              type="monotone"
              dataKey="phishing"
              stroke="var(--high)"
              strokeWidth={2}
              fill="url(#gPhishing)"
            />
            <Area
              type="monotone"
              dataKey="malware"
              stroke="var(--brand)"
              strokeWidth={2}
              fill="url(#gMalware)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
