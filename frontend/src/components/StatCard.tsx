import { Mail, ShieldAlert, Flame, Search, ArrowUpRight, ArrowDownRight } from "lucide-react"

const iconMap: Record<string, typeof Mail> = {
  analyzed: Mail,
  threats: ShieldAlert,
  highrisk: Flame,
  active: Search,
}

const toneColor: Record<string, string> = {
  brand: "var(--brand)",
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
}

interface StatCardProps {
  statKey: string
  label: string
  value: string
  delta: string
  trend: "up" | "down"
  tone: string
}

export default function StatCard({
  statKey,
  label,
  value,
  delta,
  trend,
  tone,
}: StatCardProps) {
  const Icon = iconMap[statKey] ?? Mail
  const color = toneColor[tone] ?? "var(--brand)"

  return (
    <div className="card stat-card">
      <div className="sc-top">
        <div
          className="stat-icon"
          style={{ background: `color-mix(in srgb, ${color} 14%, transparent)`, color }}
        >
          <Icon size={20} />
        </div>
      </div>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      <div className={`stat-delta ${trend === "up" ? "delta-up" : "delta-down"}`}>
        {trend === "up" ? <ArrowUpRight size={14} /> : <ArrowDownRight size={14} />}
        {delta}
        <span style={{ color: "var(--text-muted)", fontWeight: 500 }}>vs last week</span>
      </div>
    </div>
  )
}
