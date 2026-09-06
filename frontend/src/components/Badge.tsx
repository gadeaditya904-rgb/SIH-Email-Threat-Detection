import type { Severity, CaseStatus } from "../data/mockData"

export function SeverityBadge({ severity }: { severity: Severity }) {
  const label = severity.charAt(0).toUpperCase() + severity.slice(1)
  return (
    <span className={`badge badge-${severity}`}>
      <span className="b-dot" style={{ background: "currentColor" }} />
      {label}
    </span>
  )
}

export function StatusBadge({ status }: { status: CaseStatus }) {
  const label = status.charAt(0).toUpperCase() + status.slice(1)
  return <span className={`badge badge-${status}`}>{label}</span>
}
