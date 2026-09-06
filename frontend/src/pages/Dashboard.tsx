import PageHeader from "../components/PageHeader"
import StatCard from "../components/StatCard"
import ThreatTrendChart from "../components/ThreatTrendChart"
import ThreatOverview from "../components/ThreatOverview"
import AlertsPanel from "../components/AlertsPanel"
import InvestigationsTable from "../components/InvestigationsTable"
import { stats } from "../data/mockData"

export default function Dashboard() {
  return (
    <>
      <PageHeader
        title="Security Operations Overview"
        subtitle="AI-powered email threat detection, geolocation and forensic intelligence"
        live
      />

      <div className="grid stat-grid">
        {stats.map((s) => (
          <StatCard
            key={s.key}
            statKey={s.key}
            label={s.label}
            value={s.value}
            delta={s.delta}
            trend={s.trend}
            tone={s.tone}
          />
        ))}
      </div>

      <div className="dash-columns">
        <ThreatTrendChart />
        <ThreatOverview />
      </div>

      <div className="dash-columns-b">
        <InvestigationsTable />
        <AlertsPanel />
      </div>
    </>
  )
}
