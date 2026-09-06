import { investigations, severityColor } from "../data/mockData"
import { SeverityBadge, StatusBadge } from "./Badge"

export default function InvestigationsTable() {
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <h3>Recent Investigations</h3>
          <span className="ch-sub">Flagged emails requiring analyst review</span>
        </div>
      </div>

      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Case ID</th>
              <th>Sender</th>
              <th>Subject</th>
              <th>Threat Score</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Detected</th>
            </tr>
          </thead>
          <tbody>
            {investigations.map((row) => {
              const color = severityColor[row.severity]
              return (
                <tr key={row.caseId}>
                  <td>
                    <span className="case-id">{row.caseId}</span>
                  </td>
                  <td>
                    <div className="sender-cell">
                      <span className="s-name">{row.senderName}</span>
                      <span className="s-mail">{row.senderEmail}</span>
                    </div>
                  </td>
                  <td>
                    <div className="subject-cell" title={row.subject}>
                      {row.subject}
                    </div>
                  </td>
                  <td>
                    <div className="score-meter">
                      <div className="score-track">
                        <span style={{ width: `${row.score}%`, background: color }} />
                      </div>
                      <span className="score-num" style={{ color }}>
                        {row.score}
                      </span>
                    </div>
                  </td>
                  <td>
                    <SeverityBadge severity={row.severity} />
                  </td>
                  <td>
                    <StatusBadge status={row.status} />
                  </td>
                  <td style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 12 }}>
                    {row.date}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
