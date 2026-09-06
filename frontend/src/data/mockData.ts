export type Severity = "critical" | "high" | "medium" | "low"
export type CaseStatus = "open" | "investigating" | "resolved" | "quarantined"

export interface Investigation {
  caseId: string
  senderName: string
  senderEmail: string
  subject: string
  score: number
  severity: Severity
  status: CaseStatus
  date: string
}

export interface Alert {
  id: string
  severity: Severity
  title: string
  description: string
  time: string
}

export const stats = [
  {
    key: "analyzed",
    label: "Emails Analyzed",
    value: "48,392",
    delta: "+12.4%",
    trend: "up" as const,
    tone: "brand" as const,
  },
  {
    key: "threats",
    label: "Threats Detected",
    value: "1,284",
    delta: "+8.1%",
    trend: "up" as const,
    tone: "critical" as const,
  },
  {
    key: "highrisk",
    label: "High Risk Cases",
    value: "217",
    delta: "+3.6%",
    trend: "up" as const,
    tone: "high" as const,
  },
  {
    key: "active",
    label: "Active Investigations",
    value: "34",
    delta: "-2.2%",
    trend: "down" as const,
    tone: "medium" as const,
  },
]

export const threatOverview: { key: Severity; label: string; value: number; pct: number }[] = [
  { key: "critical", label: "Critical", value: 86, pct: 88 },
  { key: "high", label: "High", value: 131, pct: 64 },
  { key: "medium", label: "Medium", value: 342, pct: 42 },
  { key: "low", label: "Low", value: 725, pct: 22 },
]

export const investigations: Investigation[] = [
  {
    caseId: "CASE-9021",
    senderName: "Payroll Dept",
    senderEmail: "hr-payroll@acme-secure.co",
    subject: "URGENT: Verify your direct deposit details today",
    score: 96,
    severity: "critical",
    status: "investigating",
    date: "Mar 12, 09:41",
  },
  {
    caseId: "CASE-9018",
    senderName: "DocuSign",
    senderEmail: "no-reply@docusgn-alerts.net",
    subject: "You have a completed document waiting",
    score: 91,
    severity: "critical",
    status: "open",
    date: "Mar 12, 08:22",
  },
  {
    caseId: "CASE-9014",
    senderName: "IT Helpdesk",
    senderEmail: "support@it-helpdesk-portal.io",
    subject: "Password expires in 24 hours — reset now",
    score: 78,
    severity: "high",
    status: "quarantined",
    date: "Mar 11, 17:05",
  },
  {
    caseId: "CASE-9009",
    senderName: "Microsoft 365",
    senderEmail: "account@ms-security-team.com",
    subject: "Unusual sign-in activity detected",
    score: 72,
    severity: "high",
    status: "investigating",
    date: "Mar 11, 14:38",
  },
  {
    caseId: "CASE-9003",
    senderName: "Amazon Orders",
    senderEmail: "orders@amaz0n-delivery.shop",
    subject: "Your package could not be delivered",
    score: 54,
    severity: "medium",
    status: "open",
    date: "Mar 11, 11:12",
  },
  {
    caseId: "CASE-8997",
    senderName: "LinkedIn",
    senderEmail: "notifications@linkedin.com",
    subject: "You appeared in 9 searches this week",
    score: 21,
    severity: "low",
    status: "resolved",
    date: "Mar 10, 16:50",
  },
  {
    caseId: "CASE-8990",
    senderName: "Finance Team",
    senderEmail: "invoices@vendor-billing.biz",
    subject: "Outstanding invoice #INV-40921 attached",
    score: 83,
    severity: "high",
    status: "investigating",
    date: "Mar 10, 10:04",
  },
  {
    caseId: "CASE-8985",
    senderName: "Google Drive",
    senderEmail: "drive-share@g00gle-docs.app",
    subject: "A file has been shared with you",
    score: 89,
    severity: "critical",
    status: "quarantined",
    date: "Mar 09, 15:27",
  },
]

export const alerts: Alert[] = [
  {
    id: "a1",
    severity: "critical",
    title: "Credential harvesting kit detected",
    description: "Cloned Microsoft login page hosted on ms-security-team.com",
    time: "2 min ago",
  },
  {
    id: "a2",
    severity: "high",
    title: "SPF / DKIM authentication failed",
    description: "Spoofed sender for domain acme-secure.co",
    time: "14 min ago",
  },
  {
    id: "a3",
    severity: "high",
    title: "Malicious attachment quarantined",
    description: "invoice_INV-40921.html flagged as HTML smuggling",
    time: "38 min ago",
  },
  {
    id: "a4",
    severity: "medium",
    title: "Suspicious geolocation origin",
    description: "Email relay traced to unusual ASN in Eastern Europe",
    time: "1 hr ago",
  },
  {
    id: "a5",
    severity: "low",
    title: "Bulk sender rate spike",
    description: "Newsletter domain exceeded normal volume threshold",
    time: "2 hr ago",
  },
]

export const trendData = [
  { day: "Mon", threats: 132, phishing: 78, malware: 34 },
  { day: "Tue", threats: 168, phishing: 96, malware: 41 },
  { day: "Wed", threats: 149, phishing: 88, malware: 29 },
  { day: "Thu", threats: 204, phishing: 121, malware: 52 },
  { day: "Fri", threats: 241, phishing: 148, malware: 61 },
  { day: "Sat", threats: 118, phishing: 62, malware: 24 },
  { day: "Sun", threats: 96, phishing: 51, malware: 19 },
]

export const severityColor: Record<Severity, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
}
