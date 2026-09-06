import { Routes, Route } from "react-router-dom"
import {
  Mail,
  FileSearch,
  Link2,
  Globe2,
  Share2,
  FolderKanban,
  FileText,
} from "lucide-react"
import Layout from "./components/Layout"
import Dashboard from "./pages/Dashboard"
import Placeholder from "./pages/Placeholder"

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route
          path="/email-analysis"
          element={
            <Placeholder
              title="Email Analysis"
              subtitle="Deep inspection of message content and intent"
              icon={Mail}
              description="Analyze email bodies, sender reputation, and AI-classified intent. Detailed content scoring and attachment sandboxing will surface here."
            />
          }
        />
        <Route
          path="/header-forensics"
          element={
            <Placeholder
              title="Header Forensics"
              subtitle="Trace routing paths and authentication results"
              icon={FileSearch}
              description="Inspect raw email headers, SPF/DKIM/DMARC results, and hop-by-hop relay analysis to expose spoofing and forged origins."
            />
          }
        />
        <Route
          path="/url-intelligence"
          element={
            <Placeholder
              title="URL Intelligence"
              subtitle="Expand, detonate and score embedded links"
              icon={Link2}
              description="Unfurl shortened URLs, detonate destinations in a sandbox, and cross-reference domains against threat feeds and phishing databases."
            />
          }
        />
        <Route
          path="/ip-geolocation"
          element={
            <Placeholder
              title="IP & Geolocation"
              subtitle="Map the physical origin of threats"
              icon={Globe2}
              description="Resolve sender IPs to geographic locations, ASNs, and hosting providers to build a geospatial picture of your threat landscape."
            />
          }
        />
        <Route
          path="/investigation-graph"
          element={
            <Placeholder
              title="Investigation Graph"
              subtitle="Visualize relationships between entities"
              icon={Share2}
              description="Link senders, domains, IPs, and campaigns into an interactive graph to reveal coordinated attack infrastructure."
            />
          }
        />
        <Route
          path="/case-management"
          element={
            <Placeholder
              title="Case Management"
              subtitle="Track investigations from triage to closure"
              icon={FolderKanban}
              description="Assign cases, collaborate with your team, and manage the full lifecycle of each investigation with audit trails and SLAs."
            />
          }
        />
        <Route
          path="/forensic-reports"
          element={
            <Placeholder
              title="Forensic Reports"
              subtitle="Generate court-ready evidence packages"
              icon={FileText}
              description="Compile findings, timelines, and indicators of compromise into exportable forensic reports for stakeholders and legal teams."
            />
          }
        />
      </Route>
    </Routes>
  )
}
