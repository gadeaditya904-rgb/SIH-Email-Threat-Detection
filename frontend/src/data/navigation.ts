import {
  LayoutDashboard,
  Mail,
  FileSearch,
  Link2,
  Globe2,
  Share2,
  FolderKanban,
  FileText,
  type LucideIcon,
} from "lucide-react"

export interface NavItem {
  label: string
  path: string
  icon: LucideIcon
  count?: number
}

export const navItems: NavItem[] = [
  { label: "Dashboard", path: "/", icon: LayoutDashboard },
  { label: "Email Analysis", path: "/email-analysis", icon: Mail, count: 12 },
  { label: "Header Forensics", path: "/header-forensics", icon: FileSearch },
  { label: "URL Intelligence", path: "/url-intelligence", icon: Link2 },
  { label: "IP & Geolocation", path: "/ip-geolocation", icon: Globe2 },
  { label: "Investigation Graph", path: "/investigation-graph", icon: Share2 },
  { label: "Case Management", path: "/case-management", icon: FolderKanban, count: 34 },
  { label: "Forensic Reports", path: "/forensic-reports", icon: FileText },
]
