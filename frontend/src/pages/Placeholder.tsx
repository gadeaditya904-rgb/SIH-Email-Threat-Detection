import type { LucideIcon } from "lucide-react"
import PageHeader from "../components/PageHeader"

interface PlaceholderProps {
  title: string
  subtitle: string
  icon: LucideIcon
  description: string
}

export default function Placeholder({
  title,
  subtitle,
  icon: Icon,
  description,
}: PlaceholderProps) {
  return (
    <>
      <PageHeader title={title} subtitle={subtitle} />
      <div className="placeholder-page">
        <div className="ph-icon" aria-hidden="true">
          <Icon size={30} />
        </div>
        <h2>{title}</h2>
        <p>{description}</p>
      </div>
    </>
  )
}
