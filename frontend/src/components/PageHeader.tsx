interface PageHeaderProps {
  title: string
  subtitle: string
  live?: boolean
}

export default function PageHeader({ title, subtitle, live }: PageHeaderProps) {
  return (
    <div className="page-title-row">
      <div>
        <h1 className="page-title">{title}</h1>
        <p className="page-subtitle">{subtitle}</p>
      </div>
      {live && (
        <span className="live-badge">
          <span className="pulse-dot" aria-hidden="true" />
          Live monitoring
        </span>
      )}
    </div>
  )
}
