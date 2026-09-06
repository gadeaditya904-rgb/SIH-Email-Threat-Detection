import { useState } from "react"
import { Outlet } from "react-router-dom"
import Sidebar from "./Sidebar"
import Topbar from "./Topbar"

export default function Layout() {
  const [menuOpen, setMenuOpen] = useState(false)

  return (
    <div className="app-shell">
      <Sidebar open={menuOpen} onNavigate={() => setMenuOpen(false)} />
      <div
        className={`sidebar-backdrop${menuOpen ? " show" : ""}`}
        onClick={() => setMenuOpen(false)}
        aria-hidden="true"
      />
      <div className="main-area">
        <Topbar onMenuClick={() => setMenuOpen(true)} />
        <main className="page-body">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
