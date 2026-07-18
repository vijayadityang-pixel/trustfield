import { Routes, Route, NavLink, useNavigate } from 'react-router-dom'
import { LayoutDashboard, ShieldAlert, Settings as SettingsIcon, LogOut } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import Settings from './pages/Settings'
import Login from './pages/Login'
import ProtectedRoute from './components/ProtectedRoute'
import { logout } from './services/api'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/alerts', label: 'Alerts', icon: ShieldAlert },
  { to: '/settings', label: 'Settings', icon: SettingsIcon },
]

function AppShell() {
  const navigate = useNavigate()

  function handleLogout() {
    logout()
    navigate('/login')
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <svg className="sidebar-brand-mark" viewBox="0 0 32 32">
            <circle cx="16" cy="16" r="15" fill="#0a0d12" stroke="#4fd1c5" strokeWidth="1.5" />
            <circle cx="16" cy="9" r="2.6" fill="#4fd1c5" />
            <circle cx="9" cy="21" r="2.6" fill="#f5a623" />
            <circle cx="23" cy="21" r="2.6" fill="#f2495c" />
            <path d="M16 9 L9 21 M16 9 L23 21 M9 21 L23 21" stroke="#2a3340" strokeWidth="1.4" fill="none" />
          </svg>
          <span className="sidebar-brand-text">TrustField</span>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => `sidebar-link${isActive ? ' active' : ''}`}
            >
              <item.icon size={16} />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <button className="sidebar-link sidebar-logout" onClick={handleLogout}>
          <LogOut size={16} />
          Log out
        </button>

        <div className="sidebar-footer">
          IAM trust graph &amp; risk platform
          <br />
          v0.1.0 · capstone build
        </div>
      </aside>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  )
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/*"
        element={
          <ProtectedRoute>
            <AppShell />
          </ProtectedRoute>
        }
      />
    </Routes>
  )
}