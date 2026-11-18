import { NavLink, Outlet } from 'react-router-dom'
import {
  ShieldCheck,
  LayoutDashboard,
  Crosshair,
  Users,
  Route,
  ScanSearch,
  Bug,
  Grid3X3,
  History,
  FileText,
  Settings,
} from 'lucide-react'

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/targets', label: 'Targets', icon: Crosshair },
  { to: '/accounts', label: 'Test Accounts', icon: Users },
  { to: '/endpoints', label: 'Endpoints', icon: Route },
  { to: '/scan', label: 'New Scan', icon: ScanSearch },
  { to: '/findings', label: 'Findings', icon: Bug },
  { to: '/matrix', label: 'Access Control Matrix', icon: Grid3X3 },
  { to: '/history', label: 'Scan History', icon: History },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export default function Layout() {
  return (
    <div className="flex min-h-screen">
      <aside className="w-64 shrink-0 border-r border-navy-600/40 bg-navy-900/70 flex flex-col">
        <div className="flex items-center gap-3 px-5 py-5 border-b border-navy-600/40">
          <div className="p-2 rounded-lg bg-indigo-500/15 border border-indigo-500/30">
            <ShieldCheck size={22} className="text-indigo-400" />
          </div>
          <div>
            <div className="font-bold text-white leading-tight">API PrivacyGuard</div>
            <div className="text-[11px] text-slate-400">BOLA / IDOR Assessment</div>
          </div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive
                    ? 'bg-indigo-500/10 text-indigo-300 border border-indigo-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-navy-700/50 border border-transparent'
                }`
              }
            >
              <Icon size={17} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="px-5 py-4 border-t border-navy-600/40 text-[11px] text-slate-500">
          Authorised testing only.
          <br />
          Scope is limited to approved targets.
        </div>
      </aside>
      <main className="flex-1 min-w-0 p-6 lg:p-8 overflow-x-hidden">
        <Outlet />
      </main>
    </div>
  )
}
