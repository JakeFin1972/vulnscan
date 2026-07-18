import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Bug,
  ScanSearch,
  Code2,
  Settings,
  ShieldAlert,
  Radar,
  Target,
} from 'lucide-react'
import { cn } from '@/lib/utils'

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/findings', label: 'Findings', icon: Bug },
  { to: '/scans', label: 'Scans', icon: ScanSearch },
  { to: '/dynamic', label: 'Dynamic Scan', icon: Radar },
  { to: '/easm', label: 'EASM', icon: Target },
  { to: '/languages', label: 'Languages', icon: Code2 },
  { to: '/settings', label: 'Settings', icon: Settings },
]

interface Props {
  children: ReactNode
}

export default function Layout({ children }: Props) {
  return (
    <div className="flex h-screen overflow-hidden bg-slate-950">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 flex flex-col border-r border-slate-800 bg-slate-900">
        {/* Logo */}
        <div className="flex items-center gap-2.5 px-4 py-4 border-b border-slate-800">
          <ShieldAlert className="h-5 w-5 text-teal-500 flex-shrink-0" />
          <span className="font-semibold text-slate-100 tracking-tight">
            vulnscan
          </span>
          <span className="ml-auto text-xs text-slate-500 font-mono">v0.1</span>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto">
          {NAV.map(({ to, label, icon: Icon, exact }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-3 py-2 rounded text-sm transition-colors',
                  isActive
                    ? 'bg-slate-800 text-teal-400 border-l-2 border-teal-500 pl-2.5'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50',
                )
              }
            >
              <Icon className="h-4 w-4 flex-shrink-0" />
              {label}
            </NavLink>
          ))}
        </nav>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-slate-800 text-xs text-slate-600">
          Authorized use only
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto">
        {children}
      </main>
    </div>
  )
}
