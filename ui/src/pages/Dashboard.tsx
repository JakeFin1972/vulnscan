import { useQuery } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { AlertTriangle, CheckCircle, Shield, Activity, Plus, Loader2 } from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import { listScans, listFindings, listLanguages, startScan } from '@/api'
import type { Severity } from '@/types'
import StatusBadge from '@/components/StatusBadge'
import { useState } from 'react'

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLOR: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#60a5fa',
  info: '#64748b',
}

function relative(iso: string) {
  const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'))
  const diff = Date.now() - d.getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export default function Dashboard() {
  const navigate = useNavigate()
  const [path, setPath] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [scanError, setScanError] = useState<string | null>(null)

  const scansQ = useQuery({ queryKey: ['scans'], queryFn: listScans, refetchInterval: 3000 })
  const findingsQ = useQuery({ queryKey: ['findings'], queryFn: () => listFindings({}) })
  const langsQ = useQuery({ queryKey: ['languages'], queryFn: listLanguages })

  const scans = scansQ.data ?? []
  const findings = findingsQ.data ?? []
  const languages = langsQ.data ?? []

  const doneScans = scans.filter(s => s.status === 'done')
  const totalSources = doneScans.reduce((a, s) => a + s.source_count, 0)

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1

  const chartData = SEV_ORDER.filter(s => bySeverity[s] > 0).map(s => ({
    name: s, count: bySeverity[s], color: SEV_COLOR[s],
  }))

  const availableLangs = languages.filter(l => l.available)

  async function handleScan(e: React.FormEvent) {
    e.preventDefault()
    if (!path.trim() || !authorized) return
    setScanError(null)
    setScanning(true)
    try {
      const { id } = await startScan(path.trim())
      navigate(`/scans?highlight=${id}`)
    } catch (e: unknown) {
      setScanError(e instanceof Error ? e.message : String(e))
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold text-slate-100">Dashboard</h1>
        <span className="text-xs text-slate-500">{scans.length} total scans</span>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card label="Findings" value={findings.length} icon={<Bug />} accent="teal" />
        <Card label="Critical / High" value={bySeverity.critical + bySeverity.high} icon={<AlertTriangle />} accent="red" />
        <Card label="Sources" value={totalSources} icon={<Activity />} accent="blue" />
        <Card label="Languages" value={availableLangs.length} icon={<Shield />} accent="slate" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Severity chart */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <h2 className="text-sm font-medium text-slate-300 mb-3">Findings by Severity</h2>
          {chartData.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-slate-600 text-sm">
              No findings yet — run a scan to populate.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={chartData} barSize={28}>
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} width={30} />
                <Tooltip
                  contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 6, fontSize: 12 }}
                  cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                />
                <Bar dataKey="count" radius={[3,3,0,0]}>
                  {chartData.map(d => <Cell key={d.name} fill={d.color} fillOpacity={0.85} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Quick scan */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <h2 className="text-sm font-medium text-slate-300 mb-3">New Scan</h2>
          <form onSubmit={handleScan} className="space-y-3">
            <input
              type="text"
              value={path}
              onChange={e => setPath(e.target.value)}
              placeholder="/path/to/authorized/repo"
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-teal-600 transition-colors"
            />
            <label className="flex items-start gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={authorized}
                onChange={e => setAuthorized(e.target.checked)}
                className="mt-0.5 accent-teal-500"
              />
              <span className="text-xs text-slate-400 leading-relaxed">
                I confirm this path is authorized for scanning. This tool is for
                defensive code review only.
              </span>
            </label>
            {scanError && (
              <p className="text-xs text-red-400 font-mono">{scanError}</p>
            )}
            <button
              type="submit"
              disabled={!path.trim() || !authorized || scanning}
              className="flex items-center gap-2 px-4 py-2 bg-teal-600 hover:bg-teal-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded transition-colors"
            >
              {scanning ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
              {scanning ? 'Starting…' : 'Start Scan'}
            </button>
          </form>
        </div>
      </div>

      {/* Recent scans */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg">
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
          <h2 className="text-sm font-medium text-slate-300">Recent Scans</h2>
          <Link to="/scans" className="text-xs text-teal-500 hover:text-teal-400 transition-colors">
            View all →
          </Link>
        </div>
        {scansQ.isLoading ? (
          <Loading />
        ) : scans.length === 0 ? (
          <Empty message="No scans yet. Start one above." />
        ) : (
          <div className="divide-y divide-slate-800">
            {scans.slice(0, 6).map(s => (
              <Link
                key={s.id}
                to={`/findings?scan_id=${s.id}`}
                className="flex items-center gap-3 px-4 py-2.5 hover:bg-slate-800/50 transition-colors text-sm"
              >
                <StatusBadge status={s.status} />
                <span className="font-mono text-slate-300 truncate flex-1 text-xs">{s.path}</span>
                <span className="text-slate-500 text-xs flex-shrink-0">{s.source_count}s / {s.sink_count}sk</span>
                <span className="text-slate-600 text-xs flex-shrink-0">{relative(s.created_at)}</span>
              </Link>
            ))}
          </div>
        )}
      </div>

      {/* Language coverage */}
      {availableLangs.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <h2 className="text-sm font-medium text-slate-300 mb-3">Language Coverage</h2>
          <div className="flex flex-wrap gap-2">
            {languages.map(l => (
              <Link
                key={l.name}
                to="/languages"
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs border transition-colors ${
                  l.available
                    ? 'bg-teal-500/10 text-teal-400 border-teal-500/30 hover:bg-teal-500/20'
                    : 'bg-slate-800/50 text-slate-500 border-slate-700'
                }`}
              >
                {l.available ? <CheckCircle className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
                {l.name}
                <span className="text-xs opacity-60">({l.extensions.join(', ')})</span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function Card({ label, value, icon, accent }: {
  label: string; value: number; icon: React.ReactNode; accent: string
}) {
  const colors: Record<string, string> = {
    teal: 'text-teal-400', red: 'text-red-400', blue: 'text-blue-400', slate: 'text-slate-400',
  }
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg px-4 py-3 flex items-center gap-3">
      <span className={`h-4 w-4 flex-shrink-0 ${colors[accent] ?? 'text-slate-400'}`}>
        {icon}
      </span>
      <div>
        <div className="text-xl font-semibold text-slate-100">{value}</div>
        <div className="text-xs text-slate-500">{label}</div>
      </div>
    </div>
  )
}

function Bug() { return <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="h-4 w-4"><path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6z"/><path d="M12 20v-9"/><path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/><path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/><path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/></svg> }

function Loading() {
  return (
    <div className="flex items-center justify-center py-8 text-slate-600">
      <Loader2 className="h-4 w-4 animate-spin mr-2" />
      <span className="text-sm">Loading…</span>
    </div>
  )
}

function Empty({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center py-8 text-slate-600 text-sm">
      {message}
    </div>
  )
}
