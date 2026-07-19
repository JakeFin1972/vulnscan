import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { RotateCcw, Loader2, Plus, ExternalLink } from 'lucide-react'
import { listScans, startScan } from '@/api'
import StatusBadge from '@/components/StatusBadge'
import type { Scan } from '@/types'

function fmt(iso: string) {
  const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'))
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

export default function Scans() {
  const [searchParams] = useSearchParams()
  const highlight = searchParams.get('highlight')
  const qc = useQueryClient()
  const [scanning, setScanning] = useState(false)
  const [scanError, setScanError] = useState<string | null>(null)
  const [path, setPath] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [confirmRescanId, setConfirmRescanId] = useState<string | null>(null)

  const scansQ = useQuery({
    queryKey: ['scans'],
    queryFn: listScans,
    refetchInterval: 3000,
  })

  const scans = scansQ.data ?? []

  const rescanMut = useMutation({
    mutationFn: (scanPath: string) => startScan(scanPath),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] })
      setConfirmRescanId(null)
    },
  })

  function handleRescanClick(s: Scan) {
    if (confirmRescanId === s.id) {
      // Second click — confirmed
      rescanMut.mutate(s.path)
    } else {
      // First click — arm confirmation
      setConfirmRescanId(s.id)
    }
  }

  async function handleScan(e: React.FormEvent) {
    e.preventDefault()
    if (!path.trim() || !authorized) return
    setScanError(null)
    setScanning(true)
    try {
      await startScan(path.trim())
      await qc.invalidateQueries({ queryKey: ['scans'] })
      setPath(''); setAuthorized(false)
    } catch (e: unknown) {
      setScanError(e instanceof Error ? e.message : String(e))
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <h1 className="text-sm font-semibold text-slate-100">Scans</h1>
        <span className="text-xs text-slate-500">{scans.length} total</span>
      </div>

      {/* New scan form */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <h2 className="text-xs font-medium text-slate-400 mb-3 uppercase tracking-wider">New Scan</h2>
        <form onSubmit={handleScan} className="flex flex-wrap items-start gap-3">
          <input
            type="text"
            value={path}
            onChange={e => setPath(e.target.value)}
            placeholder="/absolute/path/to/repo"
            className="flex-1 min-w-60 bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-teal-600"
          />
          <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer self-center">
            <input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)} className="accent-teal-500" />
            Authorized
          </label>
          <button
            type="submit"
            disabled={!path.trim() || !authorized || scanning}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-teal-600 hover:bg-teal-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-medium rounded transition-colors"
          >
            {scanning ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
            {scanning ? 'Starting…' : 'Scan'}
          </button>
        </form>
        {scanError && <p className="mt-2 text-xs text-red-400 font-mono">{scanError}</p>}
      </div>

      {/* Table */}
      {scansQ.isLoading ? (
        <div className="flex items-center gap-2 text-slate-600 py-8">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span className="text-sm">Loading…</span>
        </div>
      ) : scans.length === 0 ? (
        <div className="text-sm text-slate-600 py-8 text-center">
          No scans yet. Use the form above to start one.
        </div>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-slate-950 border-b border-slate-800">
              <tr className="text-left text-slate-500">
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-4 py-2.5 font-medium">Path</th>
                <th className="px-4 py-2.5 font-medium">Started</th>
                <th className="px-4 py-2.5 font-medium text-right">Sources</th>
                <th className="px-4 py-2.5 font-medium text-right">Sinks</th>
                <th className="px-4 py-2.5 font-medium text-right">Pairs</th>
                <th className="px-4 py-2.5 w-24" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {scans.map(s => {
                const confirming = confirmRescanId === s.id
                const rescanning = rescanMut.isPending && confirmRescanId === s.id
                return (
                  <tr
                    key={s.id}
                    className={`transition-colors ${
                      highlight === s.id ? 'bg-teal-500/10' : 'hover:bg-slate-800/30'
                    }`}
                    onMouseLeave={() => { if (confirming && !rescanning) setConfirmRescanId(null) }}
                  >
                    <td className="px-4 py-2.5">
                      <StatusBadge status={s.status} />
                      {s.error && (
                        <div className="mt-0.5 text-red-400 font-mono text-xs max-w-xs truncate" title={s.error}>
                          {s.error}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-slate-300 max-w-xs">
                      <div className="truncate" title={s.path}>{s.path}</div>
                    </td>
                    <td className="px-4 py-2.5 text-slate-500 whitespace-nowrap">{fmt(s.created_at)}</td>
                    <td className="px-4 py-2.5 text-right text-slate-400">{s.source_count}</td>
                    <td className="px-4 py-2.5 text-right text-slate-400">{s.sink_count}</td>
                    <td className="px-4 py-2.5 text-right text-slate-400">{s.pair_count}</td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center justify-end gap-2">
                        {s.status === 'done' && (
                          <Link
                            to={`/findings?scan_id=${s.id}`}
                            className="flex items-center gap-1 text-teal-500 hover:text-teal-400 transition-colors"
                          >
                            <ExternalLink className="h-3 w-3" />
                          </Link>
                        )}
                        <button
                          onClick={() => handleRescanClick(s)}
                          disabled={rescanning || s.status === 'pending' || s.status === 'running'}
                          title={confirming ? 'Click again to confirm rescan' : 'Re-run scan'}
                          className={`flex items-center gap-1 px-2 py-1 rounded border text-xs font-medium transition-colors disabled:opacity-30 disabled:cursor-not-allowed ${
                            confirming
                              ? 'border-orange-600 text-orange-400 bg-orange-900/20 hover:text-orange-300'
                              : 'border-slate-700 text-slate-400 hover:border-teal-600 hover:text-teal-400 hover:bg-teal-900/20'
                          }`}
                        >
                          <RotateCcw className={`h-3 w-3 ${rescanning ? 'animate-spin' : ''}`} />
                          {rescanning ? 'Scanning…' : confirming ? 'Confirm?' : 'Rescan'}
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
