import { useState, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { RotateCcw, Loader2, Plus, ExternalLink, Sparkles, ChevronDown, ChevronUp, FileText, Upload, X, File as FileIcon } from 'lucide-react'
import { listScans, startScan, uploadScan, aiBoostScan, aiBoostAll, aiGenerateReport } from '@/api'
import type { AiBoostResponse, AiBoostAllResult, AiReport } from '@/api'
import StatusBadge from '@/components/StatusBadge'
import type { Scan } from '@/types'

function fmt(iso: string) {
  const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'))
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

const VERDICT_DOT: Record<string, string> = {
  confirmed: 'bg-red-500', false_positive: 'bg-green-500', needs_review: 'bg-yellow-400',
}

const RISK_RATING_COLOR: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high:     'bg-orange-500 text-white',
  medium:   'bg-yellow-500 text-black',
  low:      'bg-blue-500 text-white',
}

const EFFORT_COLOR: Record<string, string> = {
  low:    'bg-green-900/40 text-green-400 border-green-700/50',
  medium: 'bg-yellow-900/40 text-yellow-400 border-yellow-700/50',
  high:   'bg-red-900/40 text-red-400 border-red-700/50',
}

function ScanRow({
  s, highlight, confirming, rescanning, onRescanClick,
}: {
  s: Scan
  highlight: boolean
  confirming: boolean
  rescanning: boolean
  onRescanClick: (s: Scan) => void
}) {
  const [boostOpen, setBoostOpen] = useState(false)
  const [boostResult, setBoostResult] = useState<AiBoostResponse | null>(null)
  const [reportOpen, setReportOpen] = useState(false)
  const [reportResult, setReportResult] = useState<AiReport | null>(null)

  const boostMut = useMutation({
    mutationFn: () => aiBoostScan(s.id),
    onSuccess: (r: AiBoostResponse) => { setBoostResult(r); setBoostOpen(true) },
  })

  const reportMut = useMutation({
    mutationFn: () => aiGenerateReport(s.id),
    onSuccess: (r: AiReport) => { setReportResult(r); setReportOpen(true) },
  })

  return (
    <>
      <tr
        className={`transition-colors ${highlight ? 'bg-teal-500/10' : 'hover:bg-slate-800/30'}`}
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
            {s.status === 'done' && s.pair_count > 0 && (
              <button
                onClick={() => boostMut.isPending ? null : (boostResult ? setBoostOpen(v => !v) : boostMut.mutate())}
                disabled={boostMut.isPending}
                title="AI taint analysis on source-sink pairs"
                className="flex items-center gap-1 px-2 py-1 rounded border border-purple-700/60 text-purple-400 hover:bg-purple-900/20 hover:border-purple-500 text-xs font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {boostMut.isPending
                  ? <Loader2 className="h-3 w-3 animate-spin" />
                  : <Sparkles className="h-3 w-3" />}
                {boostMut.isPending ? 'Analyzing…' : 'AI Boost'}
                {boostResult && (boostOpen
                  ? <ChevronUp className="h-3 w-3" />
                  : <ChevronDown className="h-3 w-3" />)}
              </button>
            )}
            {s.status === 'done' && (
              <button
                onClick={() => reportMut.isPending ? null : (reportResult ? setReportOpen(v => !v) : reportMut.mutate())}
                disabled={reportMut.isPending}
                title="Generate AI executive report"
                className="flex items-center gap-1 px-2 py-1 rounded border border-cyan-700/60 text-cyan-400 hover:bg-cyan-900/20 hover:border-cyan-500 text-xs font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {reportMut.isPending
                  ? <Loader2 className="h-3 w-3 animate-spin" />
                  : <FileText className="h-3 w-3" />}
                {reportMut.isPending ? 'Generating…' : 'Report'}
                {reportResult && (reportOpen
                  ? <ChevronUp className="h-3 w-3" />
                  : <ChevronDown className="h-3 w-3" />)}
              </button>
            )}
            <button
              onClick={() => onRescanClick(s)}
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

      {/* AI Boost error */}
      {boostMut.isError && (
        <tr>
          <td colSpan={7} className="px-4 py-2 bg-red-900/10 border-t border-red-900/30">
            <p className="text-xs text-red-400">
              AI Boost failed: {boostMut.error instanceof Error ? boostMut.error.message : 'Unknown error'}
              {String(boostMut.error).includes('ANTHROPIC_API_KEY') && (
                <span className="ml-2 text-slate-400">Set ANTHROPIC_API_KEY env var and restart the server.</span>
              )}
            </p>
          </td>
        </tr>
      )}

      {/* Report error */}
      {reportMut.isError && (
        <tr>
          <td colSpan={7} className="px-4 py-2 bg-red-900/10 border-t border-red-900/30">
            <p className="text-xs text-red-400">
              Report generation failed: {reportMut.error instanceof Error ? reportMut.error.message : 'Unknown error'}
            </p>
          </td>
        </tr>
      )}

      {/* AI Boost results */}
      {boostResult && boostOpen && (
        <tr>
          <td colSpan={7} className="px-4 py-3 bg-purple-900/10 border-t border-purple-800/30">
            <div className="space-y-2">
              <div className="flex items-center gap-3 mb-2">
                <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                <span className="text-xs font-semibold text-purple-300">
                  AI Boost — {boostResult.confirmed}/{boostResult.pairs_analyzed} confirmed vulnerabilities
                </span>
                <span className="text-xs text-slate-500">{boostResult.model ?? 'ai'}</span>
              </div>
              {boostResult.results.map((r, i) => {
                const ai = r.ai
                const verdict = ai.verdict ?? 'needs_review'
                const dot = VERDICT_DOT[verdict] ?? 'bg-slate-500'
                return (
                  <div key={i} className={`rounded border p-3 text-xs space-y-1.5 ${
                    verdict === 'confirmed' ? 'border-red-800/50 bg-red-900/10'
                    : verdict === 'false_positive' ? 'border-green-800/50 bg-green-900/10'
                    : 'border-slate-700 bg-slate-800/30'
                  }`}>
                    <div className="flex items-start gap-2 flex-wrap">
                      <span className={`mt-1 h-2 w-2 rounded-full flex-shrink-0 ${dot}`} />
                      <span className="font-semibold text-slate-200">
                        {ai.vulnerability_title ?? `${(r.source as {name?:string}).name} → ${(r.sink as {name?:string}).name}`}
                      </span>
                      {ai.cwe && <span className="font-mono text-slate-500 border border-slate-700 rounded px-1">{ai.cwe}</span>}
                      {ai.severity && <span className="font-semibold text-slate-400 uppercase">{ai.severity}</span>}
                      <span className={`capitalize ${
                        ai.exploit_difficulty === 'trivial' || ai.exploit_difficulty === 'low' ? 'text-red-400'
                        : ai.exploit_difficulty === 'moderate' ? 'text-yellow-400'
                        : 'text-slate-400'
                      }`}>
                        {ai.exploit_difficulty?.replace('_', ' ')}
                      </span>
                    </div>
                    {ai.data_flow && (
                      <div className="font-mono text-slate-500 text-xs">{ai.data_flow}</div>
                    )}
                    {ai.reasoning && (
                      <p className="text-slate-400 leading-relaxed">{ai.reasoning}</p>
                    )}
                    {verdict === 'confirmed' && ai.remediation_summary && (
                      <div className="mt-1 pt-1 border-t border-slate-700/50">
                        <span className="text-slate-500">Fix: </span>
                        <span className="text-green-400">{ai.remediation_summary}</span>
                      </div>
                    )}
                    {verdict === 'confirmed' && ai.remediation_code && (
                      <pre className="mt-1 text-xs text-green-300 bg-slate-950 rounded p-2 overflow-x-auto whitespace-pre-wrap">{ai.remediation_code}</pre>
                    )}
                  </div>
                )
              })}
            </div>
          </td>
        </tr>
      )}

      {/* AI Report panel */}
      {reportResult && reportOpen && (
        <tr>
          <td colSpan={7} className="px-4 py-4 bg-cyan-900/10 border-t border-cyan-800/30">
            <div className="space-y-4 text-xs">
              {/* Header row: risk rating + score */}
              <div className="flex items-center gap-3">
                <FileText className="h-3.5 w-3.5 text-cyan-400" />
                <span className="text-xs font-semibold text-cyan-300">AI Executive Report</span>
                <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${RISK_RATING_COLOR[reportResult.risk_rating] ?? 'bg-slate-600 text-white'}`}>
                  {reportResult.risk_rating}
                </span>
                <span className="text-slate-400">Risk Score: <span className="font-semibold text-slate-200">{reportResult.risk_score}/100</span></span>
              </div>

              {/* Executive summary */}
              <div className="bg-slate-900/60 rounded border border-slate-700/50 p-3">
                <div className="text-slate-500 uppercase tracking-wider text-xs mb-1.5 font-medium">Executive Summary</div>
                <p className="text-slate-300 leading-relaxed">{reportResult.executive_summary}</p>
              </div>

              {/* Attack surface */}
              <div className="bg-slate-900/60 rounded border border-slate-700/50 p-3">
                <div className="text-slate-500 uppercase tracking-wider text-xs mb-1.5 font-medium">Attack Surface</div>
                <p className="text-slate-300 leading-relaxed">{reportResult.attack_surface}</p>
              </div>

              {/* Stats row */}
              <div className="flex gap-4">
                <div className="flex-1 bg-red-900/20 border border-red-800/30 rounded p-3 text-center">
                  <div className="text-2xl font-bold text-red-400">{reportResult.confirmed_count}</div>
                  <div className="text-slate-500 mt-0.5">Confirmed</div>
                </div>
                <div className="flex-1 bg-green-900/20 border border-green-800/30 rounded p-3 text-center">
                  <div className="text-2xl font-bold text-green-400">{reportResult.false_positive_count}</div>
                  <div className="text-slate-500 mt-0.5">False Positives</div>
                </div>
                <div className="flex-1 bg-yellow-900/20 border border-yellow-800/30 rounded p-3 text-center">
                  <div className="text-2xl font-bold text-yellow-400">{reportResult.needs_review_count}</div>
                  <div className="text-slate-500 mt-0.5">Needs Review</div>
                </div>
              </div>

              {/* Top vulnerabilities table */}
              {reportResult.top_vulnerabilities.length > 0 && (
                <div>
                  <div className="text-slate-500 uppercase tracking-wider text-xs mb-2 font-medium">Top Vulnerabilities</div>
                  <div className="border border-slate-700/50 rounded overflow-hidden">
                    <table className="w-full text-xs">
                      <thead className="bg-slate-900 border-b border-slate-700/50">
                        <tr className="text-slate-500 text-left">
                          <th className="px-3 py-2 font-medium">#</th>
                          <th className="px-3 py-2 font-medium">Title</th>
                          <th className="px-3 py-2 font-medium">CWE</th>
                          <th className="px-3 py-2 font-medium">Severity</th>
                          <th className="px-3 py-2 font-medium">Location</th>
                          <th className="px-3 py-2 font-medium">Impact</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {reportResult.top_vulnerabilities.map((v, i) => (
                          <tr key={i} className="hover:bg-slate-800/20">
                            <td className="px-3 py-2 text-slate-500">{v.priority}</td>
                            <td className="px-3 py-2 text-slate-200 font-medium">{v.title}</td>
                            <td className="px-3 py-2 font-mono text-slate-400 border border-slate-700/30 rounded px-1 whitespace-nowrap">{v.cwe}</td>
                            <td className="px-3 py-2">
                              <span className={`uppercase font-semibold ${
                                v.severity === 'critical' ? 'text-red-400'
                                : v.severity === 'high' ? 'text-orange-400'
                                : v.severity === 'medium' ? 'text-yellow-400'
                                : 'text-blue-400'
                              }`}>{v.severity}</span>
                            </td>
                            <td className="px-3 py-2 font-mono text-slate-500 whitespace-nowrap">{v.file}:{v.line}</td>
                            <td className="px-3 py-2 text-slate-400 max-w-xs">{v.impact}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Remediation roadmap */}
              {reportResult.remediation_roadmap.length > 0 && (
                <div>
                  <div className="text-slate-500 uppercase tracking-wider text-xs mb-2 font-medium">Remediation Roadmap</div>
                  <div className="space-y-2">
                    {reportResult.remediation_roadmap.map((item, i) => (
                      <div key={i} className="flex items-start gap-3 bg-slate-900/50 border border-slate-700/40 rounded p-3">
                        <span className="flex-shrink-0 h-5 w-5 rounded-full bg-cyan-800/50 text-cyan-300 text-xs font-bold flex items-center justify-center">
                          {item.priority}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="text-slate-200">{item.action}</div>
                          <div className="text-slate-500 mt-1">{item.impact}</div>
                        </div>
                        <span className={`flex-shrink-0 px-1.5 py-0.5 rounded border text-xs font-medium capitalize ${EFFORT_COLOR[item.effort] ?? 'border-slate-700 text-slate-400'}`}>
                          {item.effort}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Security posture + recommendations */}
              <div className="bg-slate-900/60 rounded border border-slate-700/50 p-3">
                <div className="text-slate-500 uppercase tracking-wider text-xs mb-1.5 font-medium">Security Posture</div>
                <p className="text-slate-300 leading-relaxed mb-3">{reportResult.security_posture}</p>
                {reportResult.recommendations.length > 0 && (
                  <>
                    <div className="text-slate-500 uppercase tracking-wider text-xs mb-1.5 font-medium">Recommendations</div>
                    <ul className="space-y-1">
                      {reportResult.recommendations.map((rec, i) => (
                        <li key={i} className="flex items-start gap-2 text-slate-400">
                          <span className="flex-shrink-0 text-cyan-600 mt-0.5">›</span>
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
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

  // File upload state
  const [uploadFiles, setUploadFiles] = useState<File[]>([])
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [uploading, setUploading] = useState(false)
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const dropped = Array.from(e.dataTransfer.files)
    setUploadFiles(prev => {
      const names = new Set(prev.map(f => f.name))
      return [...prev, ...dropped.filter(f => !names.has(f.name))]
    })
  }, [])

  function removeUploadFile(name: string) {
    setUploadFiles(prev => prev.filter(f => f.name !== name))
  }

  async function handleUpload() {
    if (!uploadFiles.length) return
    setUploadError(null)
    setUploading(true)
    try {
      await uploadScan(uploadFiles)
      await qc.invalidateQueries({ queryKey: ['scans'] })
      setUploadFiles([])
    } catch (e: unknown) {
      setUploadError(e instanceof Error ? e.message : String(e))
    } finally {
      setUploading(false)
    }
  }

  function formatBytes(b: number) {
    if (b < 1024) return `${b} B`
    if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
    return `${(b / 1024 / 1024).toFixed(1)} MB`
  }

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

  const [boostAllToast, setBoostAllToast] = useState<string | null>(null)
  const boostAllMut = useMutation({
    mutationFn: () => aiBoostAll(),
    onSuccess: (r: AiBoostAllResult) => {
      setBoostAllToast(`Boosted ${r.scans_boosted} scans — ${r.total_confirmed} confirmed vulnerabilities`)
      setTimeout(() => setBoostAllToast(null), 6000)
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
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-500">{scans.length} total</span>
          <button
            onClick={() => boostAllMut.isPending ? null : boostAllMut.mutate()}
            disabled={boostAllMut.isPending || scans.filter(s => s.status === 'done' && s.pair_count > 0).length === 0}
            title="Run AI boost on all eligible scans"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-purple-700/60 text-purple-400 hover:bg-purple-900/20 hover:border-purple-500 text-xs font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {boostAllMut.isPending
              ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
              : <Sparkles className="h-3.5 w-3.5" />}
            {boostAllMut.isPending ? 'Boosting…' : 'Boost All'}
          </button>
        </div>
      </div>

      {/* Boost All toast */}
      {boostAllToast && (
        <div className="flex items-center gap-2 px-4 py-2.5 bg-purple-900/20 border border-purple-700/40 rounded-lg text-xs text-purple-300">
          <Sparkles className="h-3.5 w-3.5 flex-shrink-0" />
          {boostAllToast}
        </div>
      )}
      {boostAllMut.isError && (
        <div className="px-4 py-2.5 bg-red-900/20 border border-red-700/40 rounded-lg text-xs text-red-400">
          Boost All failed: {boostAllMut.error instanceof Error ? boostAllMut.error.message : 'Unknown error'}
        </div>
      )}

      {/* Scan input panels — side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Repo / directory path */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <h2 className="text-xs font-medium text-slate-400 mb-3 uppercase tracking-wider">Scan Repository / Directory</h2>
          <form onSubmit={handleScan} className="flex flex-wrap items-start gap-3">
            <input
              type="text"
              value={path}
              onChange={e => setPath(e.target.value)}
              placeholder="/absolute/path/to/repo"
              className="flex-1 min-w-48 bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-teal-600"
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

        {/* File upload */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <h2 className="text-xs font-medium text-slate-400 mb-3 uppercase tracking-wider">Scan Uploaded Files</h2>

          {/* Drop zone */}
          <div
            onDrop={onDrop}
            onDragOver={e => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onClick={() => fileInputRef.current?.click()}
            className={`cursor-pointer rounded-lg border-2 border-dashed px-4 py-5 text-center transition-colors ${
              dragOver
                ? 'border-teal-500 bg-teal-900/20'
                : 'border-slate-700 hover:border-slate-600 hover:bg-slate-800/30'
            }`}
          >
            <Upload className="h-5 w-5 text-slate-500 mx-auto mb-1.5" />
            <p className="text-xs text-slate-400">Drop files here or <span className="text-teal-400 underline">browse</span></p>
            <p className="text-[10px] text-slate-600 mt-0.5">Any format — .ts .js .py .cs .go .java .php …</p>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={e => {
                const picked = Array.from(e.target.files ?? [])
                setUploadFiles(prev => {
                  const names = new Set(prev.map(f => f.name))
                  return [...prev, ...picked.filter(f => !names.has(f.name))]
                })
                e.target.value = ''
              }}
            />
          </div>

          {/* File list */}
          {uploadFiles.length > 0 && (
            <ul className="mt-2 space-y-1 max-h-28 overflow-y-auto">
              {uploadFiles.map(f => (
                <li key={f.name} className="flex items-center gap-2 px-2 py-1 rounded bg-slate-800/50 text-xs">
                  <FileIcon className="h-3 w-3 text-slate-500 flex-shrink-0" />
                  <span className="font-mono text-slate-300 flex-1 truncate">{f.name}</span>
                  <span className="text-slate-600 flex-shrink-0">{formatBytes(f.size)}</span>
                  <button onClick={() => removeUploadFile(f.name)} className="text-slate-600 hover:text-red-400 transition-colors flex-shrink-0">
                    <X className="h-3 w-3" />
                  </button>
                </li>
              ))}
            </ul>
          )}

          <div className="mt-3 flex items-center gap-3">
            <button
              onClick={handleUpload}
              disabled={!uploadFiles.length || uploading}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-teal-600 hover:bg-teal-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-medium rounded transition-colors"
            >
              {uploading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
              {uploading ? 'Uploading…' : `Scan ${uploadFiles.length > 0 ? uploadFiles.length : ''} File${uploadFiles.length !== 1 ? 's' : ''}`}
            </button>
            {uploadFiles.length > 0 && (
              <button onClick={() => setUploadFiles([])} className="text-xs text-slate-600 hover:text-slate-400 transition-colors">
                Clear all
              </button>
            )}
          </div>
          {uploadError && <p className="mt-2 text-xs text-red-400 font-mono">{uploadError}</p>}
        </div>
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
                  <ScanRow
                    key={s.id}
                    s={s}
                    highlight={highlight === s.id}
                    confirming={confirming}
                    rescanning={rescanning}
                    onRescanClick={handleRescanClick}
                  />
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
