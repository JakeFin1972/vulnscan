import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  LineChart, Line, CartesianGrid,
} from 'recharts'
import {
  Globe, Server, Network, Upload, RefreshCw, ChevronDown,
  ChevronUp, CheckCircle2, AlertTriangle, XCircle,
  Shield, Activity, Target, Zap, Info,
} from 'lucide-react'
import {
  easmDashboard, easmListAssets, easmGetAsset, easmListVulns,
  easmPatchVuln, easmComputeScore, easmScoreHistory, easmIngest, easmEnrich,
} from '../api'
import type { EasmAsset, EasmVuln, VulnStatus, ExploitMaturity } from '../types'
import { cn } from '@/lib/utils'

// ── Severity palette ──────────────────────────────────────────────────────────

const SEV_BG: Record<string, string> = {
  critical: 'bg-red-900/50 text-red-300 border-red-700',
  high:     'bg-orange-900/50 text-orange-300 border-orange-700',
  medium:   'bg-yellow-900/50 text-yellow-300 border-yellow-700',
  low:      'bg-blue-900/50 text-blue-300 border-blue-700',
  info:     'bg-slate-800 text-slate-400 border-slate-700',
}
const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500',
  medium: 'bg-yellow-400', low: 'bg-blue-400', info: 'bg-slate-500',
}
const SEV_FILL: Record<string, string> = {
  critical: '#ef4444', high: '#f97316',
  medium: '#eab308', low: '#3b82f6', info: '#64748b',
}
const SEVS = ['critical', 'high', 'medium', 'low', 'info'] as const

function SevBadge({ sev }: { sev: string }) {
  return (
    <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-bold border uppercase tracking-wide', SEV_BG[sev] ?? SEV_BG.info)}>
      {sev}
    </span>
  )
}

// ── Exploitability badge + panel ──────────────────────────────────────────────

const MATURITY_STYLE: Record<ExploitMaturity, { bg: string; label: string }> = {
  trivial:            { bg: 'bg-red-900/70 text-red-200 border-red-600',       label: 'Trivial' },
  actively_exploited: { bg: 'bg-red-900/70 text-red-200 border-red-600',       label: 'Exploited ITW' },
  proof_of_concept:   { bg: 'bg-orange-900/60 text-orange-200 border-orange-600', label: 'PoC exists' },
  moderate:           { bg: 'bg-yellow-900/60 text-yellow-200 border-yellow-600', label: 'Moderate' },
  theoretical:        { bg: 'bg-blue-900/60 text-blue-200 border-blue-600',    label: 'Theoretical' },
  requires_chain:     { bg: 'bg-slate-800 text-slate-400 border-slate-600',    label: 'Needs chain' },
  known:              { bg: 'bg-purple-900/60 text-purple-200 border-purple-600', label: 'CVE known' },
  low:                { bg: 'bg-slate-800 text-slate-500 border-slate-700',    label: 'Low risk' },
  unknown:            { bg: 'bg-slate-900 text-slate-600 border-slate-800',    label: 'Unknown' },
}

function ExploitBadge({ maturity }: { maturity: ExploitMaturity }) {
  const s = MATURITY_STYLE[maturity] ?? MATURITY_STYLE.unknown
  return (
    <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-semibold border', s.bg)}>
      {s.label}
    </span>
  )
}

function ExploitPanel({ v }: { v: EasmVuln }) {
  const hasEnrich = v.exploit_insight != null
  if (!hasEnrich) return null

  return (
    <div className="mt-2 p-2.5 rounded border border-slate-700/60 bg-slate-950/60 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <Zap className="h-3.5 w-3.5 text-yellow-400 flex-shrink-0" />
        <span className="text-[10px] font-bold text-yellow-400 uppercase tracking-wide">Exploitability</span>
        {v.exploit_maturity && <ExploitBadge maturity={v.exploit_maturity} />}
        {v.kev === 1 && (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold border bg-red-950 text-red-300 border-red-600 uppercase">
            CISA KEV
          </span>
        )}
      </div>

      {/* CVSS vector + EPSS row */}
      {(v.cvss_vector || v.epss_score != null) && (
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] font-mono">
          {v.cvss_vector && (
            <span className="text-slate-400">{v.cvss_vector}</span>
          )}
          {v.epss_score != null && (
            <span className="text-teal-400">
              EPSS {(v.epss_score * 100).toFixed(2)}%
              {v.epss_percentile != null && (
                <span className="text-slate-500 ml-1">
                  (top {((1 - v.epss_percentile) * 100).toFixed(0)}%)
                </span>
              )}
            </span>
          )}
        </div>
      )}

      {v.exploit_insight && (
        <p className="text-xs text-slate-300 leading-relaxed">{v.exploit_insight}</p>
      )}
    </div>
  )
}

// ── Grade gauge ───────────────────────────────────────────────────────────────

const GRADE_COLORS: Record<string, string> = {
  A: '#22c55e', B: '#84cc16', C: '#eab308', D: '#f97316', F: '#ef4444',
}

function ScoreGauge({ score, grade }: { score: number; grade: string }) {
  const color = GRADE_COLORS[grade] ?? '#64748b'
  const r = 52
  const circ = 2 * Math.PI * r
  // Arc covers 270° (starts at bottom-left, ends at bottom-right)
  const dashLen = (score / 100) * (circ * 0.75)
  const gapLen  = circ - dashLen
  const rotation = 135  // degrees — start of arc

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="136" height="100" viewBox="0 0 136 110">
        {/* Track */}
        <circle cx="68" cy="72" r={r} fill="none" stroke="#1e293b" strokeWidth="12"
          strokeDasharray={`${circ * 0.75} ${circ * 0.25}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          transform={`rotate(${rotation} 68 72)`} />
        {/* Value arc */}
        <circle cx="68" cy="72" r={r} fill="none" stroke={color} strokeWidth="12"
          strokeDasharray={`${dashLen} ${gapLen + circ * 0.25}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          transform={`rotate(${rotation} 68 72)`}
          style={{ transition: 'stroke-dasharray 0.6s ease' }} />
        {/* Score number */}
        <text x="68" y="70" textAnchor="middle" dominantBaseline="middle"
          fill="#f1f5f9" fontSize="24" fontWeight="700" fontFamily="monospace">
          {Math.round(score)}
        </text>
        {/* /100 */}
        <text x="68" y="88" textAnchor="middle" fill="#64748b" fontSize="10">
          / 100
        </text>
      </svg>
      {/* Grade letter */}
      <span className="text-4xl font-black" style={{ color }}>{grade}</span>
    </div>
  )
}

// ── Asset type icon ───────────────────────────────────────────────────────────

function AssetIcon({ type }: { type: string }) {
  if (type === 'domain') return <Globe className="h-3.5 w-3.5 text-teal-400" />
  if (type === 'url')    return <Network className="h-3.5 w-3.5 text-blue-400" />
  return <Server className="h-3.5 w-3.5 text-slate-400" />
}

// ── Status pill ───────────────────────────────────────────────────────────────

const STATUS_STYLE: Record<VulnStatus, string> = {
  open:           'bg-red-900/40 text-red-400',
  resolved:       'bg-green-900/40 text-green-400',
  accepted_risk:  'bg-yellow-900/40 text-yellow-400',
  false_positive: 'bg-slate-800 text-slate-500',
}
const STATUS_LABEL: Record<VulnStatus, string> = {
  open: 'Open', resolved: 'Resolved',
  accepted_risk: 'Accepted', false_positive: 'FP',
}

// ── Vuln row ──────────────────────────────────────────────────────────────────

function VulnRow({ v, onStatusChange }: {
  v: EasmVuln
  onStatusChange: (id: string, status: string) => void
}) {
  const [open, setOpen] = useState(false)
  const nextStatuses: VulnStatus[] = v.status === 'open'
    ? ['resolved', 'accepted_risk', 'false_positive']
    : ['open']

  return (
    <div className="border border-slate-800 rounded bg-slate-900/60">
      <button
        className="w-full flex items-start gap-3 p-2.5 text-left hover:bg-slate-800/40 transition-colors"
        onClick={() => setOpen(x => !x)}
      >
        <span className={cn('mt-1.5 h-2 w-2 rounded-full flex-shrink-0', SEV_DOT[v.severity] ?? SEV_DOT.info)} />
        <div className="flex-1 min-w-0 space-y-0.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm text-slate-200 truncate">{v.name}</span>
            <SevBadge sev={v.severity} />
            {v.cve && <span className="text-[10px] font-mono text-red-400">{v.cve}</span>}
            {v.exploit_maturity && <ExploitBadge maturity={v.exploit_maturity} />}
            {v.kev === 1 && (
              <span className="px-1 py-0.5 rounded text-[9px] font-bold border bg-red-950 text-red-300 border-red-700 uppercase">KEV</span>
            )}
            <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-semibold', STATUS_STYLE[v.status])}>
              {STATUS_LABEL[v.status]}
            </span>
          </div>
          <div className="flex gap-3 text-xs text-slate-500">
            <span className="font-mono">{v.category}</span>
            {v.port && <span>:{v.port}</span>}
            <span>{v.source_tool}</span>
            {v.cvss_score != null && <span>CVSS {v.cvss_score.toFixed(1)}</span>}
            {v.epss_score != null && (
              <span className="text-teal-600">EPSS {(v.epss_score * 100).toFixed(1)}%</span>
            )}
          </div>
        </div>
        {open ? <ChevronUp className="h-4 w-4 text-slate-600 flex-shrink-0 mt-0.5" />
               : <ChevronDown className="h-4 w-4 text-slate-600 flex-shrink-0 mt-0.5" />}
      </button>

      {open && (
        <div className="px-3 pb-3 border-t border-slate-800 space-y-2 pt-2">
          {v.description && (
            <p className="text-xs text-slate-400 whitespace-pre-wrap">{v.description}</p>
          )}
          {v.evidence && (
            <pre className="text-xs text-slate-500 font-mono bg-slate-950 rounded p-2 overflow-x-auto whitespace-pre-wrap">
              {v.evidence}
            </pre>
          )}
          {v.remediation && (
            <p className="text-xs text-teal-400 border-l-2 border-teal-700 pl-2">{v.remediation}</p>
          )}
          <ExploitPanel v={v} />
          <div className="flex gap-2 flex-wrap pt-1">
            {nextStatuses.map(s => (
              <button key={s}
                onClick={() => onStatusChange(v.id, s)}
                className="px-2 py-1 rounded text-xs border border-slate-700 text-slate-400 hover:border-slate-500 hover:text-slate-200 transition-colors"
              >
                Mark {STATUS_LABEL[s as VulnStatus]}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Ingest form (slide-in) ────────────────────────────────────────────────────

function IngestPanel({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [file, setFile] = useState<File | null>(null)
  const [asset, setAsset] = useState('')
  const [assetType, setAssetType] = useState('ip')
  const [label, setLabel] = useState('')
  const [toolHint, setToolHint] = useState('')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  async function submit() {
    if (!file || !asset.trim()) return
    setBusy(true); setError(null); setResult(null)
    try {
      const r = await easmIngest(file, asset.trim(), assetType, label || undefined, toolHint || undefined)
      setResult(`Imported ${r.imported} of ${r.total_parsed} findings for ${r.asset}.`)
      onDone()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1 bg-black/50" onClick={onClose} />
      <div className="w-96 bg-slate-900 border-l border-slate-700 flex flex-col overflow-y-auto">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Upload className="h-4 w-4 text-teal-500" />
            <span className="font-semibold text-slate-100">Ingest Scan File</span>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 text-xl leading-none">&times;</button>
        </div>

        <div className="flex-1 px-5 py-4 space-y-4">
          {/* File drop */}
          <div>
            <label className="block text-xs text-slate-400 mb-1.5">Scanner Output File</label>
            <div
              className={cn(
                'border-2 border-dashed rounded-lg p-4 text-center cursor-pointer transition-colors',
                file ? 'border-teal-700 bg-teal-900/20' : 'border-slate-700 hover:border-slate-500',
              )}
              onClick={() => inputRef.current?.click()}
            >
              <input ref={inputRef} type="file" className="hidden"
                accept=".xml,.json,.jsonl,.txt"
                onChange={e => setFile(e.target.files?.[0] ?? null)} />
              {file
                ? <p className="text-sm text-teal-300 font-mono">{file.name}</p>
                : <>
                    <Upload className="h-6 w-6 text-slate-600 mx-auto mb-1" />
                    <p className="text-xs text-slate-500">Click to select a file</p>
                    <p className="text-[10px] text-slate-600 mt-0.5">Nmap XML · OpenVAS XML · ZAP JSON · Nuclei JSONL</p>
                  </>
              }
            </div>
          </div>

          {/* Asset */}
          <div>
            <label className="block text-xs text-slate-400 mb-1">Asset Identifier</label>
            <input
              className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-200 font-mono placeholder-slate-600 focus:outline-none focus:border-teal-600"
              placeholder="192.168.1.1  /  example.com"
              value={asset}
              onChange={e => setAsset(e.target.value)}
            />
          </div>

          {/* Asset type */}
          <div>
            <label className="block text-xs text-slate-400 mb-1.5">Asset Type</label>
            <div className="flex gap-1.5">
              {['ip', 'domain', 'url', 'cidr'].map(t => (
                <button key={t}
                  onClick={() => setAssetType(t)}
                  className={cn(
                    'flex-1 py-1 rounded text-xs font-semibold uppercase border transition-colors',
                    assetType === t
                      ? 'bg-teal-800 border-teal-600 text-teal-200'
                      : 'bg-slate-800 border-slate-700 text-slate-500 hover:border-slate-600',
                  )}
                >{t}</button>
              ))}
            </div>
          </div>

          {/* Optional fields */}
          <div>
            <label className="block text-xs text-slate-400 mb-1">Vendor / Org Label <span className="text-slate-600">(optional)</span></label>
            <input
              className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-teal-600"
              placeholder="AcmeCorp"
              value={label}
              onChange={e => setLabel(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">Tool Override <span className="text-slate-600">(auto-detected)</span></label>
            <select
              className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:border-teal-600"
              value={toolHint}
              onChange={e => setToolHint(e.target.value)}
            >
              <option value="">Auto-detect</option>
              <option value="nmap">Nmap</option>
              <option value="openvas">OpenVAS</option>
              <option value="zap">OWASP ZAP</option>
              <option value="nuclei">Nuclei</option>
            </select>
          </div>

          {result && (
            <div className="flex items-start gap-2 p-2.5 rounded bg-green-900/30 border border-green-800">
              <CheckCircle2 className="h-4 w-4 text-green-400 flex-shrink-0 mt-0.5" />
              <p className="text-xs text-green-300">{result}</p>
            </div>
          )}
          {error && (
            <div className="flex items-start gap-2 p-2.5 rounded bg-red-900/30 border border-red-800">
              <XCircle className="h-4 w-4 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-xs text-red-300">{error}</p>
            </div>
          )}
        </div>

        <div className="px-5 py-4 border-t border-slate-800">
          <button
            disabled={!file || !asset.trim() || busy}
            onClick={submit}
            className="w-full flex items-center justify-center gap-2 py-2 rounded bg-teal-700 hover:bg-teal-600 disabled:opacity-40 disabled:cursor-not-allowed text-sm font-semibold text-white transition-colors"
          >
            {busy ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
            {busy ? 'Importing…' : 'Import'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Asset detail panel ────────────────────────────────────────────────────────

function AssetDetail({ assetId }: { assetId: string }) {
  const qc = useQueryClient()
  const [sevFilter, setSevFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('open')

  const { data: asset } = useQuery({
    queryKey: ['easm-asset', assetId],
    queryFn:  () => easmGetAsset(assetId),
  })

  const { data: vulns = [], refetch: refetchVulns } = useQuery({
    queryKey: ['easm-vulns', assetId, sevFilter, statusFilter],
    queryFn:  () => easmListVulns({
      asset_id: assetId,
      severity: sevFilter || undefined,
      status:   statusFilter || undefined,
    }),
  })

  const { data: history = [] } = useQuery({
    queryKey: ['easm-history', assetId],
    queryFn:  () => easmScoreHistory(assetId),
  })

  const scoreMut = useMutation({
    mutationFn: () => easmComputeScore(assetId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['easm-asset', assetId] })
      qc.invalidateQueries({ queryKey: ['easm-history', assetId] })
      qc.invalidateQueries({ queryKey: ['easm-dashboard'] })
      qc.invalidateQueries({ queryKey: ['easm-assets'] })
    },
  })

  const [enriched, setEnriched] = useState(false)
  const enrichMut = useMutation({
    mutationFn: () => easmEnrich(assetId),
    onSuccess: () => {
      setEnriched(true)
      // Poll vulns after a delay so background enrichment can complete
      setTimeout(() => refetchVulns(), 3000)
      setTimeout(() => refetchVulns(), 8000)
      setTimeout(() => refetchVulns(), 16000)
    },
  })

  const patchMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) => easmPatchVuln(id, status),
    onSuccess: () => {
      refetchVulns()
      qc.invalidateQueries({ queryKey: ['easm-asset', assetId] })
    },
  })

  const latestScore = asset?.latest_score

  // Prepare chart data
  const historyChart = [...history].reverse().map((h, i) => ({
    t: i + 1,
    score: h.score,
    label: h.scored_at.slice(0, 10),
  }))

  const sevCounts = vulns.reduce<Record<string, number>>((acc, v) => {
    if (v.status === 'open') acc[v.severity] = (acc[v.severity] ?? 0) + 1
    return acc
  }, {})

  const sevBarData = SEVS.filter(s => s !== 'info').map(s => ({
    name: s, count: sevCounts[s] ?? 0,
  }))

  return (
    <div className="flex-1 overflow-y-auto px-5 py-5 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <div className="flex items-center gap-2">
            <AssetIcon type={asset?.asset_type ?? 'ip'} />
            <span className="text-lg font-semibold text-slate-100 font-mono">
              {asset?.identifier}
            </span>
            {asset?.label && (
              <span className="text-xs text-slate-500 border border-slate-700 rounded px-1.5 py-0.5">
                {asset.label}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 mt-0.5 uppercase">{asset?.asset_type}</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => enrichMut.mutate()}
            disabled={enrichMut.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-yellow-700 text-yellow-400 text-xs hover:bg-yellow-900/20 disabled:opacity-40 transition-colors"
            title="Fetch CVE scores, EPSS probability and exploit insights from NVD and FIRST"
          >
            {enrichMut.isPending
              ? <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              : <Zap className="h-3.5 w-3.5" />}
            {enriched ? 'Re-Enrich' : 'Enrich'}
          </button>
          <button
            onClick={() => scoreMut.mutate()}
            disabled={scoreMut.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-teal-700 text-teal-400 text-xs hover:bg-teal-900/30 disabled:opacity-40 transition-colors"
          >
            {scoreMut.isPending
              ? <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              : <Activity className="h-3.5 w-3.5" />}
            Compute Score
          </button>
        </div>
      </div>

      {/* Enrichment status banner */}
      {enrichMut.isPending && (
        <div className="flex items-center gap-2 px-3 py-2 rounded border border-yellow-800 bg-yellow-900/20 text-xs text-yellow-300">
          <RefreshCw className="h-3.5 w-3.5 animate-spin flex-shrink-0" />
          <span>
            Fetching CVE scores and EPSS data from NVD and FIRST APIs — this may take
            a minute. Findings will update automatically when ready.
          </span>
        </div>
      )}
      {enrichMut.isSuccess && (
        <div className="flex items-center gap-2 px-3 py-2 rounded border border-yellow-800/50 bg-yellow-900/10 text-xs text-yellow-500">
          <Zap className="h-3.5 w-3.5 flex-shrink-0" />
          <span>
            Enrichment started — exploit insights will appear in findings as they complete.
            Click <span className="font-semibold">Re-Enrich</span> to refresh.
          </span>
        </div>
      )}

      {/* Score + charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Score gauge */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col items-center justify-center gap-2">
          {latestScore
            ? <>
                <ScoreGauge score={latestScore.score} grade={latestScore.grade} />
                <p className="text-xs text-slate-500 text-center">
                  Last scored {latestScore.scored_at.slice(0, 10)}
                </p>
              </>
            : <div className="text-center py-4">
                <Shield className="h-10 w-10 text-slate-700 mx-auto mb-2" />
                <p className="text-xs text-slate-500">Not scored yet</p>
                <p className="text-[10px] text-slate-600">Click "Compute Score"</p>
              </div>
          }
        </div>

        {/* Severity bar chart */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-3">Open by Severity</p>
          {sevBarData.some(d => d.count > 0)
            ? <ResponsiveContainer width="100%" height={100}>
                <BarChart data={sevBarData} barCategoryGap="30%">
                  <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis allowDecimals={false} tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 6 }}
                    labelStyle={{ color: '#94a3b8' }}
                    itemStyle={{ color: '#f1f5f9' }}
                  />
                  <Bar dataKey="count" radius={[3, 3, 0, 0]}
                    fill="#64748b"
                    label={false}
                  >
                    {sevBarData.map(entry => (
                      <rect key={entry.name} fill={SEV_FILL[entry.name]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            : <div className="flex items-center justify-center h-24 text-xs text-slate-600">No open findings</div>
          }
        </div>

        {/* Score history chart */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-3">Score History</p>
          {historyChart.length >= 2
            ? <ResponsiveContainer width="100%" height={100}>
                <LineChart data={historyChart}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="t" hide />
                  <YAxis domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 6 }}
                    labelFormatter={(_, p) => p?.[0]?.payload?.label ?? ''}
                    formatter={(v: number) => [`${v.toFixed(1)}`, 'Score']}
                    itemStyle={{ color: '#2dd4bf' }}
                  />
                  <Line type="monotone" dataKey="score" stroke="#2dd4bf" dot={false} strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            : <div className="flex items-center justify-center h-24 text-xs text-slate-600">
                {historyChart.length === 1 ? 'Score once more to see trend' : 'No history yet'}
              </div>
          }
        </div>
      </div>

      {/* Top issues from breakdown */}
      {latestScore?.breakdown?.top_issues && latestScore.breakdown.top_issues.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-3">Top Issues by Impact</p>
          <div className="space-y-1.5">
            {latestScore.breakdown.top_issues.map((issue, i) => (
              <div key={i} className="flex items-center gap-3 text-xs">
                <span className="text-slate-600 w-4 text-right font-mono">{i + 1}.</span>
                <span className={cn('h-2 w-2 rounded-full flex-shrink-0', SEV_DOT[issue.severity])} />
                <span className="text-slate-300 flex-1 truncate">{issue.name}</span>
                {issue.cve && <span className="text-red-400 font-mono">{issue.cve}</span>}
                <SevBadge sev={issue.severity} />
                <span className="text-slate-600 font-mono w-12 text-right">-{issue.penalty}pt</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Vuln table */}
      <div>
        <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
          <p className="text-xs text-slate-500 uppercase tracking-wide">Vulnerabilities</p>
          <div className="flex gap-2 flex-wrap">
            {/* Status filter */}
            {(['open', 'resolved', 'accepted_risk', 'false_positive', ''] as const).map(s => (
              <button key={s}
                onClick={() => setStatusFilter(s)}
                className={cn(
                  'px-2 py-0.5 rounded text-[11px] border transition-colors',
                  statusFilter === s
                    ? 'bg-slate-700 border-slate-500 text-slate-200'
                    : 'bg-slate-900 border-slate-800 text-slate-500 hover:border-slate-700',
                )}
              >{s === '' ? 'All' : STATUS_LABEL[s as VulnStatus]}</button>
            ))}
            <span className="text-slate-700">|</span>
            {/* Severity filter */}
            {SEVS.map(s => (
              <button key={s}
                onClick={() => setSevFilter(sf => sf === s ? '' : s)}
                className={cn(
                  'px-2 py-0.5 rounded text-[11px] border transition-colors uppercase font-semibold',
                  sevFilter === s ? SEV_BG[s] : 'bg-slate-900 border-slate-800 text-slate-600 hover:border-slate-700',
                )}
              >{s}</button>
            ))}
          </div>
        </div>

        <div className="space-y-1.5">
          {vulns.length === 0
            ? <p className="text-xs text-slate-600 py-4 text-center">No findings match the current filter.</p>
            : vulns.map(v => (
                <VulnRow key={v.id} v={v}
                  onStatusChange={(id, status) => patchMut.mutate({ id, status })} />
              ))
          }
        </div>
      </div>
    </div>
  )
}

// ── Asset list item ───────────────────────────────────────────────────────────

function AssetItem({ asset, selected, onClick }: {
  asset: EasmAsset; selected: boolean; onClick: () => void
}) {
  const score = asset.latest_score
  const grade = score?.grade ?? '–'
  const scoreVal = score?.score

  const critCount = asset.open_by_severity?.critical ?? 0
  const highCount = asset.open_by_severity?.high ?? 0

  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left px-3 py-2.5 rounded border transition-colors',
        selected
          ? 'bg-teal-900/20 border-teal-700'
          : 'bg-slate-900/40 border-slate-800 hover:border-slate-700',
      )}
    >
      <div className="flex items-center gap-2 min-w-0">
        <AssetIcon type={asset.asset_type} />
        <span className="font-mono text-xs text-slate-300 truncate flex-1">{asset.identifier}</span>
        {scoreVal != null && (
          <span className="font-mono text-xs font-bold" style={{ color: GRADE_COLORS[grade] ?? '#64748b' }}>
            {Math.round(scoreVal)}
          </span>
        )}
        <span className="font-black text-sm" style={{ color: GRADE_COLORS[grade] ?? '#64748b' }}>
          {grade}
        </span>
      </div>
      {(critCount > 0 || highCount > 0 || asset.label) && (
        <div className="flex items-center gap-2 mt-1 flex-wrap">
          {asset.label && (
            <span className="text-[10px] text-slate-600">{asset.label}</span>
          )}
          {critCount > 0 && (
            <span className="text-[10px] text-red-400 font-semibold">{critCount} crit</span>
          )}
          {highCount > 0 && (
            <span className="text-[10px] text-orange-400 font-semibold">{highCount} high</span>
          )}
        </div>
      )}
    </button>
  )
}

// ── Main EASM page ────────────────────────────────────────────────────────────

export default function EASMPage() {
  const qc = useQueryClient()
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null)
  const [showIngest, setShowIngest] = useState(false)
  const [labelFilter, setLabelFilter] = useState('')

  const { data: dashboard } = useQuery({
    queryKey: ['easm-dashboard'],
    queryFn: easmDashboard,
    staleTime: 10_000,
    refetchInterval: 30_000,
  })

  const { data: assets = [] } = useQuery({
    queryKey: ['easm-assets', labelFilter],
    queryFn: () => easmListAssets(labelFilter || undefined),
    staleTime: 10_000,
  })

  function onIngestDone() {
    qc.invalidateQueries({ queryKey: ['easm-assets'] })
    qc.invalidateQueries({ queryKey: ['easm-dashboard'] })
  }

  const avgScore = dashboard?.average_score
  const gradeColor = avgScore != null
    ? GRADE_COLORS[Object.entries(dashboard?.grade_distribution ?? {}).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'F'] ?? '#64748b'
    : '#64748b'

  return (
    <div className="flex h-full">
      {showIngest && (
        <IngestPanel
          onClose={() => setShowIngest(false)}
          onDone={() => { setShowIngest(false); onIngestDone() }}
        />
      )}

      {/* Left sidebar — summary + asset list */}
      <div className="w-72 flex-shrink-0 flex flex-col border-r border-slate-800 overflow-hidden">
        {/* Header */}
        <div className="px-4 pt-5 pb-3 border-b border-slate-800">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-2">
              <Target className="h-4 w-4 text-teal-500" />
              <h1 className="text-base font-semibold text-slate-100">EASM</h1>
            </div>
            <button
              onClick={() => setShowIngest(true)}
              className="flex items-center gap-1 px-2 py-1 rounded bg-teal-800 hover:bg-teal-700 text-teal-200 text-xs font-semibold transition-colors"
            >
              <Upload className="h-3 w-3" /> Ingest
            </button>
          </div>
          <p className="text-[10px] text-slate-600">External Attack Surface Management</p>
        </div>

        {/* Summary stats */}
        <div className="grid grid-cols-2 gap-2 p-3 border-b border-slate-800">
          <div className="bg-slate-900 rounded p-2 text-center">
            <p className="text-[10px] text-slate-500 uppercase">Assets</p>
            <p className="text-xl font-bold font-mono text-slate-200">{dashboard?.asset_count ?? 0}</p>
          </div>
          <div className="bg-slate-900 rounded p-2 text-center">
            <p className="text-[10px] text-slate-500 uppercase">Open</p>
            <p className="text-xl font-bold font-mono text-red-400">{dashboard?.open_count ?? 0}</p>
          </div>
          <div className="bg-slate-900 rounded p-2 text-center col-span-2">
            <p className="text-[10px] text-slate-500 uppercase mb-0.5">Avg Score</p>
            <p className="text-2xl font-bold font-mono" style={{ color: gradeColor }}>
              {avgScore != null ? `${avgScore.toFixed(0)} / 100` : '—'}
            </p>
          </div>
        </div>

        {/* Severity mini-bar */}
        {dashboard && Object.keys(dashboard.by_severity).length > 0 && (
          <div className="px-3 py-2 border-b border-slate-800">
            <p className="text-[10px] text-slate-500 uppercase mb-1.5">Open by Severity</p>
            <div className="space-y-1">
              {SEVS.filter(s => s !== 'info').map(s => {
                const count = dashboard.by_severity[s] ?? 0
                const max = Math.max(...Object.values(dashboard.by_severity), 1)
                return (
                  <div key={s} className="flex items-center gap-2">
                    <span className="w-12 text-[10px] text-slate-500 text-right capitalize">{s}</span>
                    <div className="flex-1 bg-slate-800 rounded-full h-1.5">
                      <div
                        className="h-1.5 rounded-full transition-all"
                        style={{ width: `${(count / max) * 100}%`, background: SEV_FILL[s] }}
                      />
                    </div>
                    <span className="w-6 text-[10px] text-slate-400 font-mono">{count}</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Label filter */}
        <div className="px-3 py-2 border-b border-slate-800">
          <input
            className="w-full bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-teal-600"
            placeholder="Filter by vendor label…"
            value={labelFilter}
            onChange={e => setLabelFilter(e.target.value)}
          />
        </div>

        {/* Asset list */}
        <div className="flex-1 overflow-y-auto px-2 py-2 space-y-1.5">
          {assets.length === 0 && (
            <div className="text-center py-8">
              <Server className="h-8 w-8 text-slate-700 mx-auto mb-2" />
              <p className="text-xs text-slate-600">No assets yet.</p>
              <p className="text-[10px] text-slate-700">Use Ingest to import scan results.</p>
            </div>
          )}
          {assets.map(a => (
            <AssetItem
              key={a.id}
              asset={a}
              selected={a.id === selectedAsset}
              onClick={() => setSelectedAsset(a.id)}
            />
          ))}
        </div>
      </div>

      {/* Right content — asset detail or empty state */}
      {selectedAsset
        ? <AssetDetail key={selectedAsset} assetId={selectedAsset} />
        : (
          <div className="flex-1 flex flex-col">
            {/* Top criticals */}
            {dashboard && dashboard.top_critical_open.length > 0 && (
              <div className="flex-1 px-6 py-6 overflow-y-auto">
                <div className="flex items-center gap-2 mb-4">
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                  <h2 className="text-sm font-semibold text-slate-200">Critical Open Findings</h2>
                  <span className="text-xs text-slate-500">across all assets · oldest first</span>
                </div>
                <div className="space-y-2">
                  {dashboard.top_critical_open.map((issue, i) => (
                    <div key={i}
                      className="flex items-center gap-3 px-3 py-2.5 bg-slate-900 border border-red-900/40 rounded cursor-pointer hover:border-red-700/60 transition-colors"
                      onClick={() => {
                        const a = assets.find(x => x.identifier === issue.asset)
                        if (a) setSelectedAsset(a.id)
                      }}
                    >
                      <span className="h-2 w-2 rounded-full bg-red-500 flex-shrink-0" />
                      <span className="text-sm text-slate-200 flex-1 truncate">{issue.name}</span>
                      {issue.cve && <span className="text-xs font-mono text-red-400">{issue.cve}</span>}
                      <span className="text-xs text-slate-500 font-mono">{issue.asset}</span>
                      <SevBadge sev={issue.severity} />
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Empty centre */}
            {(!dashboard || dashboard.top_critical_open.length === 0) && (
              <div className="flex-1 flex flex-col items-center justify-center text-center p-8">
                <Shield className="h-16 w-16 text-slate-800 mb-4" />
                <p className="text-slate-500 text-sm">Select an asset to view its findings and risk score.</p>
                <p className="text-slate-600 text-xs mt-1">Or ingest a scanner file to get started.</p>
              </div>
            )}
          </div>
        )
      }
    </div>
  )
}
