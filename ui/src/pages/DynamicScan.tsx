import React, { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Shield,
  Globe,
  Server,
  Cpu,
  Play,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  AlertTriangle,
  GitBranch,
  Zap,
  Wrench,
} from 'lucide-react'
import {
  listScanners,
  startDynamicScan,
  listDynamicScans,
  getDynamicScan,
  listDynamicFindings,
} from '../api'
import type { DynamicScan, DynamicFinding, ScanTool, TargetType } from '../types'
import { cn } from '@/lib/utils'

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: 'bg-red-900/60 text-red-300 border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border-orange-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  low:      'bg-blue-900/60 text-blue-300 border-blue-700',
  info:     'bg-slate-800 text-slate-400 border-slate-700',
}

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high:     'bg-orange-500',
  medium:   'bg-yellow-400',
  low:      'bg-blue-400',
  info:     'bg-slate-500',
}

function SeverityBadge({ sev }: { sev: string }) {
  return (
    <span className={cn('px-2 py-0.5 rounded text-xs font-semibold border uppercase tracking-wide', SEV_COLORS[sev] ?? SEV_COLORS.info)}>
      {sev}
    </span>
  )
}

// ── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    pending: 'text-slate-400 bg-slate-800',
    running: 'text-teal-400 bg-teal-900/40 animate-pulse',
    done:    'text-green-400 bg-green-900/40',
    error:   'text-red-400 bg-red-900/40',
  }
  return (
    <span className={cn('px-2 py-0.5 rounded text-xs font-semibold uppercase', map[status] ?? map.pending)}>
      {status}
    </span>
  )
}

// ── Target type icon ──────────────────────────────────────────────────────────

function TargetIcon({ type }: { type: string }) {
  if (type === 'url') return <Globe className="h-3.5 w-3.5" />
  if (type === 'mcp') return <Cpu className="h-3.5 w-3.5" />
  return <Server className="h-3.5 w-3.5" />
}

// ── Finding row ───────────────────────────────────────────────────────────────

function DetailSection({ icon: Icon, title, children }: {
  icon: React.ComponentType<{ className?: string }>
  title: string
  children: React.ReactNode
}) {
  return (
    <div className="rounded-lg border border-slate-700/60 overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 bg-slate-800/60 border-b border-slate-700/60">
        <Icon className="h-3.5 w-3.5 text-slate-400" />
        <span className="text-xs font-medium text-slate-300 uppercase tracking-wide">{title}</span>
      </div>
      <div className="p-3">{children}</div>
    </div>
  )
}

function FindingRow({ f }: { f: DynamicFinding }) {
  const [open, setOpen] = useState(false)
  return (
    <div className={cn('border rounded overflow-hidden transition-colors', open ? 'border-slate-600 bg-slate-900' : 'border-slate-800 bg-slate-900/50')}>
      {/* Summary row */}
      <button
        className="w-full flex items-start gap-3 p-3 text-left hover:bg-slate-800/50 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        <span className={cn('mt-1 h-2 w-2 rounded-full flex-shrink-0', SEV_DOT[f.severity] ?? SEV_DOT.info)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge sev={f.severity} />
            <span className="text-sm font-medium text-slate-200">{f.name}</span>
            <span className="text-xs text-slate-500 font-mono border border-slate-700 rounded px-1.5 py-0.5">{f.tool}</span>
          </div>
          <div className="flex items-center gap-3 mt-1 flex-wrap">
            <span className="text-xs text-slate-500 font-mono">{f.category}</span>
            {f.cve && <span className="text-xs text-red-400 font-mono">{f.cve}</span>}
            {f.url && <span className="text-xs text-slate-600 truncate max-w-xs">{f.url}</span>}
            {f.port && <span className="text-xs text-slate-500">port {f.port}</span>}
          </div>
        </div>
        <span className="flex-shrink-0 text-slate-600 mt-0.5">
          {open ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
        </span>
      </button>

      {/* Expanded detail */}
      {open && (
        <div className="border-t border-slate-800 p-3 space-y-3">
          {/* Description */}
          {f.description && (
            <DetailSection icon={AlertTriangle} title="Vulnerability Description">
              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">{f.description}</p>
            </DetailSection>
          )}

          {/* Technical detail */}
          <DetailSection icon={GitBranch} title="Technical Detail">
            <div className="space-y-1.5 text-xs">
              {f.target && (
                <div><span className="text-slate-500">Target: </span><span className="font-mono text-slate-300">{f.target}</span></div>
              )}
              {f.url && (
                <div className="flex items-center gap-1.5">
                  <span className="text-slate-500">URL: </span>
                  <a href={f.url} target="_blank" rel="noopener noreferrer"
                    className="text-teal-400 hover:underline flex items-center gap-1 font-mono">
                    {f.url} <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              )}
              {f.port && (
                <div><span className="text-slate-500">Port: </span><span className="font-mono text-slate-300">{f.port}</span></div>
              )}
              {f.cve && (
                <div><span className="text-slate-500">CVE: </span><span className="font-mono text-red-400">{f.cve}</span></div>
              )}
              <div><span className="text-slate-500">Tool: </span><span className="font-mono text-slate-300">{f.tool}</span></div>
              <div><span className="text-slate-500">Category: </span><span className="font-mono text-slate-300">{f.category}</span></div>
            </div>
          </DetailSection>

          {/* Evidence */}
          {f.evidence && (
            <DetailSection icon={Zap} title="Evidence">
              <pre className="text-xs text-slate-300 font-mono bg-slate-950 rounded p-2 overflow-x-auto whitespace-pre-wrap leading-relaxed">{f.evidence}</pre>
            </DetailSection>
          )}

          {/* Remediation */}
          {f.remediation && (
            <DetailSection icon={Wrench} title="Recommended Fix">
              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">{f.remediation}</p>
            </DetailSection>
          )}
        </div>
      )}
    </div>
  )
}

// ── Scan row (in history list) ────────────────────────────────────────────────

function ScanRow({
  scan,
  selected,
  onClick,
}: {
  scan: DynamicScan
  selected: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left px-3 py-2.5 rounded flex items-start gap-3 transition-colors text-sm',
        selected
          ? 'bg-teal-900/30 border border-teal-700'
          : 'bg-slate-900 border border-slate-800 hover:border-slate-700',
      )}
    >
      <TargetIcon type={scan.target_type} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-xs text-slate-300 truncate">{scan.target}</span>
          <StatusBadge status={scan.status} />
        </div>
        <div className="flex gap-2 mt-1 flex-wrap">
          <span className="text-xs text-slate-500">{scan.tools.join(', ')}</span>
          {scan.status === 'done' && (
            <span className="text-xs text-slate-400">{scan.finding_count} finding{scan.finding_count !== 1 ? 's' : ''}</span>
          )}
        </div>
      </div>
    </button>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

const TOOLS_BY_TYPE: Record<TargetType, ScanTool[]> = {
  url:  ['http', 'api', 'nmap', 'mcp'],
  host: ['nmap', 'openvas'],
  mcp:  ['mcp'],
}

export default function DynamicScanPage() {
  const qc = useQueryClient()

  // Form state
  const [target, setTarget] = useState('')
  const [targetType, setTargetType] = useState<TargetType>('url')
  const [selectedTools, setSelectedTools] = useState<ScanTool[]>(TOOLS_BY_TYPE.url)
  const [sevFilter, setSevFilter] = useState('')

  // Selected scan for detail view
  const [activeScanId, setActiveScanId] = useState<string | null>(null)

  // Queries
  const { data: scanners } = useQuery({
    queryKey: ['scanners'],
    queryFn: listScanners,
    staleTime: 30_000,
  })

  const { data: scans = [], refetch: refetchScans } = useQuery({
    queryKey: ['dynamic-scans'],
    queryFn: listDynamicScans,
    staleTime: 5_000,
  })

  const { data: activeScan } = useQuery({
    queryKey: ['dynamic-scan', activeScanId],
    queryFn: () => getDynamicScan(activeScanId!),
    enabled: !!activeScanId,
    refetchInterval: (query) => {
      const s = query.state.data?.status
      return s === 'pending' || s === 'running' ? 1500 : false
    },
  })

  const { data: findings = [] } = useQuery({
    queryKey: ['dynamic-findings', activeScanId, sevFilter],
    queryFn: () =>
      listDynamicFindings({
        scan_id: activeScanId!,
        severity: sevFilter || undefined,
      }),
    enabled: !!activeScanId && (activeScan?.status === 'done' || activeScan?.status === 'error'),
  })

  // Refetch scan list when active scan finishes
  useEffect(() => {
    if (activeScan?.status === 'done' || activeScan?.status === 'error') {
      refetchScans()
    }
  }, [activeScan?.status, refetchScans])

  // Mutation
  const startMutation = useMutation({
    mutationFn: () => startDynamicScan(target.trim(), targetType, selectedTools),
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: ['dynamic-scans'] })
      setActiveScanId(scan.id)
    },
  })

  // Update tool defaults when target type changes
  function handleTypeChange(t: TargetType) {
    setTargetType(t)
    setSelectedTools(TOOLS_BY_TYPE[t])
  }

  function toggleTool(tool: ScanTool) {
    setSelectedTools(prev =>
      prev.includes(tool) ? prev.filter(x => x !== tool) : [...prev, tool],
    )
  }

  const allTools: ScanTool[] = ['http', 'api', 'nmap', 'zap', 'openvas', 'mcp']

  const sevCounts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="flex h-full">
      {/* Left panel — form + history */}
      <div className="w-80 flex-shrink-0 flex flex-col border-r border-slate-800 overflow-y-auto">
        {/* Header */}
        <div className="px-4 pt-6 pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2 mb-1">
            <Shield className="h-5 w-5 text-teal-500" />
            <h1 className="text-lg font-semibold text-slate-100">Dynamic Scan</h1>
          </div>
          <p className="text-xs text-slate-500">Active security scanning with NMAP, ZAP, OpenVAS and MCP</p>
        </div>

        {/* Scanner availability */}
        {scanners && (
          <div className="px-4 py-3 border-b border-slate-800">
            <p className="text-xs text-slate-500 font-semibold uppercase tracking-wide mb-2">Scanner Status</p>
            <div className="space-y-1">
              {allTools.map(tool => {
                const st = scanners[tool]
                return (
                  <div key={tool} className="flex items-center gap-2 text-xs">
                    <span className={cn('h-1.5 w-1.5 rounded-full flex-shrink-0', st?.available ? 'bg-green-400' : 'bg-slate-600')} />
                    <span className="font-mono text-slate-300 w-16">{tool}</span>
                    <span className="text-slate-500 truncate">{st?.available ? 'ready' : 'not available'}</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Scan form */}
        <div className="px-4 py-4 border-b border-slate-800 space-y-3">
          {/* Target */}
          <div>
            <label className="block text-xs text-slate-400 mb-1">Target</label>
            <input
              className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-200 font-mono placeholder-slate-600 focus:outline-none focus:border-teal-600"
              placeholder="http://example.com  /  192.168.1.1"
              value={target}
              onChange={e => setTarget(e.target.value)}
            />
          </div>

          {/* Target type */}
          <div>
            <label className="block text-xs text-slate-400 mb-1">Target Type</label>
            <div className="flex gap-2">
              {(['url', 'host', 'mcp'] as TargetType[]).map(t => (
                <button
                  key={t}
                  onClick={() => handleTypeChange(t)}
                  className={cn(
                    'flex-1 py-1 rounded text-xs font-semibold uppercase tracking-wide transition-colors border',
                    targetType === t
                      ? 'bg-teal-800 border-teal-600 text-teal-300'
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600',
                  )}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* Tools */}
          <div>
            <label className="block text-xs text-slate-400 mb-1">Tools</label>
            <div className="flex flex-wrap gap-2">
              {allTools.map(tool => {
                const available = scanners?.[tool]?.available ?? tool === 'mcp'
                const checked = selectedTools.includes(tool)
                return (
                  <button
                    key={tool}
                    disabled={!available}
                    onClick={() => toggleTool(tool)}
                    className={cn(
                      'px-2.5 py-1 rounded text-xs font-mono border transition-colors',
                      checked && available
                        ? 'bg-teal-800 border-teal-600 text-teal-200'
                        : !available
                          ? 'opacity-30 cursor-not-allowed bg-slate-800 border-slate-700 text-slate-500'
                          : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600',
                    )}
                  >
                    {tool}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Start button */}
          <button
            disabled={!target.trim() || selectedTools.length === 0 || startMutation.isPending}
            onClick={() => startMutation.mutate()}
            className="w-full flex items-center justify-center gap-2 py-2 rounded bg-teal-700 hover:bg-teal-600 disabled:opacity-40 disabled:cursor-not-allowed text-sm font-semibold text-white transition-colors"
          >
            {startMutation.isPending ? (
              <RefreshCw className="h-4 w-4 animate-spin" />
            ) : (
              <Play className="h-4 w-4" />
            )}
            Start Scan
          </button>
          {startMutation.isError && (
            <p className="text-xs text-red-400">{String(startMutation.error)}</p>
          )}
        </div>

        {/* Scan history */}
        <div className="flex-1 overflow-y-auto px-3 py-3 space-y-2">
          <p className="text-xs text-slate-500 font-semibold uppercase tracking-wide px-1 mb-2">History</p>
          {scans.length === 0 && (
            <p className="text-xs text-slate-600 px-1">No scans yet.</p>
          )}
          {[...scans].reverse().map(scan => (
            <ScanRow
              key={scan.id}
              scan={scan}
              selected={scan.id === activeScanId}
              onClick={() => setActiveScanId(scan.id)}
            />
          ))}
        </div>
      </div>

      {/* Right panel — findings */}
      <div className="flex-1 overflow-y-auto px-6 py-6">
        {!activeScanId ? (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <Shield className="h-12 w-12 text-slate-700 mb-4" />
            <p className="text-slate-500 text-sm">Start a scan or select one from history</p>
          </div>
        ) : (
          <>
            {/* Scan info bar */}
            {activeScan && (
              <div className="flex items-center gap-3 mb-5 flex-wrap">
                <TargetIcon type={activeScan.target_type} />
                <span className="font-mono text-sm text-slate-200">{activeScan.target}</span>
                <StatusBadge status={activeScan.status} />
                {activeScan.status === 'running' && (
                  <RefreshCw className="h-3.5 w-3.5 text-teal-500 animate-spin" />
                )}
                {activeScan.status === 'done' && (
                  <span className="text-xs text-slate-400">{activeScan.finding_count} finding{activeScan.finding_count !== 1 ? 's' : ''}</span>
                )}
                {activeScan.error && (
                  <span className="text-xs text-red-400">{activeScan.error}</span>
                )}
              </div>
            )}

            {/* Severity summary bar */}
            {findings.length > 0 && (
              <div className="flex flex-wrap gap-2 mb-4">
                <button
                  onClick={() => setSevFilter('')}
                  className={cn(
                    'px-3 py-1 rounded text-xs border transition-colors',
                    !sevFilter
                      ? 'bg-slate-700 border-slate-500 text-slate-200'
                      : 'bg-slate-900 border-slate-700 text-slate-500 hover:border-slate-600',
                  )}
                >
                  All ({findings.length})
                </button>
                {(['critical', 'high', 'medium', 'low', 'info'] as const).map(s => {
                  const count = sevCounts[s]
                  if (!count) return null
                  return (
                    <button
                      key={s}
                      onClick={() => setSevFilter(s === sevFilter ? '' : s)}
                      className={cn(
                        'px-3 py-1 rounded text-xs border transition-colors font-semibold uppercase',
                        sevFilter === s
                          ? SEV_COLORS[s]
                          : 'bg-slate-900 border-slate-700 text-slate-400 hover:border-slate-600',
                      )}
                    >
                      {s} ({count})
                    </button>
                  )
                })}
              </div>
            )}

            {/* Running state */}
            {activeScan?.status === 'running' && (
              <div className="flex items-center gap-2 py-6 text-slate-500 text-sm">
                <RefreshCw className="h-4 w-4 animate-spin text-teal-500" />
                Scan in progress — results will appear when complete…
              </div>
            )}
            {activeScan?.status === 'pending' && (
              <div className="flex items-center gap-2 py-6 text-slate-500 text-sm">
                <RefreshCw className="h-4 w-4 animate-spin" />
                Scan queued…
              </div>
            )}

            {/* Findings list */}
            <div className="space-y-2">
              {findings.map(f => (
                <FindingRow key={f.id} f={f} />
              ))}
              {activeScan?.status === 'done' && findings.length === 0 && (
                <div className="py-8 text-center text-slate-600 text-sm">
                  No findings{sevFilter ? ` at severity "${sevFilter}"` : ''}.
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
