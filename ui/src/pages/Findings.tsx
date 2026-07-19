import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import {
  X, Loader2, ChevronRight, AlertTriangle, Code2, GitBranch,
  Zap, Wrench, ChevronDown, ChevronUp, ExternalLink, Globe, Server,
} from 'lucide-react'
import { listFindings, listScans, listDynamicFindings, listDynamicScans } from '@/api'
import type { Finding, DynamicFinding, DynamicScan, Severity } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import { getCategoryMeta } from '@/lib/categoryMeta'
import { cn } from '@/lib/utils'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high:     'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium:   'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  low:      'text-blue-400 bg-blue-500/10 border-blue-500/30',
  info:     'text-slate-400 bg-slate-500/10 border-slate-500/30',
}

const SEV_COLORS: Record<string, string> = {
  critical: 'bg-red-900/60 text-red-300 border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border-orange-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  low:      'bg-blue-900/60 text-blue-300 border-blue-700',
  info:     'bg-slate-800 text-slate-400 border-slate-700',
}

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500',
  medium: 'bg-yellow-400', low: 'bg-blue-400', info: 'bg-slate-500',
}

// ── Shared helpers ────────────────────────────────────────────────────────────

function shortPath(file: string, maxLen = 60): string {
  if (file.length <= maxLen) return file
  const parts = file.split('/')
  let result = file
  while (result.length > maxLen && parts.length > 3) {
    parts.splice(1, 1)
    result = [parts[0], '…', ...parts.slice(1)].join('/')
  }
  return result
}

function FilterSelect({
  label, value, options, onChange,
}: {
  label: string; value: string; options: string[]; onChange: (v: string) => void
}) {
  return (
    <label className="flex items-center gap-2 text-xs text-slate-400">
      {label}
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none focus:border-teal-600"
      >
        <option value="">All</option>
        {options.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  )
}

function Section({ icon: Icon, title, children }: {
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

// ── Static finding detail panel ───────────────────────────────────────────────

function StaticFindingDetail({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const meta = getCategoryMeta(finding.category)

  return (
    <div className="w-[480px] flex-shrink-0 border-l border-slate-800 bg-slate-900 flex flex-col overflow-hidden">
      <div className="flex items-start justify-between px-4 py-3 border-b border-slate-800 gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge severity={finding.severity} />
            <span className={`text-xs px-2 py-0.5 rounded border font-mono ${SEVERITY_COLOR[finding.severity as Severity] ?? SEVERITY_COLOR.info}`}>
              {meta.cwe}
            </span>
          </div>
          <div className="text-sm font-semibold text-slate-100 mt-1.5 leading-snug">{meta.title}</div>
          <div className="font-mono text-xs text-teal-400 mt-0.5 truncate">
            {shortPath(finding.file)}:<span className="text-teal-300">{finding.line}</span>
          </div>
        </div>
        <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors flex-shrink-0 mt-0.5">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="overflow-y-auto flex-1 p-3 space-y-3">
        <div className="flex flex-wrap gap-2 text-xs">
          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
            <span className="text-slate-500">kind: </span>{finding.kind}
          </span>
          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
            <span className="text-slate-500">lang: </span>{finding.language || 'unknown'}
          </span>
          <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
            <span className="text-slate-500">category: </span><span className="font-mono">{finding.category}</span>
          </span>
        </div>

        <Section icon={AlertTriangle} title="Vulnerability Description">
          <p className="text-xs text-slate-300 leading-relaxed">{meta.description}</p>
        </Section>

        <Section icon={Code2} title="Affected Location">
          <div className="space-y-1.5 text-xs">
            <div><span className="text-slate-500">File: </span><span className="font-mono text-slate-200 break-all">{finding.file}</span></div>
            <div><span className="text-slate-500">Line: </span><span className="font-mono text-teal-400">{finding.line}</span></div>
            <div><span className="text-slate-500">Symbol: </span><span className="font-mono text-slate-200">{finding.name}</span></div>
            {finding.pair_id && (
              <div><span className="text-slate-500">Taint pair: </span><span className="font-mono text-slate-400 text-xs break-all">{finding.pair_id}</span></div>
            )}
          </div>
        </Section>

        <Section icon={GitBranch} title="Data Flow">
          <div className="text-xs text-slate-300 leading-relaxed space-y-1">
            {finding.kind === 'source' ? (
              <>
                <div className="flex items-start gap-2">
                  <span className="flex-shrink-0 w-4 h-4 rounded-full bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400 text-xs font-bold mt-0.5">S</span>
                  <span><span className="font-mono text-slate-200">{finding.name}</span> — taint <span className="text-red-400 font-medium">source</span> at <span className="font-mono text-teal-400">{shortPath(finding.file)}:{finding.line}</span></span>
                </div>
                <div className="ml-2 border-l border-slate-700 pl-3 py-1 text-slate-500 text-xs">↓ tainted value propagates forward through the call graph</div>
                <div className="flex items-start gap-2">
                  <span className="flex-shrink-0 w-4 h-4 rounded-full bg-orange-500/20 border border-orange-500/40 flex items-center justify-center text-orange-400 text-xs font-bold mt-0.5">?</span>
                  <span className="text-slate-500">Sink location identified in paired finding</span>
                </div>
              </>
            ) : (
              <>
                <div className="flex items-start gap-2">
                  <span className="flex-shrink-0 w-4 h-4 rounded-full bg-slate-700 border border-slate-600 flex items-center justify-center text-slate-400 text-xs font-bold mt-0.5">S</span>
                  <span className="text-slate-500">User-controlled input (paired source finding)</span>
                </div>
                <div className="ml-2 border-l border-slate-700 pl-3 py-1 text-slate-500 text-xs">↓ tainted value flows to sink</div>
                <div className="flex items-start gap-2">
                  <span className="flex-shrink-0 w-4 h-4 rounded-full bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400 text-xs font-bold mt-0.5">K</span>
                  <span><span className="font-mono text-slate-200">{finding.name}</span> — taint <span className="text-red-400 font-medium">sink</span> at <span className="font-mono text-teal-400">{shortPath(finding.file)}:{finding.line}</span></span>
                </div>
              </>
            )}
          </div>
        </Section>

        <Section icon={Zap} title="Exploit Scenario">
          <div className="space-y-1">
            {meta.exploitScenario.split('\n').map((line, i) => (
              <p key={i} className="text-xs text-slate-300 leading-relaxed">{line}</p>
            ))}
          </div>
        </Section>

        <Section icon={Wrench} title="Recommended Fix">
          <p className="text-xs text-slate-300 leading-relaxed">{meta.recommendedFix}</p>
        </Section>
      </div>
    </div>
  )
}

// ── Dynamic finding row ───────────────────────────────────────────────────────

function DynamicFindingRow({ f }: { f: DynamicFinding }) {
  const [open, setOpen] = useState(false)
  return (
    <div className={cn('border rounded overflow-hidden transition-colors', open ? 'border-slate-600 bg-slate-900' : 'border-slate-800 bg-slate-900/50')}>
      <button
        className="w-full flex items-start gap-3 p-3 text-left hover:bg-slate-800/50 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        <span className={cn('mt-1 h-2 w-2 rounded-full flex-shrink-0', SEV_DOT[f.severity] ?? SEV_DOT.info)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn('px-2 py-0.5 rounded text-xs font-semibold border uppercase tracking-wide', SEV_COLORS[f.severity] ?? SEV_COLORS.info)}>
              {f.severity}
            </span>
            <span className="text-sm font-medium text-slate-200">{f.name}</span>
            <span className="text-xs text-slate-500 font-mono border border-slate-700 rounded px-1.5 py-0.5">{f.tool}</span>
          </div>
          <div className="flex items-center gap-3 mt-1 flex-wrap">
            <span className="text-xs text-slate-500 font-mono">{f.category}</span>
            {f.cve && <span className="text-xs text-red-400 font-mono">{f.cve}</span>}
            {f.url && <span className="text-xs text-slate-600 truncate max-w-xs font-mono">{f.url}</span>}
            {f.port && <span className="text-xs text-slate-500">:{f.port}</span>}
          </div>
        </div>
        {open ? <ChevronUp className="h-4 w-4 text-slate-600 flex-shrink-0 mt-0.5" />
               : <ChevronDown className="h-4 w-4 text-slate-600 flex-shrink-0 mt-0.5" />}
      </button>

      {open && (
        <div className="border-t border-slate-800 p-3 space-y-3">
          {f.description && (
            <Section icon={AlertTriangle} title="Description">
              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">{f.description}</p>
            </Section>
          )}
          <Section icon={GitBranch} title="Technical Detail">
            <div className="space-y-1.5 text-xs">
              <div><span className="text-slate-500">Target: </span><span className="font-mono text-slate-300">{f.target}</span></div>
              {f.url && (
                <div className="flex items-center gap-1.5">
                  <span className="text-slate-500">URL: </span>
                  <a href={f.url} target="_blank" rel="noopener noreferrer"
                    className="text-teal-400 hover:underline flex items-center gap-1 font-mono">
                    {f.url} <ExternalLink className="h-3 w-3" />
                  </a>
                </div>
              )}
              {f.port && <div><span className="text-slate-500">Port: </span><span className="font-mono text-slate-300">{f.port}</span></div>}
              {f.cve && <div><span className="text-slate-500">CVE: </span><span className="font-mono text-red-400">{f.cve}</span></div>}
              <div><span className="text-slate-500">Tool: </span><span className="font-mono text-slate-300">{f.tool}</span></div>
              <div><span className="text-slate-500">Category: </span><span className="font-mono text-slate-300">{f.category}</span></div>
            </div>
          </Section>
          {f.evidence && (
            <Section icon={Zap} title="Evidence">
              <pre className="text-xs text-slate-300 font-mono bg-slate-950 rounded p-2 overflow-x-auto whitespace-pre-wrap leading-relaxed">{f.evidence}</pre>
            </Section>
          )}
          {f.remediation && (
            <Section icon={Wrench} title="Recommended Fix">
              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">{f.remediation}</p>
            </Section>
          )}
        </div>
      )}
    </div>
  )
}

// ── Dynamic findings view ─────────────────────────────────────────────────────

function DynamicFindingsView() {
  const [scanId, setScanId] = useState('')
  const [severity, setSeverity] = useState('')
  const [tool, setTool] = useState('')
  const [category, setCategory] = useState('')

  const scansQ = useQuery<DynamicScan[]>({
    queryKey: ['dynamic-scans'],
    queryFn: listDynamicScans,
    staleTime: 15_000,
  })

  const findingsQ = useQuery<DynamicFinding[]>({
    queryKey: ['dynamic-findings-all', scanId, severity, tool, category],
    queryFn: () => listDynamicFindings({
      scan_id:  scanId   || undefined,
      severity: severity || undefined,
      tool:     tool     || undefined,
      category: category || undefined,
    }),
    refetchInterval: 10_000,
  })

  const scans   = scansQ.data  ?? []
  const findings = findingsQ.data ?? []

  const tools      = [...new Set(findings.map(f => f.tool))].sort()
  const categories = [...new Set(findings.map(f => f.category))].sort()
  const hasFilters = !!(scanId || severity || tool || category)

  function clearFilters() {
    setScanId(''); setSeverity(''); setTool(''); setCategory('')
  }

  function scanLabel(s: DynamicScan) {
    const ts = s.created_at.slice(0, 10)
    return `${s.target} · ${s.finding_count}F · ${ts}`
  }

  return (
    <div className="flex flex-col h-full">
      {/* Filter bar */}
      <div className="px-5 py-3 border-b border-slate-800 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 text-xs text-slate-400">
          Scan
          <select
            value={scanId}
            onChange={e => setScanId(e.target.value)}
            className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none focus:border-teal-600 max-w-64 truncate"
          >
            <option value="">All scans</option>
            {[...scans].map(s => (
              <option key={s.id} value={s.id}>{scanLabel(s)}</option>
            ))}
          </select>
        </label>

        <FilterSelect label="Severity" value={severity} options={SEVERITIES} onChange={setSeverity} />
        <FilterSelect label="Tool"     value={tool}     options={tools}      onChange={setTool} />
        <FilterSelect label="Category" value={category} options={categories} onChange={setCategory} />

        {hasFilters && (
          <button onClick={clearFilters} className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300 transition-colors">
            <X className="h-3 w-3" /> Clear
          </button>
        )}

        <span className="ml-auto text-xs text-slate-500">
          {findingsQ.isLoading ? '…' : `${findings.length} findings`}
        </span>
      </div>

      {/* Findings list */}
      <div className="flex-1 overflow-y-auto px-5 py-4 space-y-2">
        {findingsQ.isLoading ? (
          <div className="flex items-center justify-center py-12 text-slate-600">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />
            <span className="text-sm">Loading…</span>
          </div>
        ) : findings.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 gap-2 text-slate-600">
            <Globe className="h-8 w-8 text-slate-700" />
            <span className="text-sm">No dynamic findings</span>
            {hasFilters && <span className="text-xs">Try clearing filters</span>}
            {!hasFilters && <span className="text-xs">Run a scan from the Dynamic Scan tab to populate findings</span>}
          </div>
        ) : (
          findings.map(f => <DynamicFindingRow key={f.id} f={f} />)
        )}
      </div>
    </div>
  )
}

// ── Static findings view ──────────────────────────────────────────────────────

function StaticFindingsView() {
  const [params] = useSearchParams()
  const initialScanId = params.get('scan_id') ?? ''

  const [scanId, setScanId] = useState(initialScanId)
  const [severity, setSeverity] = useState('')
  const [language, setLanguage] = useState('')
  const [category, setCategory] = useState('')
  const [selected, setSelected] = useState<Finding | null>(null)

  const scansQ    = useQuery({ queryKey: ['scans'], queryFn: listScans })
  const findingsQ = useQuery({
    queryKey: ['findings', scanId, severity, language, category],
    queryFn:  () => listFindings({
      scan_id:  scanId   || undefined,
      severity: severity || undefined,
      language: language || undefined,
      category: category || undefined,
    }),
    refetchInterval: 5_000,
  })

  const findings  = findingsQ.data ?? []
  const scans     = scansQ.data    ?? []
  const languages = [...new Set(findings.map(f => f.language).filter(Boolean))].sort()
  const categories = [...new Set(findings.map(f => f.category))].sort()
  const hasFilters = !!(scanId || severity || language || category)

  function clearFilters() { setScanId(''); setSeverity(''); setLanguage(''); setCategory('') }

  return (
    <div className="flex flex-1 min-h-0">
      {/* Main table */}
      <div className="flex-1 flex flex-col min-w-0">
        <div className="px-5 py-3 border-b border-slate-800 flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-slate-400">
            Scan
            <select
              value={scanId}
              onChange={e => setScanId(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs focus:outline-none focus:border-teal-600 max-w-40 truncate"
            >
              <option value="">All</option>
              {scans.map(s => (
                <option key={s.id} value={s.id}>
                  {s.path.split('/').slice(-2).join('/')} ({s.status})
                </option>
              ))}
            </select>
          </label>

          <FilterSelect label="Severity" value={severity} options={SEVERITIES}  onChange={setSeverity} />
          <FilterSelect label="Language" value={language} options={languages}   onChange={setLanguage} />
          <FilterSelect label="Category" value={category} options={categories}  onChange={setCategory} />

          {hasFilters && (
            <button onClick={clearFilters} className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300 transition-colors">
              <X className="h-3 w-3" /> Clear
            </button>
          )}

          <span className="ml-auto text-xs text-slate-500">
            {findingsQ.isLoading ? '…' : `${findings.length} findings`}
          </span>
        </div>

        {findingsQ.isLoading ? (
          <div className="flex items-center justify-center flex-1 text-slate-600">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />
            <span className="text-sm">Loading findings…</span>
          </div>
        ) : findings.length === 0 ? (
          <div className="flex flex-col items-center justify-center flex-1 gap-2 text-slate-600">
            <Server className="h-8 w-8 text-slate-700" />
            <span className="text-sm">No code findings</span>
            {hasFilters
              ? <span className="text-xs">Try clearing filters</span>
              : <span className="text-xs">Run a scan from the Scans tab to analyse a repository</span>
            }
          </div>
        ) : (
          <div className="overflow-auto flex-1">
            <table className="w-full text-xs border-collapse">
              <thead className="sticky top-0 bg-slate-950 z-10">
                <tr className="text-left text-slate-500 border-b border-slate-800">
                  <th className="px-4 py-2 font-medium w-24">Severity</th>
                  <th className="px-4 py-2 font-medium">Vulnerability</th>
                  <th className="px-4 py-2 font-medium w-16">CWE</th>
                  <th className="px-4 py-2 font-medium">File:Line</th>
                  <th className="px-4 py-2 font-medium w-20">Language</th>
                  <th className="w-6" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {findings.map(f => {
                  const meta = getCategoryMeta(f.category)
                  return (
                    <tr
                      key={f.id}
                      onClick={() => setSelected(s => s?.id === f.id ? null : f)}
                      className={cn(
                        'cursor-pointer transition-colors',
                        selected?.id === f.id ? 'bg-teal-500/10' : 'hover:bg-slate-800/50',
                      )}
                    >
                      <td className="px-4 py-2.5"><SeverityBadge severity={f.severity} /></td>
                      <td className="px-4 py-2.5">
                        <div className="text-slate-200 font-medium">{meta.title}</div>
                        <div className="text-slate-500 mt-0.5 font-mono">{f.name}</div>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="font-mono text-slate-400 text-xs">{meta.cwe}</span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-slate-400 max-w-xs truncate">
                        {shortPath(f.file)}:<span className="text-teal-500">{f.line}</span>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="px-1.5 py-0.5 rounded text-xs bg-slate-800 text-slate-300 border border-slate-700">
                          {f.language || '—'}
                        </span>
                      </td>
                      <td className="pr-3">
                        <ChevronRight className={cn('h-3.5 w-3.5 text-slate-600 transition-transform', selected?.id === f.id && 'rotate-90')} />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detail panel */}
      {selected && (
        <StaticFindingDetail finding={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

type Tab = 'dynamic' | 'code'

export default function Findings() {
  const [tab, setTab] = useState<Tab>('dynamic')

  return (
    <div className="flex flex-col h-full">
      {/* Tab bar */}
      <div className="flex items-center gap-1 px-5 pt-4 pb-0 border-b border-slate-800">
        <button
          onClick={() => setTab('dynamic')}
          className={cn(
            'px-4 py-2 text-xs font-semibold rounded-t border-b-2 transition-colors',
            tab === 'dynamic'
              ? 'text-teal-300 border-teal-500 bg-teal-900/20'
              : 'text-slate-500 border-transparent hover:text-slate-300',
          )}
        >
          Dynamic Scan Findings
        </button>
        <button
          onClick={() => setTab('code')}
          className={cn(
            'px-4 py-2 text-xs font-semibold rounded-t border-b-2 transition-colors',
            tab === 'code'
              ? 'text-teal-300 border-teal-500 bg-teal-900/20'
              : 'text-slate-500 border-transparent hover:text-slate-300',
          )}
        >
          Code Analysis
        </button>
      </div>

      {/* Tab content */}
      <div className="flex-1 min-h-0 flex flex-col">
        {tab === 'dynamic' ? <DynamicFindingsView /> : <StaticFindingsView />}
      </div>
    </div>
  )
}
