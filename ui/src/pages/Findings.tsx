import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { X, Loader2, ChevronRight } from 'lucide-react'
import { listFindings, listScans } from '@/api'
import type { Finding, Severity } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

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
        {options.map(o => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
    </label>
  )
}

export default function Findings() {
  const [params] = useSearchParams()
  const initialScanId = params.get('scan_id') ?? ''

  const [scanId, setScanId] = useState(initialScanId)
  const [severity, setSeverity] = useState('')
  const [language, setLanguage] = useState('')
  const [category, setCategory] = useState('')
  const [selected, setSelected] = useState<Finding | null>(null)

  const scansQ = useQuery({ queryKey: ['scans'], queryFn: listScans })
  const findingsQ = useQuery({
    queryKey: ['findings', scanId, severity, language, category],
    queryFn: () => listFindings({ scan_id: scanId || undefined, severity: severity || undefined, language: language || undefined, category: category || undefined }),
    refetchInterval: 5000,
  })

  const findings = findingsQ.data ?? []
  const scans = scansQ.data ?? []

  const languages = [...new Set(findings.map(f => f.language).filter(Boolean))].sort()
  const categories = [...new Set(findings.map(f => f.category))].sort()

  function clearFilters() {
    setScanId(''); setSeverity(''); setLanguage(''); setCategory('')
  }
  const hasFilters = !!(scanId || severity || language || category)

  return (
    <div className="flex h-full">
      {/* Main table */}
      <div className="flex-1 flex flex-col min-w-0">
        <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center gap-3">
          <h1 className="text-sm font-semibold text-slate-100 mr-2">Findings</h1>

          {/* Scan filter */}
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

          <FilterSelect label="Severity" value={severity} options={SEVERITIES} onChange={setSeverity} />
          <FilterSelect label="Language" value={language} options={languages} onChange={setLanguage} />
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

        {findingsQ.isLoading ? (
          <div className="flex items-center justify-center flex-1 text-slate-600">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />
            <span className="text-sm">Loading findings…</span>
          </div>
        ) : findings.length === 0 ? (
          <div className="flex flex-col items-center justify-center flex-1 gap-2 text-slate-600">
            <span className="text-sm">No findings</span>
            {hasFilters && <span className="text-xs">Try clearing filters</span>}
          </div>
        ) : (
          <div className="overflow-auto flex-1">
            <table className="w-full text-xs border-collapse">
              <thead className="sticky top-0 bg-slate-950 z-10">
                <tr className="text-left text-slate-500 border-b border-slate-800">
                  <th className="px-4 py-2 font-medium w-24">Severity</th>
                  <th className="px-4 py-2 font-medium w-16">Kind</th>
                  <th className="px-4 py-2 font-medium w-20">Language</th>
                  <th className="px-4 py-2 font-medium">Category</th>
                  <th className="px-4 py-2 font-medium">File:Line</th>
                  <th className="px-4 py-2 font-medium">Name</th>
                  <th className="w-6" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {findings.map(f => (
                  <tr
                    key={f.id}
                    onClick={() => setSelected(s => s?.id === f.id ? null : f)}
                    className={`cursor-pointer transition-colors ${
                      selected?.id === f.id
                        ? 'bg-teal-500/10'
                        : 'hover:bg-slate-800/50'
                    }`}
                  >
                    <td className="px-4 py-2">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-4 py-2 text-slate-400 font-mono">{f.kind}</td>
                    <td className="px-4 py-2">
                      <span className="px-1.5 py-0.5 rounded text-xs bg-slate-800 text-slate-300 border border-slate-700">
                        {f.language || '—'}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-slate-300">{f.category}</td>
                    <td className="px-4 py-2 font-mono text-slate-400 max-w-xs truncate">
                      {shortPath(f.file)}:<span className="text-teal-500">{f.line}</span>
                    </td>
                    <td className="px-4 py-2 font-mono text-slate-200 max-w-xs truncate">{f.name}</td>
                    <td className="pr-3">
                      <ChevronRight className={`h-3.5 w-3.5 text-slate-600 transition-transform ${selected?.id === f.id ? 'rotate-90' : ''}`} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detail drawer */}
      {selected && (
        <div className="w-96 flex-shrink-0 border-l border-slate-800 bg-slate-900 flex flex-col overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
            <span className="text-sm font-medium text-slate-200">Finding Detail</span>
            <button onClick={() => setSelected(null)} className="text-slate-500 hover:text-slate-300 transition-colors">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="overflow-y-auto flex-1 p-4 space-y-4 text-xs">
            <div>
              <SeverityBadge severity={selected.severity} className="mb-2" />
              <div className="font-mono text-slate-200 text-sm mt-1">{selected.name}</div>
            </div>

            <Field label="Kind" value={selected.kind} />
            <Field label="Category" value={selected.category} mono />
            <Field label="Language" value={selected.language || '(unknown)'} />
            <Field
              label="Location"
              value={`${selected.file}:${selected.line}`}
              mono
            />

            {selected.pair_id && (
              <div className="rounded bg-slate-800/60 border border-slate-700 p-3">
                <div className="text-slate-500 text-xs mb-1">Part of pair</div>
                <div className="font-mono text-teal-400 text-xs break-all">{selected.pair_id}</div>
              </div>
            )}

            <div className="rounded bg-slate-950 border border-slate-700 p-3">
              <div className="text-slate-500 text-xs mb-1">Full path</div>
              <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap break-all leading-relaxed">
                {selected.file}:{selected.line}
              </pre>
            </div>

            <div className="rounded bg-slate-950 border border-slate-700 p-3">
              <div className="text-slate-500 text-xs mb-1">Raw JSON</div>
              <pre className="font-mono text-xs text-slate-400 whitespace-pre-wrap overflow-auto">
                {JSON.stringify(selected, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-slate-500 mb-0.5">{label}</div>
      <div className={mono ? 'font-mono text-slate-300' : 'text-slate-300'}>{value}</div>
    </div>
  )
}
