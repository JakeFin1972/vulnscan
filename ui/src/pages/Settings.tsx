import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Save, Plus, Trash2, CheckCircle, XCircle, Loader2 } from 'lucide-react'
import { health } from '@/api'

const API_URL_KEY = 'vulnscan_api_url'
const PATHS_KEY = 'vulnscan_authorized_paths'

function loadPaths(): string[] {
  try { return JSON.parse(localStorage.getItem(PATHS_KEY) ?? '[]') as string[] }
  catch { return [] }
}

export default function Settings() {
  const [apiUrl, setApiUrl] = useState(
    localStorage.getItem(API_URL_KEY) ?? 'http://localhost:8765'
  )
  const [saved, setSaved] = useState(false)
  const [paths, setPaths] = useState<string[]>(loadPaths)
  const [newPath, setNewPath] = useState('')

  const healthQ = useQuery({
    queryKey: ['health', apiUrl],
    queryFn: health,
    retry: false,
    staleTime: 5000,
  })

  function saveApiUrl() {
    localStorage.setItem(API_URL_KEY, apiUrl)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
    healthQ.refetch()
  }

  function addPath() {
    const p = newPath.trim()
    if (!p || paths.includes(p)) return
    const updated = [...paths, p]
    setPaths(updated)
    localStorage.setItem(PATHS_KEY, JSON.stringify(updated))
    setNewPath('')
  }

  function removePath(p: string) {
    const updated = paths.filter(x => x !== p)
    setPaths(updated)
    localStorage.setItem(PATHS_KEY, JSON.stringify(updated))
  }

  return (
    <div className="p-6 max-w-xl space-y-6">
      <h1 className="text-sm font-semibold text-slate-100">Settings</h1>

      {/* Engine */}
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
        <h2 className="text-xs font-medium text-slate-400 uppercase tracking-wider">Engine</h2>
        <div className="flex items-center gap-2">
          {healthQ.isLoading ? (
            <Loader2 className="h-3.5 w-3.5 text-slate-500 animate-spin" />
          ) : healthQ.isSuccess ? (
            <CheckCircle className="h-3.5 w-3.5 text-teal-400" />
          ) : (
            <XCircle className="h-3.5 w-3.5 text-red-400" />
          )}
          <span className="text-xs text-slate-400">
            {healthQ.isLoading ? 'Connecting…'
              : healthQ.isSuccess ? `Connected — ${healthQ.data.scan_count} scans, ${healthQ.data.language_count} languages`
              : 'Not reachable'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="text"
            value={apiUrl}
            onChange={e => setApiUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && saveApiUrl()}
            className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 focus:outline-none focus:border-teal-600"
          />
          <button
            onClick={saveApiUrl}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded border border-slate-700 transition-colors"
          >
            <Save className="h-3.5 w-3.5" />
            {saved ? 'Saved!' : 'Save'}
          </button>
        </div>
        <p className="text-xs text-slate-600">
          Stored in localStorage. Start the API with:{' '}
          <code className="font-mono text-slate-500">uvicorn vulnscan.api:app --port 8765</code>
        </p>
      </section>

      {/* Authorized paths */}
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
        <h2 className="text-xs font-medium text-slate-400 uppercase tracking-wider">Authorized Paths</h2>
        <p className="text-xs text-slate-500">
          Paths you commonly scan. This is a convenience allowlist for quick
          access — the scanner always requires per-scan confirmation.
        </p>

        {paths.length > 0 ? (
          <ul className="space-y-1.5">
            {paths.map(p => (
              <li key={p} className="flex items-center gap-2 bg-slate-800/50 rounded px-3 py-1.5">
                <span className="font-mono text-xs text-slate-300 flex-1 truncate">{p}</span>
                <button
                  onClick={() => removePath(p)}
                  className="text-slate-600 hover:text-red-400 transition-colors"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <div className="text-xs text-slate-600 py-2">No authorized paths saved.</div>
        )}

        <div className="flex items-center gap-2">
          <input
            type="text"
            value={newPath}
            onChange={e => setNewPath(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && addPath()}
            placeholder="/path/to/authorized/repo"
            className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-teal-600"
          />
          <button
            onClick={addPath}
            disabled={!newPath.trim()}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 text-xs rounded border border-slate-700 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Add
          </button>
        </div>
      </section>

      {/* About */}
      <section className="text-xs text-slate-600 space-y-1">
        <p>vulnscan v0.1 — forward-taint adversarial vulnerability scanner.</p>
        <p>Defensive tooling for authorized code review only.</p>
      </section>
    </div>
  )
}
