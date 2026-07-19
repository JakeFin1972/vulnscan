import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Save, Plus, Trash2, CheckCircle, XCircle, Loader2 } from 'lucide-react'
import { health } from '@/api'

const API_URL_KEY = 'vulnscan_api_url'
const PATHS_KEY = 'vulnscan_authorized_paths'
const ZAP_CONFIG_KEY = 'vulnscan_zap_config'
const OPENVAS_CONFIG_KEY = 'vulnscan_openvas_config'

function loadPaths(): string[] {
  try { return JSON.parse(localStorage.getItem(PATHS_KEY) ?? '[]') as string[] }
  catch { return [] }
}

interface ZapConfig {
  host: string
  port: string
  api_key: string
}

interface OpenVasConfig {
  host: string
  port: string
  user: string
  password: string
}

function loadZapConfig(): ZapConfig {
  try {
    const stored = JSON.parse(localStorage.getItem(ZAP_CONFIG_KEY) ?? 'null')
    if (stored) return stored as ZapConfig
  } catch {}
  return { host: 'localhost', port: '8080', api_key: '' }
}

function loadOpenVasConfig(): OpenVasConfig {
  try {
    const stored = JSON.parse(localStorage.getItem(OPENVAS_CONFIG_KEY) ?? 'null')
    if (stored) return stored as OpenVasConfig
  } catch {}
  return { host: 'localhost', port: '9390', user: 'admin', password: 'admin' }
}

export default function Settings() {
  const [apiUrl, setApiUrl] = useState(
    localStorage.getItem(API_URL_KEY) ?? 'http://localhost:8765'
  )
  const [saved, setSaved] = useState(false)
  const [paths, setPaths] = useState<string[]>(loadPaths)
  const [newPath, setNewPath] = useState('')

  const [zapConfig, setZapConfig] = useState<ZapConfig>(loadZapConfig)
  const [zapSaved, setZapSaved] = useState(false)
  const [openVasConfig, setOpenVasConfig] = useState<OpenVasConfig>(loadOpenVasConfig)
  const [openVasSaved, setOpenVasSaved] = useState(false)

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

  function saveZapConfig() {
    localStorage.setItem(ZAP_CONFIG_KEY, JSON.stringify(zapConfig))
    setZapSaved(true)
    setTimeout(() => setZapSaved(false), 2000)
  }

  function saveOpenVasConfig() {
    localStorage.setItem(OPENVAS_CONFIG_KEY, JSON.stringify(openVasConfig))
    setOpenVasSaved(true)
    setTimeout(() => setOpenVasSaved(false), 2000)
  }

  const zapConfigured = zapConfig.host !== 'localhost' || zapConfig.api_key !== '' || zapConfig.port !== '8080'
  const openVasConfigured = openVasConfig.host !== 'localhost' || openVasConfig.port !== '9390' || openVasConfig.user !== 'admin'

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

      {/* OWASP ZAP */}
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex items-center gap-2">
          <h2 className="text-xs font-medium text-slate-400 uppercase tracking-wider">OWASP ZAP</h2>
          <span className={`h-2 w-2 rounded-full flex-shrink-0 ${zapConfigured ? 'bg-teal-400' : 'bg-slate-600'}`} />
          <span className={`text-xs ${zapConfigured ? 'text-teal-400' : 'text-slate-600'}`}>
            {zapConfigured ? 'configured' : 'not configured'}
          </span>
        </div>
        <p className="text-xs text-slate-500">
          Connect to a running ZAP daemon. Start with:{' '}
          <code className="font-mono text-slate-400">docker run -u zap -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -port 8080 -config api.disablekey=true</code>
        </p>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="block text-xs text-slate-500 mb-1">Host</label>
            <input
              type="text"
              value={zapConfig.host}
              onChange={e => setZapConfig(c => ({ ...c, host: e.target.value }))}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 focus:outline-none focus:border-teal-600"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Port</label>
            <input
              type="text"
              value={zapConfig.port}
              onChange={e => setZapConfig(c => ({ ...c, port: e.target.value }))}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 focus:outline-none focus:border-teal-600"
            />
          </div>
        </div>
        <div>
          <label className="block text-xs text-slate-500 mb-1">API Key</label>
          <input
            type="text"
            value={zapConfig.api_key}
            onChange={e => setZapConfig(c => ({ ...c, api_key: e.target.value }))}
            placeholder="leave empty if disabled"
            className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-teal-600"
          />
        </div>
        <button
          onClick={saveZapConfig}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded border border-slate-700 transition-colors"
        >
          <Save className="h-3.5 w-3.5" />
          {zapSaved ? 'Saved!' : 'Save'}
        </button>
      </section>

      {/* OpenVAS / GVM */}
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex items-center gap-2">
          <h2 className="text-xs font-medium text-slate-400 uppercase tracking-wider">OpenVAS / GVM</h2>
          <span className={`h-2 w-2 rounded-full flex-shrink-0 ${openVasConfigured ? 'bg-teal-400' : 'bg-slate-600'}`} />
          <span className={`text-xs ${openVasConfigured ? 'text-teal-400' : 'text-slate-600'}`}>
            {openVasConfigured ? 'configured' : 'not configured'}
          </span>
        </div>
        <p className="text-xs text-slate-500">
          Connect to a GVM daemon. Start with:{' '}
          <code className="font-mono text-slate-400">docker run -d --name openvas -p 9390:9390 greenbone/community-edition</code>
        </p>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="block text-xs text-slate-500 mb-1">Host</label>
            <input
              type="text"
              value={openVasConfig.host}
              onChange={e => setOpenVasConfig(c => ({ ...c, host: e.target.value }))}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 focus:outline-none focus:border-teal-600"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Port</label>
            <input
              type="text"
              value={openVasConfig.port}
              onChange={e => setOpenVasConfig(c => ({ ...c, port: e.target.value }))}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 focus:outline-none focus:border-teal-600"
            />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="block text-xs text-slate-500 mb-1">Username</label>
            <input
              type="text"
              value={openVasConfig.user}
              onChange={e => setOpenVasConfig(c => ({ ...c, user: e.target.value }))}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 focus:outline-none focus:border-teal-600"
            />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1">Password</label>
            <input
              type="password"
              value={openVasConfig.password}
              onChange={e => setOpenVasConfig(c => ({ ...c, password: e.target.value }))}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 focus:outline-none focus:border-teal-600"
            />
          </div>
        </div>
        <button
          onClick={saveOpenVasConfig}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded border border-slate-700 transition-colors"
        >
          <Save className="h-3.5 w-3.5" />
          {openVasSaved ? 'Saved!' : 'Save'}
        </button>
      </section>

      {/* About */}
      <section className="text-xs text-slate-600 space-y-1">
        <p>vulnscan v0.1 — forward-taint adversarial vulnerability scanner.</p>
        <p>Defensive tooling for authorized code review only.</p>
      </section>
    </div>
  )
}
