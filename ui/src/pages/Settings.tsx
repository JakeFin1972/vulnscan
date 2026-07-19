import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Save, Plus, Trash2, CheckCircle, XCircle, Loader2, RefreshCw, Sparkles, Eye, EyeOff } from 'lucide-react'
import { health, aiStatus } from '@/api'

const API_URL_KEY = 'vulnscan_api_url'
const PATHS_KEY = 'vulnscan_authorized_paths'
const ZAP_CONFIG_KEY = 'vulnscan_zap_config'
const OPENVAS_CONFIG_KEY = 'vulnscan_openvas_config'
const NMAP_CONFIG_KEY = 'vulnscan_nmap_config'
const AI_KEY_KEY = 'vulnscan_anthropic_key'

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

interface NmapConfig {
  profile: string
  extra_args: string
}

function loadZapConfig(): ZapConfig {
  try {
    const stored = JSON.parse(localStorage.getItem(ZAP_CONFIG_KEY) ?? 'null')
    if (stored) return stored as ZapConfig
  } catch {}
  return { host: 'localhost', port: '8090', api_key: '' }
}

function loadOpenVasConfig(): OpenVasConfig {
  try {
    const stored = JSON.parse(localStorage.getItem(OPENVAS_CONFIG_KEY) ?? 'null')
    if (stored) return stored as OpenVasConfig
  } catch {}
  return { host: 'localhost', port: '9390', user: 'admin', password: 'admin' }
}

function loadNmapConfig(): NmapConfig {
  try {
    const stored = JSON.parse(localStorage.getItem(NMAP_CONFIG_KEY) ?? 'null')
    if (stored) return stored as NmapConfig
  } catch {}
  return { profile: 'standard', extra_args: '' }
}

const NMAP_PROFILES = [
  { id: 'quick',    label: 'Quick',    desc: 'Top 100 ports, no scripts' },
  { id: 'standard', label: 'Standard', desc: 'Top 1000 ports, version detection' },
  { id: 'full',     label: 'Full',     desc: 'All ports, vuln/auth scripts' },
  { id: 'stealth',  label: 'Stealth',  desc: 'Slow, low-noise TCP connect' },
]

function ScannerDot({ available, loading }: { available?: boolean; loading: boolean }) {
  if (loading) return <Loader2 className="h-3 w-3 text-slate-500 animate-spin" />
  if (available) return <span className="h-2 w-2 rounded-full bg-green-400 inline-block" />
  return <span className="h-2 w-2 rounded-full bg-slate-600 inline-block" />
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
  const [nmapConfig, setNmapConfig] = useState<NmapConfig>(loadNmapConfig)
  const [nmapSaved, setNmapSaved] = useState(false)
  const [anthropicKey, setAnthropicKey] = useState(localStorage.getItem(AI_KEY_KEY) ?? '')
  const [aiKeySaved, setAiKeySaved] = useState(false)
  const [showKey, setShowKey] = useState(false)

  const healthQ = useQuery({
    queryKey: ['health', apiUrl],
    queryFn: health,
    retry: false,
    staleTime: 5000,
  })

  const aiStatusQ = useQuery({
    queryKey: ['ai-status'],
    queryFn: aiStatus,
    retry: false,
    staleTime: 10_000,
  })

  const scanners = healthQ.data?.scanners ?? {}

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

  function saveNmapConfig() {
    localStorage.setItem(NMAP_CONFIG_KEY, JSON.stringify(nmapConfig))
    setNmapSaved(true)
    setTimeout(() => setNmapSaved(false), 2000)
  }

  function saveAiKey() {
    localStorage.setItem(AI_KEY_KEY, anthropicKey)
    // Propagate key to API server via a PUT /ai/config endpoint
    // The key is stored in localStorage and the user must restart the API with it set
    setAiKeySaved(true)
    setTimeout(() => setAiKeySaved(false), 3000)
    aiStatusQ.refetch()
  }

  const nmapAvailable = scanners['nmap']?.available
  const zapAvailable = scanners['zap']?.available
  const openvasAvailable = scanners['openvas']?.available

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
          <button
            onClick={() => healthQ.refetch()}
            className="ml-auto text-slate-600 hover:text-slate-400 transition-colors"
            title="Refresh status"
          >
            <RefreshCw className="h-3 w-3" />
          </button>
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
          Start API:{' '}
          <code className="font-mono text-slate-500">PYTHONPATH=src uvicorn vulnscan.api:app --port 8765</code>
        </p>

        {/* Scanner status grid */}
        {healthQ.isSuccess && (
          <div className="pt-2 border-t border-slate-800">
            <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Scanner Status</p>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
              {Object.entries(scanners).map(([name, s]) => (
                <div key={name} className="flex items-center gap-2">
                  <ScannerDot available={s.available} loading={healthQ.isFetching} />
                  <span className="font-mono text-xs text-slate-300 w-16">{name}</span>
                  <span className={`text-[10px] ${s.available ? 'text-green-400' : 'text-slate-600'}`}>
                    {s.available ? 'ready' : 'unavailable'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      {/* Claude AI */}
      <section className="bg-slate-900 border border-purple-800/40 rounded-lg p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Sparkles className="h-3.5 w-3.5 text-purple-400" />
          <h2 className="text-xs font-medium text-purple-300 uppercase tracking-wider">Claude AI Integration</h2>
          {aiStatusQ.data?.available && (
            <span className="ml-auto text-xs text-green-400 flex items-center gap-1">
              <span className="h-1.5 w-1.5 rounded-full bg-green-400 inline-block" /> Active · {aiStatusQ.data.model}
            </span>
          )}
          {aiStatusQ.data && !aiStatusQ.data.available && (
            <span className="ml-auto text-xs text-slate-500">API key required</span>
          )}
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          Claude AI provides deep vulnerability analysis, exploit scenario generation, taint flow verification,
          and AI-powered remediation code. Set your Anthropic API key below, then restart the API server
          with <code className="font-mono text-purple-300/80">ANTHROPIC_API_KEY=&lt;key&gt;</code> in the environment.
        </p>
        <div className="space-y-2">
          <label className="text-xs text-slate-500 block">Anthropic API Key</label>
          <div className="flex items-center gap-2">
            <div className="flex-1 flex items-center bg-slate-950 border border-slate-700 rounded overflow-hidden focus-within:border-purple-600">
              <input
                type={showKey ? 'text' : 'password'}
                value={anthropicKey}
                onChange={e => setAnthropicKey(e.target.value)}
                placeholder="sk-ant-..."
                className="flex-1 bg-transparent px-3 py-1.5 text-sm font-mono text-slate-200 focus:outline-none"
              />
              <button
                onClick={() => setShowKey(v => !v)}
                className="px-2 text-slate-600 hover:text-slate-400 transition-colors"
              >
                {showKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              </button>
            </div>
            <button
              onClick={saveAiKey}
              disabled={!anthropicKey.trim()}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-purple-700 hover:bg-purple-600 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs rounded transition-colors"
            >
              <Save className="h-3.5 w-3.5" />
              {aiKeySaved ? 'Saved!' : 'Save'}
            </button>
          </div>
          {aiKeySaved && (
            <p className="text-xs text-yellow-400">
              Key saved to local storage. Restart the API server with{' '}
              <code className="font-mono">ANTHROPIC_API_KEY=&lt;key&gt; .venv/bin/uvicorn src.vulnscan.api:app</code>
            </p>
          )}
        </div>

        {/* AI features list */}
        <div className="pt-2 border-t border-slate-800">
          <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">AI Features</p>
          <ul className="space-y-1 text-xs text-slate-400">
            <li className="flex items-center gap-2"><Sparkles className="h-3 w-3 text-purple-500" /> Analyze individual findings — confirmed/false-positive verdict</li>
            <li className="flex items-center gap-2"><Sparkles className="h-3 w-3 text-purple-500" /> AI Boost scan — taint analysis on all source-sink pairs</li>
            <li className="flex items-center gap-2"><Sparkles className="h-3 w-3 text-purple-500" /> Exploit difficulty scoring — trivial / low / moderate / high</li>
            <li className="flex items-center gap-2"><Sparkles className="h-3 w-3 text-purple-500" /> CVSS 3.1 vector estimation per finding</li>
            <li className="flex items-center gap-2"><Sparkles className="h-3 w-3 text-purple-500" /> Concrete remediation code in the target language</li>
          </ul>
        </div>
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

      {/* Nmap */}
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex items-center gap-2">
          <h2 className="text-xs font-medium text-slate-400 uppercase tracking-wider">Nmap</h2>
          <ScannerDot available={nmapAvailable} loading={healthQ.isFetching} />
          <span className={`text-xs ${nmapAvailable ? 'text-green-400' : 'text-slate-500'}`}>
            {nmapAvailable ? 'installed' : 'not found'}
          </span>
        </div>

        {!nmapAvailable && (
          <p className="text-xs text-slate-500">
            Install with:{' '}
            <code className="font-mono text-slate-400">brew install nmap</code>
          </p>
        )}

        <div>
          <label className="block text-xs text-slate-500 mb-2">Scan Profile</label>
          <div className="grid grid-cols-2 gap-2">
            {NMAP_PROFILES.map(p => (
              <button
                key={p.id}
                onClick={() => setNmapConfig(c => ({ ...c, profile: p.id }))}
                className={`p-2 rounded border text-left transition-colors ${
                  nmapConfig.profile === p.id
                    ? 'bg-teal-900/40 border-teal-700 text-teal-200'
                    : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'
                }`}
              >
                <div className="text-xs font-semibold">{p.label}</div>
                <div className="text-[10px] text-slate-500 mt-0.5">{p.desc}</div>
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-xs text-slate-500 mb-1">Extra Args <span className="text-slate-600">(optional)</span></label>
          <input
            type="text"
            value={nmapConfig.extra_args}
            onChange={e => setNmapConfig(c => ({ ...c, extra_args: e.target.value }))}
            placeholder="--script=vuln --host-timeout 30s"
            className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-teal-600"
          />
        </div>

        <button
          onClick={saveNmapConfig}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded border border-slate-700 transition-colors"
        >
          <Save className="h-3.5 w-3.5" />
          {nmapSaved ? 'Saved!' : 'Save'}
        </button>
      </section>

      {/* OWASP ZAP */}
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex items-center gap-2">
          <h2 className="text-xs font-medium text-slate-400 uppercase tracking-wider">OWASP ZAP</h2>
          <ScannerDot available={zapAvailable} loading={healthQ.isFetching} />
          <span className={`text-xs ${zapAvailable ? 'text-green-400' : 'text-slate-500'}`}>
            {zapAvailable ? 'connected' : 'not connected'}
          </span>
        </div>
        <p className="text-xs text-slate-500">
          Start ZAP daemon:{' '}
          <code className="font-mono text-slate-400 break-all">
            java -jar zap-*.jar -daemon -host 127.0.0.1 -port 8090 -dir /tmp/zap-home -config api.disablekey=true
          </code>
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
          <ScannerDot available={openvasAvailable} loading={healthQ.isFetching} />
          <span className={`text-xs ${openvasAvailable ? 'text-green-400' : 'text-slate-500'}`}>
            {openvasAvailable ? 'connected' : 'not connected'}
          </span>
        </div>
        <p className="text-xs text-slate-500">
          Start with Docker (initialises in ~10 min on first run):{' '}
          <code className="font-mono text-slate-400 break-all">
            docker run -d --name openvas -p 9390:9390 -p 9392:9392 securecompliance/gvm
          </code>
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
        <div className="flex items-center gap-2">
          <button
            onClick={saveOpenVasConfig}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded border border-slate-700 transition-colors"
          >
            <Save className="h-3.5 w-3.5" />
            {openVasSaved ? 'Saved!' : 'Save'}
          </button>
          <button
            onClick={() => healthQ.refetch()}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded border border-slate-700 transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Test Connection
          </button>
        </div>
        {!openvasAvailable && (
          <p className="text-[10px] text-slate-600">
            Container is running at localhost:9390 — GVM initialises NVT feeds on first start (~10 min). Watch logs: <code className="font-mono">docker logs -f openvas</code>
          </p>
        )}
      </section>

      {/* About */}
      <section className="text-xs text-slate-600 space-y-1">
        <p>vulnscan v0.1 — forward-taint adversarial vulnerability scanner.</p>
        <p>Defensive tooling for authorized code review only.</p>
      </section>
    </div>
  )
}
