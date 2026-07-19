import type {
  DynamicFinding,
  DynamicScan,
  EasmAsset,
  EasmDashboard,
  EasmScoreRow,
  EasmVuln,
  Finding,
  HealthStatus,
  Language,
  LanguageDetail,
  RunTestResult,
  Scan,
  ScannerStatus,
  ScanTool,
  TargetType,
  ValidationResult,
} from './types'

function getBaseUrl(): string {
  const stored = localStorage.getItem('vulnscan_api_url')
  if (stored) return stored
  // In production the UI is served by the same FastAPI process — use relative URLs
  if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
    return ''
  }
  return 'http://localhost:8765'
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const url = `${getBaseUrl()}${path}`
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) {
    let detail: string
    try {
      const err = await res.json() as { detail?: string }
      detail = err.detail ?? res.statusText
    } catch {
      detail = res.statusText
    }
    throw new Error(`${res.status}: ${detail}`)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

// Health
export const health = () => request<HealthStatus>('GET', '/health')

// Scans
export const listScans = () => request<Scan[]>('GET', '/scans')
export const getScan = (id: string) => request<Scan>('GET', `/scans/${id}`)
export const startScan = (path: string) =>
  request<{ id: string }>('POST', '/scans', { path, authorized: true })

// Findings
export const listFindings = (params: {
  scan_id?: string
  severity?: string
  language?: string
  category?: string
}) => {
  const q = new URLSearchParams()
  if (params.scan_id) q.set('scan_id', params.scan_id)
  if (params.severity) q.set('severity', params.severity)
  if (params.language) q.set('language', params.language)
  if (params.category) q.set('category', params.category)
  return request<Finding[]>('GET', `/findings?${q.toString()}`)
}

// Languages
export const listLanguages = () => request<Language[]>('GET', '/languages')
export const getLanguage = (name: string) =>
  request<LanguageDetail>('GET', `/languages/${name}`)
export const createLanguage = (name: string, yaml_content: string) =>
  request<ValidationResult>('POST', '/languages', { name, yaml_content })
export const updateLanguage = (name: string, yaml_content: string) =>
  request<ValidationResult>('PUT', `/languages/${name}`, { yaml_content })

// Validate only (does not persist — POST + DELETE sequence not needed;
// we use POST for creation which validates first)
export const validateYaml = async (
  name: string,
  yaml_content: string,
): Promise<ValidationResult> => {
  try {
    // Use POST to validate; if it succeeds we created it — caller decides
    await createLanguage(name, yaml_content)
    return { ok: true, errors: [], name }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    return { ok: false, errors: [msg] }
  }
}

// Runtest
export const runTest = (repo: string, target: string, framework?: string) =>
  request<RunTestResult>('POST', '/runtest', { repo, target, framework })

// Scanners
export const listScanners = () =>
  request<Record<string, ScannerStatus>>('GET', '/scanners')

// Dynamic scans
export const startDynamicScan = (
  target: string,
  target_type: TargetType,
  tools?: ScanTool[],
  options?: Record<string, unknown>,
) =>
  request<DynamicScan>('POST', '/dynamic-scans', {
    target,
    target_type,
    tools,
    authorized: true,
    options,
  })

export const listDynamicScans = () =>
  request<DynamicScan[]>('GET', '/dynamic-scans')

export const getDynamicScan = (id: string) =>
  request<DynamicScan>('GET', `/dynamic-scans/${id}`)

export const listDynamicFindings = (params: {
  scan_id?: string
  severity?: string
  tool?: string
  category?: string
}) => {
  const q = new URLSearchParams()
  if (params.scan_id) q.set('scan_id', params.scan_id)
  if (params.severity) q.set('severity', params.severity)
  if (params.tool) q.set('tool', params.tool)
  if (params.category) q.set('category', params.category)
  return request<DynamicFinding[]>('GET', `/dynamic-findings?${q.toString()}`)
}

// ── EASM API ──────────────────────────────────────────────────────────────────

export const easmDashboard = () =>
  request<EasmDashboard>('GET', '/easm/dashboard')

export const easmListAssets = (label?: string) => {
  const q = label ? `?label=${encodeURIComponent(label)}` : ''
  return request<EasmAsset[]>('GET', `/easm/assets${q}`)
}

export const easmGetAsset = (id: string) =>
  request<EasmAsset>('GET', `/easm/assets/${id}`)

export const easmCreateAsset = (payload: {
  identifier: string
  asset_type: string
  label?: string
  tags?: string[]
}) => request<EasmAsset>('POST', '/easm/assets', payload)

export const easmListVulns = (params: {
  asset_id?: string
  label?: string
  severity?: string
  status?: string
  cve?: string
  category?: string
  tool?: string
}) => {
  const q = new URLSearchParams()
  Object.entries(params).forEach(([k, v]) => v && q.set(k, v))
  return request<EasmVuln[]>('GET', `/easm/vulnerabilities?${q}`)
}

export const easmPatchVuln = (id: string, status: string) =>
  request<{ id: string; status: string }>('PATCH', `/easm/vulnerabilities/${id}`, { status })

export const easmComputeScore = (assetId: string) =>
  request<EasmScoreRow>('POST', `/easm/score/${assetId}`)

export const easmGetScore = (assetId: string) =>
  request<EasmScoreRow>('GET', `/easm/score/${assetId}`)

export const easmScoreHistory = (assetId: string) =>
  request<EasmScoreRow[]>('GET', `/easm/scores/history/${assetId}`)

export const easmIngest = async (
  file: File,
  asset: string,
  assetType: string,
  label?: string,
  toolHint?: string,
): Promise<{ imported: number; total_parsed: number; asset_id: string; asset: string }> => {
  const form = new FormData()
  form.append('file', file)
  form.append('asset', asset)
  form.append('asset_type', assetType)
  if (label) form.append('label', label)
  if (toolHint) form.append('tool_hint', toolHint)

  const url = `${localStorage.getItem('vulnscan_api_url') ?? 'http://localhost:8765'}/easm/ingest`
  const res = await fetch(url, { method: 'POST', body: form })
  if (!res.ok) {
    const err = await res.json().catch(() => ({})) as { detail?: string }
    throw new Error(err.detail ?? res.statusText)
  }
  return res.json()
}
