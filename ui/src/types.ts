export type ScanStatus = 'pending' | 'running' | 'done' | 'error'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface Scan {
  id: string
  path: string
  status: ScanStatus
  created_at: string
  finished_at?: string
  source_count: number
  sink_count: number
  pair_count: number
  error?: string
  report?: Record<string, unknown>
}

export interface Finding {
  id: string
  scan_id: string
  kind: 'source' | 'sink'
  category: string
  file: string
  line: number
  name: string
  language: string
  severity: Severity
  pair_id?: string
  confidence?: number
  code_snippet?: string
}

export interface Language {
  name: string
  extensions: string[]
  grammar: string
  source_count: number
  sink_count: number
  available: boolean
}

export interface LanguageDetail extends Language {
  yaml_content: string
  sources?: unknown[]
  sinks?: unknown[]
}

export interface ValidationResult {
  ok: boolean
  errors: string[]
  name?: string
}

export interface RunTestResult {
  passed: boolean
  framework: string
  command: string
  returncode?: number
  output_tail: string
  error?: string
}

export interface HealthStatus {
  status: string
  scan_count: number
  language_count: number
  dynamic_scan_count?: number
  scanners?: Record<string, { available: boolean; description: string }>
}

export type TargetType = 'url' | 'host' | 'mcp'
export type DynamicScanStatus = 'pending' | 'running' | 'done' | 'error'
export type ScanTool = 'nmap' | 'http' | 'api' | 'zap' | 'openvas' | 'mcp' | 'nuclei'

export interface DynamicScan {
  id: string
  target: string
  target_type: TargetType
  tools: ScanTool[]
  status: DynamicScanStatus
  created_at: string
  finished_at?: string
  finding_count: number
  error?: string
}

export interface DynamicFinding {
  id: string
  scan_id: string
  tool: ScanTool
  target: string
  name: string
  description: string
  severity: Severity
  category: string
  evidence?: string
  url?: string
  port?: number
  cve?: string
  remediation?: string
  created_at: string
}

export interface ScannerStatus {
  available: boolean
  description: string
}

// ── EASM types ────────────────────────────────────────────────────────────────

export type AssetType  = 'ip' | 'domain' | 'url' | 'cidr'
export type VulnStatus = 'open' | 'resolved' | 'accepted_risk' | 'false_positive'
export type SourceTool = 'nmap' | 'openvas' | 'zap' | 'nuclei' | 'manual'

export interface EasmAsset {
  id: string
  identifier: string
  asset_type: AssetType
  label?: string
  tags: string[]
  created_at: string
  updated_at: string
  latest_score?: EasmScoreRow | null
  open_by_severity?: Record<string, number>
}

export type ExploitMaturity =
  | 'trivial'
  | 'actively_exploited'
  | 'proof_of_concept'
  | 'moderate'
  | 'theoretical'
  | 'low'
  | 'requires_chain'
  | 'known'
  | 'unknown'

export interface EasmVuln {
  id: string
  asset_id: string
  source_tool: SourceTool
  source_file?: string
  name: string
  description?: string
  severity: Severity
  cvss_score?: number
  cve?: string
  cwe?: string
  category: string
  port?: number
  protocol?: string
  url?: string
  evidence?: string
  remediation?: string
  discovered_at: string
  last_seen_at: string
  resolved_at?: string
  status: VulnStatus
  // enrichment fields
  cvss_vector?: string
  epss_score?: number
  epss_percentile?: number
  kev?: number
  exploit_maturity?: ExploitMaturity
  exploit_insight?: string
  // joined from easm_assets
  identifier?: string
  asset_type?: AssetType
  label?: string
}

export interface EasmScoreRow {
  id: string
  asset_id?: string
  vendor_label?: string
  score: number
  grade: string
  scored_at: string
  breakdown?: EasmBreakdown
  breakdown_json?: string
}

export interface EasmBreakdown {
  by_severity: Record<string, number>
  deduction_by_severity: Record<string, number>
  total_deduction: number
  top_issues: Array<{
    name: string
    severity: string
    cve?: string
    category: string
    asset: string
    penalty: number
  }>
  oldest_open_days: number
  open_count: number
}

export interface EasmDashboard {
  asset_count: number
  vuln_count: number
  open_count: number
  by_severity: Record<string, number>
  average_score: number | null
  grade_distribution: Record<string, number>
  top_critical_open: Array<{
    name: string
    cve?: string
    severity: string
    category: string
    asset: string
  }>
}
