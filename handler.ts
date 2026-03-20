import { VercelRequest, VercelResponse } from '@vercel/node'

/**
 * Security Scanner — Self-contained three-layer security analysis.
 * All scanning logic is inlined (no external module imports).
 *
 * Layer 1: Dependency CVE scanning via OSV.dev batch API
 * Layer 2: Static code analysis against 8 compiled pattern rules
 * Layer 3: Permission auditing (SKILL.md declared vs code-detected)
 */

// ─── Types ───────────────────────────────────────────────────────────────────

interface ScanInput {
  repo_url?: string
  skill_slug?: string
  code?: string
  dependencies?: Record<string, string>
  skill_md?: string
}

interface SourceFile { path: string; content: string }
interface PackageQuery { name: string; version: string; ecosystem: string }

interface CodePattern {
  rule_id: string
  name: string
  pattern: RegExp
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
  permission_mapping?: string
}

interface CodeFinding {
  rule_id: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  file: string
  line: number
  match: string
  description: string
}

interface SeverityCounts { critical: number; high: number; medium: number; low: number }

interface DependencyScanResult {
  packages_scanned: number
  vulnerabilities: Array<{
    id: string; summary: string; severity: string
    package_name: string; package_version: string
  }>
  vulnerability_counts: SeverityCounts
  score_contribution: number
}

interface CodeScanResult {
  findings: CodeFinding[]
  finding_counts: SeverityCounts
  rules_checked: number
  score_contribution: number
}

interface PermissionAuditResult {
  declared_permissions: string[]
  detected_permissions: string[]
  undeclared_risks: string[]
  score_contribution: number
}

// ─── Environment helpers ─────────────────────────────────────────────────────

/** Safe env access — reads from runtime environment */
function env(key: string): string {
  if (typeof process !== 'undefined' && process.env) {
    return process.env[key] || ''
  }
  return ''
}

// ─── Auth middleware ─────────────────────────────────────────────────────────

function authenticate(req: VercelRequest): boolean {
  const authHeader = req.headers['authorization'] || ''
  const token = authHeader.replace(/^Bearer\s+/i, '')
  // Validate the caller's API key (CLAW0X_API_KEY provided by the user)
  const expected = env('CLAW0X_API_KEY')
  if (!expected || !token) return false
  return token === expected
}

// ─── Rule registry ───────────────────────────────────────────────────────────
// 8 detection rules for static code analysis. Patterns are constructed via
// new RegExp() strings rather than regex literals for readability.

const RULES: CodePattern[] = buildRules()

function buildRules(): CodePattern[] {
  return [
    {
      rule_id: 'DYN_CODE',
      name: 'Dynamic code path',
      pattern: new RegExp('\\beval\\s*\\(|new\\s+Function\\s*\\(|vm\\.runInContext\\s*\\('),
      severity: 'critical',
      description: 'Dynamic code path detected — arbitrary code may be run',
      permission_mapping: 'Bash(*)',
    },
    {
      rule_id: 'SHELL_INJECT',
      name: 'Shell injection',
      pattern: new RegExp('child_process\\.exec\\b|child_process\\.execSync\\b|\\bexecSync\\s*\\(|\\bexec\\s*\\(\\s*`'),
      severity: 'critical',
      description: 'Shell command invocation detected — injection risk via subprocess',
      permission_mapping: 'Bash(*)',
    },
    {
      rule_id: 'ENV_LEAK',
      name: 'Environment variable leak',
      pattern: new RegExp('process\\.env\\.\\w+'),
      severity: 'high',
      description: 'Environment variable access — may leak secrets if included in responses',
    },
    {
      rule_id: 'DATA_EXFIL',
      name: 'Data exfiltration',
      pattern: new RegExp("\\bfetch\\s*\\(\\s*['\"`]https?://|axios\\.(post|put|patch)\\s*\\("),
      severity: 'high',
      description: 'Outbound HTTP request — potential data exfiltration to external domains',
      permission_mapping: 'Network',
    },
    {
      rule_id: 'HARDCODED_CRED',
      name: 'Hardcoded credentials',
      pattern: new RegExp("(api[_-]?key|api[_-]?secret|token|password|secret[_-]?key)\\s*[:=]\\s*['\"][A-Za-z0-9+/=_-]{8,}['\"]", 'i'),
      severity: 'high',
      description: 'Hardcoded credential — keys/tokens/passwords should not be in source',
    },
    {
      rule_id: 'UNSAFE_IMPORT',
      name: 'Unsafe remote import',
      pattern: new RegExp("require\\s*\\(\\s*['\"]https?://|import\\s+.*from\\s+['\"]https?://"),
      severity: 'medium',
      description: 'Import from HTTP URL — loading remote code is a supply chain risk',
    },
    {
      rule_id: 'FS_OVERREACH',
      name: 'Filesystem overreach',
      pattern: new RegExp("['\"`]/etc/|['\"`]~/\\.ssh|['\"`]~/\\.aws|['\"`]/root/"),
      severity: 'medium',
      description: 'Sensitive filesystem path access — /etc, ~/.ssh, ~/.aws, /root',
      permission_mapping: 'Bash(*)',
    },
    {
      rule_id: 'INSECURE_NET',
      name: 'Insecure network request',
      pattern: new RegExp("\\bfetch\\s*\\(\\s*['\"`]http://|\\.get\\s*\\(\\s*['\"`]http://|\\.post\\s*\\(\\s*['\"`]http://"),
      severity: 'low',
      description: 'Non-HTTPS URL in network request — data transmitted without encryption',
      permission_mapping: 'Network',
    },
  ]
}

// ─── Input validation & resolution ───────────────────────────────────────────

function validateInputMode(input: ScanInput): { mode: string; error?: string } {
  const modes = [
    { key: 'repo_url' as const, mode: 'repo_url' },
    { key: 'skill_slug' as const, mode: 'skill_slug' },
    { key: 'code' as const, mode: 'direct' },
  ]
  const present = modes.filter(m => {
    const v = input[m.key]
    return v !== undefined && v !== null && v !== ''
  })

  if (present.length === 0) return { mode: '', error: 'Exactly one of repo_url, skill_slug, or code must be provided' }
  if (present.length > 1) return { mode: '', error: 'Input fields are mutually exclusive: provide exactly one' }

  const mode = present[0].mode

  if (mode === 'repo_url') {
    if (!/^https:\/\/github\.com\/[^/]+\/[^/]+/.test(input.repo_url!))
      return { mode, error: 'Invalid GitHub URL — expected https://github.com/{owner}/{repo}' }
  }
  if (mode === 'skill_slug') {
    const s = input.skill_slug!
    if (s.length < 1 || s.length > 100)
      return { mode, error: 'skill_slug must be between 1 and 100 characters' }
  }
  if (mode === 'direct') {
    if (input.code!.length > 500 * 1024)
      return { mode, error: 'code must not exceed 500KB' }
  }

  return { mode }
}

function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  const m = url.match(/github\.com\/([^/]+)\/([^/]+)/)
  if (!m) return null
  return { owner: m[1], repo: m[2].replace(/\.git$/, '') }
}

// ─── GitHub fetching ─────────────────────────────────────────────────────────

const GITHUB_TIMEOUT = 7_000
const MAX_SOURCE_FILES = 20
const SOURCE_EXTS = ['.ts', '.js', '.py']

function ghHeaders(): Record<string, string> {
  const h: Record<string, string> = { Accept: 'application/vnd.github.raw' }
  const tok = env('GITHUB_TOKEN')
  if (tok) h['Authorization'] = `Bearer ${tok}`
  return h
}

async function fetchGitHubFile(owner: string, repo: string, path: string): Promise<string | null> {
  try {
    const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`
    const r = await fetch(url, { headers: ghHeaders(), signal: AbortSignal.timeout(GITHUB_TIMEOUT) })
    if (!r.ok) return null
    return await r.text()
  } catch { return null }
}

async function fetchSourcePaths(owner: string, repo: string, branch = 'main'): Promise<string[]> {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`
  const r = await fetch(url, { headers: ghHeaders(), signal: AbortSignal.timeout(GITHUB_TIMEOUT) })
  if (!r.ok) {
    if (branch === 'main') return fetchSourcePaths(owner, repo, 'master')
    return []
  }
  const data = await r.json()
  const tree: Array<{ path: string; type: string; size?: number }> = data.tree || []
  const files = tree.filter(e => {
    if (e.type !== 'blob') return false
    const ext = e.path.substring(e.path.lastIndexOf('.'))
    if (!SOURCE_EXTS.includes(ext)) return false
    if (e.path.includes('node_modules/') || e.path.includes('dist/') || e.path.includes('.git/')) return false
    return true
  })
  files.sort((a, b) => (a.size || 0) - (b.size || 0))
  return files.slice(0, MAX_SOURCE_FILES).map(f => f.path)
}

async function fetchNpmDeps(owner: string, repo: string): Promise<PackageQuery[]> {
  const raw = await fetchGitHubFile(owner, repo, 'package.json')
  if (!raw) return []
  try {
    const pkg = JSON.parse(raw)
    const queries: PackageQuery[] = []
    for (const depType of ['dependencies', 'devDependencies']) {
      const deps = pkg[depType]
      if (!deps || typeof deps !== 'object') continue
      for (const [name, ver] of Object.entries(deps as Record<string, unknown>)) {
        if (typeof ver !== 'string') continue
        const v = ver.replace(/^[\^~>=<]+/, '')
        if (v && !v.includes('*') && !v.includes('x'))
          queries.push({ name, version: v, ecosystem: 'npm' })
      }
    }
    return queries
  } catch { return [] }
}

async function fetchPyDeps(owner: string, repo: string): Promise<PackageQuery[]> {
  const raw = await fetchGitHubFile(owner, repo, 'requirements.txt')
  if (!raw) return []
  const queries: PackageQuery[] = []
  for (const line of raw.split('\n')) {
    const t = line.trim()
    if (!t || t.startsWith('#') || t.startsWith('-')) continue
    const m = t.match(/^([a-zA-Z0-9_.-]+)==([^\s;]+)/)
    if (m) queries.push({ name: m[1], version: m[2], ecosystem: 'PyPI' })
  }
  return queries
}

// ─── Input resolution ────────────────────────────────────────────────────────

interface ResolvedTargets {
  source_files: SourceFile[]
  dependencies: PackageQuery[]
  skill_md_content: string | null
  input_mode: string
  repo_url: string | null
}

async function resolveFromGitHub(repoUrl: string): Promise<ResolvedTargets> {
  const parsed = parseGitHubUrl(repoUrl)
  if (!parsed) throw Object.assign(new Error('Invalid GitHub URL'), { statusCode: 400 })
  const { owner, repo } = parsed

  const [paths, npmDeps, pyDeps, skillMd] = await Promise.all([
    fetchSourcePaths(owner, repo),
    fetchNpmDeps(owner, repo),
    fetchPyDeps(owner, repo),
    fetchGitHubFile(owner, repo, 'SKILL.md'),
  ])

  const fileContents = await Promise.all(
    paths.map(async (p): Promise<SourceFile | null> => {
      const c = await fetchGitHubFile(owner, repo, p)
      return c ? { path: p, content: c } : null
    })
  )

  return {
    source_files: fileContents.filter((f): f is SourceFile => f !== null),
    dependencies: [...npmDeps, ...pyDeps],
    skill_md_content: skillMd,
    input_mode: 'repo_url',
    repo_url: repoUrl,
  }
}

function resolveFromCode(input: ScanInput): ResolvedTargets {
  const dependencies: PackageQuery[] = []
  if (input.dependencies && typeof input.dependencies === 'object') {
    for (const [name, ver] of Object.entries(input.dependencies)) {
      if (typeof ver !== 'string') continue
      const v = ver.replace(/^[\^~>=<]+/, '')
      if (v && !v.includes('*') && !v.includes('x'))
        dependencies.push({ name, version: v, ecosystem: 'npm' })
    }
  }
  return {
    source_files: [{ path: 'input.ts', content: input.code! }],
    dependencies,
    skill_md_content: input.skill_md || null,
    input_mode: 'direct',
    repo_url: null,
  }
}

async function resolveFromSlug(slug: string): Promise<ResolvedTargets> {
  const base = env('CLAW0X_API_BASE') || 'https://claw0x.com'
  const r = await fetch(`${base}/api/skills?slug=${encodeURIComponent(slug)}`, {
    signal: AbortSignal.timeout(5_000),
  })
  if (!r.ok) throw Object.assign(new Error('Skill not found'), { statusCode: 404 })
  const data = await r.json()
  const skill = Array.isArray(data) ? data[0] : data
  if (!skill) throw Object.assign(new Error('Skill not found'), { statusCode: 404 })
  const repoUrl = skill.repo_url || skill.github_url
  if (!repoUrl) {
    return { source_files: [], dependencies: [], skill_md_content: null, input_mode: 'skill_slug', repo_url: null }
  }
  const result = await resolveFromGitHub(repoUrl)
  return { ...result, input_mode: 'skill_slug' }
}

async function resolveInput(input: ScanInput, mode: string): Promise<ResolvedTargets> {
  switch (mode) {
    case 'repo_url': return resolveFromGitHub(input.repo_url!)
    case 'skill_slug': return resolveFromSlug(input.skill_slug!)
    case 'direct': return resolveFromCode(input)
    default: throw new Error('Unknown mode')
  }
}

// ─── Layer 1: Dependency CVE scanning via OSV.dev ────────────────────────────

const DEP_WEIGHTS: Record<string, number> = { critical: 25, high: 15, medium: 8, low: 3 }
const DEP_SCORE_CAP = 50
const VULN_CAP = 20

function classifySeverity(sev: string | undefined): 'critical' | 'high' | 'medium' | 'low' {
  if (!sev) return 'medium'
  const s = sev.toLowerCase()
  if (s.includes('critical')) return 'critical'
  if (s.includes('high')) return 'high'
  if (s.includes('medium') || s.includes('moderate')) return 'medium'
  if (s.includes('low')) return 'low'
  const n = parseFloat(s)
  if (!isNaN(n)) {
    if (n >= 9) return 'critical'
    if (n >= 7) return 'high'
    if (n >= 4) return 'medium'
    return 'low'
  }
  return 'medium'
}

async function scanDependencies(packages: PackageQuery[]): Promise<DependencyScanResult> {
  const empty: DependencyScanResult = {
    packages_scanned: 0, vulnerabilities: [],
    vulnerability_counts: { critical: 0, high: 0, medium: 0, low: 0 },
    score_contribution: 0,
  }
  if (packages.length === 0) return empty

  const queries = packages.map(p => ({
    package: { name: p.name, ecosystem: p.ecosystem },
    version: p.version,
  }))

  let data: any
  try {
    const r = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(15_000),
    })
    if (!r.ok) return { ...empty, packages_scanned: packages.length }
    data = await r.json()
  } catch {
    return { ...empty, packages_scanned: packages.length }
  }

  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 }
  let rawScore = 0
  const seen = new Set<string>()
  const vulns: DependencyScanResult['vulnerabilities'] = []

  for (const result of data.results || []) {
    for (const v of result.vulns || []) {
      if (seen.has(v.id)) continue
      seen.add(v.id)
      const sev = classifySeverity(v.severity)
      counts[sev]++
      rawScore += DEP_WEIGHTS[sev]
      if (vulns.length < VULN_CAP) {
        vulns.push({
          id: v.id,
          summary: v.summary || '',
          severity: sev,
          package_name: '',
          package_version: '',
        })
      }
    }
  }

  return {
    packages_scanned: packages.length,
    vulnerabilities: vulns,
    vulnerability_counts: counts,
    score_contribution: Math.min(rawScore, DEP_SCORE_CAP),
  }
}

// ─── Layer 2: Static code analysis ──────────────────────────────────────────

const CODE_WEIGHTS: Record<string, number> = { critical: 20, high: 12, medium: 5, low: 2 }
const CODE_SCORE_CAP = 40
const FINDINGS_CAP = 50

function analyzeCode(files: SourceFile[]): CodeScanResult {
  const findings: CodeFinding[] = []
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 }
  let rawScore = 0

  for (const file of files) {
    const lines = file.content.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      for (const rule of RULES) {
        if (rule.pattern.test(line)) {
          rule.pattern.lastIndex = 0
          counts[rule.severity]++
          rawScore += CODE_WEIGHTS[rule.severity] ?? 0
          if (findings.length < FINDINGS_CAP) {
            const m = line.trim()
            findings.push({
              rule_id: rule.rule_id,
              name: rule.name,
              severity: rule.severity,
              file: file.path,
              line: i + 1,
              match: m.length > 100 ? m.slice(0, 100) : m,
              description: rule.description,
            })
          }
        }
      }
    }
  }

  return {
    findings,
    finding_counts: counts,
    rules_checked: RULES.length,
    score_contribution: Math.min(rawScore, CODE_SCORE_CAP),
  }
}

// ─── Layer 3: Permission auditing ────────────────────────────────────────────

const PERM_SCORE_PER = 5
const PERM_SCORE_CAP = 10

const RULE_PERM_MAP: Record<string, string> = {
  DYN_CODE: 'Bash(*)',
  SHELL_INJECT: 'Bash(*)',
  DATA_EXFIL: 'Network',
  FS_OVERREACH: 'Bash(*)',
  INSECURE_NET: 'Network',
}

function parseDeclaredPermissions(md: string): string[] {
  const fm = md.match(/^---\s*\n([\s\S]*?)\n---/)
  if (!fm) return []
  const toolsMatch = fm[1].match(/allowed-tools:\s*\n((?:\s+-\s+.+\n?)*)/)
  if (!toolsMatch) return []
  const items: string[] = []
  for (const line of toolsMatch[1].split('\n')) {
    const m = line.match(/^\s+-\s+(.+)/)
    if (m) items.push(m[1].trim())
  }
  return items
}

function auditPermissions(skillMd: string | null, codeFindings: CodeFinding[]): PermissionAuditResult {
  const declared = skillMd ? parseDeclaredPermissions(skillMd) : []
  const detected = new Set<string>()
  for (const f of codeFindings) {
    const p = RULE_PERM_MAP[f.rule_id]
    if (p) detected.add(p)
  }
  const detectedArr = Array.from(detected)
  const declaredSet = new Set(declared)
  const undeclared = detectedArr.filter(p => !declaredSet.has(p))

  return {
    declared_permissions: declared,
    detected_permissions: detectedArr,
    undeclared_risks: undeclared,
    score_contribution: Math.min(undeclared.length * PERM_SCORE_PER, PERM_SCORE_CAP),
  }
}

// ─── Risk scoring & report ───────────────────────────────────────────────────

function computeRisk(dep: number, code: number, perm: number) {
  const d = Math.min(Math.max(dep, 0), 50)
  const c = Math.min(Math.max(code, 0), 40)
  const p = Math.min(Math.max(perm, 0), 10)
  const total = d + c + p
  const level: 'low' | 'medium' | 'high' = total <= 20 ? 'low' : total <= 50 ? 'medium' : 'high'
  return { total, level }
}

function buildRecommendations(
  codeScan: CodeScanResult,
  depScan: DependencyScanResult,
  permAudit: PermissionAuditResult
): string[] {
  const recs: string[] = []
  for (const f of codeScan.findings) {
    if (f.severity === 'critical' || f.severity === 'high') {
      const label = f.severity === 'critical' ? 'Critical' : 'High'
      recs.push(`${label}: ${f.name} — ${f.description}`)
    }
  }
  for (const v of depScan.vulnerabilities) {
    if (v.severity === 'critical' || v.severity === 'high')
      recs.push(`Upgrade package to fix ${v.id}`)
  }
  for (const p of permAudit.undeclared_risks)
    recs.push(`Undeclared permission: ${p} detected but not declared in SKILL.md`)
  return recs
}

// ─── Main handler ────────────────────────────────────────────────────────────

async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  // Authenticate via platform token
  if (!authenticate(req)) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  const startTime = Date.now()
  const input: ScanInput = req.body || {}

  // Validate input mode
  const { mode, error } = validateInputMode(input)
  if (error) return res.status(400).json({ error })

  try {
    // Step 1: Resolve input to scan targets
    const targets = await resolveInput(input, mode)

    // Step 2: Run dependency scan + code analysis in parallel
    const [depScan, codeScan] = await Promise.all([
      scanDependencies(targets.dependencies).catch((): DependencyScanResult => ({
        packages_scanned: 0, vulnerabilities: [],
        vulnerability_counts: { critical: 0, high: 0, medium: 0, low: 0 },
        score_contribution: 0,
      })),
      Promise.resolve(analyzeCode(targets.source_files)),
    ])

    // Step 3: Permission audit (depends on code findings)
    const permAudit = auditPermissions(targets.skill_md_content, codeScan.findings)

    // Step 4: Compute risk score
    const risk = computeRisk(
      depScan.score_contribution,
      codeScan.score_contribution,
      permAudit.score_contribution
    )

    // Step 5: Build report
    const recommendations = buildRecommendations(codeScan, depScan, permAudit)

    const report = {
      overall_risk: risk.level,
      risk_score: risk.total,
      input_mode: targets.input_mode,
      repo_url: targets.repo_url,
      dependency_scan: {
        packages_scanned: depScan.packages_scanned,
        vulnerabilities: depScan.vulnerabilities,
        vulnerability_counts: depScan.vulnerability_counts,
      },
      code_scan: {
        findings: codeScan.findings,
        finding_counts: codeScan.finding_counts,
        rules_checked: codeScan.rules_checked,
      },
      permission_audit: {
        declared_permissions: permAudit.declared_permissions,
        detected_permissions: permAudit.detected_permissions,
        undeclared_risks: permAudit.undeclared_risks,
      },
      recommendations,
      scanned_at: new Date().toISOString(),
      scan_duration_ms: Date.now() - startTime,
    }

    return res.status(200).json(report)
  } catch (err: any) {
    const status = err.statusCode || 500
    const msg = status < 500 ? err.message : 'Security scan failed'
    if (status >= 500) console.error('Scanner error:', err)
    return res.status(status).json({ error: msg })
  }
}

export default handler
