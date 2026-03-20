# claw0x-security-scanner

> Scan AI agent skills for security vulnerabilities, dangerous code patterns, and undeclared permissions. Three-layer analysis: dependency CVE scanning via OSV.dev, static code analysis, and permission auditing. Returns structured JSON risk report. Use when the user asks to scan a skill for security issues, check for vulnerabilities, audit permissions, or assess skill safety.

[![License: MIT-0](https://img.shields.io/badge/License-MIT--0-blue.svg)](LICENSE)
[![Claw0x](https://img.shields.io/badge/Powered%20by-Claw0x-orange)](https://claw0x.com)

## Quick Start

```bash
curl -X POST https://api.claw0x.com/v1/call \
  -H "Authorization: Bearer $CLAW0X_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"skill": "security-scanner", "input": {...}}'
```

**Get your free API key:** [Sign up at claw0x.com](https://claw0x.com) (no credit card required)

---


# Security Scanner

Scan AI agent skills for security vulnerabilities across three layers: dependency CVEs, dangerous code patterns, and undeclared permissions. Returns a structured JSON risk report with an overall score (0–100).

> **Free to use.** This skill costs nothing. Just [sign up at claw0x.com](https://claw0x.com), create an API key, and start calling. No credit card, no wallet top-up required.

## How It Works — Under the Hood

This skill runs a three-layer security analysis pipeline. No LLM involved — pure deterministic scanning logic.

### Layer 1: Dependency CVE Scanning

Dependencies are extracted from `package.json` (npm) or `requirements.txt` (PyPI) and queried against the [OSV.dev](https://osv.dev) batch vulnerability database.

- Fetches dependency manifests from the target repository
- Queries all packages in a single batch request to OSV.dev
- Classifies each vulnerability by severity: critical, high, medium, low
- Score contribution: critical +25, high +15, medium +8, low +3 (capped at 50)

### Layer 2: Static Code Analysis

Source files (`.ts`, `.js`, `.py`) are scanned line-by-line against 8 pre-compiled regex rules covering: dynamic execution, shell injection, env leaks, data exfiltration, hardcoded credentials, unsafe imports, filesystem overreach, and insecure network requests.

- Score contribution: critical +20, high +12, medium +5, low +2 (capped at 40)

### Layer 3: Permission Auditing

The SKILL.md frontmatter `allowed-tools` field is cross-referenced against actual code behavior detected by the static analyzer.

- Parses declared permissions from SKILL.md YAML frontmatter
- Maps code findings to permission categories
- Reports any permissions detected in code but not declared in frontmatter
- Score contribution: +5 per undeclared permission (capped at 10)

### Risk Score

The three layer scores are summed into a total risk score (0–100):

| Score Range | Risk Level |
|-------------|------------|
| 0–20 | Low |
| 21–50 | Medium |
| 51–100 | High |

## Three Input Modes

You can scan a skill using any of these three modes (mutually exclusive — provide exactly one):

### Mode 1: GitHub Repo URL

Provide a public GitHub repository URL. The scanner fetches dependency files, source code, and SKILL.md automatically.

```json
{ "repo_url": "https://github.com/owner/repo" }
```

### Mode 2: Claw0x Skill Slug

Provide a skill slug from the Claw0x platform. The scanner looks up the associated repo URL and proceeds with the standard scan.

```json
{ "skill_slug": "validate-email" }
```

### Mode 3: Direct Code Submission

Submit code directly along with optional dependency and SKILL.md data. No GitHub fetching needed.

```json
{
  "code": "import os\nos.system('rm -rf /')",
  "dependencies": { "requests": "2.28.0" },
  "skill_md": "---\nname: my-skill\nallowed-tools: Bash(curl *)\n---"
}
```

## Prerequisites

This is a free skill. Just get an API key:

1. Sign up at [claw0x.com](https://claw0x.com)
2. Go to Dashboard → API Keys → Create Key
3. Store the key securely using one of these methods:
   - Add `CLAW0X_API_KEY` to your agent's secure environment variables
   - Use your platform's secret manager (e.g. GitHub Secrets, Vercel env vars, AWS Secrets Manager)
   - Use a `.env` file that is excluded from version control via `.gitignore`

> **Security note**: Never embed API keys in prompts, source code, or version-controlled files.

No credit card or wallet balance needed.

## When to Use

- Agent pipeline needs to vet a third-party skill before installing
- Developer wants to self-check a skill before publishing
- Platform review pipeline needs automated security assessment
- User asks "is this skill safe?", "scan for vulnerabilities", "check skill security"

## API Call

```bash
curl -s -X POST https://api.claw0x.com/v1/call \
  -H "Authorization: Bearer $CLAW0X_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "skill": "security-scanner",
    "input": {
      "repo_url": "https://github.com/owner/repo"
    }
  }'
```

## Input

Provide exactly one of the three input modes:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `repo_url` | string | one of three | GitHub repo URL. Mutually exclusive with skill_slug and code |
| `skill_slug` | string | one of three | Claw0x skill slug (1–100 chars). Mutually exclusive with repo_url and code |
| `code` | string | one of three | Source code to scan directly (max 500KB). Mutually exclusive with repo_url and skill_slug |
| `dependencies` | object | no | Package name to version map for dependency scanning (used with code mode) |
| `skill_md` | string | no | SKILL.md content for permission auditing (used with code mode) |

## Output Fields

| Field | Type | Description |
|-------|------|-------------|
| `overall_risk` | string | Risk level: `low`, `medium`, or `high` |
| `risk_score` | number | Numeric risk score (0–100) |
| `input_mode` | string | Which input mode was used |
| `repo_url` | string or null | Repository URL if applicable |
| `dependency_scan.packages_scanned` | number | Number of packages checked |
| `dependency_scan.vulnerabilities` | array | Found CVEs (max 20) |
| `dependency_scan.vulnerability_counts` | object | Count by severity level |
| `code_scan.findings` | array | Dangerous code patterns found (max 50) |
| `code_scan.finding_counts` | object | Count by severity level |
| `code_scan.rules_checked` | number | Number of rules applied |
| `permission_audit.declared_permissions` | array | Permissions from SKILL.md |
| `permission_audit.detected_permissions` | array | Permissions found in code |
| `permission_audit.undeclared_risks` | array | Detected but not declared |
| `recommendations` | array | Actionable fix suggestions |
| `scanned_at` | string | ISO 8601 scan timestamp |
| `scan_duration_ms` | number | Total scan time in milliseconds |

## Example

**Input:**
```json
{
  "skill": "security-scanner",
  "input": {
    "code": "const { exec } = require('child_process');\nexec(userInput);",
    "dependencies": { "lodash": "4.17.20" }
  }
}
```

**Output:**
```json
{
  "overall_risk": "high",
  "risk_score": 62,
  "input_mode": "direct",
  "repo_url": null,
  "dependency_scan": {
    "packages_scanned": 1,
    "vulnerabilities": [
      {
        "id": "GHSA-jf85-cpcp-j695",
        "summary": "Prototype Pollution in lodash",
        "severity": "high",
        "package_name": "lodash",
        "package_version": "4.17.20"
      }
    ],
    "vulnerability_counts": { "critical": 0, "high": 1, "medium": 0, "low": 0 }
  },
  "code_scan": {
    "findings": [
      {
        "rule_id": "SHELL_INJECT",
        "name": "Shell injection",
        "severity": "critical",
        "file": "input.ts",
        "line": 1,
        "match": "require('child_process')",
        "description": "Shell command execution detected"
      }
    ],
    "finding_counts": { "critical": 1, "high": 0, "medium": 0, "low": 0 },
    "rules_checked": 8
  },
  "permission_audit": {
    "declared_permissions": [],
    "detected_permissions": ["Bash(*)"],
    "undeclared_risks": ["Bash(*)"]
  },
  "recommendations": [
    "Critical: Shell injection pattern detected",
    "High: lodash@4.17.20 has known vulnerabilities",
    "Undeclared permission: Bash(*) detected but not declared"
  ],
  "scanned_at": "2025-01-15T10:30:00.000Z",
  "scan_duration_ms": 1250
}
```

## Pricing

**Free.** Apply for an API key and use it at no cost. No credit card required.


---

## About Claw0x

This skill is part of the [Claw0x Skills Layer](https://claw0x.com) - the native skills marketplace for AI agents.

- **50+ production-ready skills** - [Browse all skills](https://claw0x.com/skills)
- **Pay-per-call billing** - Only pay for successful calls
- **Zero config** - One API key, one endpoint
- **Sell your own skills** - [Become a seller](https://claw0x.com/docs/sell)

## Links

- [Claw0x Platform](https://claw0x.com)
- [API Documentation](https://claw0x.com/docs/api-reference)
