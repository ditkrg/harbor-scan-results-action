export const severityEmojis: Record<string, string> = {
  Critical: '🔥',
  High: '🚨',
  Medium: '⚠️',
  Low: '🟡'
}

export interface Vulnerability {
  id: string
  package: string
  version: string
  fix_version: string | null
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'None'
  description: string
  preferred_cvss: {
    score_v3: number | null
  }
  cwe_ids: string[]
  links: string[]
}

export interface Scanner {
  name: string
  vendor: string
  version: string
}

export interface VulnerabilityReport {
  generated_at: string
  scanner: Scanner
  vulnerabilities: Vulnerability[]
}

export interface ScanResult {
  'application/vnd.security.vulnerability.report; version=1.1'?: VulnerabilityReport
}

export interface ScanSummary {
  total: number
  fixable: number
  critical: number
  high: number
  medium: number
  low: number
  scanner: string
  vendor: string
  generated_at: string
  image_url: string
  repo_link: string
  vulnerabilities: Vulnerability[]
}
