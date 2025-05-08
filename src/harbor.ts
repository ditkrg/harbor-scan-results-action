import {
  ScanResult,
  ScanSummary,
  Vulnerability,
  severityEmojis
} from './types.js'

export async function getScanResults(
  harborUrl: string,
  username: string,
  password: string,
  projectName: string,
  repositoryName: string,
  digest: string
): Promise<ScanResult> {
  const response = await fetch(
    `${harborUrl}/api/v2.0/projects/${projectName}/repositories/${repositoryName}/artifacts/${digest}/additions/vulnerabilities`,
    {
      headers: {
        Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`
      }
    }
  )

  if (!response.ok) {
    throw new Error(`Failed to get scan results: ${response.statusText}`)
  }

  return response.json() as Promise<ScanResult>
}

export function checkScanStatus(result: ScanResult): boolean {
  if (!result['application/vnd.security.vulnerability.report; version=1.1']) {
    return false
  }
  return true
}

export function generateScanSummary(
  result: ScanResult,
  harborUrl: string,
  projectName: string,
  repositoryName: string,
  digest: string
): ScanSummary {
  const report =
    result['application/vnd.security.vulnerability.report; version=1.1']
  if (!report) {
    throw new Error('No vulnerability report found')
  }

  const vulnerabilities = report.vulnerabilities
  const total = vulnerabilities.length
  const fixable = vulnerabilities.filter(
    (v: Vulnerability) => v.fix_version !== null && v.fix_version !== ''
  ).length
  const critical = vulnerabilities.filter(
    (v: Vulnerability) => v.severity === 'Critical'
  ).length
  const high = vulnerabilities.filter(
    (v: Vulnerability) => v.severity === 'High'
  ).length
  const medium = vulnerabilities.filter(
    (v: Vulnerability) => v.severity === 'Medium'
  ).length
  const low = vulnerabilities.filter(
    (v: Vulnerability) => v.severity === 'Low'
  ).length

  const imageUrl = `${harborUrl}/harbor/projects/${projectName}/repositories/${repositoryName}/artifacts-tab/artifacts/${digest}`
  const repoLink = `${harborUrl}/harbor/projects/${projectName}/repositories/${repositoryName}`

  // Sort vulnerabilities by severity
  const sortedVulns = [...vulnerabilities].sort(
    (a: Vulnerability, b: Vulnerability) => {
      const severityOrder: Record<string, number> = {
        Critical: 0,
        High: 1,
        Medium: 2,
        Low: 3,
        None: 4
      }
      return severityOrder[a.severity] - severityOrder[b.severity]
    }
  )

  return {
    total,
    fixable,
    critical,
    high,
    medium,
    low,
    scanner: `${report.scanner.name} ${report.scanner.version}`,
    vendor: report.scanner.vendor,
    generated_at: report.generated_at,
    image_url: imageUrl,
    repo_link: repoLink,
    vulnerabilities: sortedVulns
  }
}

export function generateMarkdownReport(summary: ScanSummary): string {
  const severityCounts = [
    summary.critical > 0
      ? `${severityEmojis['Critical']} ${summary.critical} critical`
      : null,
    summary.high > 0 ? `${severityEmojis['High']} ${summary.high} high` : null,
    summary.medium > 0
      ? `${severityEmojis['Medium']} ${summary.medium} medium`
      : null,
    summary.low > 0 ? `${severityEmojis['Low']} ${summary.low} low` : null
  ]
    .filter(Boolean)
    .join(' ')

  const vulnDetails = summary.vulnerabilities
    .slice(0, 10)
    .map((v: Vulnerability) => formatVulnerability(v))
    .join('\n\n')

  const moreLine =
    summary.vulnerabilities.length > 10
      ? `\n...and ${summary.vulnerabilities.length - 10} more. [See all in Harbor](${summary.repo_link})`
      : ''

  return `**Harbor Image Vulnerability Report**

Results for image [${summary.image_url}](${summary.image_url})

${severityCounts}

**Total ${summary.total} vulnerabilities found - ${summary.fixable} fixable**

Scanned with \`${summary.scanner}\` from \`${summary.vendor}\`  
Report generated at \`${summary.generated_at}\`

### Vulnerabilities Found:
${vulnDetails}${moreLine}`
}

function formatVulnerability(vuln: Vulnerability): string {
  return `<details>
  <summary><strong>${vuln.id}</strong> (${severityEmojis[vuln.severity] || ''} ${vuln.severity})</summary>
  
  - **Package**: ${vuln.package} ${vuln.version}
  - **Description**: ${vuln.description}
  - **CVSS Score**: ${vuln.preferred_cvss.score_v3 ?? 'N/A'}
  - **CWE IDs**: ${vuln.cwe_ids.join(', ')}
  - **Links**: ${vuln.links.join(', ')}
</details>`
}
