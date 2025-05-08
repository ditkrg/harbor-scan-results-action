import * as core from '@actions/core'
import {
  getScanResults,
  checkScanStatus,
  generateScanSummary,
  generateMarkdownReport
} from './harbor.js'
import { wait } from './wait.js'

/**
 * The main function for the action.
 *
 * @returns Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    // Get inputs
    const harborUrl = core.getInput('harbor-url', { required: true })
    const harborUsername = core.getInput('username', { required: true })
    const harborPassword = core.getInput('password', { required: true })
    const projectName = core.getInput('project-name', { required: true })
    const repositoryName = core.getInput('repository-name', { required: true })
    const digest = core.getInput('digest', { required: true })
    const maxAttempts = parseInt(core.getInput('max-attempts') || '30', 10)
    const sleepInterval =
      parseInt(core.getInput('sleep-interval') || '5', 10) * 1000 // Convert to milliseconds

    core.info('Waiting for Harbor scan to complete...')

    // Poll for scan results
    let attempt = 1
    let scanResult

    while (attempt <= maxAttempts) {
      core.info(`Attempt ${attempt} of ${maxAttempts}`)

      try {
        scanResult = await getScanResults(
          harborUrl,
          harborUsername,
          harborPassword,
          projectName,
          repositoryName,
          digest
        )

        if (checkScanStatus(scanResult)) {
          break
        }
      } catch (error) {
        core.debug(
          `Attempt ${attempt} failed: ${error instanceof Error ? error.message : String(error)}`
        )
      }

      if (attempt < maxAttempts) {
        await wait(sleepInterval)
      }
      attempt++
    }

    if (!scanResult || !checkScanStatus(scanResult)) {
      throw new Error('Timeout waiting for scan results')
    }

    // Generate summary and report
    const summary = generateScanSummary(
      scanResult,
      harborUrl,
      projectName,
      repositoryName,
      digest
    )
    const markdownReport = generateMarkdownReport(summary)

    // Set outputs
    core.setOutput('scan-results', JSON.stringify(summary))
    core.setOutput('report-markdown', markdownReport)

    // Print summary to console
    core.info(
      `Found ${summary.total} vulnerabilities (${summary.fixable} fixable)`
    )
    core.info(
      `Critical: ${summary.critical}, High: ${summary.high}, Medium: ${summary.medium}, Low: ${summary.low}`
    )
  } catch (error) {
    // Fail the workflow run if an error occurs
    if (error instanceof Error) {
      core.setFailed(error.message)
    } else {
      core.setFailed('An unknown error occurred')
    }
  }
}
