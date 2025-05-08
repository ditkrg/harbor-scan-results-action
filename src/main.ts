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

    const proto = core.getInput('proto', { required: false })

    if (proto !== 'http' && proto !== 'https') {
      throw new Error(`Invalid protocol ${proto}. Please use http or https.`)
    }

    const port = core.getInput('port', { required: false })

    const digest = core.getInput('digest', { required: true })
    const username = core.getInput('username', { required: true })
    const password = core.getInput('password', { required: true })

    const image = core.getInput('image', { required: false })
    let registry = core.getInput('registry', { required: false })
    let projectName = core.getInput('project-name', { required: false })
    let repositoryName = core.getInput('repository-name', { required: false })

    // Either tag or registry, projectName, repositoryName and digest must be provided
    if (!image && (!registry || !projectName || !repositoryName)) {
      throw new Error(
        'Either tag or registry, projectName, and repositoryName  must be provided'
      )
    }

    // If tag is provided, extract projectName, repositoryName from it
    if (image) {
      // Make sure image is a valid docker image
      const imageRegex =
        /^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)(:[a-zA-Z0-9_.-]+)?(@sha256:[a-zA-Z0-9_.-]+)?$/
      const match = image.match(imageRegex)

      if (!match) {
        throw new Error(
          'Invalid image format. Please use the format registry/project/repository:tag or registry/project/repository@digest'
        )
      }

      registry = match[1]
      projectName = match[2]
      repositoryName = match[3]
    }

    const registryUrl = `${proto || 'https'}://${registry}:${port || ''}`

    core.info(`registryUrl: ${registryUrl}`)
    core.info(`projectName: ${projectName}`)
    core.info(`repositoryName: ${repositoryName}`)

    const maxAttempts = parseInt(core.getInput('max-attempts') || '30', 10)
    const sleepInterval =
      parseInt(core.getInput('sleep-interval') || '5', 10) * 1000 // Convert to milliseconds

    core.info('Waiting for Harbor scan to complete...')

    await wait(sleepInterval)

    // Poll for scan results
    let attempt = 1
    let scanResult

    while (attempt <= maxAttempts) {
      core.info(`Attempt ${attempt} of ${maxAttempts}`)

      try {
        scanResult = await getScanResults(
          registryUrl,
          username,
          password,
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
      registryUrl,
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
