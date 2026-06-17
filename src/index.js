// @ts-check
const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');
const { version: ACTION_VERSION } = require('../package.json');

const SEVERITY_ORDER = ['Low', 'Medium', 'High', 'Critical'];
const PR_COMMENT_MARKER = '<!-- shieldly-analysis-comment -->';

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.github',
  'dist',
  'build',
  'coverage',
  '.cache',
  '.next',
  '__pycache__',
]);
const SKIP_FILENAMES = new Set([
  'package.json',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'cdk.json',
  'tsconfig.json',
  'jsconfig.json',
  'biome.json',
  'jest.config.json',
  'manifest.json',
  '.eslintrc.json',
  'samconfig.toml',
  'docker-compose.yml',
  'docker-compose.yaml',
  'docker-compose.override.yml',
  '.travis.yml',
]);

function severityRank(s) {
  // Case-insensitive so a user-supplied `fail-on-severity: high` matches the
  // canonical "High" instead of silently ranking 0 (which would fail on everything).
  const target = String(s ?? '').toLowerCase();
  const i = SEVERITY_ORDER.findIndex((x) => x.toLowerCase() === target);
  return i === -1 ? 0 : i;
}

/** Sanitize a string for a markdown table cell: collapse newlines, escape pipes. */
function mdCell(s) {
  return String(s ?? '')
    .replace(/\r?\n/g, ' ')
    .replace(/\|/g, '\\|')
    .trim();
}

// Short text health tag for a 0-100 score (higher = safer). No emoji.
// Mirrors the old scoreEmoji thresholds (80+ green, 50+ yellow, else red).
function scoreTag(score) {
  if (score === null || score === undefined) return '';
  if (score >= 80) return '[Good]';
  if (score >= 50) return '[Fair]';
  return '[Poor]';
}

/**
 * Minimal HTTP request — no external deps beyond @actions/core and @actions/github.
 * @returns {Promise<{status: number, data: any}>}
 */
function request(method, url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const payload = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `Shieldly-GitHubAction/${ACTION_VERSION}`,
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...headers,
      },
    };
    const transport = parsed.protocol === 'https:' ? https : http;
    const req = transport.request(opts, (res) => {
      let raw = '';
      res.on('data', (c) => {
        raw += c;
      });
      res.on('end', () => {
        let data;
        try {
          data = JSON.parse(raw);
        } catch {
          data = raw;
        }
        resolve({ status: res.statusCode ?? 0, data });
      });
    });
    req.on('error', reject);
    // Never hang the CI job on a dead connection.
    req.setTimeout(60_000, () => {
      req.destroy(new Error('Request timed out'));
    });
    if (payload) req.write(payload);
    req.end();
  });
}

/** Detect if a parsed JSON object is a standalone IAM policy. */
function isIAMPolicy(obj) {
  return (
    obj && typeof obj === 'object' && obj.Version === '2012-10-17' && Array.isArray(obj.Statement)
  );
}

/** Detect if a parsed JSON object is a CloudFormation template. */
function isCFTemplate(obj) {
  return obj && typeof obj === 'object' && obj.Resources && typeof obj.Resources === 'object';
}

/**
 * Read CDK manifest.json and return the CF stack template paths for the current synthesis.
 * Returns null when the directory is not a CDK output dir or manifest is unreadable.
 * @param {string} dir
 * @returns {string[] | null}
 */
function readCDKManifest(dir) {
  try {
    const raw = fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8');
    const manifest = JSON.parse(raw);
    if (!manifest.artifacts || typeof manifest.artifacts !== 'object') return null;
    const files = Object.values(manifest.artifacts)
      .filter((a) => a.type === 'aws:cloudformation:stack' && a.properties?.templateFile)
      .map((a) => path.join(dir, a.properties.templateFile))
      .filter((p) => fs.existsSync(p));
    return files.length > 0 ? files : null;
  } catch {
    return null;
  }
}

/**
 * Walk a directory and return IaC files to analyze.
 * @param {string} dirPath
 * @returns {{ filePath: string, hint: 'cf' | 'auto' }[]}
 */
function findIaCFiles(dirPath) {
  const results = [];

  function walk(dir, depth) {
    if (depth > 4) return;

    // Check if this is a CDK output directory — use manifest to get current-synthesis
    // stacks only, then skip recursing (avoids stale templates from prior synths).
    const manifestFiles = readCDKManifest(dir);
    if (manifestFiles) {
      for (const filePath of manifestFiles) {
        results.push({ filePath, hint: 'cf' });
      }
      return;
    }

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          walk(path.join(dir, entry.name), depth + 1);
        }
        continue;
      }
      if (!entry.isFile()) continue;

      const name = entry.name;
      const filePath = path.join(dir, name);

      if (SKIP_FILENAMES.has(name)) continue;
      if (name.endsWith('.lock') || name.endsWith('.assets.json')) continue;

      // CDK synthesized stack template
      if (name.endsWith('.template.json')) {
        results.push({ filePath, hint: 'cf' });
        continue;
      }
      // Serverless Framework CloudFormation output
      if (name.startsWith('cloudformation-template') && name.endsWith('.json')) {
        results.push({ filePath, hint: 'cf' });
        continue;
      }
      // Common plain CF naming conventions
      if (
        name === 'template.json' ||
        name === 'template.yaml' ||
        name === 'template.yml' ||
        name === 'cloudformation.json' ||
        name === 'cloudformation.yaml' ||
        name === 'cloudformation.yml'
      ) {
        results.push({ filePath, hint: 'auto' });
        continue;
      }
      // At root depth only: detect any .json/.yaml by content (repo root or explicit scan-path)
      if (
        depth === 0 &&
        (name.endsWith('.json') || name.endsWith('.yaml') || name.endsWith('.yml'))
      ) {
        results.push({ filePath, hint: 'auto' });
      }
    }
  }

  walk(dirPath, 0);
  return results;
}

/**
 * Poll job-status until complete or failed. Backoff: 2s→3s→5s…
 * @param {string} jobId
 * @param {string|undefined} apiKey
 * @param {string} apiUrl
 * @returns {Promise<object|null>}
 */
async function pollJob(jobId, apiKey, apiUrl) {
  const delays = [2000, 3000, 5000];
  const headers = {};
  if (apiKey) headers.Authorization = `Bearer ${apiKey}`;
  const startMs = Date.now();
  let consecutiveErrors = 0;
  for (let i = 0; i < 180; i++) {
    const delay = delays[Math.min(i, delays.length - 1)];
    await new Promise((r) => setTimeout(r, delay));
    const elapsed = Math.round((Date.now() - startMs) / 1000);
    core.info(`  → AI-Powered analysis in progress… (${elapsed}s elapsed)`);
    let status, data;
    try {
      ({ status, data } = await request(
        'GET',
        `${apiUrl}/v1/jobs/${encodeURIComponent(jobId)}`,
        null,
        headers
      ));
    } catch (err) {
      // Transient network failure must not abandon a still-running job.
      if (++consecutiveErrors >= 3) {
        core.warning(`Shieldly: job poll network error — ${err.message}`);
        return null;
      }
      continue;
    }
    if (status !== 200) {
      if (++consecutiveErrors >= 3) {
        core.warning(`Shieldly: job poll error ${status}`);
        return null;
      }
      continue;
    }
    consecutiveErrors = 0;
    if (data.status === 'complete') return data.result;
    if (data.status === 'failed') {
      core.warning(`Shieldly: async analysis failed — ${data.error ?? 'unknown'}`);
      return null;
    }
  }
  core.warning('Shieldly: async analysis timed out after polling');
  return null;
}

/**
 * Analyze a single file against the Shieldly API.
 * Returns null when the file is not a recognized IaC artifact or the API call fails non-fatally.
 */
async function analyzeFile(filePath, hint, apiKey, apiUrl) {
  let fileContent;
  try {
    fileContent = fs.readFileSync(filePath, 'utf8');
  } catch {
    core.warning(`Shieldly: could not read ${filePath} — skipping.`);
    return null;
  }
  if (!fileContent.trim()) {
    core.warning(`Shieldly: ${filePath} is empty — skipping.`);
    return null;
  }

  let policyType = 'iam_identity';
  let label = 'IAM Policy';

  if (hint === 'cf') {
    policyType = 'cf';
    label = 'CloudFormation Template';
  } else {
    // Auto-detect from content
    const isYaml = filePath.endsWith('.yaml') || filePath.endsWith('.yml');
    if (isYaml) {
      // Quick sanity check: CloudFormation templates must have a Resources section.
      // Prevents amplify.yml, buildspec.yml, appspec.yml, etc. from being sent to
      // the CF analyzer when they appear at the root of the scan-path.
      if (!fileContent.includes('Resources:')) {
        core.info(
          `Shieldly: ${path.basename(filePath)} — no "Resources:" section, skipping (not a CF template).`
        );
        return null;
      }
      policyType = 'cf';
      label = 'CloudFormation Template';
    } else {
      try {
        const obj = JSON.parse(fileContent);
        if (isCFTemplate(obj)) {
          policyType = 'cf';
          label = 'CloudFormation Template';
        } else if (isIAMPolicy(obj)) {
          policyType = 'iam_identity';
          label = 'IAM Policy';
        } else {
          core.info(
            `Shieldly: ${path.basename(filePath)} — not a recognized CF template or IAM policy, skipping.`
          );
          return null;
        }
      } catch {
        core.info(`Shieldly: ${path.basename(filePath)} — could not parse as JSON, skipping.`);
        return null;
      }
    }
  }

  core.info(`  → ${path.basename(filePath)} (${label})`);

  // Size gate — mirrors the web app multiplier reject thresholds (CF >600KB,
  // IAM >25k chars). Catch oversize input here with an actionable message
  // instead of letting the API return a cryptic error.
  const tooLarge =
    policyType === 'cf' ? fileContent.length / 1024 > 600 : fileContent.length > 25000;
  if (tooLarge) {
    const hint = policyType === 'cf' ? 'split your CDK stacks' : 'split into smaller policies';
    core.warning(
      `Shieldly: ${path.basename(filePath)} is too large to analyze — ${hint}. Skipping.`
    );
    return null;
  }

  // Authenticated only — run() guarantees apiKey is present (no demo in CI).
  const headers = { Authorization: `Bearer ${apiKey}` };
  const endpoint = policyType === 'cf' ? `${apiUrl}/v1/analyze/cf` : `${apiUrl}/v1/analyze/iam`;
  const bodyPayload =
    policyType === 'cf' ? { template: fileContent } : { policy: fileContent, policyType };

  let status, data;
  try {
    ({ status, data } = await request('POST', endpoint, bodyPayload, headers));
  } catch (err) {
    core.warning(`Shieldly: network error for ${path.basename(filePath)} — ${err.message}`);
    return null;
  }

  if (status === 202 && data?.jobId) {
    core.info(`  → Analysis queued (jobId=${data.jobId}), waiting for result…`);
    const polled = await pollJob(data.jobId, apiKey, apiUrl);
    if (!polled) return null;
    data = polled;
    status = 200;
  }

  // 429 (cap) and 401/403 (auth) won't fix themselves on the next file — abort the
  // whole batch instead of re-hitting the API for every remaining template.
  if (status === 429) {
    core.setFailed(
      'Shieldly: daily analysis limit reached. Enable PAYG or upgrade at shieldly.io/pricing'
    );
    return { __abort: true };
  }
  if (status === 401 || status === 403) {
    core.setFailed(`Shieldly: unauthorized — check your api-key input. ${data?.error ?? ''}`);
    return { __abort: true };
  }
  if (status !== 200) {
    core.warning(
      `Shieldly: API error ${status} for ${path.basename(filePath)} — ${data?.error ?? 'unknown error'}`
    );
    return null;
  }

  return {
    filePath,
    label,
    score: data.score ?? null,
    riskLevel: data.riskLevel ?? data.overallRisk ?? 'Low',
    findings: data.findings ?? [],
    aiGrade: data.aiGrade ?? 'Standard AI',
    summary: data.summary ?? '',
  };
}

/** Build PR comment for a single analyzed file. */
function buildPrComment({ filePath, label, score, riskLevel, findings, aiGrade, summary, apiUrl }) {
  const hasFindings = findings.length > 0;
  const criticalCount = findings.filter((f) => f.severity === 'Critical').length;
  const highCount = findings.filter((f) => f.severity === 'High').length;
  const statusIcon = criticalCount > 0 ? '[FAIL]' : highCount > 0 ? '[WARN]' : '[PASS]';
  const statusText =
    criticalCount > 0
      ? `${criticalCount} Critical issue${criticalCount !== 1 ? 's' : ''} found`
      : highCount > 0
        ? `${highCount} High issue${highCount !== 1 ? 's' : ''} found`
        : 'No critical issues found';

  const lines = [
    PR_COMMENT_MARKER,
    `## ${statusIcon} Shieldly AI-Powered Security Analysis`,
    '',
    `| | |`,
    `|---|---|`,
    `| **File** | \`${filePath}\` (${label}) |`,
    `| **Score** | **${score !== null && score !== undefined ? score : '—'}/100** ${scoreTag(score)} |`,
    `| **Risk Level** | **${riskLevel}** |`,
    `| **AI Grade** | ${aiGrade || 'Standard AI'} |`,
    `| **Status** | ${statusText} |`,
    '',
  ];

  if (summary) {
    lines.push(`> ${summary}`);
    lines.push('');
  }

  if (!hasFindings) {
    lines.push('**No security findings detected.** Your policy looks clean.');
  } else {
    lines.push(`### Findings (${findings.length})`);
    lines.push('');
    lines.push('| Severity | Finding | Resource | Remediation |');
    lines.push('|---|---|---|---|');
    for (const f of findings) {
      const rem = mdCell(f.remediation).substring(0, 120);
      const title = mdCell(f.title || f.description);
      const resource = mdCell(f.resource || '—');
      lines.push(
        `| ${f.severity} | ${title} | ${resource} | ${rem}${rem.length === 120 ? '…' : ''} |`
      );
    }

    const criticals = findings.filter((f) => f.severity === 'Critical');
    if (criticals.length > 0) {
      lines.push('');
      lines.push('<details>');
      lines.push('<summary>Critical Findings — Click to expand</summary>');
      lines.push('');
      for (const f of criticals) {
        lines.push(`**${f.title}**`);
        lines.push('');
        lines.push(f.description || '');
        if (f.remediation) {
          lines.push('');
          lines.push(`> **Fix:** ${f.remediation}`);
        }
        if (f.affectedStatement) {
          lines.push('');
          lines.push('```json');
          lines.push(JSON.stringify(f.affectedStatement, null, 2));
          lines.push('```');
        }
        lines.push('');
      }
      lines.push('</details>');
    }
  }

  lines.push('');
  lines.push(
    `---\n_Analyzed by [Shieldly](https://www.shieldly.io) — AI-Powered Security Analysis for AWS · [Get full report](${apiUrl})_`
  );
  return lines.join('\n');
}

/** Build aggregated PR comment when multiple stacks/files were analyzed. */
function buildMultiPrComment(results, scanPath, apiUrl) {
  const taggedFindings = results.flatMap((r) =>
    r.findings.map((f) => ({ ...f, _file: r.filePath }))
  );
  const totalFindings = taggedFindings.length;
  const criticalCount = taggedFindings.filter((f) => f.severity === 'Critical').length;
  const highCount = taggedFindings.filter((f) => f.severity === 'High').length;
  const statusIcon = criticalCount > 0 ? '[FAIL]' : highCount > 0 ? '[WARN]' : '[PASS]';
  const statusText =
    criticalCount > 0
      ? `${criticalCount} Critical issue${criticalCount !== 1 ? 's' : ''} across ${results.length} stacks`
      : highCount > 0
        ? `${highCount} High issue${highCount !== 1 ? 's' : ''} across ${results.length} stacks`
        : `No critical issues — ${results.length} stacks analyzed`;

  const lines = [
    PR_COMMENT_MARKER,
    `## ${statusIcon} Shieldly AI-Powered Security Analysis`,
    '',
    `**Scan path:** \`${scanPath}\` · **Stacks analyzed:** ${results.length} · **Status:** ${statusText}`,
    '',
    '| Stack | Score | Risk | Findings |',
    '|---|---|---|---|',
  ];

  for (const r of results) {
    const name = path.basename(r.filePath);
    const scoreStr = r.score !== null ? `${r.score}/100 ${scoreTag(r.score)}` : '—';
    lines.push(`| \`${name}\` | ${scoreStr} | ${r.riskLevel} | ${r.findings.length} |`);
  }
  lines.push('');

  if (totalFindings === 0) {
    lines.push('**No security findings detected across all stacks.**');
  } else {
    const sorted = [...taggedFindings].sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity)
    );
    lines.push(`### All Findings (${totalFindings})`);
    lines.push('');
    lines.push('| Severity | Finding | Stack | Resource | Remediation |');
    lines.push('|---|---|---|---|---|');
    for (const f of sorted) {
      const rem = mdCell(f.remediation).substring(0, 100);
      const title = mdCell(f.title || f.description);
      const resource = mdCell(f.resource || '—');
      const stackName = path.basename(f._file);
      lines.push(
        `| ${f.severity} | ${title} | \`${stackName}\` | ${resource} | ${rem}${rem.length === 100 ? '…' : ''} |`
      );
    }

    const criticals = sorted.filter((f) => f.severity === 'Critical');
    if (criticals.length > 0) {
      lines.push('');
      lines.push('<details>');
      lines.push('<summary>Critical Findings — Click to expand</summary>');
      lines.push('');
      for (const f of criticals) {
        lines.push(`**${f.title}** (\`${path.basename(f._file)}\`)`);
        lines.push('');
        lines.push(f.description || '');
        if (f.remediation) {
          lines.push('');
          lines.push(`> **Fix:** ${f.remediation}`);
        }
        if (f.affectedStatement) {
          lines.push('');
          lines.push('```json');
          lines.push(JSON.stringify(f.affectedStatement, null, 2));
          lines.push('```');
        }
        lines.push('');
      }
      lines.push('</details>');
    }
  }

  lines.push('');
  lines.push(
    `---\n_Analyzed by [Shieldly](https://www.shieldly.io) — AI-Powered Security Analysis for AWS · [Get full report](${apiUrl})_`
  );
  return lines.join('\n');
}

/**
 * Find and update an existing Shieldly PR comment, or create a new one.
 */
async function upsertPrComment(octokit, { owner, repo, pullNumber, body }) {
  const comments = await octokit.paginate(octokit.rest.issues.listComments, {
    owner,
    repo,
    issue_number: pullNumber,
    per_page: 100,
  });

  const existing = comments.find((c) => c.body?.includes(PR_COMMENT_MARKER));

  if (existing) {
    await octokit.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existing.id,
      body,
    });
    core.info(`Shieldly: Updated existing PR comment (id=${existing.id})`);
  } else {
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: pullNumber,
      body,
    });
    core.info('Shieldly: Created new PR comment');
  }
}

/** Post an informational "no files found" PR comment when scan-path yields nothing. */
async function maybePostNoFilesComment({ postPrComment, githubToken, scanPath }) {
  if (!postPrComment || !githubToken) return;
  const ctx = github.context;
  const isPr = ctx.eventName === 'pull_request' || ctx.eventName === 'pull_request_target';
  if (!isPr) return;
  try {
    const octokit = github.getOctokit(githubToken);
    const pullNumber = ctx.payload.pull_request?.number;
    if (!pullNumber) return;
    const body = [
      PR_COMMENT_MARKER,
      '## Shieldly AI-Powered Security Analysis',
      '',
      `No CloudFormation templates or IAM policies were found at \`scan-path: ${scanPath}\`.`,
      '',
      'Make sure your IaC step runs **before** this action:',
      '- **CDK** — `npx cdk synth` or `npx cdk deploy`, then set `scan-path: ./cdk.out`',
      '- **Serverless** — `npx serverless package` or `npx serverless deploy`, then set `scan-path: ./.serverless`',
      '',
      '---',
      '_[Shieldly](https://www.shieldly.io) — AI-Powered Security Analysis for AWS_',
    ].join('\n');
    await upsertPrComment(octokit, {
      owner: ctx.repo.owner,
      repo: ctx.repo.repo,
      pullNumber,
      body,
    });
  } catch {
    // Non-fatal — informational comment failure should not surface as an error
  }
}

async function run() {
  try {
    const apiKey = core.getInput('api-key').trim();
    const scanPath = core.getInput('scan-path').trim() || '.';
    const failOnSeverity = core.getInput('fail-on-severity').trim();
    const apiUrl = core.getInput('api-url').replace(/\/$/, '');
    const postPrComment = core.getInput('post-pr-comment').trim().toLowerCase() !== 'false';
    const githubToken = process.env.GITHUB_TOKEN || core.getInput('github-token').trim();

    core.info('Shieldly AI-Powered Security Analysis');
    core.info(`Scan path: ${scanPath}`);
    core.info(`API: ${apiUrl}`);

    // An API key is required in CI. Demo mode is intentionally not available in
    // the Action: CI runners rotate IPs, so the server's per-IP demo cap cannot
    // bound usage and the free path could be used indefinitely. Get an API key (Builder plan or above)
    // at https://www.shieldly.io/app/api and store it as a repo secret.
    if (!apiKey) {
      core.setFailed(
        'Shieldly: api-key is required. Demo mode is not available in CI. ' +
          'Get an API key (Builder plan or above) at https://www.shieldly.io/app/api and pass it as ' +
          // biome-ignore lint/suspicious/noTemplateCurlyInString: literal GitHub Actions expression shown to the user, not a JS template
          '`api-key: ${{ secrets.SHIELDLY_API_KEY }}`.'
      );
      return;
    }

    // Resolve files to analyze
    let filesToScan = [];
    const stat = fs.statSync(scanPath, { throwIfNoEntry: false });

    if (!stat) {
      core.warning(`Shieldly: scan-path "${scanPath}" does not exist.`);
      await maybePostNoFilesComment({ postPrComment, githubToken, scanPath });
      return;
    }

    if (stat.isFile()) {
      filesToScan = [{ filePath: scanPath, hint: 'auto' }];
    } else {
      filesToScan = findIaCFiles(scanPath);
    }

    if (filesToScan.length === 0) {
      core.warning(
        `Shieldly: No CloudFormation templates or IAM policies found at "${scanPath}". ` +
          'Ensure your IaC step (cdk synth, serverless package, etc.) runs before this action.'
      );
      await maybePostNoFilesComment({ postPrComment, githubToken, scanPath });
      return;
    }

    core.info(`Found ${filesToScan.length} file(s) to analyze:`);

    // Analyze each file sequentially
    const results = [];
    for (const { filePath, hint } of filesToScan) {
      const result = await analyzeFile(filePath, hint, apiKey, apiUrl);
      // Auth/cap failure already called setFailed — stop the batch, don't re-hit the API.
      if (result?.__abort) break;
      if (result) results.push(result);
    }

    if (results.length === 0) {
      core.warning('Shieldly: All candidate files were skipped or failed to analyze.');
      return;
    }

    // Aggregate worst-case outputs across all results
    const allTaggedFindings = results.flatMap((r) =>
      r.findings.map((f) => ({ ...f, _file: r.filePath }))
    );
    const totalFindings = allTaggedFindings.length;
    const criticalCount = allTaggedFindings.filter((f) => f.severity === 'Critical').length;
    const lowestScore = results.reduce(
      (min, r) => (r.score !== null && (min === null || r.score < min) ? r.score : min),
      null
    );
    const highestRisk = results.reduce((worst, r) => {
      return severityRank(r.riskLevel) > severityRank(worst) ? r.riskLevel : worst;
    }, 'Low');

    core.setOutput('score', lowestScore !== null ? String(lowestScore) : '');
    core.setOutput('risk-level', highestRisk);
    core.setOutput('findings-count', String(totalFindings));
    core.setOutput('critical-count', String(criticalCount));

    // GitHub Step Summary
    const summary = core.summary.addHeading('Shieldly AI-Powered Security Analysis', 2);
    if (results.length === 1) {
      const r = results[0];
      summary.addRaw(`\n**File:** \`${r.filePath}\` (${r.label})\n\n`);
      if (r.score !== null) {
        summary.addRaw(
          `**Score:** ${r.score}/100 &nbsp; **Risk:** ${r.riskLevel} &nbsp; **AI Grade:** ${r.aiGrade}\n\n`
        );
      }
      if (r.summary) {
        summary.addRaw(`> ${r.summary}\n\n`);
      }
    } else {
      summary.addRaw(
        `\n**Scan path:** \`${scanPath}\` · **Stacks analyzed:** ${results.length}\n\n`
      );
      summary.addTable([
        [
          { data: 'Stack', header: true },
          { data: 'Score', header: true },
          { data: 'Risk', header: true },
          { data: 'Findings', header: true },
        ],
        ...results.map((r) => [
          path.basename(r.filePath),
          r.score !== null ? `${r.score}/100` : '—',
          r.riskLevel,
          String(r.findings.length),
        ]),
      ]);
    }

    if (totalFindings === 0) {
      summary.addRaw('No security findings detected.\n');
    } else {
      summary.addHeading(`All Findings (${totalFindings})`, 3);
      const sortedForSummary = [...allTaggedFindings].sort(
        (a, b) => severityRank(b.severity) - severityRank(a.severity)
      );
      summary.addTable([
        [
          { data: 'Severity', header: true },
          { data: 'Title', header: true },
          { data: 'Stack', header: true },
          { data: 'Resource', header: true },
          { data: 'Remediation', header: true },
        ],
        ...sortedForSummary.map((f) => [
          `${f.severity}`,
          f.title ?? f.description ?? '',
          path.basename(f._file),
          f.resource ?? '',
          f.remediation ?? '',
        ]),
      ]);
    }

    summary.addRaw(
      '\n---\n_Analyzed by [Shieldly](https://www.shieldly.io) — AI-Powered Security Analysis for AWS_\n'
    );
    await summary.write();

    // Log findings to console
    if (allTaggedFindings.length > 0) {
      core.info(`\nFindings: ${totalFindings} total`);
      for (const f of allTaggedFindings) {
        const msg = `[${f.severity}] ${f.title ?? f.description}${f.resource ? ` (${f.resource})` : ''} — ${path.basename(f._file)}`;
        if (f.severity === 'Critical' || f.severity === 'High') {
          core.error(msg);
        } else if (f.severity === 'Medium') {
          core.warning(msg);
        } else {
          core.notice(msg);
        }
      }
    } else {
      core.info('No security findings across all analyzed files.');
    }

    // Post PR comment
    const ctx = github.context;
    const isPr = ctx.eventName === 'pull_request' || ctx.eventName === 'pull_request_target';

    if (postPrComment && isPr && githubToken) {
      try {
        const octokit = github.getOctokit(githubToken);
        const pullNumber = ctx.payload.pull_request?.number;
        if (pullNumber) {
          const commentBody =
            results.length === 1
              ? buildPrComment({ ...results[0], apiUrl: 'https://www.shieldly.io' })
              : buildMultiPrComment(results, scanPath, 'https://www.shieldly.io');
          await upsertPrComment(octokit, {
            owner: ctx.repo.owner,
            repo: ctx.repo.repo,
            pullNumber,
            body: commentBody,
          });
        }
      } catch (commentErr) {
        core.warning(`Shieldly: could not post PR comment — ${commentErr.message}`);
        core.warning(
          'Make sure GITHUB_TOKEN has write permissions and the workflow grants `pull-requests: write`.'
        );
      }
    } else if (postPrComment && !isPr) {
      core.info('Shieldly: not a pull_request event — skipping PR comment.');
    } else if (postPrComment && !githubToken) {
      core.warning(
        // biome-ignore lint/suspicious/noTemplateCurlyInString: literal GitHub Actions expression shown to the user, not a JS template
        'Shieldly: GITHUB_TOKEN not set — cannot post PR comment. Set the `github-token` input or add `env: GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}`.'
      );
    }

    // Determine whether to fail the workflow
    if (failOnSeverity && failOnSeverity.toLowerCase() !== 'none') {
      const isKnown = SEVERITY_ORDER.some((x) => x.toLowerCase() === failOnSeverity.toLowerCase());
      if (!isKnown) {
        core.warning(
          `Shieldly: unrecognized fail-on-severity "${failOnSeverity}". ` +
            'Expected one of Critical, High, Medium, Low, none. Skipping the fail gate.'
        );
      } else {
        const threshold = severityRank(failOnSeverity);
        const breaching = allTaggedFindings.filter((f) => severityRank(f.severity) >= threshold);
        if (breaching.length > 0) {
          core.setFailed(
            `Shieldly: ${breaching.length} finding(s) at or above "${failOnSeverity}" severity. ` +
              `Set fail-on-severity: none to allow the workflow to continue.`
          );
        }
      }
    }
  } catch (err) {
    core.setFailed(`Shieldly: unexpected error — ${err.message}`);
  }
}

run();
