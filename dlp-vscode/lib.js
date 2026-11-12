'use strict';
// Pure helpers (no `vscode` import) so they can be unit-tested with plain Node.

const SEVERITY = { critical: 'error', high: 'error', medium: 'warning', low: 'info' };
const LEVELS = ['low', 'medium', 'high', 'critical'];

function buildArgs(target, failOn) {
  const level = LEVELS.includes(failOn) ? failOn : 'low';
  return ['scan', '--path', target, '--format', 'json', '--fail-on', level];
}

/**
 * Parse `dlp scan --format json` output.
 * Returns { ok, diagnostics[], error? }. Exit codes: 0/1 are normal results,
 * anything else is an error whose stderr is shown without the scanned content.
 */
function parseCliResult({ code, stdout, stderr }, minSeverity = 'low') {
  if (code !== 0 && code !== 1) {
    const first = String(stderr || '').split('\n').find((l) => l.trim()) || `dlp exited with code ${code}`;
    return { ok: false, diagnostics: [], error: first.slice(0, 300) };
  }
  let data;
  try {
    data = JSON.parse(stdout);
  } catch (e) {
    return { ok: false, diagnostics: [], error: 'dlp returned output that is not valid JSON' };
  }
  const floor = LEVELS.indexOf(LEVELS.includes(minSeverity) ? minSeverity : 'low');
  const diagnostics = [];
  for (const f of Array.isArray(data.findings) ? data.findings : []) {
    if (LEVELS.indexOf(f.severity) < floor) continue;
    const line = Math.max(0, (f.line | 0) - 1);
    const start = Math.max(0, (f.column | 0) - 1);
    const end = Math.max(start + 1, (f.end_column | 0) - 1);
    diagnostics.push({
      path: String(f.path),
      line, start, end,
      severity: SEVERITY[f.severity] || 'warning',
      code: String(f.rule_id),
      message: `${f.description}: ${f.masked}. ${f.guidance || ''}`.trim(),
    });
  }
  return { ok: true, diagnostics };
}

/** Group diagnostics by file path. */
function groupByPath(diagnostics) {
  const map = new Map();
  for (const d of diagnostics) {
    if (!map.has(d.path)) map.set(d.path, []);
    map.get(d.path).push(d);
  }
  return map;
}

module.exports = { buildArgs, parseCliResult, groupByPath, SEVERITY, LEVELS };
