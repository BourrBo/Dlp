'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { buildArgs, parseCliResult, groupByPath } = require('../lib');

const sample = {
  findings: [
    { rule_id: 'DLP002', severity: 'critical', path: 'src/a.py', line: 2, column: 8, end_column: 28, description: 'AWS access key ID', masked: 'AK****LE', guidance: 'Rotate it.' },
    { rule_id: 'DLP012', severity: 'low', path: 'src/a.py', line: 5, column: 1, end_column: 10, description: 'Email address', masked: 'so****st', guidance: '' },
  ],
};

test('buildArgs passes target after --path and validates severity', () => {
  assert.deepStrictEqual(buildArgs('a b.py', 'high'), ['scan', '--path', 'a b.py', '--format', 'json', '--fail-on', 'high']);
  assert.strictEqual(buildArgs('x', 'bogus')[6], 'low');
});

test('findings become zero-based ranges with mapped severity', () => {
  const r = parseCliResult({ code: 1, stdout: JSON.stringify(sample), stderr: '' });
  assert.ok(r.ok);
  assert.deepStrictEqual(r.diagnostics[0], {
    path: 'src/a.py', line: 1, start: 7, end: 27, severity: 'error', code: 'DLP002',
    message: 'AWS access key ID: AK****LE. Rotate it.',
  });
  assert.strictEqual(r.diagnostics[1].severity, 'info');
  assert.strictEqual(r.diagnostics[1].end, 9);
});

test('minimum severity filters diagnostics', () => {
  const r = parseCliResult({ code: 1, stdout: JSON.stringify(sample), stderr: '' }, 'high');
  assert.strictEqual(r.diagnostics.length, 1);
});

test('exit codes other than 0 and 1 are errors with a short message', () => {
  const r = parseCliResult({ code: 3, stdout: '', stderr: '\ngit error: not a repository\nmore' });
  assert.deepStrictEqual(r, { ok: false, diagnostics: [], error: 'git error: not a repository' });
  assert.strictEqual(parseCliResult({ code: 2, stdout: '', stderr: '' }).error, 'dlp exited with code 2');
});

test('invalid JSON is reported, not thrown', () => {
  const r = parseCliResult({ code: 0, stdout: 'garbage', stderr: '' });
  assert.strictEqual(r.ok, false);
});

test('zero-width or missing columns still produce a visible range', () => {
  const r = parseCliResult({ code: 1, stdout: JSON.stringify({ findings: [{ rule_id: 'X', severity: 'high', path: 'a', line: 1, column: 0, end_column: 0, description: 'd', masked: 'm' }] }), stderr: '' });
  assert.deepStrictEqual([r.diagnostics[0].start, r.diagnostics[0].end], [0, 1]);
});

test('groupByPath groups by file', () => {
  const r = parseCliResult({ code: 1, stdout: JSON.stringify(sample), stderr: '' });
  assert.strictEqual(groupByPath(r.diagnostics).get('src/a.py').length, 2);
});

test('works against the real CLI when it is installed', (t) => {
  const probe = spawnSync('dlp', ['--version']);
  if (probe.error) return t.skip('dlp CLI not installed');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dlpvs-'));
  fs.writeFileSync(path.join(dir, 'a.py'), 'x = 1\nk = "' + 'AKIA' + 'IOSFODNN7' + 'EXAMPLE"\n');
  const res = spawnSync('dlp', buildArgs('a.py', 'low'), { cwd: dir, encoding: 'utf8' });
  const parsed = parseCliResult({ code: res.status, stdout: res.stdout, stderr: res.stderr });
  assert.ok(parsed.ok);
  assert.strictEqual(parsed.diagnostics.length, 1);
  assert.strictEqual(parsed.diagnostics[0].line, 1);
  assert.strictEqual(parsed.diagnostics[0].start, 5);
  assert.ok(!JSON.stringify(parsed).includes('AKIAIOSFODNN7EXAMPLE'));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('package.json is valid and registers every command it contributes', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const src = fs.readFileSync(path.join(__dirname, '..', 'extension.js'), 'utf8');
  for (const c of pkg.contributes.commands) assert.ok(src.includes(`'${c.command}'`), c.command);
  assert.strictEqual(pkg.main, './extension.js');
  assert.deepStrictEqual(pkg.capabilities.untrustedWorkspaces.restrictedConfigurations, ['dlp.cliPath']);
});

test('extension.js parses', () => {
  execFileSync(process.execPath, ['--check', path.join(__dirname, '..', 'extension.js')]);
});
