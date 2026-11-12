'use strict';
const vscode = require('vscode');
const path = require('path');
const { execFile } = require('child_process');
const { buildArgs, parseCliResult, groupByPath } = require('./lib');

const MAX_OUTPUT = 20 * 1024 * 1024;
let collection;
let warnedMissing = false;

function settings() {
  const c = vscode.workspace.getConfiguration('dlp');
  return {
    cli: c.get('cliPath', 'dlp'),
    failOn: c.get('failOn', 'low'),
    timeout: Math.max(1, c.get('timeoutSeconds', 20)) * 1000,
    onSave: c.get('scanOnSave', true),
  };
}

function runCli(cwd, target) {
  const s = settings();
  return new Promise((resolve) => {
    execFile(s.cli, buildArgs(target, s.failOn), { cwd, timeout: s.timeout, maxBuffer: MAX_OUTPUT, windowsHide: true },
      (err, stdout, stderr) => {
        if (err && err.code === 'ENOENT') return resolve({ missing: true });
        if (err && err.killed) return resolve({ code: 3, stdout: '', stderr: 'DLP scan timed out' });
        resolve({ code: err ? (typeof err.code === 'number' ? err.code : 3) : 0, stdout, stderr });
      });
  });
}

function severityOf(name) {
  return { error: vscode.DiagnosticSeverity.Error, warning: vscode.DiagnosticSeverity.Warning, info: vscode.DiagnosticSeverity.Information }[name];
}

function publish(root, diagnostics, replaceAll, scannedFiles) {
  const grouped = groupByPath(diagnostics);
  if (replaceAll) collection.clear();
  for (const file of scannedFiles) {
    if (!grouped.has(file)) collection.delete(vscode.Uri.file(path.join(root, file)));
  }
  for (const [file, items] of grouped) {
    collection.set(vscode.Uri.file(path.join(root, file)), items.map((d) => {
      const diag = new vscode.Diagnostic(new vscode.Range(d.line, d.start, d.line, d.end), d.message, severityOf(d.severity));
      diag.source = 'DLP';
      diag.code = d.code;
      return diag;
    }));
  }
}

async function scan(root, target, { replaceAll, scannedFiles, quiet }) {
  const result = await runCli(root, target);
  if (result.missing) {
    if (!warnedMissing) {
      warnedMissing = true;
      vscode.window.showWarningMessage('DLP: the "dlp" command was not found. Install it with "pip install dlp-cli" or set dlp.cliPath.');
    }
    return;
  }
  const parsed = parseCliResult(result, settings().failOn);
  if (!parsed.ok) {
    if (!quiet) vscode.window.showErrorMessage(`DLP: ${parsed.error}`);
    return;
  }
  publish(root, parsed.diagnostics, replaceAll, scannedFiles);
  if (!quiet) {
    vscode.window.setStatusBarMessage(`DLP: ${parsed.diagnostics.length} finding(s)`, 4000);
  }
}

function rootFor(uri) {
  const folder = vscode.workspace.getWorkspaceFolder(uri);
  return folder ? folder.uri.fsPath : undefined;
}

function activate(context) {
  collection = vscode.languages.createDiagnosticCollection('dlp');
  context.subscriptions.push(collection);

  const scanDocument = async (doc, quiet) => {
    if (doc.uri.scheme !== 'file') return;
    const root = rootFor(doc.uri);
    if (!root) return;
    const rel = path.relative(root, doc.uri.fsPath).split(path.sep).join('/');
    if (rel.startsWith('..')) return;
    await scan(root, rel, { replaceAll: false, scannedFiles: [rel], quiet });
  };

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => { if (settings().onSave) scanDocument(doc, true); }),
    vscode.commands.registerCommand('dlp.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) return scanDocument(editor.document, false);
    }),
    vscode.commands.registerCommand('dlp.scanWorkspace', async () => {
      const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
      if (folder) await scan(folder.uri.fsPath, '.', { replaceAll: true, scannedFiles: [], quiet: false });
    }),
    vscode.commands.registerCommand('dlp.clear', () => collection.clear()),
  );
}

function deactivate() { if (collection) collection.dispose(); }

module.exports = { activate, deactivate };
