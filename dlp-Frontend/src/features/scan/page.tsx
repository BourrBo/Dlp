import { useCallback, useEffect, useMemo, useState, type DragEvent, type FormEvent } from "react";
import { Ban, CheckCircle2, Clock3, FileSearch, LoaderCircle, RefreshCw, Upload } from "lucide-react";

import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { useOrg } from "@/hooks/use-org";
import { supabase } from "@/integrations/supabase/client";

type Location = Record<string, string | number | boolean>;
type Finding = { id: string; data_type: string; confidence: number; matched_snippet: string; label?: string | null };
type ChunkResult = { location: Location; findings: Finding[]; decision: string; reason: string };
type FileResult = {
  filename: string;
  size_bytes: number;
  extracted_chars: number;
  encoding?: string | null;
  skipped_reason?: string | null;
  chunks: ChunkResult[];
};
type UploadResult = { files: FileResult[] };
type JobStatus = "queued" | "running" | "completed" | "failed" | "cancelled" | "interrupted";
type ScanJob = {
  id: string;
  status: JobStatus;
  phase: string;
  progress: number;
  filename: string;
  size_bytes: number;
  created_at: string;
  updated_at: string;
  cancel_requested: boolean;
  error_message?: string | null;
  result?: UploadResult | null;
};
type JobList = { jobs: ScanJob[] };

const BACKEND_URL = (import.meta.env["VITE_DLP_BACKEND_URL"] || "http://localhost:8000").replace(/\/$/, "");
const ACTIVE = new Set<JobStatus>(["queued", "running"]);
const MAX_FILES_PER_UPLOAD = 20;
const MAX_FILE_BYTES = 25 * 1024 * 1024;

async function authHeaders(): Promise<Record<string, string>> {
  const { data, error } = await supabase.auth.getSession();
  if (error || !data.session?.access_token) throw new Error("Your session expired. Sign in again to continue.");
  return { Authorization: `Bearer ${data.session.access_token}` };
}

function formatLocation(location: Location): string {
  if (location["page"]) return `Page ${location["page"]}${location["ocr"] ? " (OCR)" : ""}`;
  if (location["slide"]) return `Slide ${location["slide"]}${location["content"] === "notes" ? " notes" : ""}`;
  if (location["sheet"] && location["row"]) return `${location["sheet"]}, row ${location["row"]}`;
  if (location["archive_member"]) return `${location["archive_member"]}${location["line_start"] ? `, lines ${location["line_start"]}-${location["line_end"] ?? location["line_start"]}` : ""}`;
  if (location["line_start"]) return `Lines ${location["line_start"]}-${location["line_end"] ?? location["line_start"]}`;
  if (location["table"]) return `Table ${location["table"]}, row ${location["row"] ?? "?"}`;
  if (location["row"]) return `Row ${location["row"]}`;
  if (location["json_path"]) return `JSON ${location["json_path"]}`;
  if (location["xml_path"]) return `XML ${location["xml_path"]}`;
  if (location["paragraph"]) return `Paragraph ${location["paragraph"]}`;
  if (location["comment_id"]) return `Comment ${location["comment_id"]}`;
  return `Chunk ${location["chunk_index"] ?? 0}`;
}

function jobTitle(job: ScanJob): string {
  return `${job.filename} · ${job.status}`;
}

export function ScanPage() {
  const { data: orgId } = useOrg();
  const [files, setFiles] = useState<File[]>([]);
  const [uploadStatuses, setUploadStatuses] = useState<Array<{ id: number; name: string; status: string; detail?: string }>>([]);
  const [queueProgress, setQueueProgress] = useState(0);
  const [dragging, setDragging] = useState(false);
  const [destination, setDestination] = useState("file-upload");
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const upsertJob = useCallback((next: ScanJob) => {
    setJobs((current) => [next, ...current.filter((job) => job.id !== next.id)].slice(0, 100));
  }, []);

  const refreshJobs = useCallback(async () => {
    if (!orgId) return;
    const query = new URLSearchParams({ org_id: orgId });
    const response = await fetch(`${BACKEND_URL}/scan-jobs?${query}`, { headers: await authHeaders() });
    if (!response.ok) throw new Error(`Could not load scan jobs (${response.status})`);
    const data = (await response.json()) as JobList;
    setJobs(data.jobs);
    setActiveJobId((current) => current ?? data.jobs.find((job) => ACTIVE.has(job.status))?.id ?? data.jobs[0]?.id ?? null);
  }, [orgId]);

  useEffect(() => {
    if (!orgId) return;
    let cancelled = false;
    refreshJobs().catch((cause) => {
      if (!cancelled) setError(cause instanceof Error ? cause.message : "Could not load scan history");
    });
    return () => { cancelled = true; };
  }, [orgId, refreshJobs]);

  useEffect(() => {
    if (!activeJobId || !orgId) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const query = new URLSearchParams({ org_id: orgId });
    async function poll() {
      try {
        const response = await fetch(`${BACKEND_URL}/scan-jobs/${activeJobId}?${query}`, { headers: await authHeaders() });
        if (!response.ok) throw new Error(`Could not refresh scan status (${response.status})`);
        const job = (await response.json()) as ScanJob;
        if (cancelled) return;
        upsertJob(job);
        if (ACTIVE.has(job.status)) timer = setTimeout(poll, 1000);
      } catch (cause) {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : "Could not refresh scan status");
          timer = setTimeout(poll, 2500);
        }
      }
    }
    timer = setTimeout(poll, 250);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [activeJobId, orgId, upsertJob]);

  function setSelectedFiles(nextFiles: File[]) {
    setError(null);
    setUploadStatuses([]);
    setQueueProgress(0);
    if (nextFiles.length > MAX_FILES_PER_UPLOAD) {
      setFiles([]);
      setError(`Choose up to ${MAX_FILES_PER_UPLOAD} files at a time.`);
      return;
    }
    const oversized = nextFiles.find((candidate) => candidate.size > MAX_FILE_BYTES);
    if (oversized) {
      setFiles([]);
      setError(`“${oversized.name}” exceeds the 25 MiB per-file limit.`);
      return;
    }
    setFiles(nextFiles);
  }

  function onDropFiles(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    const items = Array.from(event.dataTransfer.items ?? []);
    const hasFolder = items.some((item) => {
      const fileItem = item as DataTransferItem & { webkitGetAsEntry?: () => { isDirectory?: boolean } | null };
      if (fileItem.kind !== "file" || typeof fileItem.webkitGetAsEntry !== "function") return false;
      try { return Boolean(fileItem.webkitGetAsEntry()?.isDirectory); } catch { return true; }
    });
    if (hasFolder) {
      setFiles([]);
      setError("Folders are not supported here yet. Choose individual files instead.");
      return;
    }
    setSelectedFiles(Array.from(event.dataTransfer.files));
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!files.length || !orgId) return;
    const batch = files;
    setUploadStatuses(batch.map((item, id) => ({ id, name: item.name, status: "waiting" })));
    setBusy(true);
    setError(null);
    let queued = 0;
    let failed = 0;
    try {
      for (let index = 0; index < batch.length; index += 1) {
        const item = batch[index];
        if (!item) continue;
        setQueueProgress(index + 1);
        setUploadStatuses((current) => current.map((status) => status.id === index ? { ...status, status: "uploading" } : status));
        try {
          const body = new FormData();
          body.set("file", item);
          body.set("org_id", orgId);
          body.set("destination", destination.trim() || "file-upload");
          const response = await fetch(`${BACKEND_URL}/scan-jobs`, { method: "POST", headers: await authHeaders(), body });
          if (!response.ok) {
            const detail = await response.text();
            throw new Error(`HTTP ${response.status}: ${detail.slice(0, 300)}`);
          }
          const job = (await response.json()) as ScanJob;
          upsertJob(job);
          setActiveJobId(job.id);
          setUploadStatuses((current) => current.map((status) => status.id === index ? { ...status, status: "queued" } : status));
          queued += 1;
        } catch (cause) {
          failed += 1;
          setUploadStatuses((current) => current.map((status) => status.id === index ? {
            ...status,
            status: "failed",
            detail: cause instanceof Error ? cause.message : "Could not queue this file",
          } : status));
        }
      }
      setFiles([]);
      const input = document.getElementById("scan-file") as HTMLInputElement | null;
      if (input) input.value = "";
      if (failed) setError(`${queued} file${queued === 1 ? "" : "s"} queued; ${failed} could not be queued. Review the per-file messages below.`);
    } finally {
      setBusy(false);
    }
  }

  async function cancelJob(job: ScanJob) {
    if (!orgId) return;
    setError(null);
    const query = new URLSearchParams({ org_id: orgId });
    try {
      const response = await fetch(`${BACKEND_URL}/scan-jobs/${job.id}?${query}`, { method: "DELETE", headers: await authHeaders() });
      if (!response.ok) throw new Error(`Could not cancel scan (${response.status})`);
      upsertJob((await response.json()) as ScanJob);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not cancel this scan");
    }
  }

  const selectedJob = jobs.find((job) => job.id === activeJobId) ?? null;
  const scannedFile = selectedJob?.result?.files[0];
  const findings = useMemo(() => scannedFile?.chunks.flatMap((chunk) =>
    chunk.findings.map((finding) => ({ ...finding, location: chunk.location, decision: chunk.decision, reason: chunk.reason })),
  ) ?? [], [scannedFile]);
  const canCancel = selectedJob && ACTIVE.has(selectedJob.status) && !selectedJob.cancel_requested;
  const queueButtonLabel = files.length === 0 ? "Queue scans" : files.length === 1 ? "Queue 1 scan" : `Queue ${files.length} scans`;

  return (
    <AppShell title="Scan files" description="Queue encrypted uploads for background extraction and policy scanning.">
      <div className="mx-auto max-w-5xl space-y-5">
        <form onSubmit={submit} className="space-y-4 rounded-lg border border-border bg-card p-5">
          <label htmlFor="scan-file" className="block text-sm font-medium">Choose files</label>
          <input
            id="scan-file"
            type="file"
            multiple
            onChange={(event) => setSelectedFiles(Array.from(event.target.files ?? []))}
            className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
          />
          <div
            onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
            onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
            onDragLeave={(event) => { event.preventDefault(); setDragging(false); }}
            onDrop={onDropFiles}
            className={`rounded-md border border-dashed p-5 text-center text-sm ${dragging ? "border-primary bg-primary/5" : "border-border"}`}
          >
            Drop files here or use Choose files above. Up to {MAX_FILES_PER_UPLOAD} files, 25 MiB each.
          </div>
          <p className="text-xs text-muted-foreground">Supports text/code, CSV, JSON, XML, PDF, DOCX, XLSX, PPTX and ZIP/TAR/GZ archives. Files are queued one at a time.</p>
          {files.length ? (
            <ul className="space-y-1" aria-label="Selected files">
              {files.map((item, index) => <li key={`${item.name}-${index}`} className="flex justify-between gap-3 rounded border border-border px-3 py-2 text-sm"><span className="min-w-0 truncate" title={item.name}>{item.name}</span><span className="shrink-0 text-muted-foreground">{(item.size / 1024).toFixed(1)} KiB</span></li>)}
            </ul>
          ) : null}
          {uploadStatuses.length ? (
            <ul className="space-y-1" aria-live="polite" aria-label="File upload statuses">
              {uploadStatuses.map((status) => <li key={status.id} className="flex flex-wrap justify-between gap-2 rounded border border-border px-3 py-2 text-sm"><span className="min-w-0 truncate" title={status.name}>{status.name}</span><span className={status.status === "failed" ? "text-destructive" : "text-muted-foreground"}>{status.status}{status.detail ? ` · ${status.detail}` : ""}</span></li>)}
            </ul>
          ) : null}
          <label htmlFor="scan-destination" className="block text-sm font-medium">Destination or context</label>
          <input
            id="scan-destination"
            value={destination}
            onChange={(event) => setDestination(event.target.value)}
            className="block w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            placeholder="e.g. external-partner.example"
          />
          <Button type="submit" disabled={!files.length || !orgId || busy}>
            {busy ? <LoaderCircle className="mr-2 size-4 animate-spin" /> : <Upload className="mr-2 size-4" />}
            {busy ? `Queueing ${queueProgress} of ${uploadStatuses.length}…` : queueButtonLabel}
          </Button>
          {!orgId ? <p className="text-sm text-muted-foreground">Loading your signed-in workspace…</p> : null}
        </form>

        {error ? (
          <div className="flex items-center justify-between gap-3 rounded-md border border-destructive/40 bg-destructive/5 p-4 text-sm text-destructive" role="alert">
            <span>{error}</span>
            <Button variant="ghost" size="sm" onClick={() => { setError(null); void refreshJobs(); }}><RefreshCw className="mr-2 size-4" />Retry</Button>
          </div>
        ) : null}

        <section className="space-y-3 rounded-lg border border-border bg-card p-5" aria-label="Scan job history">
          <div className="flex items-center justify-between">
            <h2 className="font-semibold">Scan jobs</h2>
            <Button variant="outline" size="sm" onClick={() => void refreshJobs()}><RefreshCw className="mr-2 size-4" />Refresh</Button>
          </div>
          {jobs.length ? (
            <div className="space-y-2">
              {jobs.map((job) => (
                <button
                  key={job.id}
                  type="button"
                  onClick={() => setActiveJobId(job.id)}
                  className={`flex w-full items-center justify-between gap-4 rounded-md border px-3 py-2 text-left text-sm ${job.id === activeJobId ? "border-primary bg-primary/5" : "border-border hover:bg-muted/40"}`}
                >
                  <span className="min-w-0 truncate" title={job.filename}>{job.filename}</span>
                  <span className="shrink-0 capitalize text-muted-foreground">{job.status} · {job.progress}%</span>
                </button>
              ))}
            </div>
          ) : <p className="text-sm text-muted-foreground">No scans queued yet.</p>}
        </section>

        {selectedJob ? (
          <section className="space-y-4 rounded-lg border border-border bg-card p-5" aria-live="polite">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="font-semibold">{jobTitle(selectedJob)}</h2>
                <p className="text-sm text-muted-foreground">{(selectedJob.size_bytes / 1024).toFixed(1)} KiB · {selectedJob.phase}</p>
              </div>
              {canCancel ? (
                <Button variant="outline" size="sm" onClick={() => void cancelJob(selectedJob)}><Ban className="mr-2 size-4" />Cancel scan</Button>
              ) : selectedJob.cancel_requested ? <span className="text-sm text-muted-foreground">Cancellation requested…</span> : null}
            </div>
            <div className="space-y-1">
              <div className="h-2 overflow-hidden rounded-full bg-muted" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={selectedJob.progress} aria-label="Scan progress">
                <div className="h-full bg-primary transition-all" style={{ width: `${selectedJob.progress}%` }} />
              </div>
              <p className="text-right text-xs text-muted-foreground">{selectedJob.progress}%</p>
            </div>
            {selectedJob.status === "queued" ? <p className="flex items-center gap-2 text-sm text-muted-foreground"><Clock3 className="size-4" />Waiting for a worker. Queued work survives a container restart.</p> : null}
            {selectedJob.status === "running" ? <p className="flex items-center gap-2 text-sm text-muted-foreground"><LoaderCircle className="size-4 animate-spin" />{selectedJob.phase === "scanning" ? "Scanning extracted content…" : "Extracting uploaded file…"}</p> : null}
            {selectedJob.status === "failed" ? <p className="rounded-md border border-destructive/40 p-3 text-sm text-destructive">{selectedJob.error_message || "The scan failed."}</p> : null}
            {selectedJob.status === "cancelled" ? <p className="rounded-md border border-border p-3 text-sm">Scan cancelled. Partial results are shown below.</p> : null}
            {selectedJob.status === "interrupted" ? <p className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm">{selectedJob.error_message || "The backend restarted during this scan. Partial results are shown below; upload the file again to rescan it."}</p> : null}
            {scannedFile ? (
              <>
                <p className="text-sm text-muted-foreground">{scannedFile.extracted_chars.toLocaleString()} extracted characters</p>
                {scannedFile.skipped_reason ? (
                  <p className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-sm">Skipped: {scannedFile.skipped_reason}</p>
                ) : findings.length ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead><tr className="border-b border-border text-muted-foreground"><th className="p-2">Type</th><th className="p-2">Evidence (masked)</th><th className="p-2">Location</th><th className="p-2">Decision</th></tr></thead>
                      <tbody>
                        {findings.map((finding, index) => (
                          <tr key={`${finding.id}-${index}`} className="border-b border-border/60">
                            <td className="p-2">{finding.label || finding.data_type}</td>
                            <td className="p-2 font-mono">{finding.matched_snippet}</td>
                            <td className="p-2">{formatLocation(finding.location)}</td>
                            <td className="p-2 uppercase">{finding.decision}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : selectedJob.status === "completed" ? (
                  <div className="flex items-center gap-3 rounded-md border border-border p-4 text-sm">
                    <CheckCircle2 className="size-5 text-emerald-500" />No findings. The extracted content completed policy scanning.
                  </div>
                ) : selectedJob.status === "running" ? (
                  <p className="text-sm text-muted-foreground">Results appear here as each chunk is scanned.</p>
                ) : (
                  <div className="flex items-center gap-3 rounded-md border border-border p-4 text-sm"><FileSearch className="size-5 text-muted-foreground" />No results were produced.</div>
                )}
              </>
            ) : null}
          </section>
        ) : null}
      </div>
    </AppShell>
  );
}
