import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { KeyRound, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { CopyButton } from "@/components/copy-button";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDateTime } from "@/lib/dlp";
import { createApiKey, listApiKeys, revokeApiKey, type CreatedApiKey } from "@/lib/platform-api";

export const Route = createFileRoute("/_authenticated/api-keys")({
  head: () => ({ meta: [{ title: "API keys — DLP Console" }] }),
  component: ApiKeysPage,
});

const SCOPES = [{ value: "scan:request", label: "Scan content (extension, CLI, agents, CI)" }];

function ApiKeysPage() {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [created, setCreated] = useState<CreatedApiKey | null>(null);

  const keys = useQuery({ queryKey: ["platform", "api-keys"], queryFn: listApiKeys, retry: false });

  const create = useMutation({
    mutationFn: () => createApiKey(name.trim(), SCOPES.map((s) => s.value)),
    onSuccess: (key) => {
      setCreated(key);
      setName("");
      void queryClient.invalidateQueries({ queryKey: ["platform", "api-keys"] });
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => revokeApiKey(id),
    onSuccess: () => {
      toast.success("API key revoked");
      void queryClient.invalidateQueries({ queryKey: ["platform", "api-keys"] });
    },
    onError: (error: Error) => toast.error(error.message),
  });

  return (
    <AppShell
      title="API keys"
      description="Scoped keys for the Chrome extension, CLI, endpoint agent and CI. Only organization admins can create them."
    >
      <div className="space-y-6">
        {created && (
          <div role="status" className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4">
            <p className="text-sm font-semibold">Copy your new key now — it is shown only once.</p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <code className="break-all rounded bg-background px-2 py-1 text-xs">{created.key}</code>
              <CopyButton value={created.key} label="Copy key" />
              <Button size="sm" variant="ghost" onClick={() => setCreated(null)}>
                Done
              </Button>
            </div>
          </div>
        )}

        <form
          className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-card p-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (name.trim()) create.mutate();
          }}
        >
          <div className="min-w-64 flex-1 space-y-1.5">
            <Label htmlFor="key-name">Key name</Label>
            <Input id="key-name" value={name} maxLength={120} placeholder="e.g. Chrome extension — Finance team" onChange={(e) => setName(e.target.value)} />
          </div>
          <Button type="submit" disabled={!name.trim() || create.isPending}>
            <Plus className="mr-1.5 size-4" /> Create key
          </Button>
        </form>

        {keys.isError && (
          <div role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-700">
            {keys.error instanceof Error ? keys.error.message : "Could not load API keys."}
          </div>
        )}

        <div className="rounded-lg border border-border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Prefix</TableHead>
                <TableHead>Scopes</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Last used</TableHead>
                <TableHead className="w-24" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(keys.data ?? []).map((key) => (
                <TableRow key={key.id}>
                  <TableCell className="font-medium">
                    <KeyRound className="mr-1.5 inline size-3.5 text-muted-foreground" />
                    {key.name}
                  </TableCell>
                  <TableCell className="font-mono text-xs">dlp_{key.prefix}…</TableCell>
                  <TableCell className="text-xs">{key.scopes.join(", ")}</TableCell>
                  <TableCell className="text-xs">{formatDateTime(key.created_at)}</TableCell>
                  <TableCell className="text-xs">{key.last_used_at ? formatDateTime(key.last_used_at) : "Never"}</TableCell>
                  <TableCell>
                    {key.revoked_at ? (
                      <span className="text-xs text-muted-foreground">Revoked</span>
                    ) : (
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label={`Revoke ${key.name}`}
                        disabled={revoke.isPending}
                        onClick={() => {
                          if (window.confirm(`Revoke "${key.name}"? Anything using it stops working immediately.`)) revoke.mutate(key.id);
                        }}
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {keys.isSuccess && keys.data.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="py-10 text-center text-sm text-muted-foreground">
                    No API keys yet.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </div>
    </AppShell>
  );
}
