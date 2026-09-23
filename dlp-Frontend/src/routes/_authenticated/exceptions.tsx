import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { supabase } from "@/integrations/supabase/client";
import { useOrg } from "@/hooks/use-org";
import { AppShell } from "@/components/app-shell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatDateTime } from "@/lib/dlp";

export const Route = createFileRoute("/_authenticated/exceptions")({
  head: () => ({
    meta: [
      { title: "Exceptions — DLP Console" },
      { name: "description", content: "Documented, time-bound exceptions to data loss prevention enforcement." },
      { property: "og:title", content: "Exceptions — DLP Console" },
      { property: "og:description", content: "Documented, time-bound exceptions to DLP enforcement." },
    ],
  }),
  component: ExceptionsPage,
});

type Exception = {
  id: string;
  destination_or_user: string;
  reason: string;
  approved_by: string | null;
  expires_at: string | null;
  created_at: string;
};

const EMPTY = { destination_or_user: "", reason: "", approved_by: "", expires_at: "" };

function ExceptionsPage() {
  const { data: orgId } = useOrg();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<typeof EMPTY | null>(null);

  const exceptions = useQuery({
    queryKey: ["exceptions", orgId],
    enabled: !!orgId,
    queryFn: async () => {
      const { data, error } = await supabase
        .from("dlp_exceptions")
        .select("id, destination_or_user, reason, approved_by, expires_at, created_at")
        .eq("org_id", orgId!)
        .order("created_at", { ascending: false });
      if (error) throw error;
      return data as Exception[];
    },
  });

  const save = useMutation({
    mutationFn: async (state: typeof EMPTY) => {
      const { error } = await supabase.from("dlp_exceptions").insert({
        org_id: orgId!,
        destination_or_user: state.destination_or_user.trim(),
        reason: state.reason.trim(),
        approved_by: state.approved_by.trim() || null,
        expires_at: state.expires_at ? new Date(state.expires_at).toISOString() : null,
      });
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exceptions"] });
      setForm(null);
      toast.success("Exception documented");
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Could not save exception"),
  });

  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("dlp_exceptions").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["exceptions"] });
      toast.success("Exception revoked");
    },
  });

  const rows = exceptions.data ?? [];

  return (
    <AppShell
      title="Exceptions"
      description="Approved carve-outs, with an owner and an expiry"
      actions={
        <Button size="sm" onClick={() => setForm(EMPTY)}>
          <Plus className="size-4" />
          New exception
        </Button>
      }
    >
      <div className="panel overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>Destination or user</TableHead>
              <TableHead>Reason</TableHead>
              <TableHead className="w-[170px]">Approved by</TableHead>
              <TableHead className="w-[170px]">Expires</TableHead>
              <TableHead className="w-[60px]" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="py-12 text-center text-sm text-muted-foreground">
                  No exceptions on record.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((x) => {
                const expired = x.expires_at ? new Date(x.expires_at) < new Date() : false;
                return (
                  <TableRow key={x.id}>
                    <TableCell className="font-mono text-xs">{x.destination_or_user}</TableCell>
                    <TableCell className="max-w-[340px] text-sm text-muted-foreground">{x.reason}</TableCell>
                    <TableCell className="text-sm">{x.approved_by ?? "—"}</TableCell>
                    <TableCell className="text-xs">
                      {x.expires_at ? (
                        <span className={expired ? "text-block" : "text-muted-foreground"}>
                          {formatDateTime(x.expires_at)}
                          {expired ? " · expired" : ""}
                        </span>
                      ) : (
                        <span className="text-warn">No expiry</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="size-7 text-muted-foreground hover:text-destructive"
                        onClick={() => remove.mutate(x.id)}
                      >
                        <Trash2 className="size-3.5" />
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>

      <Dialog open={!!form} onOpenChange={(open) => !open && setForm(null)}>
        <DialogContent className="sm:max-w-md">
          {form ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                save.mutate(form);
              }}
            >
              <DialogHeader>
                <DialogTitle>Document an exception</DialogTitle>
                <DialogDescription>
                  Exceptions are auditable. Record who approved it and when it lapses.
                </DialogDescription>
              </DialogHeader>

              <div className="grid gap-4 py-5">
                <div className="space-y-1.5">
                  <Label htmlFor="target">Destination or user</Label>
                  <Input
                    id="target"
                    required
                    placeholder="vendor.com or analyst@company.com"
                    value={form.destination_or_user}
                    onChange={(e) => setForm({ ...form, destination_or_user: e.target.value })}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="reason">Reason</Label>
                  <Textarea
                    id="reason"
                    required
                    rows={3}
                    placeholder="Contracted processor under DPA-2291."
                    value={form.reason}
                    onChange={(e) => setForm({ ...form, reason: e.target.value })}
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="approver">Approved by</Label>
                    <Input
                      id="approver"
                      placeholder="Security lead"
                      value={form.approved_by}
                      onChange={(e) => setForm({ ...form, approved_by: e.target.value })}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="expires">Expires</Label>
                    <Input
                      id="expires"
                      type="date"
                      value={form.expires_at}
                      onChange={(e) => setForm({ ...form, expires_at: e.target.value })}
                    />
                  </div>
                </div>
              </div>

              <DialogFooter>
                <Button type="button" variant="ghost" onClick={() => setForm(null)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={save.isPending}>
                  Save exception
                </Button>
              </DialogFooter>
            </form>
          ) : null}
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
