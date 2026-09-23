import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { supabase } from "@/integrations/supabase/client";
import { useOrg } from "@/hooks/use-org";
import { AppShell } from "@/components/app-shell";
import { DecisionBadge } from "@/components/decision-badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ACTIONS, CHANNELS, CHANNEL_LABELS, DATA_TYPES, DATA_TYPE_LABELS, DECISION_LABELS } from "@/lib/dlp";

export const Route = createFileRoute("/_authenticated/policies")({
  head: () => ({
    meta: [
      { title: "Policies — DLP Console" },
      { name: "description", content: "Create and edit data loss prevention policies per data type and channel." },
      { property: "og:title", content: "Policies — DLP Console" },
      { property: "og:description", content: "Create and edit DLP policies per data type and channel." },
    ],
  }),
  component: PoliciesPage,
});

type Policy = {
  id: string;
  data_type: string;
  channel: string;
  condition: { approved_destinations?: string[]; min_confidence?: number } | null;
  action: string;
  is_exception: boolean;
  created_at: string;
};

type FormState = {
  id: string | null;
  data_type: string;
  channel: string;
  approved_destinations: string;
  min_confidence: string;
  action: string;
  is_exception: boolean;
};

const EMPTY: FormState = {
  id: null,
  data_type: "pii",
  channel: "email",
  approved_destinations: "",
  min_confidence: "0.8",
  action: "block",
  is_exception: false,
};

function PoliciesPage() {
  const { data: orgId } = useOrg();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<FormState | null>(null);

  const policies = useQuery({
    queryKey: ["policies", orgId],
    enabled: !!orgId,
    queryFn: async () => {
      const { data, error } = await supabase
        .from("dlp_policies")
        .select("id, data_type, channel, condition, action, is_exception, created_at")
        .eq("org_id", orgId!)
        .order("created_at", { ascending: false });
      if (error) throw error;
      return data as unknown as Policy[];
    },
  });

  const save = useMutation({
    mutationFn: async (state: FormState) => {
      const payload = {
        org_id: orgId!,
        data_type: state.data_type,
        channel: state.channel,
        action: state.action,
        is_exception: state.is_exception,
        condition: {
          approved_destinations: state.approved_destinations
            .split(/[\n,]/)
            .map((s) => s.trim())
            .filter(Boolean),
          min_confidence: Number(state.min_confidence) || 0,
        },
      };
      if (state.id) {
        const { error } = await supabase.from("dlp_policies").update(payload).eq("id", state.id);
        if (error) throw error;
      } else {
        const { error } = await supabase.from("dlp_policies").insert(payload);
        if (error) throw error;
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
      setForm(null);
      toast.success("Policy saved");
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Could not save policy"),
  });

  const remove = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("dlp_policies").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["policies"] });
      toast.success("Policy deleted");
    },
  });

  const rows = policies.data ?? [];

  return (
    <AppShell
      title="Policies"
      description="Rules evaluated against every classified transfer"
      actions={
        <Button size="sm" onClick={() => setForm(EMPTY)}>
          <Plus className="size-4" />
          New policy
        </Button>
      }
    >
      <div className="panel overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>Data type</TableHead>
              <TableHead>Channel</TableHead>
              <TableHead>Approved destinations</TableHead>
              <TableHead className="w-[130px]">Min confidence</TableHead>
              <TableHead className="w-[110px]">Action</TableHead>
              <TableHead className="w-[90px]" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="py-12 text-center text-sm text-muted-foreground">
                  No policies yet. Create one to start enforcing.
                </TableCell>
              </TableRow>
            ) : (
              rows.map((p) => {
                const dests = p.condition?.approved_destinations ?? [];
                return (
                  <TableRow key={p.id}>
                    <TableCell className="text-sm">
                      {DATA_TYPE_LABELS[p.data_type] ?? p.data_type}
                      {p.is_exception ? (
                        <span className="ml-2 rounded border border-border px-1.5 py-0.5 text-[10px] uppercase text-muted-foreground">
                          Exception
                        </span>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-sm">{CHANNEL_LABELS[p.channel] ?? p.channel}</TableCell>
                    <TableCell className="max-w-[300px] truncate font-mono text-xs text-muted-foreground">
                      {dests.length ? dests.join(", ") : "Any"}
                    </TableCell>
                    <TableCell className="font-mono text-xs tabular-nums">
                      {Math.round((p.condition?.min_confidence ?? 0) * 100)}%
                    </TableCell>
                    <TableCell>
                      <DecisionBadge decision={p.action} />
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7"
                          onClick={() =>
                            setForm({
                              id: p.id,
                              data_type: p.data_type,
                              channel: p.channel,
                              approved_destinations: dests.join("\n"),
                              min_confidence: String(p.condition?.min_confidence ?? 0),
                              action: p.action,
                              is_exception: p.is_exception,
                            })
                          }
                        >
                          <Pencil className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-7 text-muted-foreground hover:text-destructive"
                          onClick={() => remove.mutate(p.id)}
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
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
                <DialogTitle>{form.id ? "Edit policy" : "New policy"}</DialogTitle>
                <DialogDescription>
                  Applies when the classifier matches this data type on this channel.
                </DialogDescription>
              </DialogHeader>

              <div className="grid gap-4 py-5">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label>Data type</Label>
                    <Select value={form.data_type} onValueChange={(v) => setForm({ ...form, data_type: v })}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {DATA_TYPES.map((d) => (
                          <SelectItem key={d} value={d}>
                            {DATA_TYPE_LABELS[d]}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label>Channel</Label>
                    <Select value={form.channel} onValueChange={(v) => setForm({ ...form, channel: v })}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {CHANNELS.map((c) => (
                          <SelectItem key={c} value={c}>
                            {CHANNEL_LABELS[c]}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="dests">Approved destinations</Label>
                  <Textarea
                    id="dests"
                    rows={3}
                    placeholder={"partner.com\nvault.internal"}
                    value={form.approved_destinations}
                    onChange={(e) => setForm({ ...form, approved_destinations: e.target.value })}
                  />
                  <p className="text-xs text-muted-foreground">One per line. Leave empty to match any destination.</p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="conf">Min confidence</Label>
                    <Input
                      id="conf"
                      type="number"
                      step="0.05"
                      min="0"
                      max="1"
                      value={form.min_confidence}
                      onChange={(e) => setForm({ ...form, min_confidence: e.target.value })}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label>Action</Label>
                    <Select value={form.action} onValueChange={(v) => setForm({ ...form, action: v })}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {ACTIONS.map((a) => (
                          <SelectItem key={a} value={a}>
                            {DECISION_LABELS[a]}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="flex items-center justify-between rounded-md border border-border p-3">
                  <div>
                    <p className="text-sm font-medium">Exception policy</p>
                    <p className="text-xs text-muted-foreground">Overrides matching enforcement rules.</p>
                  </div>
                  <Switch
                    checked={form.is_exception}
                    onCheckedChange={(v) => setForm({ ...form, is_exception: v })}
                  />
                </div>
              </div>

              <DialogFooter>
                <Button type="button" variant="ghost" onClick={() => setForm(null)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={save.isPending}>
                  Save policy
                </Button>
              </DialogFooter>
            </form>
          ) : null}
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
