import { Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import {
  Activity,
  LayoutDashboard,
  Search,
  Bell,
  ChevronDown,
  Shield,
  AlertTriangle,
  ShieldCheck,
  ShieldOff,
  KeyRound,
  Layers,
  Upload,
  LogOut,
  Zap,
  Sun,
  Moon,
  Lock,
} from "lucide-react";

import { useQuery } from "@tanstack/react-query";

import { FIXTURE_MODE } from "@/lib/env";
import { formatDateTime } from "@/lib/dlp";
import { loadFindings } from "@/lib/findings-api";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Button } from "@/components/ui/button";

const NAV = [
  { to: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { to: "/events", label: "Events", icon: Activity },
  { to: "/findings", label: "Findings", icon: Search },
  { to: "/incidents", label: "Incidents", icon: AlertTriangle },
  { to: "/scan", label: "Scan a file", icon: Upload },
  { to: "/policies", label: "Policies", icon: ShieldCheck },
  { to: "/exceptions", label: "Exceptions", icon: ShieldOff },
  { to: "/api-keys", label: "API keys", icon: KeyRound },
  { to: "/platform", label: "Platform", icon: Layers },
] as const;

const THEME_STORAGE_KEY = "dlp-theme";

/** Bell menu: the newest open findings, refreshed once a minute. */
function NotificationsMenu() {
  const { data, isError, isLoading } = useQuery({
    queryKey: ["notifications", "open-findings"],
    queryFn: loadFindings,
    refetchInterval: 60_000,
    staleTime: 30_000,
    retry: false,
  });
  const open = (data ?? []).filter((finding) => finding.status === "open");
  const latest = [...open]
    .sort((a, b) => b.created_at.localeCompare(a.created_at))
    .slice(0, 5);

  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={open.length > 0 ? `Notifications, ${open.length} open findings` : "Notifications"}
          className="relative flex size-8 items-center justify-center rounded-xl border transition-colors hover:bg-accent"
          style={{ borderColor: "var(--border)", background: "var(--surface-2)" }}
        >
          <Bell className="size-3.5" style={{ color: "var(--muted-foreground)" }} />
          {open.length > 0 && (
            <span
              className="absolute -right-1 -top-1 flex min-w-4 items-center justify-center rounded-full px-1 text-[9px] font-bold leading-4"
              style={{ background: "var(--critical)", color: "white" }}
            >
              {open.length > 9 ? "9+" : open.length}
            </span>
          )}
        </button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 p-0">
        <div className="border-b px-4 py-3" style={{ borderColor: "var(--border)" }}>
          <p className="text-sm font-semibold">Notifications</p>
          <p className="text-xs text-muted-foreground">
            {open.length === 0 ? "No open findings" : `${open.length} open finding${open.length === 1 ? "" : "s"}`}
          </p>
        </div>
        <div className="max-h-72 overflow-auto">
          {isLoading && <p className="px-4 py-6 text-center text-xs text-muted-foreground">Loading…</p>}
          {isError && (
            <p className="px-4 py-6 text-center text-xs text-muted-foreground">
              Notifications could not be loaded.
            </p>
          )}
          {!isLoading && !isError && latest.length === 0 && (
            <p className="px-4 py-6 text-center text-xs text-muted-foreground">You're all caught up.</p>
          )}
          {latest.map((finding) => (
            <Link
              key={finding.id}
              to="/findings"
              className="flex items-start gap-3 border-b px-4 py-3 text-left transition-colors last:border-b-0 hover:bg-accent"
              style={{ borderColor: "var(--border)" }}
            >
              <span
                className="mt-1.5 size-2 shrink-0 rounded-full"
                style={{ background: "var(--critical)" }}
                aria-hidden="true"
              />
              <span className="min-w-0">
                <span className="block truncate text-xs font-semibold capitalize">
                  {finding.severity} · {finding.detector}
                </span>
                <span className="block truncate text-[11px] text-muted-foreground">
                  {finding.source} · {formatDateTime(finding.created_at)}
                </span>
              </span>
            </Link>
          ))}
        </div>
        <div className="border-t p-2" style={{ borderColor: "var(--border)" }}>
          <Link
            to="/findings"
            className="block rounded-md px-3 py-2 text-center text-xs font-medium transition-colors hover:bg-accent"
          >
            View all findings
          </Link>
        </div>
      </PopoverContent>
    </Popover>
  );
}

export function AppShell({
  title,
  description,
  actions,
  children,
}: {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState<string | null>(null);
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const savedTheme = localStorage.getItem(THEME_STORAGE_KEY);
    const dark = savedTheme === "dark";
    setIsDark(dark);
    document.documentElement.classList.toggle("dark", dark);
  }, []);

  useEffect(() => {
    if (FIXTURE_MODE) {
      setEmail("fixture@example.com");
      return;
    }
    import("@/integrations/supabase/client")
      .then(({ supabase }) =>
        supabase.auth.getUser().then(({ data }) => setEmail(data.user?.email ?? null)),
      )
      .catch(() => {});
  }, []);

  function toggleTheme() {
    const dark = !isDark;
    setIsDark(dark);
    document.documentElement.classList.toggle("dark", dark);
    localStorage.setItem(THEME_STORAGE_KEY, dark ? "dark" : "light");
  }

  async function handleSignOut() {
    await queryClient.cancelQueries();
    queryClient.clear();
    if (!FIXTURE_MODE) {
      try {
        const { supabase } = await import("@/integrations/supabase/client");
        await supabase.auth.signOut();
      } catch (error) {
        console.error("Unable to sign out from Supabase", error);
      }
    }
    navigate({ to: "/auth", replace: true });
  }

  const displayName = email?.split("@")[0] ?? "Account";

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      {/* ── Sidebar ────────────────────────────────────────────── */}
      <aside
        className="hidden md:flex w-[252px] shrink-0 flex-col border-r"
        style={{ background: "var(--sidebar)", borderColor: "var(--sidebar-border)" }}
      >
        {/* Logo */}
        <div
          className="flex items-center gap-3 px-5 py-5 border-b"
          style={{ borderColor: "var(--sidebar-border)" }}
        >
          <div
            className="flex size-9 items-center justify-center rounded-xl"
            style={{
              background: "var(--sidebar-primary)",
              boxShadow: "0 2px 6px oklch(0 0 0 / 0.18)",
            }}
          >
            <Shield className="size-5" style={{ color: "var(--sidebar-primary-foreground)" }} />
          </div>
          <div className="leading-tight">
            <p
              className="text-sm font-bold tracking-tight"
              style={{ color: "var(--foreground)" }}
            >
              DLP Console
            </p>
            <p className="text-[10.5px]" style={{ color: "var(--muted-foreground)" }}>
              Data Loss Prevention
            </p>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex flex-1 flex-col gap-0.5 px-3 py-4">
          <p
            className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-widest"
            style={{ color: "var(--muted-foreground)" }}
          >
            Main Menu
          </p>
          {NAV.map((item) => {
            return (
              <Link
                key={item.label}
                to={item.to}
                className="flex items-center gap-3 rounded-xl px-3 py-2 text-[13px] transition-all hover:bg-[var(--sidebar-accent)]"
                activeProps={{
                  className:
                    "flex items-center gap-3 rounded-xl px-3 py-2 text-[13px] font-semibold transition-all",
                  style: {
                    background: "var(--sidebar-primary)",
                    color: "var(--sidebar-primary-foreground)",
                    boxShadow: "0 1px 4px oklch(0 0 0 / 0.12)",
                  },
                }}
                style={{ color: "var(--sidebar-foreground)" }}
              >
                <item.icon className="size-[16px]" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Promo card */}
        <div className="px-3 pb-3">
          <div
            className="relative overflow-hidden rounded-2xl border p-4"
            style={{ background: "var(--sidebar-accent)", borderColor: "var(--sidebar-border)" }}
          >
            <Lock className="relative z-10 mb-2 size-5" style={{ color: "var(--foreground)", opacity: 0.8 }} />
            <p className="relative z-10 text-[13px] font-semibold" style={{ color: "var(--foreground)" }}>
              Keep your data safe
            </p>
            <p className="relative z-10 mt-1 text-[10.5px]" style={{ color: "var(--muted-foreground)" }}>
              Real-time DLP monitoring across all channels.
            </p>
            <Link
              to="/api-keys"
              className="relative z-10 mt-3 block w-full rounded-lg border px-3 py-1.5 text-center text-[11px] font-semibold transition-colors hover:bg-accent"
              style={{ borderColor: "var(--sidebar-border)", color: "var(--foreground)", background: "var(--background)" }}
            >
              Manage API keys
            </Link>
          </div>
        </div>

        {/* User / sign out */}
        <div
          className="flex items-center gap-3 border-t p-4"
          style={{ borderColor: "var(--sidebar-border)" }}
        >
          <div
            className="flex size-8 shrink-0 items-center justify-center rounded-full text-[11px] font-bold"
            style={{ background: "var(--sidebar-primary)", color: "var(--sidebar-primary-foreground)" }}
          >
            {displayName.charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <p
              className="truncate text-xs font-semibold"
              style={{ color: "var(--foreground)" }}
            >
              {displayName}
            </p>
            <p className="truncate text-[10px]" style={{ color: "var(--muted-foreground)" }}>
              {email ?? "—"}
            </p>
          </div>
          <Button variant="ghost" size="icon" className="size-7 shrink-0" onClick={handleSignOut}>
            <LogOut className="size-3.5" style={{ color: "var(--muted-foreground)" }} />
          </Button>
        </div>
      </aside>

      {/* ── Main content ──────────────────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Top header */}
        <header
          className="flex items-center gap-3 border-b px-6 py-2.5 sticky top-0 z-10"
          style={{
            background: "color-mix(in oklch, var(--background) 85%, transparent)",
            backdropFilter: "blur(14px)",
            borderColor: "var(--border)",
          }}
        >
          {/* Search */}
          <div
            className="flex flex-1 max-w-sm items-center gap-2 rounded-xl border px-3 py-[7px]"
            style={{
              background: "var(--surface-2)",
              borderColor: "var(--border)",
            }}
          >
            <Search className="size-3.5 shrink-0" style={{ color: "var(--muted-foreground)" }} />
            <input
              className="flex-1 bg-transparent text-[13px] outline-none placeholder:text-[13px]"
              placeholder="Search findings, files, users..."
              aria-label="Search findings, files, and users"
              disabled
              title="Search is not available yet"
              style={{ color: "var(--foreground)" }}
            />
            <kbd
              className="hidden sm:flex items-center gap-0.5 rounded-md border px-1.5 py-0.5 text-[10px] font-medium"
              style={{
                color: "var(--muted-foreground)",
                borderColor: "var(--border)",
                background: "var(--surface-2)",
              }}
            >
              Ctrl K
            </kbd>
          </div>

          <div className="flex items-center gap-1.5 ml-auto">
            {/* Theme toggle */}
            <button
              type="button"
              onClick={toggleTheme}
              aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
              title={isDark ? "Switch to light mode" : "Switch to dark mode"}
              className="flex size-8 items-center justify-center rounded-xl border transition-colors hover:bg-accent"
              style={{ borderColor: "var(--border)", background: "var(--surface-2)" }}
            >
              {isDark ? (
                <Sun className="size-3.5" aria-hidden="true" />
              ) : (
                <Moon className="size-3.5" aria-hidden="true" />
              )}
            </button>

            {/* Notifications */}
            <NotificationsMenu />

            {/* User menu */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  type="button"
                  aria-label="Account menu"
                  className="flex items-center gap-2 rounded-xl border px-2.5 py-1.5 transition-colors hover:bg-accent"
                  style={{ borderColor: "var(--border)", background: "var(--surface-2)" }}
                >
                  <div
                    className="flex size-6 items-center justify-center rounded-full text-[10px] font-bold"
                    style={{ background: "var(--primary)", color: "var(--primary-foreground)" }}
                  >
                    {displayName.charAt(0).toUpperCase()}
                  </div>
                  <div className="hidden text-left sm:block">
                    <p className="text-[12px] font-semibold leading-tight" style={{ color: "var(--foreground)" }}>
                      {displayName}
                    </p>
                    <p className="text-[10px] leading-tight" style={{ color: "var(--muted-foreground)" }}>
                      Signed in
                    </p>
                  </div>
                  <ChevronDown className="size-3" style={{ color: "var(--muted-foreground)" }} />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-60">
                <DropdownMenuLabel className="font-normal">
                  <p className="truncate text-sm font-semibold">{displayName}</p>
                  <p className="truncate text-xs text-muted-foreground">{email ?? "—"}</p>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem asChild>
                  <Link to="/api-keys" className="cursor-pointer">
                    <KeyRound className="mr-2 size-4" /> API keys
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuItem asChild>
                  <Link to="/platform" className="cursor-pointer">
                    <Layers className="mr-2 size-4" /> Platform
                  </Link>
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={toggleTheme} className="cursor-pointer">
                  {isDark ? <Sun className="mr-2 size-4" /> : <Moon className="mr-2 size-4" />}
                  {isDark ? "Light mode" : "Dark mode"}
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => void handleSignOut()} className="cursor-pointer">
                  <LogOut className="mr-2 size-4" /> Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>

        <main className="flex-1 overflow-auto">
          {title ? (
            <div className="flex flex-wrap items-start justify-between gap-4 px-6 pt-6">
              <div>
                <h1 className="text-xl font-bold" style={{ color: "var(--foreground)" }}>
                  {title}
                </h1>
                {description ? (
                  <p className="mt-0.5 text-[13px]" style={{ color: "var(--muted-foreground)" }}>
                    {description}
                  </p>
                ) : null}
              </div>
              {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
            </div>
          ) : null}
          {title ? <div className="px-6 py-6">{children}</div> : children}
        </main>

        {/* Mobile bottom nav */}
        <nav
          className="flex border-t md:hidden"
          style={{ background: "var(--sidebar)", borderColor: "var(--sidebar-border)" }}
        >
          {NAV.slice(0, 5).map((item) => {
            return (
              <Link
                key={item.to}
                to={item.to}
                className="flex flex-1 flex-col items-center gap-1 py-2.5 text-[10px]"
                activeProps={{ style: { color: "var(--primary)" } }}
                style={{ color: "var(--muted-foreground)" }}
              >
                <item.icon className="size-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>
      </div>
    </div>
  );
}

// Keep Zap in scope (used only to avoid TS unused import warning)
void Zap;
