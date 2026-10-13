import { Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import {
  LayoutDashboard,
  Search,
  Bell,
  ChevronDown,
  Shield,
  AlertTriangle,
  FileText,
  Radio,
  ShieldCheck,
  Settings,
  LogOut,
  Zap,
  Sun,
  Moon,
  Lock,
} from "lucide-react";

import { FIXTURE_MODE } from "@/lib/env";
import { Button } from "@/components/ui/button";

const NAV = [
  { to: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { to: "/findings", label: "Findings", icon: Search },
  { to: "/incidents", label: "Incidents", icon: AlertTriangle },
  { to: null, label: "Alerts", icon: Bell },
  { to: null, label: "Reports", icon: FileText },
  { to: null, label: "Channels", icon: Radio },
  { to: "/policies", label: "Policies", icon: ShieldCheck },
  { to: null, label: "Settings", icon: Settings },
] as const;

const THEME_STORAGE_KEY = "dlp-theme";

export function AppShell({
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
      setEmail("ashish@corp.com");
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

  const displayName = email?.split("@")[0] ?? "Ashish";

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
            if (!item.to) {
              return (
                <button
                  key={item.label}
                  type="button"
                  disabled
                  className="flex items-center gap-3 rounded-xl px-3 py-2 text-[13px] w-full text-left cursor-not-allowed opacity-50"
                  style={{
                    color: "var(--muted-foreground)",
                  }}
                  title={`${item.label} is not available yet`}
                >
                  <item.icon className="size-[16px]" style={{ color: "var(--muted-foreground)" }} />
                  {item.label}
                </button>
              );
            }
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
            className="rounded-2xl p-4 relative overflow-hidden"
            style={{
              background: "var(--sidebar-primary)",
            }}
          >
            <div
              className="absolute -top-4 -right-4 size-16 rounded-full opacity-10"
              style={{ background: "white" }}
            />
            <div
              className="absolute -bottom-6 -left-4 size-20 rounded-full opacity-[0.06]"
              style={{ background: "white" }}
            />
            <Lock className="size-5 mb-2 relative z-10" style={{ color: "var(--sidebar-primary-foreground)", opacity: 0.8 }} />
            <p className="text-[13px] font-semibold relative z-10" style={{ color: "var(--sidebar-primary-foreground)" }}>
              Keep your data safe
            </p>
            <p className="text-[10.5px] mt-1 relative z-10" style={{ color: "var(--sidebar-primary-foreground)", opacity: 0.6 }}>
              Real-time DLP monitoring across all channels.
            </p>
            <button
              type="button"
              disabled
              className="mt-3 w-full rounded-lg px-3 py-1.5 text-[11px] font-semibold transition-opacity hover:opacity-90 relative z-10 cursor-not-allowed"
              title="Plan upgrades are not available yet"
              style={{
                background: "oklch(1 0 0 / 0.15)",
                color: "var(--sidebar-primary-foreground)",
                border: "1px solid oklch(1 0 0 / 0.2)",
              }}
            >
              Upgrade Plan
            </button>
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
            <button
              type="button"
              disabled
              aria-label="Notifications"
              title="Notifications are not available yet"
              className="relative flex size-8 items-center justify-center rounded-xl border transition-colors hover:bg-accent"
              style={{ borderColor: "var(--border)", background: "var(--surface-2)" }}
            >
              <Bell className="size-3.5" style={{ color: "var(--muted-foreground)" }} />
              <span
                className="absolute top-1.5 right-1.5 size-1.5 rounded-full"
                style={{ background: "var(--critical)" }}
              />
            </button>

            {/* User */}
            <button
              type="button"
              disabled
              aria-label="User profile"
              title="Profile settings are not available yet"
              className="flex items-center gap-2 rounded-xl border px-2.5 py-1.5 transition-colors hover:bg-accent"
              style={{ borderColor: "var(--border)", background: "var(--surface-2)" }}
            >
              <div
                className="flex size-6 items-center justify-center rounded-full text-[10px] font-bold"
                style={{ background: "var(--primary)", color: "var(--primary-foreground)" }}
              >
                {displayName.charAt(0).toUpperCase()}
              </div>
              <div className="hidden sm:block text-left">
                <p
                  className="text-[12px] font-semibold leading-tight"
                  style={{ color: "var(--foreground)" }}
                >
                  {displayName}
                </p>
                <p
                  className="text-[10px] leading-tight"
                  style={{ color: "var(--muted-foreground)" }}
                >
                  Admin
                </p>
              </div>
              <ChevronDown className="size-3" style={{ color: "var(--muted-foreground)" }} />
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-auto">{children}</main>

        {/* Mobile bottom nav */}
        <nav
          className="flex border-t md:hidden"
          style={{ background: "var(--sidebar)", borderColor: "var(--sidebar-border)" }}
        >
          {NAV.slice(0, 5).map((item) => {
            if (!item.to) {
              return (
                <button
                  key={item.label}
                  type="button"
                  disabled
                  title={`${item.label} is not available yet`}
                  className="flex flex-1 flex-col items-center gap-1 py-2.5 text-[10px] cursor-not-allowed opacity-60"
                  style={{ color: "var(--muted-foreground)" }}
                >
                  <item.icon className="size-4" />
                  {item.label}
                </button>
              );
            }
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
