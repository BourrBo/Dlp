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
    if (FIXTURE_MODE) { setEmail("ashish@corp.com"); return; }
    import("@/integrations/supabase/client").then(({ supabase }) =>
      supabase.auth.getUser().then(({ data }) => setEmail(data.user?.email ?? null))
    ).catch(() => {});
  }, []);

  function toggleTheme() {
    setIsDark((d) => {
      document.documentElement.classList.toggle("dark", !d);
      return !d;
    });
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
    <div className="flex min-h-screen" style={{ background: "oklch(0.95 0.006 250)" }}>
      {/* Sidebar */}
      <aside
        className="hidden md:flex w-64 shrink-0 flex-col border-r"
        style={{
          background: "oklch(0.99 0.002 250)",
          borderColor: "oklch(0.90 0.007 250)",
        }}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5 border-b" style={{ borderColor: "oklch(0.90 0.007 250)" }}>
          <div
            className="flex size-9 items-center justify-center rounded-xl"
            style={{ background: "oklch(0.44 0.17 255)", boxShadow: "0 2px 8px oklch(0.44 0.17 255 / 0.35)" }}
          >
            <Shield className="size-5 text-white" />
          </div>
          <div className="leading-tight">
            <p className="text-sm font-bold tracking-tight" style={{ color: "oklch(0.18 0.015 250)" }}>
              DLP Console
            </p>
            <p className="text-[11px]" style={{ color: "oklch(0.52 0.018 250)" }}>
              Data Loss Prevention
            </p>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex flex-1 flex-col gap-1 px-3 py-4">
          <p
            className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-widest"
            style={{ color: "oklch(0.65 0.015 250)" }}
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
                  className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm w-full text-left cursor-not-allowed opacity-60"
                  style={{
                    color: "oklch(0.52 0.018 250)",
                  }}
                  title={`${item.label} is not available yet`}
                >
                  <span
                    className="flex size-7 items-center justify-center rounded-lg"
                    style={{ background: "oklch(0.93 0.006 250)" }}
                  >
                    <item.icon className="size-4" style={{ color: "oklch(0.52 0.018 250)" }} />
                  </span>
                  {item.label}
                </button>
              );
            }
            return (
              <Link
                key={item.label}
                to={item.to}
                className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-all"
                activeProps={{
                  className:
                    "flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-semibold transition-all",
                  style: {
                    background: "oklch(0.18 0.015 250)",
                    color: "oklch(0.99 0.002 250)",
                    boxShadow: "0 2px 8px oklch(0.18 0.015 250 / 0.25)",
                  },
                }}
                style={{ color: "oklch(0.40 0.018 250)" }}
              >
                <span
                  className="flex size-7 items-center justify-center rounded-lg"
                  style={{ background: "oklch(0.93 0.006 250)" }}
                >
                  <item.icon className="size-4" style={{ color: "oklch(0.52 0.018 250)" }} />
                </span>
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
              background: "linear-gradient(135deg, oklch(0.44 0.17 255), oklch(0.38 0.20 280))",
            }}
          >
            <div
              className="absolute -top-4 -right-4 size-16 rounded-full opacity-20"
              style={{ background: "white" }}
            />
            <div
              className="absolute -bottom-6 -left-4 size-20 rounded-full opacity-10"
              style={{ background: "white" }}
            />
            <Lock className="size-6 text-white/90 mb-2 relative z-10" />
            <p className="text-sm font-semibold text-white relative z-10">Keep your sensitive data safe</p>
            <p className="text-[11px] text-white/70 mt-1 relative z-10">
              Real-time DLP monitoring across all channels.
            </p>
            <button
              type="button"
              disabled
              className="mt-3 w-full rounded-lg px-3 py-1.5 text-xs font-semibold transition-opacity hover:opacity-90 relative z-10"
              title="Plan upgrades are not available yet"
              style={{
                background: "oklch(1 0 0 / 0.2)",
                color: "white",
                border: "1px solid oklch(1 0 0 / 0.3)",
              }}
            >
              Upgrade Plan
            </button>
          </div>
        </div>

        {/* User / sign out */}
        <div
          className="flex items-center gap-3 border-t p-4"
          style={{ borderColor: "oklch(0.90 0.007 250)" }}
        >
          <div
            className="flex size-8 shrink-0 items-center justify-center rounded-full text-xs font-bold text-white"
            style={{ background: "oklch(0.44 0.17 255)" }}
          >
            {displayName.charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-xs font-semibold" style={{ color: "oklch(0.22 0.015 250)" }}>
              {displayName}
            </p>
            <p className="truncate text-[10px]" style={{ color: "oklch(0.55 0.015 250)" }}>
              {email ?? "—"}
            </p>
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="size-7 shrink-0"
            onClick={handleSignOut}
          >
            <LogOut className="size-3.5" style={{ color: "oklch(0.55 0.015 250)" }} />
          </Button>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Top header */}
        <header
          className="flex items-center gap-3 border-b px-6 py-3 sticky top-0 z-10"
          style={{
            background: "oklch(0.99 0.002 250 / 0.9)",
            backdropFilter: "blur(12px)",
            borderColor: "oklch(0.90 0.007 250)",
          }}
        >
          {/* Search */}
          <div
            className="flex flex-1 max-w-md items-center gap-2 rounded-xl border px-3 py-2"
            style={{
              background: "oklch(0.96 0.004 250)",
              borderColor: "oklch(0.88 0.008 250)",
            }}
          >
            <Search className="size-4 shrink-0" style={{ color: "oklch(0.60 0.015 250)" }} />
            <input
              className="flex-1 bg-transparent text-sm outline-none placeholder:text-sm"
              placeholder="Search findings, files, users..."
              aria-label="Search findings, files, and users"
              disabled
              title="Search is not available yet"
              style={{ color: "oklch(0.25 0.015 250)" }}
            />
            <kbd
              className="hidden sm:flex items-center gap-0.5 rounded-md border px-1.5 py-0.5 text-[10px] font-medium"
              style={{
                color: "oklch(0.55 0.015 250)",
                borderColor: "oklch(0.85 0.008 250)",
                background: "oklch(0.93 0.005 250)",
              }}
            >
              Ctrl K
            </kbd>
          </div>

          <div className="flex items-center gap-2 ml-auto">
            {/* Theme toggle */}
            <button
              onClick={toggleTheme}
              className="flex size-9 items-center justify-center rounded-xl border transition-colors hover:bg-accent"
              style={{ borderColor: "oklch(0.88 0.008 250)", background: "oklch(0.96 0.004 250)" }}
            >
              {isDark ? (
                <Sun className="size-4" style={{ color: "oklch(0.55 0.015 250)" }} />
              ) : (
                <Moon className="size-4" style={{ color: "oklch(0.55 0.015 250)" }} />
              )}
            </button>

            {/* Notifications */}
            <button
              type="button"
              disabled
              aria-label="Notifications"
              title="Notifications are not available yet"
              className="relative flex size-9 items-center justify-center rounded-xl border transition-colors hover:bg-accent"
              style={{ borderColor: "oklch(0.88 0.008 250)", background: "oklch(0.96 0.004 250)" }}
            >
              <Bell className="size-4" style={{ color: "oklch(0.55 0.015 250)" }} />
              <span
                className="absolute top-1.5 right-1.5 size-2 rounded-full"
                style={{ background: "oklch(0.55 0.22 25)" }}
              />
            </button>

            {/* User */}
            <button
              type="button"
              disabled
              aria-label="User profile"
              title="Profile settings are not available yet"
              className="flex items-center gap-2 rounded-xl border px-3 py-2 transition-colors hover:bg-accent"
              style={{ borderColor: "oklch(0.88 0.008 250)", background: "oklch(0.96 0.004 250)" }}
            >
              <div
                className="flex size-6 items-center justify-center rounded-full text-[10px] font-bold text-white"
                style={{ background: "oklch(0.44 0.17 255)" }}
              >
                {displayName.charAt(0).toUpperCase()}
              </div>
              <div className="hidden sm:block text-left">
                <p className="text-xs font-semibold leading-tight" style={{ color: "oklch(0.22 0.015 250)" }}>
                  {displayName}
                </p>
                <p className="text-[10px] leading-tight" style={{ color: "oklch(0.55 0.015 250)" }}>
                  Admin
                </p>
              </div>
              <ChevronDown className="size-3.5" style={{ color: "oklch(0.55 0.015 250)" }} />
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-auto">{children}</main>

        {/* Mobile bottom nav */}
        <nav
          className="flex border-t md:hidden"
          style={{ background: "oklch(0.99 0.002 250)", borderColor: "oklch(0.90 0.007 250)" }}
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
                  style={{ color: "oklch(0.55 0.015 250)" }}
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
                activeProps={{ style: { color: "oklch(0.44 0.17 255)" } }}
                style={{ color: "oklch(0.55 0.015 250)" }}
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
