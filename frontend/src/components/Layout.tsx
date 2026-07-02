import { Link, useLocation } from "react-router";

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const isHome = location.pathname === "/";

  return (
    <div className="min-h-screen flex flex-col">
      {!isHome && (
        <header className="border-b border-border px-6 py-3 flex items-center gap-4">
          <Link to="/" className="text-accent font-bold text-lg tracking-tight hover:opacity-80 transition-opacity">
            VibeSec
          </Link>
          <span className="text-muted text-sm">Security Recon</span>
        </header>
      )}
      <main className="flex-1">{children}</main>
    </div>
  );
}
