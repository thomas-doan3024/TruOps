import type { Metadata } from "next";
import Link from "next/link";
import ThemeToggle from "@/components/ThemeToggle";
import "./globals.css";

export const metadata: Metadata = {
  title: "TruOps · NIST CSF 2.0 Posture",
  description: "AI-powered, control-first NIST CSF 2.0 compliance posture assessment.",
};

// Applies the saved (or system-preferred) theme before paint to avoid a flash.
const themeInitScript = `(function(){try{var t=localStorage.getItem('theme');var m=window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches;if(t==='light'||(!t&&m)){document.documentElement.classList.add('light');}}catch(e){}})();`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body>
        <header className="border-b border-edge/80 bg-ink/60 backdrop-blur sticky top-0 z-20">
          <div className="mx-auto max-w-7xl px-6 py-3 flex items-center justify-between">
            <Link href="/" className="flex items-center gap-3 group">
              <span className="grid h-9 w-9 place-items-center rounded-lg bg-brand/15 ring-1 ring-brand/40 text-brand font-bold">
                T
              </span>
              <div className="leading-tight">
                <div className="font-semibold tracking-tight group-hover:text-brand transition-colors">
                  TruOps Posture
                </div>
                <div className="text-[11px] text-slate-400 -mt-0.5">
                  NIST CSF 2.0 · control-first · AI-assessed
                </div>
              </div>
            </Link>
            <nav className="flex items-center gap-5 text-sm text-slate-300">
              <Link href="/" className="hover:text-slate-100 transition-colors">
                Dashboard
              </Link>
              <a
                href="https://www.nist.gov/cyberframework"
                target="_blank"
                rel="noreferrer"
                className="hover:text-slate-100 transition-colors"
              >
                Framework ↗
              </a>
              <ThemeToggle />
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-7xl px-6 py-8">{children}</main>
        <footer className="mx-auto max-w-7xl px-6 py-10 text-xs text-slate-500">
          Coverage and pass/fail are AI-assessed from connected evidence sources and should be reviewed by a
          qualified assessor.
        </footer>
      </body>
    </html>
  );
}
