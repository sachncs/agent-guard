import type { Metadata } from "next";
import { cookies } from "next/headers";
import { Geist, Geist_Mono } from "next/font/google";
import { Toaster } from "@/components/ui/sonner";
import { ConsoleNav } from "@/components/console_nav";
import { authConfig } from "@/lib/auth/config";
import {
  SESSION_COOKIE,
  type SessionClaims,
  parseCookieHeader,
  verifySession,
} from "@/lib/auth/session";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

// The console shell renders the signed-in identity; every request must
// be server-rendered against fresh cookies (never prerendered).
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "agentguard console",
  description:
    "Cedar-powered authorization for AI agents — dashboard, policy simulator and delegation console",
};

export default async function RootLayout({ children }: LayoutProps<"/">) {
  let user: SessionClaims | null = null;
  const cfg = authConfig();
  if (cfg.valid) {
    const cookieStore = await cookies();
    const result = await verifySession(
      cfg.config.sessionSecret,
      parseCookieHeader(cookieStore.toString())[SESSION_COOKIE]
    );
    user = result.ok ? result.claims : null;
  }

  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <ConsoleNav user={user} />
        <main className="mx-auto w-full max-w-6xl flex-1 px-6 py-8">
          {children}
        </main>
        <Toaster richColors position="top-right" />
      </body>
    </html>
  );
}
