import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sentinel AI — Autonomous Code Security Command Center",
  description:
    "AI Security Co-Pilot that analyzes AI-generated code, detects vulnerabilities, explains threats, applies one-click secure fixes, simulates attacks, and generates security reports.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Mona+Sans:wght@400;500;600;700&family=Commissioner:wght@400;500;600&family=Fragment+Mono&display=swap"
          rel="stylesheet"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=block"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-screen bg-background text-on-background antialiased selection:bg-primary-container/30 selection:text-primary">
        {children}
      </body>
    </html>
  );
}
