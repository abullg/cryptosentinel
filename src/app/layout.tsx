import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CryptoSentinel — AI Vulnerability Scanner",
  description: "Autonomous AI-powered smart contract and crypto exchange vulnerability scanner with OpenRouter GLM models.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
      </head>
      <body className="antialiased bg-background text-foreground font-sans">
        {children}
      </body>
    </html>
  );
}
