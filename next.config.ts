import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: 'standalone',
  typescript: { ignoreBuildErrors: true },
  reactStrictMode: false,
  serverExternalPackages: [],
  env: {
    GITHUB_TOKEN: process.env.GITHUB_TOKEN || '',
  },
};

export default nextConfig;
