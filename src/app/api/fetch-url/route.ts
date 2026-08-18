import { NextResponse } from 'next/server';
export const maxDuration = 600; // VPS KVM 2 — no Render/Vercel limits; allow 10min for slow sites with WAF
// analyzeWebApp removed — lightweight fetchWebsite + multi-pass AI in /api/analyze is faster
import { checkStandardRateLimit } from '@/lib/rate-limit';
import { isSsrfBlocked } from '@/lib/ssrf';

/**
 * GitHub API headers — includes Authorization token if GITHUB_TOKEN is set.
 * Authenticated requests: 5,000/hour + access to private repos (if token has repo scope).
 * Unauthenticated requests: 60/hour, public repos only.
 */
function getGitHubHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'User-Agent': 'CryptoSentinel/1.0',
    'Accept': 'application/vnd.github.v3+json',
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

const FETCH_TIMEOUT = 15_000;
const GH_FILE_TIMEOUT = 10_000;
const MAX_FILES = 10;
const MAX_FILE_SIZE = 30_000;
const MAX_TOTAL_SIZE = 200_000;

/**
 * Fetch content from a URL for analysis
 * - GitHub repos: fetches Solidity source files
 * - Exchange/website URLs: fetches page content for web vuln analysis
 * - Hackenproof URLs: fetches project description, priorities & scope
 */
export async function POST(req: Request) {
  const rl = checkStandardRateLimit(req);
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited', retryAfter: Math.ceil(rl.retryAfterMs / 1000) }, { status: 429 });
  try {
    const body = await req.json();
    const { url, type } = body;

    if (!url || typeof url !== 'string') {
      return NextResponse.json({ error: 'URL is required' }, { status: 400 });
    }

    // ── URL Normalization ──
    // 1. Trim whitespace
    let normalized = url.trim();

    // 2. Remove leading wildcard patterns like "*." or "*. "
    normalized = normalized.replace(/^\*\.?\s*/, '');

    // 3. Add https:// protocol if missing
    if (!normalized.match(/^https?:\/\//i)) {
      normalized = 'https://' + normalized;
    }

    // 4. Remove trailing slash for consistency (except root)
    if (normalized.length > 8 && normalized.endsWith('/')) {
      normalized = normalized.slice(0, -1);
    }

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(normalized);
    } catch (urlErr) {
      console.error('[fetch-url] invalid URL:', url, '→ normalized:', normalized, urlErr);
      return NextResponse.json(
        { error: `Invalid URL format: "${url}". Use format like https://example.com or just example.com` },
        { status: 400 }
      );
    }

    // ─── SSRF protection (audit fix MED-1) ───────────────────────────
    // Block private IPs, loopback, link-local, metadata service, sensitive ports.
    // Note: GitHub + block explorer + hackenproof URLs are exempted from
    // PORT blocking (they're 443 anyway) but NOT from IP blocking.
    const ssrfHostname = parsedUrl.hostname.toLowerCase();
    const ssrfIsGithub = ssrfHostname === 'github.com' || ssrfHostname === 'www.github.com'
      || ssrfHostname === 'raw.githubusercontent.com' || ssrfHostname === 'api.github.com'
      || ssrfHostname.endsWith('.githubusercontent.com');
    const ssrfIsHackenproof = ssrfHostname.includes('hackenproof');
    const ssrfIsBlockExplorer = /(?:etherscan|bscscan|polygonscan|arbiscan|snowtrace|ftmscan|basescan|optimistic\.etherscan|cronoscan|moonscan|avascan)\.io/.test(ssrfHostname)
      || /(?:explorer)\.(?:near\.org|solana\.com)/.test(ssrfHostname)
      || /(?:suiexplorer|starkscan|blockscout)/.test(ssrfHostname);

    if (!ssrfIsGithub && !ssrfIsHackenproof && !ssrfIsBlockExplorer) {
      const ssrfCheck = isSsrfBlocked(normalized);
      if (ssrfCheck.blocked) {
        console.warn('[fetch-url] SSRF blocked:', normalized, '→', ssrfCheck.reason);
        return NextResponse.json(
          { error: `URL blocked by SSRF protection: ${ssrfCheck.reason}. If this is a legitimate target, contact the administrator.` },
          { status: 403 }
        );
      }
    }

    // Auto-detect Hackenproof URLs regardless of type
    if (parsedUrl.hostname.toLowerCase().includes('hackenproof')) {
      return await fetchHackenproof(parsedUrl);
    }

    // Auto-detect block explorer URLs (Etherscan, BscScan, Polygonscan, etc.)
    const hostname = parsedUrl.hostname.toLowerCase();
    const isBlockExplorer = /(?:etherscan|bscscan|polygonscan|arbiscan|snowtrace|ftmscan|basescan|optimistic\.etherscan|cronoscan|moonscan|avascan)\.io/.test(hostname)
      || /(?:explorer)\.(?:near\.org|solana\.com)/.test(hostname)
      || /(?:suiexplorer|starkscan|blockscout)/.test(hostname);

    if (isBlockExplorer) {
      return await fetchBlockExplorer(parsedUrl);
    }

    // Auto-detect raw source URLs (.sol, .vy, .rs, .move, .cairo, .ts, .js, .py)
    const pathLower = parsedUrl.pathname.toLowerCase();
    const isDirectSource = /\.(?:sol|vy|rs|move|cairo|ts|tsx|js|jsx|py|go)$/.test(pathLower);
    if (isDirectSource && type === 'contract') {
      return await fetchDirectSource(parsedUrl);
    }

    if (type === 'contract') {
      if (!hostname.includes('github')) {
        // Non-GitHub contract URL: could be a web app hosting contracts
        // Use the new web app analyzer for comprehensive analysis
        return await fetchWebAppWithAI(parsedUrl, true);
      }
      return await fetchGitHubRepo(parsedUrl);
    } else {
      // Web application analysis: use the new comprehensive analyzer
      return await fetchWebAppWithAI(parsedUrl);
    }
  } catch (e) {
    console.error('[fetch-url] POST error', e);
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}

/**
 * Fetch Solidity files from a GitHub repository
 * Strategy:
 * 1. Get repo info to find the default branch
 * 2. Try recursive tree (fast, but may be truncated for large repos)
 * 3. If truncated, fall back to non-recursive + directory walk
 * 4. Download source files from raw.githubusercontent.com
 */
async function fetchGitHubRepo(parsedUrl: URL) {
  const hostname = parsedUrl.hostname.toLowerCase();

  // Support both github.com and GitHub Enterprise
  const isGitHub = hostname === 'github.com' || hostname === 'www.github.com';
  const apiBase = isGitHub
    ? 'https://api.github.com'
    : `https://${hostname}/api/v3`;

  if (!hostname.includes('github')) {
    return NextResponse.json(
      { error: 'For smart contract analysis, provide a GitHub URL (e.g. https://github.com/user/repo)' },
      { status: 400 }
    );
  }

  const parts = parsedUrl.pathname.split('/').filter(Boolean);
  if (parts.length < 2) {
    return NextResponse.json({ error: 'Invalid GitHub URL. Use: https://github.com/owner/repo' }, { status: 400 });
  }

  const owner = parts[0];
  const repo = parts[1];
  let subPath = '';

  // Parse URL path for branch/subdir
  // /owner/repo → whole repo
  // /owner/repo/tree/branch/path → specific branch + path
  // /owner/repo/blob/branch/file.sol → single file
  let explicitBranch: string | null = null;
  let singleFile: string | null = null;

  if (parts.length > 3 && parts[2] === 'tree') {
    explicitBranch = parts[3];
    subPath = parts.slice(4).join('/');
  } else if (parts.length > 3 && parts[2] === 'blob') {
    explicitBranch = parts[3];
    singleFile = parts.slice(4).join('/');
  }

  // Step 1: Get repo metadata to find default branch
  let defaultBranch = 'main';
  let repoPrivate = false;

  try {
    const ghHeaders = getGitHubHeaders();
    const repoRes = await fetch(`${apiBase}/repos/${owner}/${repo}`, {
      headers: ghHeaders,
      signal: AbortSignal.timeout(10_000),
    });

    if (repoRes.ok) {
      const repoData = await repoRes.json();
      defaultBranch = repoData.default_branch || 'main';
      repoPrivate = repoData.private || false;
    } else if (repoRes.status === 404) {
      const hasToken = !!process.env.GITHUB_TOKEN;
      return NextResponse.json({
        error: hasToken
          ? `Repository "${owner}/${repo}" not found on GitHub. Even with authentication, the repo is inaccessible. It may have been deleted or your token lacks access.`
          : `Repository "${owner}/${repo}" not found on GitHub. It may be private or doesn't exist. To access private repos, set the GITHUB_TOKEN environment variable.`,
      }, { status: 400 });
    } else if (repoRes.status === 403 || repoRes.status === 429) {
      const body = await repoRes.text();
      if (body.includes('rate limit')) {
        // Try to extract reset time from headers
        const resetHeader = repoRes.headers.get('x-ratelimit-reset');
        const resetInfo = resetHeader
          ? ` Resets at ${new Date(parseInt(resetHeader) * 1000).toISOString()}.`
          : '';
        const hasToken = !!process.env.GITHUB_TOKEN;
        const limitHeader = repoRes.headers.get('x-ratelimit-limit');
        const limitInfo = limitHeader ? ` (${limitHeader} requests/hour)` : '';
        return NextResponse.json({
          error: hasToken
            ? `GitHub API rate limit exceeded${limitInfo}. Wait and try again.${resetInfo}`
            : `GitHub API rate limit exceeded (60 requests/hour for unauthenticated). Set GITHUB_TOKEN for 5,000 requests/hour.${resetInfo}`,
        }, { status: 429 });
      }
      // If 403 but not rate limit (e.g. SSO-enforced org, or token lacks repo scope)
      return NextResponse.json({
        error: `GitHub API returned 403 for "${owner}/${repo}". Access may be restricted (SSO-enforced org, insufficient token scope, or repo is private). ${process.env.GITHUB_TOKEN ? 'Check that your GITHUB_TOKEN has "repo" scope.' : 'Set GITHUB_TOKEN with "repo" scope to access private repositories.'}`,
      }, { status: 400 });
    }
    // If repo fetch failed but not 404/403, continue with default branch guess
  } catch {
    // Network error - continue with default branch
  }

  if (repoPrivate) {
    return NextResponse.json({
      error: `Repository "${owner}/${repo}" is private. Only public repositories can be analyzed.`,
    }, { status: 400 });
  }

  // Handle single file URL
  if (singleFile) {
    const branch = explicitBranch || defaultBranch;
    return await fetchSingleFile(owner, repo, branch, singleFile);
  }

  // Step 2: Try to get the tree
  const branch = explicitBranch || defaultBranch;
  const branchesToTry = explicitBranch ? [explicitBranch] : [defaultBranch, defaultBranch === 'main' ? 'master' : 'main'];

  for (const b of branchesToTry) {
    try {
      const result = await fetchGitHubTree(apiBase, owner, repo, b, subPath);
      if (result) return result;
    } catch (e) {
      const msg = String(e);
      if (msg.includes('abort') || msg.includes('timeout') || msg.includes('Timeout')) {
        if (b === branchesToTry[branchesToTry.length - 1]) {
          return NextResponse.json({
            error: 'GitHub API request timed out. The repository may be too large. Try specifying a subdirectory path (e.g. /owner/repo/tree/main/contracts).',
          }, { status: 408 });
        }
        continue;
      }
      throw e;
    }
  }

  return NextResponse.json({
    error: `Could not fetch files from "${owner}/${repo}". Tried branches: ${branchesToTry.join(', ')}. Ensure the repo is public and contains Solidity files (.sol, .vy, .move, .rs, .cairo).`,
  }, { status: 400 });
}

/**
 * Try to fetch GitHub tree for a specific branch
 * Returns NextResponse or null if branch doesn't exist
 */
async function fetchGitHubTree(
  apiBase: string,
  owner: string,
  repo: string,
  branch: string,
  subPath: string
): Promise<NextResponse | null> {
  // Try recursive tree first
  const treeUrl = `${apiBase}/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;

  const ghHeaders = getGitHubHeaders();
  const treeRes = await fetch(treeUrl, {
    headers: ghHeaders,
    signal: AbortSignal.timeout(FETCH_TIMEOUT),
  });

  if (!treeRes.ok) {
    if (treeRes.status === 404) {
      // Branch doesn't exist — return null so caller can try next branch
      return null;
    }
    if (treeRes.status === 403 || treeRes.status === 429) {
      const body = await treeRes.text();
      if (body.includes('rate limit')) {
        const hasToken = !!process.env.GITHUB_TOKEN;
        return NextResponse.json({
          error: hasToken
            ? 'GitHub API rate limit exceeded. Wait and try again.'
            : 'GitHub API rate limit exceeded (60/hour for unauthenticated). Set GITHUB_TOKEN for 5,000/hour.',
        }, { status: 429 });
      }
    }
    // For other errors, try non-recursive tree as fallback
    return await fetchGitHubTreeNonRecursive(apiBase, owner, repo, branch, subPath);
  }

  const treeData = await treeRes.json();
  const tree = treeData.tree || [];

  // If tree was truncated, fall back to non-recursive
  if (treeData.truncated) {
    return await fetchGitHubTreeNonRecursive(apiBase, owner, repo, branch, subPath);
  }

  return await processGitHubTree(tree, owner, repo, branch, subPath);
}

/**
 * Fallback: non-recursive tree + walk subdirectories
 */
async function fetchGitHubTreeNonRecursive(
  apiBase: string,
  owner: string,
  repo: string,
  branch: string,
  subPath: string
): Promise<NextResponse | null> {
  // Get top-level tree
  const treeUrl = `${apiBase}/repos/${owner}/${repo}/git/trees/${branch}`;

  const ghHeaders = getGitHubHeaders();
  const treeRes = await fetch(treeUrl, {
    headers: ghHeaders,
    signal: AbortSignal.timeout(FETCH_TIMEOUT),
  });

  if (!treeRes.ok) return null;

  const treeData = await treeRes.json();
  const tree = treeData.tree || [];

  // Walk one level into directories that likely contain contracts
  const targetDirs = ['contracts', 'src', 'test', 'contracts/src', subPath].filter(Boolean);
  const allFiles: { path: string; type: string }[] = [...tree];

  for (const dir of targetDirs) {
    const dirEntry = tree.find((f: { path: string; type: string }) => f.path === dir && f.type === 'tree');
    if (dirEntry?.sha) {
      try {
        const subTreeRes = await fetch(`${apiBase}/repos/${owner}/${repo}/git/trees/${dirEntry.sha}`, {
          headers: ghHeaders,
          signal: AbortSignal.timeout(10_000),
        });
        if (subTreeRes.ok) {
          const subTree = await subTreeRes.json();
          for (const f of (subTree.tree || [])) {
            allFiles.push({ path: `${dir}/${f.path}`, type: f.type });
          }
        }
      } catch {
        // Skip failed subdirectory walks
      }
    }
  }

  return await processGitHubTree(allFiles, owner, repo, branch, subPath);
}

/**
 * Process a GitHub tree: find target files and download their content
 */
async function processGitHubTree(
  tree: { path: string; type: string }[],
  owner: string,
  repo: string,
  branch: string,
  subPath: string
) {
  const targetExtensions = ['.sol', '.vy', '.move', '.rs', '.cairo'];
  let targetFiles = tree.filter(
    (f) => f.type === 'blob' && targetExtensions.some(ext => f.path.endsWith(ext))
  );

  if (subPath) {
    targetFiles = targetFiles.filter((f) => f.path.startsWith(subPath));
  }

  // Prioritize contracts/ and src/ directories
  targetFiles.sort((a, b) => {
    const aScore = (a.path.startsWith('contracts/') ? 0 : a.path.startsWith('src/') ? 1 : 2);
    const bScore = (b.path.startsWith('contracts/') ? 0 : b.path.startsWith('src/') ? 1 : 2);
    return aScore - bScore;
  });

  // Limit number of files
  targetFiles = targetFiles.slice(0, MAX_FILES);

  if (targetFiles.length === 0) {
    return NextResponse.json({
      error: `No smart contract files (.sol, .vy, .move, .rs, .cairo) found in "${owner}/${repo}"${subPath ? ` under ${subPath}` : ''}. Try specifying a subdirectory with contracts (e.g. /tree/main/contracts).`,
    }, { status: 404 });
  }

  const files: { path: string; content: string }[] = [];
  let totalSize = 0;

  for (const file of targetFiles) {
    if (totalSize >= MAX_TOTAL_SIZE) break;

    try {
      const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${file.path}`;
      const contentRes = await fetch(rawUrl, {
        headers: { 'User-Agent': 'CryptoSentinel/1.0' },
        signal: AbortSignal.timeout(GH_FILE_TIMEOUT),
      });
      if (contentRes.ok) {
        const content = await contentRes.text();
        const truncated = content.slice(0, MAX_FILE_SIZE);
        files.push({ path: file.path, content: truncated });
        totalSize += truncated.length;
      }
    } catch {
      // Skip files that fail or timeout
    }
  }

  if (files.length === 0) {
    return NextResponse.json({
      error: 'Could not download any source files from the repository. The files may be too large or access may be restricted.',
    }, { status: 404 });
  }

  const combinedSource = files
    .map(f => `// File: ${f.path}\n// Source: https://github.com/${owner}/${repo}/blob/${branch}/${f.path}\n\n${f.content}`)
    .join('\n\n' + '='.repeat(60) + '\n\n');

  const contractName = files.length > 0
    ? files[0].path.split('/').pop()?.replace(/\.(sol|vy|move|rs|cairo)$/, '') || repo
    : repo;

  const firstExt = files[0]?.path.split('.').pop();
  const language = firstExt === 'sol' ? 'solidity'
    : firstExt === 'vy' ? 'vyper'
    : firstExt === 'move' ? 'move'
    : firstExt === 'rs' ? 'rust'
    : firstExt === 'cairo' ? 'cairo'
    : 'solidity';

  return NextResponse.json({
    sourceCode: combinedSource,
    contractName,
    language,
    filesCount: files.length,
    totalSize: combinedSource.length,
    files: files.map(f => f.path),
    repo: `${owner}/${repo}`,
    branch,
  });
}

/**
 * Fetch a single file from a GitHub repo (for /blob/ URLs)
 */
async function fetchSingleFile(owner: string, repo: string, branch: string, filePath: string) {
  const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`;

  try {
    const contentRes = await fetch(rawUrl, {
      headers: { 'User-Agent': 'CryptoSentinel/1.0' },
      signal: AbortSignal.timeout(GH_FILE_TIMEOUT),
    });

    if (!contentRes.ok) {
      return NextResponse.json({
        error: `Failed to fetch file "${filePath}" from "${owner}/${repo}" (branch: ${branch}). HTTP ${contentRes.status}.`,
      }, { status: 400 });
    }

    const content = await contentRes.text();
    const contractName = filePath.split('/').pop()?.replace(/\.(sol|vy|move|rs|cairo)$/, '') || 'Contract';

    return NextResponse.json({
      sourceCode: `// File: ${filePath}\n// Source: https://github.com/${owner}/${repo}/blob/${branch}/${filePath}\n\n${content}`,
      contractName,
      language: 'solidity',
      filesCount: 1,
      totalSize: content.length,
      files: [filePath],
      repo: `${owner}/${repo}`,
      branch,
    });
  } catch (e) {
    const msg = String(e);
    if (msg.includes('abort') || msg.includes('timeout')) {
      return NextResponse.json({ error: 'File download timed out.' }, { status: 408 });
    }
    return NextResponse.json({ error: `Failed to fetch file: ${msg}` }, { status: 500 });
  }
}

/**
 * Fetch Hackenproof project page: description, priorities, scope, severity assessments
 */
async function fetchHackenproof(parsedUrl: URL) {
  const urlStr = parsedUrl.toString();

  try {
    const pageRes = await fetch(urlStr, {
      headers: {
        'User-Agent': 'CryptoSentinel/1.0 (+https://cryptosentinel.app)',
        'Accept': 'text/html,application/json,*/*',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });

    if (!pageRes.ok) {
      return NextResponse.json({ error: `Failed to fetch Hackenproof page: HTTP ${pageRes.status}` }, { status: 400 });
    }

    const html = await pageRes.text();

    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    const title = titleMatch?.[1]?.trim() || 'Hackenproof Project';

    const metaDescMatch = html.match(/<meta[^>]+(?:name|property)=['"]description['"][^>]+content=['"]([^'"]+)['"]/i);
    const metaDesc = metaDescMatch?.[1]?.trim() || '';

    const textContent = html
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/<style[\s\S]*?<\/style>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 15000);

    const priorityMatch = textContent.match(/(?:priority|priorities|severity|scope|focus)[^.]*(?:critical|high|medium|low)[^.]{0,300}/i);
    const prioritySection = priorityMatch?.[0] || '';

    const jsonLdMatches = [...html.matchAll(/<script[^>]+type=['"]application\/ld\+json['"][^>]*>([\s\S]*?)<\/script>/gi)];
    let structuredData = '';
    for (const m of jsonLdMatches) {
      try {
        const json = JSON.parse(m[1]);
        structuredData += JSON.stringify(json, null, 2) + '\n';
      } catch {
        // skip invalid JSON-LD
      }
    }

    const analysisSource = `// Hackenproof Project Analysis Source
// URL: ${urlStr}
// Fetched: ${new Date().toISOString()}
// Title: ${title}

== PROJECT DESCRIPTION ==
${metaDesc || 'No meta description found'}

== HACKENPROOF PAGE CONTENT ==
${textContent}

== PRIORITY / SEVERITY INFORMATION ==
${prioritySection || 'No explicit priority/severity section found in page content. Priorities may be embedded in the project description above.'}

== STRUCTURED DATA (JSON-LD) ==
${structuredData || 'No structured data found'}

== SECURITY ANALYSIS NOTES ==
- Hackenproof project: use description and priorities as context for vulnerability analysis
- Focus on areas marked as high/critical priority in the project scope
- Cross-reference any mentioned attack vectors with Smart Contract code
- Check for: Reentrancy, Access Control, Oracle Manipulation, Flash Loan vectors
- Validate all findings against the project's declared scope and severity assessments
- HakenProof format: include detailed validation steps, root cause analysis, and PoC outlines
`;

    const parts = parsedUrl.pathname.split('/').filter(Boolean);
    const projectName = parts.length > 0 ? parts[parts.length - 1] : 'hackenproof-project';

    return NextResponse.json({
      sourceCode: analysisSource,
      contractName: projectName.replace(/-/g, '_'),
      language: 'solidity',
      filesCount: 1,
      totalSize: analysisSource.length,
      url: urlStr,
      title,
      isHackenproof: true,
      hackenproofContext: {
        description: metaDesc,
        priorities: prioritySection,
        projectName,
      },
    });
  } catch (e) {
    const msg = String(e);
    if (msg.includes('abort') || msg.includes('timeout') || msg.includes('Timeout')) {
      return NextResponse.json({ error: 'Hackenproof page request timed out. Check the URL and try again.' }, { status: 408 });
    }
    return NextResponse.json({ error: `Failed to fetch Hackenproof URL: ${msg}` }, { status: 500 });
  }
}

/**
 * New web application analysis using the comprehensive WebAppAnalyzer
 * with heavy AI (GLM 5.2) integration.
 *
 * Pipeline:
 *  1. Smart URL Resolution (handle SPAs, redirects, 404s)
 *  2. Multi-page Crawler/Spider
 *  3. JavaScript Bundle Deep Analysis
 *  4. DOM Structure Analysis (XSS sinks)
 *  5. API Endpoint Discovery
 *  6. Security Header Analysis
 *  7. Crypto/Web3 Pattern Detection
 *  8. AI Pass 1: Architecture & Attack Surface
 *  9. AI Pass 2: Vulnerability Hunting
 * 10. AI Pass 3: Crypto-Specific Vulnerabilities
 * 11. AI Pass 4: Exploit Construction
 */
async function fetchWebAppWithAI(parsedUrl: URL, isContractFallback = false) {
  const urlStr = parsedUrl.toString();

  try {
    // FAST PATH: Lightweight crawl (4-5 requests, ~5-10s) returns rich data for AI.
    // AI analysis runs separately in /api/analyze via multi-pass GLM agents.
    // This avoids the old 40-min bottleneck from sequential HTTP + AI in analyzeWebApp.
    console.log(`[fetchWebAppWithAI] Fast crawl for ${urlStr} (AI in /api/analyze)`);

    return await fetchWebsite(parsedUrl, isContractFallback);

  } catch (e) {
    const msg = String(e);
    if (msg.includes('abort') || msg.includes('timeout') || msg.includes('Timeout')) {
      return NextResponse.json({
        error: 'Web application analysis timed out. The site may be slow or blocking requests. Try again later.',
      }, { status: 408 });
    }
    console.error('[fetchWebAppWithAI] Error:', e);
    return NextResponse.json({ error: `Analysis failed: ${msg.slice(0, 200)}` }, { status: 500 });
  }
}

/**
 * Legacy website reconnaissance (kept as fallback)
 *
 * Exchange/crypto sites often block simple fetch() with WAF/Cloudflare challenges.
 * This function uses a layered approach:
 *  1. Security headers reconnaissance (HEAD request — rarely blocked)
 *  2. robots.txt / sitemap.xml / .well-known/security.txt discovery
 *  3. Direct page fetch with browser-like headers
 *  4. If blocked → CORS proxy fallback (allorigins)
 *  5. JavaScript bundle extraction & analysis (JS files rarely behind WAF)
 *  6. Passive analysis of everything collected
 */
async function fetchWebsite(parsedUrl: URL, isContractFallback = false) {
  const urlStr = parsedUrl.toString();
  const hostname = parsedUrl.hostname;
  const origin = parsedUrl.origin;

  const sections: string[] = [];
  let pageTitle = hostname;
  let totalScripts = 0;
  let totalEndpoints = 0;
  let totalForms = 0;
  let wafDetected = false;
  let pageHtml = '';

  // ── PHASE 1: Security Headers (HEAD request — almost never blocked) ──
  const securityHeaders = await reconSecurityHeaders(urlStr);
  sections.push(securityHeaders.section);

  // ── PHASE 2: robots.txt, sitemap, security.txt ──
  const reconFiles = await reconWellKnownFiles(origin);
  sections.push(reconFiles.section);

  // ── PHASE 3: Try direct page fetch with browser-like headers ──
  const BROWSER_HEADERS: Record<string, string> = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'no-cache',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Ch-Ua': '"Chromium";v="131", "Not_A Brand";v="24"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"Windows"',
    'Upgrade-Insecure-Requests': '1',
  };

  let fetchOk = false;
  try {
    const pageRes = await fetch(urlStr, {
      headers: BROWSER_HEADERS,
      redirect: 'follow',
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });

    if (pageRes.ok) {
      fetchOk = true;
      pageHtml = await pageRes.text();

      // Detect WAF challenge pages (Cloudflare, AWS WAF, etc.)
      if (isWAFChallenge(pageHtml)) {
        wafDetected = true;
        sections.push(`== WAF / BOT PROTECTION DETECTED ==\nThe site returned a WAF challenge page (Cloudflare/AWS WAF/bot protection).\nDirect HTML analysis is not possible. Falling back to passive reconnaissance.\nThis is common for crypto exchanges and high-security sites.`);
      } else {
        const htmlAnalysis = analyzeHtml(pageHtml, hostname);
        pageTitle = htmlAnalysis.title || pageTitle;
        totalScripts = htmlAnalysis.scriptCount;
        totalEndpoints = htmlAnalysis.endpointCount;
        totalForms = htmlAnalysis.formCount;
        sections.push(htmlAnalysis.section);
      }
    } else if (pageRes.status === 403 || pageRes.status === 404) {
      // WAF likely blocking — try CORS proxy fallback
      wafDetected = true;
    }
  } catch {
    wafDetected = true;
  }

  // ── PHASE 4: CORS proxy fallback if direct fetch failed ──
  if (!fetchOk || wafDetected) {
    try {
      const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(urlStr)}`;
      const proxyRes = await fetch(proxyUrl, {
        signal: AbortSignal.timeout(FETCH_TIMEOUT),
      });
      if (proxyRes.ok) {
        const proxyHtml = await proxyRes.text();
        if (proxyHtml.length > 200 && !isWAFChallenge(proxyHtml)) {
          const htmlAnalysis = analyzeHtml(proxyHtml, hostname);
          pageTitle = htmlAnalysis.title || pageTitle;
          totalScripts = htmlAnalysis.scriptCount;
          totalEndpoints = htmlAnalysis.endpointCount;
          totalForms = htmlAnalysis.formCount;
          sections.push(`== PAGE CONTENT (via proxy) ==\n${htmlAnalysis.section}`);
          fetchOk = true;
        }
      }
    } catch {
      // Proxy also failed — continue with passive recon only
    }
  }

  // ── PHASE 5: JavaScript bundle analysis ──
  if (pageHtml && !wafDetected) {
    const jsAnalysis = await analyzeJsBundles(pageHtml, origin);
    if (jsAnalysis.section) {
      totalEndpoints += jsAnalysis.endpointCount;
      sections.push(jsAnalysis.section);
    }
  }

  // ── PHASE 5.5: Deep Sitemap Crawl — fetch key pages in parallel for richer AI context ──
  const sitemapUrls = extractSitemapUrls(sections.join('\n'), origin);
  if (sitemapUrls.length > 0) {
    const deepCrawlLimit = 3; // Crawl 3 sitemap pages — fast, doesn't timeout on mobile
    const urlsToCrawl = sitemapUrls.slice(0, deepCrawlLimit);
    console.log(`[fetchWebsite] Deep crawl: ${urlsToCrawl.length} sitemap pages in parallel`);
    const deepResults = await Promise.allSettled(
      urlsToCrawl.map(async (pageUrl) => {
        try {
          const res = await fetch(pageUrl, {
            headers: BROWSER_HEADERS,
            redirect: 'follow',
            signal: AbortSignal.timeout(8000),
          });
          if (!res.ok) return null;
          const html = await res.text();
          if (isWAFChallenge(html)) return null;
          const analysis = analyzeHtml(html, new URL(pageUrl).hostname);
          return { url: pageUrl, analysis };
        } catch { return null; }
      })
    );
    const successfulCrawls = deepResults
      .filter((r): r is PromiseFulfilledResult<{url: string; analysis: ReturnType<typeof analyzeHtml>}> => r.status === 'fulfilled' && r.value !== null)
      .map(r => r.value);
    if (successfulCrawls.length > 0) {
      const deepSection = [`== DEEP CRAWL: ${successfulCrawls.length} pages from sitemap ==`];
      for (const crawl of successfulCrawls) {
        const path = new URL(crawl.url).pathname;
        deepSection.push(`\n--- ${path} ---`);
        deepSection.push(crawl.analysis.section.slice(0, 3000)); // More context per page for deeper AI analysis
        totalEndpoints += crawl.analysis.endpointCount;
        totalForms += crawl.analysis.formCount;
      }
      sections.push(deepSection.join('\n'));
    }
  }

  // ── PHASE 6: SSL/TLS check ──
  const sslInfo = await checkSSL(origin);
  sections.push(sslInfo.section);

  // ── PHASE 6.5: Common API & Admin Path Discovery ──
  // Probe common paths in parallel to find hidden endpoints, admin panels, API docs
  const COMMON_PATHS = [
    '/api', '/api/v1', '/api/v2', '/api/docs', '/api/swagger', '/api/openapi.json',
    '/graphql', '/admin', '/dashboard', '/login', '/auth', '/oauth',
    '/.env', '/.git/HEAD', '/.well-known/openid-configuration',
    '/swagger-ui.html', '/docs', '/redoc',
  ];
  const pathResults = await Promise.allSettled(
    COMMON_PATHS.map(async (path) => {
      try {
        const res = await fetch(`${origin}${path}`, {
          method: 'HEAD',
          headers: BROWSER_HEADERS,
          redirect: 'follow',
          signal: AbortSignal.timeout(5000),
        });
        return { path, status: res.status, ok: res.ok };
      } catch { return null; }
    })
  );
  const foundPaths = pathResults
    .filter((r): r is PromiseFulfilledResult<{path: string; status: number; ok: boolean} | null> => r.status === 'fulfilled' && r.value !== null)
    .map(r => r.value!)
    .filter(r => r !== null && r.ok);
  if (foundPaths.length > 0) {
    const pathSection = [`== DISCOVERED PATHS (${foundPaths.length}) ==`];
    for (const p of foundPaths) {
      pathSection.push(`  ${p.path} → ${p.status}`);
      totalEndpoints++;
    }
    // Flag sensitive paths
    const sensitiveFound = foundPaths.filter(p => 
      p.path.includes('.env') || p.path.includes('.git') || p.path.includes('admin') || p.path.includes('swagger')
    );
    if (sensitiveFound.length > 0) {
      pathSection.push(`\n⚠️  SENSITIVE PATHS EXPOSED: ${sensitiveFound.map(p => p.path).join(', ')}`);
      pathSection.push(`These may expose: .env secrets, .git source code, admin panels, API documentation`);
    }
    sections.push(pathSection.join('\n'));
  }

  // ── Build comprehensive analysis source ──
  const reconType = wafDetected ? 'Passive (WAF blocked active scan)' : 'Active + Passive';
  const analysisSource = `// Target: ${urlStr}
// Type: Exchange / Web Application
// Reconnaissance: ${reconType}
// Title: ${pageTitle}
// Fetched: ${new Date().toISOString()}

${sections.join('\n\n')}

== CRYPTOSENTINEL WEB VULNERABILITY ANALYSIS CONTEXT ==
Target: ${hostname}
Recon method: ${reconType}
${wafDetected ? `WAF detected: Active HTML fetch was blocked. Analysis is based on passive reconnaissance (headers, SSL, metadata, robots.txt, JS bundles).` : 'Full HTML + passive recon available.'}

Focus areas for AI analysis:
1. Security Headers: Check for missing CSP, X-Frame-Options, HSTS, X-Content-Type-Options
2. CORS: Check if API allows cross-origin requests from arbitrary origins
3. Cookie Security: Check HttpOnly, Secure, SameSite flags on session cookies
4. XSS Vectors: Look for DOM manipulation sinks, innerHTML, eval, document.write in JS
5. CSRF: Check for anti-CSRF tokens in forms, SameSite cookie protection
6. API Security: Check auth patterns, rate limiting, IDOR in API endpoints
7. Subdomain Takeover: Check CNAME records, dangling DNS
8. SSRF: Check for URL fetch patterns in API, open redirect chains
9. Sensitive Data: Check for API keys, secrets in JS bundles, localStorage usage
10. Crypto-specific: Wallet connect hijack, token approval exploits, signature replay, phishing vectors
11. Authentication: Session management, JWT handling, 2FA bypass, privilege escalation
12. Business Logic: Payment manipulation, withdrawal flow, trading engine abuse, price oracle manipulation

== HACKENPROOF SEVERITY PRIORITIES (Web & Mobile) ==
CRITICAL: Payment manipulation, SQL Injection, RCE, Business logic with fund loss, Command Injection
HIGH: Wallet subdomain takeover, Stored XSS, SSRF, Sensitive data exposure >15%, Auth Bypass, IDOR, Privilege Escalation
MEDIUM: Reflected XSS, Non-wallet subdomain takeover, 2FA bypass, CSRF
LOW: HTML Injection, Rate limiting missing on non-critical endpoints
OUT OF SCOPE: Theoretical without exploit, UI/UX bugs, Descriptive errors, Open redirects, Rate limiting on non-critical, 2FA sessions, Third-party apps
`;

  if (!fetchOk && !wafDetected) {
    const hint = isContractFallback
      ? ' For smart contract analysis, use a GitHub URL or paste Solidity code directly.'
      : '';
    return NextResponse.json({
      error: `Could not fetch ${urlStr}. The site may be down or blocking requests. Passive reconnaissance was performed where possible.${hint}`,
    }, { status: 400 });
  }

  return NextResponse.json({
    sourceCode: analysisSource,
    contractName: hostname.replace(/\./g, '_'),
    language: 'web',
    filesCount: 1,
    totalSize: analysisSource.length,
    url: urlStr,
    title: pageTitle,
    scriptsFound: totalScripts,
    apiEndpointsFound: totalEndpoints,
    formsFound: totalForms,
    wafDetected,
    reconType,
  });
}

// ──────────────── Helper Functions ────────────────

/**
 * Extract URLs from sitemap.xml content in the reconnaissance sections.
 * Prioritizes: /api, /trade, /swap, /bridge, /wallet, /auth, /login, /docs, /app
 * These are the most security-relevant pages for crypto/Web3 apps.
 */
function extractSitemapUrls(reconText: string, origin: string): string[] {
  const urls: string[] = [];
  // Extract all <loc> URLs from sitemap content
  const locMatches = [...reconText.matchAll(/<loc>([^<]+)<\/loc>/gi)];
  for (const m of locMatches) {
    const url = m[1].trim();
    if (url.startsWith('http')) urls.push(url);
  }
  // Also extract URLs from Disallow in robots.txt (these are hidden paths = interesting)
  const disallowMatches = [...reconText.matchAll(/Disallow:\s*(.+)/gi)];
  for (const m of disallowMatches) {
    const path = m[1].trim();
    if (path !== '/' && path !== '') urls.push(`${origin}${path.startsWith('/') ? path : '/' + path}`);
  }
  // Deduplicate and prioritize security-relevant paths
  const priorityPatterns = [/\/api/i, /\/trade/i, /\/swap/i, /\/bridge/i, /\/wallet/i, /\/auth/i, /\/login/i, /\/docs/i, /\/app/i, /\/admin/i, /\/dashboard/i, /\/settings/i, /\/account/i, /\/withdraw/i, /\/deposit/i, /\/transfer/i, /\/governance/i, /\/vote/i, /\/stake/i];
  const priorityUrls = urls.filter(u => priorityPatterns.some(p => p.test(u)));
  const otherUrls = urls.filter(u => !priorityPatterns.some(p => p.test(u)));
  // Return priority first, then others, deduped
  const seen = new Set<string>();
  const result: string[] = [];
  for (const u of [...priorityUrls, ...otherUrls]) {
    if (!seen.has(u)) { seen.add(u); result.push(u); }
  }
  return result;
}

/**
 * Detect WAF challenge pages (Cloudflare, AWS WAF, PerimeterX, etc.)
 */
function isWAFChallenge(html: string): boolean {
  const lower = html.toLowerCase();
  const indicators = [
    'cf-browser-verification', 'cf-challenge', 'cloudflare', 'aws-waf',
    'challenge-platform', 'px-captcha', 'perimeterx', 'datadome',
    'akamai-bot-manager', 'imperva', 'incapsula', 'under attack',
    'please wait while we verify', 'checking your browser',
    'browser verification', 'are you a robot', 'are you human',
    'challenge-runner', 'hcaptcha', 'recaptcha',
  ];
  // Only flag as WAF if the page is short AND contains challenge indicators
  if (html.length > 50000) return false; // Real pages are usually larger
  return indicators.some(ind => lower.includes(ind));
}

/**
 * Phase 1: Security headers via HEAD request
 */
async function reconSecurityHeaders(urlStr: string): Promise<{ section: string }> {
  const lines: string[] = ['== SECURITY HEADERS (HEAD request) =='];

  try {
    const headRes = await fetch(urlStr, {
      method: 'HEAD',
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CryptoSentinel/1.0)' },
      redirect: 'follow',
      signal: AbortSignal.timeout(8000),
    });

    lines.push(`HTTP Status: ${headRes.status}`);

    const importantHeaders = [
      'content-security-policy', 'x-frame-options', 'x-content-type-options',
      'strict-transport-security', 'x-xss-protection', 'referrer-policy',
      'permissions-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy',
      'access-control-allow-origin', 'access-control-allow-methods',
      'access-control-allow-headers', 'access-control-allow-credentials',
      'x-powered-by', 'server', 'set-cookie', 'cache-control',
      'x-request-id', 'x-ratelimit-limit', 'x-ratelimit-remaining',
    ];

    const allHeaders: Record<string, string> = {};
    headRes.headers.forEach((value, key) => { allHeaders[key.toLowerCase()] = value; });

    for (const h of importantHeaders) {
      const val = allHeaders[h];
      if (val) {
        lines.push(`  ${h}: ${val.slice(0, 200)}`);
      }
    }

    // Security analysis
    const missing: string[] = [];
    if (!allHeaders['content-security-policy']) missing.push('Content-Security-Policy (CSP) — XSS risk');
    if (!allHeaders['x-frame-options']) missing.push('X-Frame-Options — Clickjacking risk');
    if (!allHeaders['strict-transport-security']) missing.push('Strict-Transport-Security (HSTS) — MITM risk');
    if (!allHeaders['x-content-type-options']) missing.push('X-Content-Type-Options — MIME sniffing risk');
    if (!allHeaders['referrer-policy']) missing.push('Referrer-Policy — Info leak risk');
    if (allHeaders['x-powered-by']) missing.push(`X-Powered-By exposed: ${allHeaders['x-powered-by']} — Tech fingerprint`);
    if (allHeaders['server']) lines.push(`  [INFO] Server: ${allHeaders['server']} — Tech fingerprint available`);

    // CORS analysis
    const corsOrigin = allHeaders['access-control-allow-origin'];
    if (corsOrigin === '*') {
      missing.push('CORS: Allow-Origin is * — API may be accessible from any origin');
    } else if (corsOrigin) {
      lines.push(`  [CORS] Allow-Origin: ${corsOrigin}`);
    }

    // Cookie analysis
    const setCookie = allHeaders['set-cookie'];
    if (setCookie) {
      const cookieFlags: string[] = [];
      if (!setCookie.toLowerCase().includes('httponly')) cookieFlags.push('Missing HttpOnly — JS can read cookie (XSS risk)');
      if (!setCookie.toLowerCase().includes('secure')) cookieFlags.push('Missing Secure — sent over HTTP (MITM risk)');
      if (!setCookie.toLowerCase().includes('samesite')) cookieFlags.push('Missing SameSite — CSRF risk');
      if (cookieFlags.length > 0) {
        lines.push('  [COOKIE SECURITY ISSUES]');
        for (const f of cookieFlags) lines.push(`    - ${f}`);
      } else {
        lines.push('  [COOKIES] Session cookies appear properly secured (HttpOnly, Secure, SameSite)');
      }
    }

    if (missing.length > 0) {
      lines.push('\n  [MISSING / INSECURE HEADERS]');
      for (const m of missing) lines.push(`    ⚠ ${m}`);
    }
  } catch (e) {
    lines.push(`  HEAD request failed: ${String(e).slice(0, 100)}`);
  }

  return { section: lines.join('\n') };
}

/**
 * Phase 2: robots.txt, sitemap.xml, .well-known/security.txt
 */
async function reconWellKnownFiles(origin: string): Promise<{ section: string }> {
  const lines: string[] = ['== RECONNAISSANCE: Well-Known Files =='];
  const filesToCheck = [
    { path: '/robots.txt', label: 'robots.txt' },
    { path: '/sitemap.xml', label: 'sitemap.xml' },
    { path: '/.well-known/security.txt', label: 'security.txt' },
    { path: '/.well-known/openid-configuration', label: 'OpenID Connect config' },
    { path: '/swagger.json', label: 'Swagger/OpenAPI spec' },
    { path: '/api-docs', label: 'API docs' },
  ];

  for (const file of filesToCheck) {
    try {
      const res = await fetch(`${origin}${file.path}`, {
        headers: { 'User-Agent': 'CryptoSentinel/1.0' },
        redirect: 'follow',
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        const text = await res.text();
        // For sitemap.xml, keep full content (needed for deep crawl URL extraction)
        // For other files, truncate to 2000 chars
        const truncated = file.path === '/sitemap.xml' ? text.slice(0, 10000) : text.slice(0, 2000);
        lines.push(`\n  --- ${file.label} (${text.length} bytes) ---`);
        lines.push(truncated);

        // Extract interesting info from robots.txt
        if (file.path === '/robots.txt') {
          const disallowed = [...truncated.matchAll(/Disallow:\s*(.+)/gi)].map(m => m[1].trim());
          if (disallowed.length > 0) {
            lines.push('\n  [DISCOVERED PATHS FROM ROBOTS.TXT — HIGH VALUE FOR VULN HUNTING]');
            for (const d of disallowed.slice(0, 20)) {
              lines.push(`    - ${d} (hidden path — probe for: IDOR, auth bypass, info leak, admin panel)`);
            }
          }
          // Extract sitemap URL from robots.txt
          const sitemapMatch = truncated.match(/Sitemap:\s*(.+)/i);
          if (sitemapMatch) {
            lines.push(`  [SITEMAP] ${sitemapMatch[1].trim()} — will crawl for deeper analysis`);
          }
        }
      }
    } catch {
      // Skip unavailable files
    }
  }

  if (lines.length === 1) {
    lines.push('  No well-known files found.');
  }

  return { section: lines.join('\n') };
}

/**
 * Analyze HTML content: extract scripts, forms, endpoints, metadata
 */
function analyzeHtml(html: string, hostname: string): {
  title: string; scriptCount: number; endpointCount: number; formCount: number; section: string;
} {
  const lines: string[] = ['== PAGE HTML ANALYSIS =='];

  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  const title = titleMatch?.[1]?.trim() || hostname;

  const scriptSrcs = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map(m => m[1]).slice(0, 30);

  const inlineScripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)]
    .map(m => m[1]).filter(s => s.trim().length > 20).slice(0, 10);

  const apiEndpoints = [...new Set([
    ...html.matchAll(/["'](?:\/api\/[^"']+|\/v[0-9]+\/[^"']+)["'/]/gi),
    ...html.matchAll(/(?:fetch|axios|XMLHttpRequest|\.get|\.post)\s*\(\s*["']([^"']+)["']/gi),
    ...html.matchAll(/(?:action|href|src)=["'](\/[^"']*api[^"']*)["']/gi),
  ].flatMap(r => r[1] ? [r[1]] : []))].filter(e => e.startsWith('/') || e.startsWith('http')).slice(0, 30);

  const formActions = [...html.matchAll(/<form[^>]+action=["']([^"']+)["']/gi)]
    .map(m => m[1]).slice(0, 15);

  const metaTags = [...html.matchAll(/<meta[^>]+(?:name|property|http-equiv)=["']([^"']+)["'][^>]+content=["']([^"']+)["']/gi)]
    .map(m => `${m[1]}: ${m[2]}`).slice(0, 20);

  // Detect wallet/crypto-specific patterns
  const cryptoPatterns: string[] = [];
  const lowerHtml = html.toLowerCase();
  if (lowerHtml.includes('ethereum') || lowerHtml.includes('web3')) cryptoPatterns.push('Ethereum/Web3 integration detected');
  if (lowerHtml.includes('walletconnect') || lowerHtml.includes('wallet_connect')) cryptoPatterns.push('WalletConnect integration detected');
  if (lowerHtml.includes('metamask')) cryptoPatterns.push('MetaMask integration detected');
  if (lowerHtml.includes('solana') && lowerHtml.includes('phantom')) cryptoPatterns.push('Solana/Phantom wallet integration');
  if (lowerHtml.includes('signmessage') || lowerHtml.includes('sign_message') || lowerHtml.includes('personal_sign')) cryptoPatterns.push('Message signing functionality (signature replay risk)');
  if (lowerHtml.includes('approve') && (lowerHtml.includes('erc20') || lowerHtml.includes('token'))) cryptoPatterns.push('Token approval pattern (unlimited approval risk)');
  if (lowerHtml.includes('iframe') && (lowerHtml.includes('wallet') || lowerHtml.includes('connect'))) cryptoPatterns.push('Wallet iframe (clickjacking risk)');

  // Detect localStorage/sessionStorage usage (sensitive data storage risk)
  const storagePatterns = [...html.matchAll(/(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*["']([^"']+)["']/gi)]
    .map(m => m[1]).slice(0, 10);

  lines.push(`Title: ${title}`);
  lines.push(`\nExternal Scripts (${scriptSrcs.length}):`);
  for (const s of scriptSrcs) lines.push(`  - ${s}`);
  lines.push(`\nInline Scripts: ${inlineScripts.length} found`);
  lines.push(`\nAPI Endpoints (${apiEndpoints.length}):`);
  for (const e of apiEndpoints) lines.push(`  - ${e}`);
  lines.push(`\nForm Actions (${formActions.length}):`);
  for (const f of formActions) lines.push(`  - ${f}`);
  lines.push(`\nMeta Tags:`);
  for (const m of metaTags) lines.push(`  ${m}`);

  if (cryptoPatterns.length > 0) {
    lines.push(`\n[CRYPTO/WALLET PATTERNS DETECTED]`);
    for (const p of cryptoPatterns) lines.push(`  🔑 ${p}`);
  }
  if (storagePatterns.length > 0) {
    lines.push(`\n[CLIENT-SIDE STORAGE]`);
    for (const s of storagePatterns) lines.push(`  📦 Key: "${s}" — may contain sensitive data`);
  }

  lines.push(`\nHTML snippet (first 3000 chars):\n${html.slice(0, 3000)}`);

  return {
    title, scriptCount: scriptSrcs.length, endpointCount: apiEndpoints.length,
    formCount: formActions.length, section: lines.join('\n'),
  };
}

/**
 * Phase 5: Download and analyze JS bundles for API endpoints, keys, patterns
 */
async function analyzeJsBundles(html: string, origin: string): Promise<{ section: string; endpointCount: number }> {
  const scriptSrcs = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map(m => m[1] as string).slice(0, 8); // Analyze up to 8 JS bundles

  if (scriptSrcs.length === 0) return { section: '', endpointCount: 0 };

  const lines: string[] = ['== JAVASCRIPT BUNDLE ANALYSIS =='];
  let allEndpoints: string[] = [];

  for (const src of scriptSrcs) {
    try {
      const fullUrl = src.startsWith('http') ? src : `${origin}${src}`;
      const res = await fetch(fullUrl, {
        headers: { 'User-Agent': 'Mozilla/5.0', 'Accept-Encoding': 'gzip' },
        signal: AbortSignal.timeout(GH_FILE_TIMEOUT),
      });
      if (!res.ok) continue;

      const js = await res.text();
      const shortPath = src.split('/').pop() || src;
      lines.push(`\n--- ${shortPath} (${(js.length/1024).toFixed(0)} KB) ---`);

      // Extract API endpoints
      const endpoints = [...new Set([
        ...js.matchAll(/["']((?:\/api\/|\/v[0-9]+\/)[^"']+)["']/gi),
        ...js.matchAll(/["'](https?:\/\/[^"']+(?:api|graphql|rpc)[^"']*)["']/gi),
      ].flatMap(r => r[1] ? [r[1] as string] : []))].slice(0, 15);
      allEndpoints = allEndpoints.concat(endpoints);
      if (endpoints.length > 0) {
        lines.push(`  API endpoints: ${endpoints.join(', ')}`);
      }

      // Detect sensitive patterns
      const sensitivePatterns: string[] = [];

      // Hardcoded keys/secrets
      const apiKeyMatch = js.match(/(?:api[_-]?key|apikey|secret|token|password|private[_-]?key)\s*[:=]\s*["']([^"']{8,})["']/i);
      if (apiKeyMatch) sensitivePatterns.push(`POSSIBLE HARDCODED SECRET: key=${apiKeyMatch[0].slice(0, 80)}...`);

      // eval / Function usage
      if (/\beval\s*\(|new\s+Function\s*\(/.test(js)) sensitivePatterns.push('Uses eval/Function — XSS/code injection risk');

      // innerHTML / document.write
      if (/\.innerHTML\s*=|document\.write\s*\(/.test(js)) sensitivePatterns.push('Uses innerHTML/document.write — XSS risk');

      // postMessage without origin check
      if (/postMessage\s*\(/.test(js) && !/targetOrigin\s*!==?\s*["']/.test(js)) sensitivePatterns.push('postMessage without origin check — message hijack risk');

      // localStorage with sensitive data
      const lsMatch = js.match(/localStorage\.setItem\s*\(\s*["']([^"']*(?:token|key|secret|auth|session|password|wallet|private)[^"']*)["']/i);
      if (lsMatch) sensitivePatterns.push(`localStorage stores sensitive key: "${lsMatch[1]}"`);

      // Wallet/crypto patterns
      if (/personal_sign|eth_signTypedData|signMessage/.test(js)) sensitivePatterns.push('Signing function present — signature replay risk');
      if (/\.approve\s*\(\s*[^,]+,\s*["']0x[fF]{64}["']/.test(js) || /MAX_UINT/.test(js)) sensitivePatterns.push('Unlimited token approval — fund drain risk');

      if (sensitivePatterns.length > 0) {
        lines.push('  [SECURITY FINDINGS]');
        for (const p of sensitivePatterns) lines.push(`    ⚠ ${p}`);
      }
    } catch {
      // Skip failed JS fetches
    }
  }

  if (allEndpoints.length > 0) {
    lines.push(`\n[DISCOVERED API ENDPOINTS FROM JS BUNDLES] (${allEndpoints.length})`);
    for (const e of [...new Set(allEndpoints)].slice(0, 30)) lines.push(`  - ${e}`);
  }

  return { section: lines.join('\n'), endpointCount: allEndpoints.length };
}

/**
 * Phase 6: SSL/TLS certificate check
 */
async function checkSSL(origin: string): Promise<{ section: string }> {
  const lines: string[] = ['== SSL/TLS CHECK =='];

  try {
    // Try fetching the site to see if HTTPS works
    const res = await fetch(origin, {
      method: 'HEAD',
      headers: { 'User-Agent': 'CryptoSentinel/1.0' },
      signal: AbortSignal.timeout(8000),
    });

    const protocol = res.url?.startsWith('https://') ? 'HTTPS' : 'HTTP';
    lines.push(`Protocol: ${protocol}`);
    lines.push(`URL after redirects: ${res.url || origin}`);

    if (protocol === 'HTTP' && origin.startsWith('https://')) {
      lines.push('⚠ HTTPS redirects to HTTP — SSL misconfiguration');
    }
    if (protocol === 'HTTPS') {
      lines.push('✓ Site uses HTTPS');
    }

    // Check HSTS
    const hsts = res.headers.get('strict-transport-security');
    if (hsts) {
      lines.push(`HSTS: ${hsts}`);
      if (hsts.includes('includeSubDomains')) lines.push('  ✓ includeSubDomains — protects subdomains');
      if (hsts.includes('preload')) lines.push('  ✓ preload — HSTS preloaded in browsers');
    } else {
      lines.push('⚠ No HSTS header — vulnerable to SSL stripping');
    }
  } catch (e) {
    lines.push(`SSL check failed: ${String(e).slice(0, 100)}`);
  }

  return { section: lines.join('\n') };
}

/**
 * Fetch verified contract source from block explorer (Etherscan, BscScan, etc.)
 * Uses the public API to get verified Solidity source code
 */
async function fetchBlockExplorer(parsedUrl: URL) {
  const hostname = parsedUrl.hostname.toLowerCase();
  const urlStr = parsedUrl.toString();

  // Extract address from URL: /address/0x... or /token/0x...
  const addressMatch = parsedUrl.pathname.match(/\/(?:address|token)\/(0x[a-fA-F0-9]{40})/);
  if (!addressMatch) {
    return NextResponse.json({
      error: `Could not extract contract address from the URL. Use format: https://etherscan.io/address/0x...`,
    }, { status: 400 });
  }
  const address = addressMatch[1];

  // Map hostname → API base (V2) + API key env var + chain ID
  const explorerConfig: Record<string, { apiBase: string; chain: string; chainId: number; apiKeyEnv: string }> = {
    'etherscan.io': { apiBase: 'https://api.etherscan.io/v2/api', chain: 'ethereum', chainId: 1, apiKeyEnv: 'ETHERSCAN_API_KEY' },
    'goerli.etherscan.io': { apiBase: 'https://api.etherscan.io/v2/api', chain: 'ethereum', chainId: 5, apiKeyEnv: 'ETHERSCAN_API_KEY' },
    'bscscan.com': { apiBase: 'https://api.bscscan.com/v2/api', chain: 'bsc', chainId: 56, apiKeyEnv: 'BSCSCAN_API_KEY' },
    'polygonscan.com': { apiBase: 'https://api.polygonscan.com/v2/api', chain: 'polygon', chainId: 137, apiKeyEnv: 'POLYGONSCAN_API_KEY' },
    'arbiscan.io': { apiBase: 'https://api.arbiscan.io/v2/api', chain: 'arbitrum', chainId: 42161, apiKeyEnv: 'ARBISCAN_API_KEY' },
    'basescan.org': { apiBase: 'https://api.basescan.org/v2/api', chain: 'base', chainId: 8453, apiKeyEnv: 'BASESCAN_API_KEY' },
    'optimistic.etherscan.io': { apiBase: 'https://api.etherscan.io/v2/api', chain: 'optimism', chainId: 10, apiKeyEnv: 'OPTIMISM_API_KEY' },
    'ftmscan.com': { apiBase: 'https://api.ftmscan.com/v2/api', chain: 'fantom', chainId: 250, apiKeyEnv: 'FTMSCAN_API_KEY' },
    'snowtrace.io': { apiBase: 'https://api.snowtrace.io/v2/api', chain: 'avalanche', chainId: 43114, apiKeyEnv: 'SNOWTRACE_API_KEY' },
    'cronoscan.com': { apiBase: 'https://api.cronoscan.com/v2/api', chain: 'cronos', chainId: 25, apiKeyEnv: 'CRONOSCAN_API_KEY' },
  };

  // Find matching config (exact match or substring)
  let config = explorerConfig[hostname];
  if (!config) {
    for (const [key, val] of Object.entries(explorerConfig)) {
      if (hostname.includes(key) || key.includes(hostname)) {
        config = val;
        break;
      }
    }
  }

  if (!config) {
    // Generic fallback: try to construct API URL from hostname
    config = { apiBase: `https://api.${hostname}/v2/api`, chain: 'unknown', chainId: 1, apiKeyEnv: '' };
  }

  try {
    // Build API URL for verified source code (V2 requires chainid param)
    const apiKey = process.env[config.apiKeyEnv as keyof typeof process.env] || '';
    const apiUrl = `${config.apiBase}?chainid=${config.chainId}&module=contract&action=getsourcecode&address=${address}${apiKey ? `&apikey=${apiKey}` : ''}`;

    const apiRes = await fetch(apiUrl, {
      headers: { 'User-Agent': 'CryptoSentinel/1.0' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });

    if (!apiRes.ok) {
      return NextResponse.json({
        error: `Block explorer API returned HTTP ${apiRes.status}. The contract may not be verified or the API is unavailable.`,
      }, { status: 400 });
    }

    const apiData = await apiRes.json();

    // Handle API key requirement
    if (apiData.status === '0' && typeof apiData.result === 'string' && apiData.result.includes('API Key')) {
      return NextResponse.json({
        error: `Etherscan V2 API requires an API key. Get a free key at https://etherscan.io/apis and set the ${config.apiKeyEnv} environment variable.`,
      }, { status: 400 });
    }

    if (apiData.status === '0' || !apiData.result || (Array.isArray(apiData.result) && apiData.result.length === 0)) {
      return NextResponse.json({
        error: `Contract ${address} is not verified on ${hostname}, or the address is not a contract. Only verified contracts can be analyzed from block explorers. ${!apiKey ? `Set ${config.apiKeyEnv} for API access.` : ''}`,
      }, { status: 400 });
    }

    const contractData = apiData.result[0];
    const sourceCode = contractData.SourceCode;
    const contractName = contractData.ContractName || 'UnknownContract';

    if (!sourceCode || sourceCode.trim().length === 0) {
      return NextResponse.json({
        error: `Contract ${contractName} (${address}) source code is empty. It may not be fully verified.`,
      }, { status: 400 });
    }

    // Handle multi-file verification (sourceCode may be JSON string with {{...}})
    let combinedSource = sourceCode;
    if (sourceCode.startsWith('{{') && sourceCode.endsWith('}}')) {
      try {
        const multiFile = JSON.parse(sourceCode.slice(1, -1));
        const sources = multiFile.sources || {};
        const files = Object.entries(sources) as [string, { content: string }][];
        if (files.length > 0) {
          combinedSource = files.map(([path, data]) =>
            `// File: ${path}\n\n${data.content || ''}`
          ).join('\n\n' + '='.repeat(60) + '\n\n');
        }
      } catch {
        // If parsing fails, use raw sourceCode
      }
    }

    const analysisSource = `// Contract: ${contractName}
// Address: ${address}
// Chain: ${config.chain}
// Explorer: ${hostname}
// Source: ${urlStr}
// Fetched: ${new Date().toISOString()}
// Compiler: ${contractData.CompilerVersion || 'unknown'}

${combinedSource}`;

    return NextResponse.json({
      sourceCode: analysisSource,
      contractName,
      language: 'solidity',
      filesCount: 1,
      totalSize: analysisSource.length,
      address,
      chain: config.chain,
      explorer: hostname,
      compiler: contractData.CompilerVersion || 'unknown',
      isVerified: true,
    });
  } catch (e) {
    const msg = String(e);
    if (msg.includes('abort') || msg.includes('timeout')) {
      return NextResponse.json({ error: 'Block explorer API request timed out. Try again later.' }, { status: 408 });
    }
    return NextResponse.json({ error: `Failed to fetch from block explorer: ${msg}` }, { status: 500 });
  }
}

/**
 * Fetch a direct source file from a URL (e.g. raw .sol file)
 */
async function fetchDirectSource(parsedUrl: URL) {
  const urlStr = parsedUrl.toString();
  const ext = parsedUrl.pathname.split('.').pop()?.toLowerCase() || '';
  const langMap: Record<string, string> = {
    sol: 'solidity', vy: 'vyper', rs: 'rust', move: 'move',
    cairo: 'cairo', ts: 'typescript', tsx: 'typescript', js: 'javascript',
    jsx: 'javascript', py: 'python', go: 'go',
  };
  const language = langMap[ext] || 'solidity';

  try {
    const res = await fetch(urlStr, {
      headers: {
        'User-Agent': 'CryptoSentinel/1.0',
        'Accept': 'text/plain,*/*',
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });

    if (!res.ok) {
      return NextResponse.json({
        error: `Failed to fetch source file: HTTP ${res.status}. Make sure the URL points to a publicly accessible file.`,
      }, { status: 400 });
    }

    const sourceCode = await res.text();
    const fileName = parsedUrl.pathname.split('/').pop() || 'contract';
    const contractName = fileName.replace(/\.(sol|vy|rs|move|cairo|ts|tsx|js|jsx|py|go)$/, '');

    return NextResponse.json({
      sourceCode: `// File: ${fileName}\n// Source: ${urlStr}\n// Fetched: ${new Date().toISOString()}\n\n${sourceCode}`,
      contractName,
      language,
      filesCount: 1,
      totalSize: sourceCode.length,
      files: [fileName],
    });
  } catch (e) {
    const msg = String(e);
    if (msg.includes('abort') || msg.includes('timeout')) {
      return NextResponse.json({ error: 'Source file download timed out.' }, { status: 408 });
    }
    return NextResponse.json({ error: `Failed to fetch source file: ${msg}` }, { status: 500 });
  }
}
