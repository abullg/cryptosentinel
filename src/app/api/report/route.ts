import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { checkStandardRateLimit } from '@/lib/rate-limit';

export async function POST(req: Request) {
  const rl = checkStandardRateLimit(req);
  if (!rl.allowed) return NextResponse.json({ error: 'Rate limited', retryAfter: Math.ceil(rl.retryAfterMs / 1000) }, { status: 429 });
  try {
    const body = await req.json();
    const { auditId, projectId } = body;

    // Get all vulnerabilities for this project
    const vulns = await db.vulnerability.findMany({
      where: { contract: { projectId } },
      include: { contract: true },
      orderBy: { confidence: 'desc' },
    });

    const project = await db.project.findUnique({ where: { id: projectId } });
    if (!project) return NextResponse.json({ error: 'Project not found' }, { status: 404 });

    const now = new Date().toISOString().replace('T', ' ').slice(0, 19);

    // Generate HakenProof-format TXT report
    let report = '';
    const separator = '='.repeat(80);

    report += `${separator}\n`;
    report += `CRYPTOSENTINEL AUDIT REPORT\n`;
    report += `HakenProof Format — Reproducible Vulnerability Report\n`;
    report += `${separator}\n\n`;

    report += `Report Date:    ${now}\n`;
    report += `Project:        ${project.name}\n`;
    report += `Chain:          ${project.chain}\n`;
    report += `Language:       ${project.language}\n`;
    report += `Total Findings: ${vulns.length}\n`;
    report += `Confirmed:      ${vulns.filter(v => v.status === 'confirmed').length}\n`;
    report += `Validated:      ${vulns.filter(v => v.status === 'validated').length}\n`;
    report += `Avg Confidence: ${(vulns.reduce((s, v) => s + v.confidence, 0) / Math.max(vulns.length, 1) * 100).toFixed(1)}%\n\n`;

    for (let i = 0; i < vulns.length; i++) {
      const v = vulns[i];
      const num = String(i + 1).padStart(2, '0');

      report += `${separator}\n`;
      report += `FINDING #${num}\n`;
      report += `${separator}\n\n`;

      report += `Title:\n`;
      report += `  ${v.title}\n\n`;

      report += `Target:\n`;
      report += `  ${v.target || v.contract?.name || 'Unknown'}\n`;
      report += `  Location: ${v.location || 'N/A'}\n`;
      if (v.contract?.address) {
        report += `  Address: ${v.contract.address}\n`;
      }
      report += `\n`;

      report += `Vulnerability Category:\n`;
      report += `  ${v.vulnCategory || v.type}\n`;
      report += `  Classification: ${v.type}\n`;
      report += `  Pattern: ${v.patternTag || 'N/A'}\n\n`;

      report += `Severity:\n`;
      report += `  ${v.severity.toUpperCase()}\n`;
      report += `  Confidence: ${(v.confidence * 100).toFixed(1)}%\n`;
      report += `  Status: ${v.status.toUpperCase()}\n\n`;

      report += `Vulnerability Details:\n`;
      report += `  ${v.description}\n\n`;

      // Validation pipeline scores
      report += `  Validation Pipeline Scores:\n`;
      report += `    V1 Symbolic Execution: ${v.v1Symbolic != null ? (v.v1Symbolic * 100).toFixed(0) + '%' : 'N/A'} (weight: 30%)\n`;
      report += `    V2 Fuzzing & Property: ${v.v2Fuzzing != null ? (v.v2Fuzzing * 100).toFixed(0) + '%' : 'N/A'} (weight: 25%)\n`;
      report += `    V3 Formal Verification: ${v.v3Formal != null ? (v.v3Formal * 100).toFixed(0) + '%' : 'N/A'} (weight: 25%)\n`;
      report += `    V4 Economic Simulation: ${v.v4Economic != null ? (v.v4Economic * 100).toFixed(0) + '%' : 'N/A'} (weight: 20%)\n\n`;

      // Code snippet
      if (v.codeSnippet) {
        report += `  Affected Code:\n`;
        report += `    ${v.codeSnippet.split('\n').join('\n    ')}\n\n`;
      }

      report += `Validation Steps:\n`;
      report += `  ${(v.validationSteps || 'Validation pending.').split('\n').join('\n  ')}\n\n`;

      // Proof of Concept — full inline code
      if (v.poc && v.poc.trim().length > 0) {
        report += `Proof of Concept (Reproducible Foundry Test):\n`;
        report += `  File: ${v.pocFilename || 'attack.t.sol'}\n`;
        report += `  Reproduction:\n`;
        report += `    1. Install Foundry: curl -L https://foundry.paradigm.xyz | bash\n`;
        report += `    2. forge init poc-test && cd poc-test\n`;
        report += `    3. Copy the code below into test/${v.pocFilename || 'attack.t.sol'}\n`;
        report += `    4. forge test -vvvv\n\n`;
        report += `  --- BEGIN PoC CODE ---\n`;
        const pocLines = v.poc.split('\n');
        for (const line of pocLines) {
          report += `  ${line}\n`;
        }
        report += `  --- END PoC CODE ---\n\n`;
      } else if (v.pocFilename) {
        report += `Proof of Concept:\n`;
        report += `  File: ${v.pocFilename}\n`;
        report += `  See attached ZIP archive for full reproducible PoC\n\n`;
      }

      report += `Anti-Duplicate:\n`;
      report += `  Hash: ${v.hashSignature?.slice(0, 24) || 'N/A'}...\n`;
      report += `  Is Duplicate: ${v.isDuplicate ? 'YES' : 'NO'}\n\n`;
    }

    // Summary
    report += `${separator}\n`;
    report += `SUMMARY\n`;
    report += `${separator}\n\n`;

    const bySeverity: Record<string, number> = {};
    for (const v of vulns) {
      bySeverity[v.severity] = (bySeverity[v.severity] || 0) + 1;
    }

    report += `Severity Distribution:\n`;
    for (const [sev, cnt] of Object.entries(bySeverity).sort()) {
      report += `  ${sev.toUpperCase()}: ${cnt}\n`;
    }
    report += `\n`;

    const byType: Record<string, number> = {};
    for (const v of vulns) {
      byType[v.type] = (byType[v.type] || 0) + 1;
    }
    report += `Vulnerability Types:\n`;
    for (const [type, cnt] of Object.entries(byType).sort()) {
      report += `  ${type}: ${cnt}\n`;
    }
    report += `\n`;

    report += `Confidence Thresholds Met:\n`;
    report += `  >= 95% (Confirmed):  ${vulns.filter(v => v.confidence >= 0.95).length}\n`;
    report += `  >= 80% (Probable):   ${vulns.filter(v => v.confidence >= 0.80 && v.confidence < 0.95).length}\n`;
    report += `  >= 60% (Possible):   ${vulns.filter(v => v.confidence >= 0.60 && v.confidence < 0.80).length}\n`;
    report += `  < 60% (Info):        ${vulns.filter(v => v.confidence < 0.60).length}\n\n`;

    report += `PoC Summary:\n`;
    const withPoc = vulns.filter(v => v.poc && v.poc.trim().length > 0);
    report += `  With Reproducible PoC: ${withPoc.length} / ${vulns.length}\n`;
    for (const v of withPoc) {
      report += `    - [${v.severity.toUpperCase()}] ${v.title} → ${v.pocFilename}\n`;
    }
    report += `\n`;

    report += `Generated by CryptoSentinel v0.1\n`;
    report += `Pipeline: V1(30%) + V2(25%) + V3(25%) + V4(20%) + orthogonality_bonus\n`;

    return NextResponse.json({ report, filename: `${project.name}_audit_report.txt` });
  } catch (e) {
    console.error('Report generation error:', e);
    return NextResponse.json({ error: String(e) }, { status: 500 });
  }
}
