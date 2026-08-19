const { PrismaClient } = require("@prisma/client");
const p = new PrismaClient({ datasources: { db: { url: "file:/tmp/cryptosentinel.db" } } });

(async () => {
  const all = await p.vulnerability.groupBy({ by: ["status"], _count: true });
  console.log("=== BY STATUS ===");
  for (const s of all) console.log(`  ${s.status}: ${s._count}`);

  const byType = await p.vulnerability.findMany({
    where: { status: "candidate" },
    select: { type: true },
  });
  const typeCounts = {};
  for (const v of byType) typeCounts[v.type] = (typeCounts[v.type] || 0) + 1;
  console.log("\n=== CANDIDATES BY TYPE ===");
  for (const [t, n] of Object.entries(typeCounts).sort((a,b) => b[1]-a[1])) console.log(`  ${t}: ${n}`);

  const candidates = await p.vulnerability.findMany({
    where: { status: "candidate" },
    select: { id: true, title: true, type: true, severity: true, validationScope: true, description: true, location: true },
    orderBy: [{ severity: "desc" }, { createdAt: "desc" }],
    take: 30,
  });
  console.log("\n=== CANDIDATES DETAIL (" + candidates.length + " shown) ===\n");
  for (const v of candidates) {
    console.log("--- " + v.severity.toUpperCase() + " | " + v.type + " | " + v.id + " ---");
    console.log("TITLE: " + v.title);
    console.log("SCOPE: " + (v.validationScope || "null"));
    console.log("LOC: " + (v.location || "").substring(0, 150));
    const desc = v.description || "";
    // Find the verdict label
    const labels = ["[INCONCLUSIVE]", "[EXPLOITABLE]", "[NOT_EXPLOITABLE]", "[AGGRESSIVE-FALLBACK]", "[OBVIOUS"];
    let found = "";
    for (const lbl of labels) {
      const idx = desc.indexOf(lbl);
      if (idx >= 0) {
        const end = desc.indexOf("\n", idx);
        found = desc.substring(idx, end > 0 ? Math.min(end, idx + 400) : idx + 400);
        break;
      }
    }
    if (found) console.log("VERDICT_LINE: " + found);
    else console.log("VERDICT_LINE: (no label) " + desc.substring(0, 200));
    console.log("");
  }

  // Also check confirmed findings for sanity (should be only true positives)
  const confirmed = await p.vulnerability.findMany({
    where: { status: { in: ["confirmed", "validated"] } },
    select: { title: true, type: true, severity: true, status: true, validationScope: true },
    orderBy: [{ severity: "desc" }],
    take: 10,
  });
  console.log("\n=== CONFIRMED/VALIDATED (sanity check) ===");
  for (const v of confirmed) {
    console.log(`  [${v.status}] ${v.severity.toUpperCase()} ${v.type}: ${v.title.substring(0, 80)}`);
  }

  await p.$disconnect();
})().catch(e => { console.error("ERROR:", e.message); process.exit(1); });
