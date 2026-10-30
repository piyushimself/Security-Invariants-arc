import { allInvariants, domainMetadata } from '../src/data/invariantsRegistry';

console.log(`\n=== CURRICULUM VERIFICATION AUDIT ===`);
console.log(`Total Invariants Loaded: ${allInvariants.length}`);
console.log(`Total Domains: ${Object.keys(domainMetadata).length}`);

// Domain counts
for (const [domId, meta] of Object.entries(domainMetadata)) {
  const actualCount = allInvariants.filter(r => r.domain === domId).length;
  console.log(`Domain [${domId.padEnd(16)}]: declared ${meta.count}, actual ${actualCount}`);
  if (meta.count !== actualCount) {
    console.error(`MISMATCH for domain ${domId}: declared ${meta.count} vs actual ${actualCount}`);
  }
}

// Check ID uniqueness
const idMap = new Map<string, number>();
const titleMap = new Map<string, number>();
const questionMap = new Map<string, number>();
const formulaMap = new Map<string, number>();

let dupIdCount = 0;
let dupTitleCount = 0;
let dupQuestionCount = 0;
let dupFormulaCount = 0;

for (const inv of allInvariants) {
  // ID check
  idMap.set(inv.id, (idMap.get(inv.id) || 0) + 1);
  if ((idMap.get(inv.id) || 0) > 1) {
    console.error(`Duplicate ID: ${inv.id}`);
    dupIdCount++;
  }

  // Title check
  titleMap.set(inv.title, (titleMap.get(inv.title) || 0) + 1);
  if ((titleMap.get(inv.title) || 0) > 1) {
    console.error(`Duplicate Title: "${inv.title}" (Rule: ${inv.id})`);
    dupTitleCount++;
  }

  // Question check
  const q = inv.interviewChallenge?.question;
  if (q) {
    questionMap.set(q, (questionMap.get(q) || 0) + 1);
    if ((questionMap.get(q) || 0) > 1) {
      console.error(`Duplicate Question: "${q}" (Rule: ${inv.id})`);
      dupQuestionCount++;
    }
  }

  // Formal invariant check
  const f = inv.formalInvariant;
  if (f) {
    formulaMap.set(f, (formulaMap.get(f) || 0) + 1);
    if ((formulaMap.get(f) || 0) > 1) {
      console.error(`Duplicate Formula: "${f}" (Rule: ${inv.id})`);
      dupFormulaCount++;
    }
  }
}

console.log(`\n--- Uniqueness Report ---`);
console.log(`Duplicate IDs: ${dupIdCount}`);
console.log(`Duplicate Titles: ${dupTitleCount}`);
console.log(`Duplicate Questions: ${dupQuestionCount}`);
console.log(`Duplicate Formulas: ${dupFormulaCount}`);

if (allInvariants.length > 1000 && dupIdCount === 0 && dupTitleCount === 0 && dupQuestionCount === 0 && dupFormulaCount === 0) {
  console.log(`\nSUCCESS: 1,000+ Formal Security Invariants verified with 100% uniqueness!`);
  process.exit(0);
} else {
  console.error(`\nFAILED: Found duplicates or count <= 1000`);
  process.exit(1);
}
