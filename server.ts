import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';
import { allInvariants, securityTopicsTaxonomy, getInvariantsForTopic } from './src/data/invariantsRegistry';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: '10mb' }));

const port = Number(process.env.PORT) || 3000;
const isProd = process.env.NODE_ENV === 'production';

// Models in priority order: start with highly responsive & available flash-lite
const CANDIDATE_MODELS = [
  'gemini-3.1-flash-lite',
  'gemini-flash-latest',
  'gemini-2.5-flash',
  'gemini-3.8-flash',
];

function getGenAIClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return null;
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

async function callGeminiWithFallback(
  ai: GoogleGenAI,
  contents: any,
  config: any
): Promise<string> {
  let lastError: any = null;
  for (const model of CANDIDATE_MODELS) {
    try {
      const response = await ai.models.generateContent({
        model,
        contents,
        config,
      });
      if (response && response.text && response.text.trim().length > 0) {
        return response.text;
      }
    } catch (err: any) {
      console.warn(`Model ${model} failed, attempting next model in cascade:`, err?.message || err);
      lastError = err;
    }
  }
  throw lastError || new Error('All Gemini candidate models failed');
}

// -------------------------------------------------------------
// Core Knowledge Retrieval Engine across 1,110 Invariants & 37 Topics
// -------------------------------------------------------------
interface RetrievedContext {
  invariants: typeof allInvariants;
  matchedTopic?: (typeof securityTopicsTaxonomy)[0];
  contextSummary: string;
}

function retrieveSecurityContext(
  query: string,
  domainHint?: string,
  limit: number = 6
): RetrievedContext {
  const q = (query || '').toLowerCase().trim();
  const tokens = q.split(/[\s,.:;/?!()[\]{}'"]+/).filter(t => t.length > 2);

  // 1. Identify if a specific 37-topic is matched
  const matchedTopic = securityTopicsTaxonomy.find(t => {
    const nameMatch = q.includes(t.name.toLowerCase());
    const idMatch = q.includes(t.id.replace(/_/g, ' '));
    const cweMatch = t.cwes.some(c => q.includes(c.toLowerCase()));
    const topicNumMatch = q.includes(`topic #${t.topicNumber}`) || q.includes(`topic ${t.topicNumber}`);
    return nameMatch || idMatch || cweMatch || topicNumMatch;
  });

  // 2. Score invariants based on query, topic, and domain
  const scored = allInvariants.map(inv => {
    let score = 0;
    const invIdLower = inv.id.toLowerCase();
    const invTitleLower = inv.title.toLowerCase();
    const invSubLower = inv.subdomain.toLowerCase();
    const invPlainLower = inv.plainEnglish.toLowerCase();
    const invFormulaLower = inv.formalInvariant.toLowerCase();
    const invStandardsLower = inv.standards.join(' ').toLowerCase();

    // Exact ID or number match
    if (q.includes(invIdLower)) score += 200;
    if (q.includes(`rule ${inv.ruleNumber}`) || q.includes(`rule #${inv.ruleNumber}`)) score += 150;

    // Direct topic match
    if (matchedTopic && inv.topicId === matchedTopic.id) score += 60;
    if (inv.isRareRule) score += 5; // slight boost to high-value rare rules

    // Domain match
    if (domainHint && inv.domain === domainHint) score += 15;
    if (matchedTopic && inv.domain === matchedTopic.domainId) score += 20;

    // Token scoring
    for (const token of tokens) {
      if (invIdLower.includes(token)) score += 40;
      if (invTitleLower.includes(token)) score += 25;
      if (invStandardsLower.includes(token)) score += 20;
      if (invSubLower.includes(token)) score += 15;
      if (invFormulaLower.includes(token)) score += 10;
      if (invPlainLower.includes(token)) score += 8;
    }

    return { inv, score };
  });

  // Sort descending by score
  scored.sort((a, b) => b.score - a.score);

  // Take top invariants (fallback to topic invariants if low score)
  let topInvariants = scored.slice(0, limit).filter(s => s.score > 0).map(s => s.inv);

  if (topInvariants.length === 0 && matchedTopic) {
    topInvariants = getInvariantsForTopic(matchedTopic.id, allInvariants).slice(0, limit);
  }

  if (topInvariants.length === 0) {
    topInvariants = allInvariants.slice(0, limit);
  }

  // Build clean markdown summary of retrieved invariants
  const contextSummary = topInvariants
    .map(
      (inv, idx) => `### Invariant Reference [${idx + 1}]: ${inv.id} - ${inv.title}
- **Domain:** ${inv.domainName} (${inv.subdomain}) | **Standards:** ${inv.standards.join(', ')} | **Type:** ${inv.standardType}
- **Formal Invariant Theorem:** \`${inv.formalInvariant}\`
- **Plain English Principle:** ${inv.plainEnglish}
- **Why It Matters (Blast Radius):** ${inv.whyItMatters}
- **Vulnerable Pattern (${inv.vulnerableExample.language}):**
\`\`\`${inv.vulnerableExample.language}
${inv.vulnerableExample.code}
\`\`\`
*Defect:* ${inv.vulnerableExample.explanation}
- **Secure Hardening (${inv.secureExample.language}):**
\`\`\`${inv.secureExample.language}
${inv.secureExample.code}
\`\`\`
*Hardening Rationale:* ${inv.secureExample.explanation}
- **Automated Verification:** \`${inv.howToTest.commandExample}\`
- **Staff Interview Drill:**
  - *Scenario:* ${inv.interviewChallenge.scenario}
  - *Question:* ${inv.interviewChallenge.question}
  - *Staff Model Answer:* ${inv.interviewChallenge.sampleAnswer}
  - *Key Takeaway:* ${inv.interviewChallenge.keyTakeaway}`
    )
    .join('\n\n');

  return {
    invariants: topInvariants,
    matchedTopic,
    contextSummary,
  };
}

// -------------------------------------------------------------
// POST /api/ai/chat
// Dedicated assistant for clearing doubts, discussing concepts & whiteboard drills
// -------------------------------------------------------------
app.post('/api/ai/chat', async (req, res) => {
  try {
    const { messages, currentInvariant, domain, userContext } = req.body;

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ error: 'Messages array is required' });
    }

    const ai = getGenAIClient();
    const lastUserMsg = messages[messages.length - 1]?.content || '';

    // Retrieve live context from our 1,110 invariants
    const retrieved = retrieveSecurityContext(lastUserMsg, domain, 5);

    // Build rich, grounded system instruction with human, practical tone
    let systemInstruction = `You are a Senior Security Architect and friendly Staff Interview Coach for the Security Invariants Platform.
You have authoritative access to all 1,110 security invariants and 37 vulnerability domains across the entire curriculum.

THE USER IS DISCUSSING SECURITY CONCEPTS, ASKING QUESTIONS, REVIEWING CODE, AND PREPARING FOR SENIOR/STAFF INTERVIEWS.

CORE GUIDELINES:
1. TALK LIKE A REAL, APPROACHABLE ENGINEER: Use clear, simple, professional language. Explain how things work in practice and why systems break. Avoid dense academic jargon, robotic templates, or bookish textbook phrasing. Keep it direct, intuitive, and practical.
2. CLEAN UNICODE FORMULAS (NO RAW LATEX): Whenever you write mathematical invariant rules, write them directly using standard Unicode symbols (∀, ∃, ⇒, ∧, ∨, ¬, ⇔, ∈, ∉, ⊂, ⊆, ≠, ≤, ≥). DO NOT use raw LaTeX markup like \\forall, \\land, \\in, or \\_ in your formulas or text.
3. CONCRETE REAL-WORLD CODE: Show practical, production-grade code (TypeScript, Go, Python, Rust) comparing what breaks (vulnerable) vs. how to harden it cleanly.
4. WHITEBOARD EXPLANATIONS: When asked about interviews, explain how to articulate the design out loud naturally, what tradeoffs to mention, and what traps interviewers look for.
5. GROUNDING IN DATABASE: Ground your explanations in the following retrieved security invariants:

=== RETRIEVED CURRICULUM CONTEXT ===
${retrieved.contextSummary}
====================================`;

    if (currentInvariant) {
      systemInstruction += `\n\nACTIVE RULE IN STUDY VIEW:
- ID: ${currentInvariant.id}
- Title: ${currentInvariant.title}
- Domain: ${currentInvariant.domainName || currentInvariant.domain} (${currentInvariant.subdomain})
- Formal Logic: ${currentInvariant.formalInvariant}
- Standards: ${(currentInvariant.standards || []).join(', ')}
- Plain English: ${currentInvariant.plainEnglish}`;
    }

    if (ai) {
      try {
        const formattedContents = messages.map((m: { role: string; content: string }) => ({
          role: m.role === 'assistant' || m.role === 'model' ? 'model' : 'user',
          parts: [{ text: m.content }],
        }));

        const replyText = await callGeminiWithFallback(ai, formattedContents, {
          systemInstruction,
          temperature: 0.65,
        });

        return res.json({
          reply: replyText,
          retrievedInvariants: retrieved.invariants.map(inv => ({
            id: inv.id,
            title: inv.title,
            domainName: inv.domainName,
            subdomain: inv.subdomain,
            standards: inv.standards,
          })),
        });
      } catch (genErr: any) {
        console.warn('Gemini chat model cascade failed, falling back to dynamic synthesizer:', genErr?.message || genErr);
      }
    }

    // Dynamic document-grounded synthesizer fallback with conversational, natural tone
    const dynamicReply = synthesizeDocumentGroundedChatReply(lastUserMsg, retrieved, currentInvariant);
    return res.json({
      reply: dynamicReply,
      retrievedInvariants: retrieved.invariants.map(inv => ({
        id: inv.id,
        title: inv.title,
        domainName: inv.domainName,
        subdomain: inv.subdomain,
        standards: inv.standards,
      })),
    });
  } catch (err: any) {
    console.error('Error in /api/ai/chat:', err);
    return res.status(500).json({
      error: 'Failed to process AI chat request',
      details: err?.message || String(err),
    });
  }
});

// Dynamic fallback chat synthesizer using real retrieved invariants with conversational, human explanation
function synthesizeDocumentGroundedChatReply(
  userQuery: string,
  retrieved: RetrievedContext,
  currentInvariant?: any
): string {
  const invs = retrieved.invariants;
  const isListQuery = /list|rules|all|what are|overview|show me/i.test(userQuery);

  if (isListQuery && invs.length > 1) {
    const topicLabel = retrieved.matchedTopic ? retrieved.matchedTopic.name : (invs[0].domainName || 'Security');
    let out = `Here is a clear, practical breakdown of the key **${topicLabel}** security rules you need to know:\n\n`;

    invs.slice(0, 5).forEach((inv, i) => {
      out += `### ${i + 1}. ${inv.title} (${inv.id})\n`;
      out += `**Core Rule:** \`${inv.formalInvariant}\`\n\n`;
      out += `**How it works in plain English:** ${inv.plainEnglish}\n\n`;
      out += `**Why it matters:** ${inv.whyItMatters}\n\n`;
      out += `**Verification test:**\n\`\`\`bash\n${inv.howToTest.commandExample}\n\`\`\`\n\n---\n\n`;
    });

    out += `💡 *Interview Tip:* When asked about ${topicLabel} on a whiteboard, always emphasize fail-closed defaults and strict canonicalization at the ingress boundary before passing data to backend services.`;
    return out;
  }

  const primaryInv = currentInvariant || (invs.length > 0 ? invs[0] : null);

  if (!primaryInv) {
    return `### Security Architecture & Practical Defense\n\n` +
      `Regarding: "${userQuery}"\n\n` +
      `At a high level, defensive architecture in production systems relies on a simple rule: **never mutate state or trust input without validating preconditions first**:\n\n` +
      `\`\`\`\n∀ request ∈ Ingress, Valid(request) ∧ Authorized(request.principal, request.target) ⇒ Process(request)\n\`\`\`\n\n` +
      `When this boundary breaks, common vulnerabilities arise (like IDOR/BOLA, request smuggling, or privilege escalation). Feel free to ask about any specific vulnerability, code example, or whiteboard interview scenario!`;
  }

  return `### Practical Breakdown: ${primaryInv.title} (${primaryInv.id})\n\n` +
    `**Domain:** ${primaryInv.domainName} · **Subdomain:** ${primaryInv.subdomain} · **Standard:** ${primaryInv.standards.join(', ')}\n\n` +
    `#### 1. What This Means in Plain English\n` +
    `${primaryInv.plainEnglish}\n\n` +
    `*Why it matters in production:* ${primaryInv.whyItMatters}\n\n` +
    `#### 2. The Formal Invariant Rule\n` +
    `\`\`\`\n${primaryInv.formalInvariant}\n\`\`\`\n\n` +
    `#### 3. Code Review: What Breaks vs. How to Fix It\n` +
    `##### ❌ Vulnerable Pattern (${primaryInv.vulnerableExample.language})\n` +
    `\`\`\`${primaryInv.vulnerableExample.language}\n${primaryInv.vulnerableExample.code}\n\`\`\`\n` +
    `*Why this fails:* ${primaryInv.vulnerableExample.explanation}\n\n` +
    `##### ✅ Hardened Production Fix (${primaryInv.secureExample.language})\n` +
    `\`\`\`${primaryInv.secureExample.language}\n${primaryInv.secureExample.code}\n\`\`\`\n` +
    `*How it fixes the issue:* ${primaryInv.secureExample.explanation}\n\n` +
    `#### 4. Whiteboard Interview Drill & How to Explain It\n` +
    `> **Scenario:** ${primaryInv.interviewChallenge.scenario}\n` +
    `> **Interviewer Question:** ${primaryInv.interviewChallenge.question}\n` +
    `> **How to Answer Naturally:** "${primaryInv.interviewChallenge.sampleAnswer}"\n\n` +
    `💡 **Key Takeaway to Remember:** ${primaryInv.interviewChallenge.keyTakeaway}`;
}

// -------------------------------------------------------------
// POST /api/ai/generate-report
// Generates publication-grade, multi-page comprehensive interview workbooks
// -------------------------------------------------------------
app.post('/api/ai/generate-report', async (req, res) => {
  try {
    const {
      topicPrompt,
      reportType = 'Staff Interview Whiteboard Workbook',
      domains = [],
      targetAudience = 'Senior / Staff Security Engineers',
      customRequirements = '',
      userMasteryContext = null,
      codeLanguage = 'TypeScript & Go',
    } = req.body;

    if (!topicPrompt) {
      return res.status(400).json({ error: 'topicPrompt is required' });
    }

    // Retrieve top 8 matching invariants from the 1,110 database
    const retrieved = retrieveSecurityContext(topicPrompt, domains[0], 8);

    const ai = getGenAIClient();

    const systemInstruction = `You are a Principal Security Architect, Distinquished Engineer, and Technical Author.
You are tasked with generating an exhaustive, publication-grade, deeply technical Security Invariant Masterclass Workbook and Defense Dossier for: "${topicPrompt}".

TARGET AUDIENCE: ${targetAudience}
REPORT FORMAT: ${reportType}
CODE PREFERENCE: ${codeLanguage}

CRITICAL QUALITY REQUIREMENTS:
- DO NOT generate a brief or superficial outline. Write a substantial, deep, multi-page reference workbook (1,800 to 2,500 words).
- GROUND THE REPORT IN THE RETRIEVED CURRICULUM INVARIANTS provided below. Include their actual mathematical formal logic notation, exact RFC/CWE references, and verification commands.
- WRITE FORMULAS IN CLEAN UNICODE: Always write mathematical logic directly in standard Unicode symbols (∀, ∃, ⇒, ∧, ∨, ¬, ⇔, ∈, ∉, ⊂, ⊆, ≠, ≤, ≥). DO NOT use raw LaTeX markup like \\forall, \\land, \\in, or \\_ in text or formulas.
- PROFESSIONAL, HUMAN TONE: Explain concepts clearly, practically, and conversationally like a senior staff engineer mentoring a peer. Avoid convoluted academic jargon or textbook filler.
- PROVIDE COMPLETE, PRODUCTION-READY CODE BLOCKS with error handling and defense-in-depth, not trivial pseudo-code.
- INCLUDE REALISTIC STAFF INTERVIEW DRILLS with probing interviewer follow-up questions, candidate failure traps, and verbatim spoken whiteboard answers.

MANDATORY SECTIONS (Follow this exact structure):
# [Authoritative, Engaging Title]
**Target Role / Focus:** ${targetAudience}
**Report Category:** ${reportType}
**Standards Grounding:** [Cite relevant CWEs, RFCs, NIST SP 800 series, OWASP]
**Date Generated:** ${new Date().toISOString().split('T')[0]}

---

## 1. Executive Summary & Threat Landscape
- Real-world threat vectors, blast radius, historical breach precedents, and STRIDE classification.
- Explain why standard perimeter defenses fail and why formal invariant enforcement is mathematically necessary.

## 2. Core Formal Invariants & Mathematical Logic
- Present 4 to 6 precise formal theorems using first-order logic notation (∀, ∃, ⇒, ∧, ¬, ⇔).
- Provide a clear symbol breakdown table for each formula.
- Explain the precondition, state transition invariant, and postcondition guarantees.

## 3. High-Impact Attack Vectors, Bypass Mechanics & Root Causes
- Step-by-step breakdown of how sophisticated adversaries exploit subtle invariant violations.
- Cover advanced bypass techniques (e.g. parser differentials, double encoding, symlink races, TOCTOU, unicode canonicalization, unvalidated hop headers, second-order injections).

## 4. Production Code Review: Vulnerable vs. Secure Hardened Implementations
- Provide comprehensive code examples in ${codeLanguage}.
- Show the Vulnerable implementation with inline annotations highlighting the defect.
- Show the Hardened Production implementation implementing the formal invariant with complete validation.

## 5. Automated Verification, CI/CD Gates & Policy Enforcement
- Concrete, executable testing procedures:
  - Curl or CLI verification command.
  - Static Analysis AST rule (Semgrep or CodeQL pattern).
  - Open Policy Agent (OPA) Rego policy or Kubernetes admission rule.

## 6. Staff & Principal Whiteboard Interview Drills
- Present 2 to 3 progressive interview whiteboard scenarios (from senior to staff level).
- For each scenario:
  - System Design Scenario Context.
  - The Interviewer's Core Challenge.
  - Common Candidate Traps & Failure Modes.
  - Verbatim Spoken Whiteboard Model Answer & Architectural Rationale.
  - Follow-up Stress Test Questions.

## 7. Actionable Production Hardening & Operational Audit Checklist
- Comprehensive markdown checklist with priority (P0/P1/P2), control description, and audit verification step.`;

    const userPrompt = `Generate the complete, publication-grade, exhaustive security report for:
Topic Prompt: "${topicPrompt}"
Report Category: ${reportType}
Selected Domains: ${domains.length > 0 ? domains.join(', ') : 'All Relevant Domains'}
Target Audience: ${targetAudience}
Custom Requirements: ${customRequirements || 'Provide maximum depth, mathematical rigor, and realistic staff interview drills.'}

GROUNDING CURRICULUM DATA RETRIEVED FROM DATABASE:
${retrieved.contextSummary}

Write the complete, unabbreviated Markdown report now.`;

    if (ai) {
      try {
        const markdownContent = await callGeminiWithFallback(ai, userPrompt, {
          systemInstruction,
          temperature: 0.6,
        });

        const titleMatch = markdownContent.match(/^#\s+(.+)$/m);
        const title = titleMatch ? titleMatch[1].trim() : `Masterclass Report: ${topicPrompt.slice(0, 50)}`;

        return res.json({
          title,
          reportType,
          generatedAt: new Date().toISOString(),
          markdownContent,
          retrievedInvariantsCount: retrieved.invariants.length,
        });
      } catch (genErr: any) {
        console.warn('Gemini report generation failed, building document-grounded report:', genErr?.message || genErr);
      }
    }

    // Dynamic, high-fidelity report synthesizer constructed from actual database invariants
    const dynamicReport = buildFullDocumentGroundedReport(topicPrompt, reportType, targetAudience, retrieved);
    return res.json({
      title: dynamicReport.title,
      reportType,
      generatedAt: new Date().toISOString(),
      markdownContent: dynamicReport.markdown,
      retrievedInvariantsCount: retrieved.invariants.length,
    });
  } catch (err: any) {
    console.error('Error in /api/ai/generate-report:', err);
    return res.status(500).json({
      error: 'Failed to generate custom security report',
      details: err?.message || String(err),
    });
  }
});

// High-fidelity fallback report generator that builds directly from retrieved invariants
function buildFullDocumentGroundedReport(
  topicPrompt: string,
  reportType: string,
  targetAudience: string,
  retrieved: RetrievedContext
) {
  const invs = retrieved.invariants;
  const primary = invs[0] || allInvariants[0];
  const topicMeta = retrieved.matchedTopic;

  const title = topicMeta ? `${topicMeta.name}: Staff Architectural Invariants & Whiteboard Defense` : `${topicPrompt}: Comprehensive Security Invariants Masterclass`;

  const standards = topicMeta ? [topicMeta.primaryStandard, ...topicMeta.cwes] : primary.standards;

  let markdown = `# ${title}
**Target Role / Focus:** ${targetAudience}
**Report Category:** ${reportType}
**Standards Grounding:** ${standards.join(', ')}
**Date Generated:** ${new Date().toISOString().split('T')[0]}

---

## 1. Executive Summary & Threat Landscape
This masterclass technical report examines the formal defensive architecture and invariant boundaries for **${topicPrompt}**. In modern distributed and cloud-native systems, single-tier perimeter defenses fail under adversarial manipulation. Attackers exploit parser differentials, unvalidated metadata, and asynchronous state races to breach trust boundaries.

By enforcing mathematically provable invariants at the ingress, execution, and storage layers, engineering organizations guarantee fail-closed resilience against unauthorized state mutation, privilege escalation, and lateral movement.

---

## 2. Core Formal Invariants & Mathematical Logic
The following formal theorems govern secure execution within this operational boundary:

`;

  invs.slice(0, 4).forEach((inv, i) => {
    markdown += `### Invariant ${i + 1}: ${inv.title} (${inv.id})
\`\`\`
${inv.formalInvariant}
\`\`\`
- **Mathematical Specification:** ${inv.plainEnglish}
- **Symbol Breakdown:**
${inv.symbolBreakdown.map(s => `  - \`${s.symbol}\`: ${s.meaning}`).join('\n')}
- **Enforcement Layer:** Evaluated at ingress gateway with fail-closed semantics before downstream dispatch.

`;
  });

  markdown += `---

## 3. High-Impact Attack Vectors & Exploit Mechanics
When formal invariants are not strictly maintained in production, adversaries exploit boundary discrepancies through the following attack chains:

1. **Parser Discrepancy & Ambiguous Framing:**
   - *Mechanic:* Upstream reverse proxies and downstream application runtimes parse input streams using different RFC implementations or normalization routines.
   - *Exploit Impact:* Attackers smuggle malicious state transitions past WAFs, poison shared cache layers, or desynchronize persistent socket connections.

2. **Second-Order State Desynchronization:**
   - *Mechanic:* Input safely stored in initial transactions is later consumed by asynchronous background workers or reporting jobs without re-validation.
   - *Exploit Impact:* Delayed execution of injected commands, path escapes, or unauthorized privilege escalation.

3. **Time-of-Check to Time-of-Use (TOCTOU) Concurrency Races:**
   - *Mechanic:* Validating permission at timestamp $T_1$ while mutating system state at timestamp $T_2$ without atomic database locking.
   - *Exploit Impact:* Limit overrun attacks, double withdrawals, and file symlink hijacking.

---

## 4. Production Code Review: Vulnerable vs. Secure Implementation

`;

  invs.slice(0, 2).forEach(inv => {
    markdown += `### Case Study: ${inv.title}

#### ❌ Vulnerable Implementation (${inv.vulnerableExample.language})
\`\`\`${inv.vulnerableExample.language}
${inv.vulnerableExample.code}
\`\`\`
**Vulnerability Analysis:** ${inv.vulnerableExample.explanation}

#### ✅ Hardened Production Implementation (${inv.secureExample.language})
\`\`\`${inv.secureExample.language}
${inv.secureExample.code}
\`\`\`
**Defensive Rationale:** ${inv.secureExample.explanation}

`;
  });

  markdown += `---

## 5. Automated Verification & CI/CD Test Harness
To ensure continuous compliance in production pipelines, integrate the following test procedures into automated regression suites:

### Executable CLI Verification Test
\`\`\`bash
${primary.howToTest.commandExample}
\`\`\`

### Verification Procedure
${primary.howToTest.steps.map((s, idx) => `${idx + 1}. ${s}`).join('\n')}

---

## 6. Staff-Level Interview Whiteboard Script & Scenario Defense

### Scenario Challenge
> **Scenario:** ${primary.interviewChallenge.scenario}
> **Core Question:** ${primary.interviewChallenge.question}
> **Candidate Trap:** Failing to evaluate invariants at the architectural boundary and relying on client-side or implicit framework trust.

### Staff Model Answer & Spoken Whiteboard Script
> *"To solve this systematically, I design the defense around formal invariant enforcement at the trust boundary. ${primary.interviewChallenge.sampleAnswer}"*

**Key Takeaway:** ${primary.interviewChallenge.keyTakeaway}

---

## 7. Actionable Hardening Checklist
- [x] **Boundary Canonicalization:** Canonicalize all inputs and enforce strict type allowlists prior to operational processing.
- [x] **Fail-Closed Default Posture:** Guarantee that any unhandled exception, syntax error, or ambiguous parameter defaults to immediate abort.
- [x] **Atomic State Mutation:** Use database row-level locking or optimistic CAS to eliminate TOCTOU race conditions.
- [x] **Automated Regression Gates:** Embed invariant verification tests into CI/CD build gates.
- [x] **Least Privilege Sandbox:** Run unprivileged workloads in isolated namespaces with read-only root filesystems.
`;

  return { title, markdown };
}

// -------------------------------------------------------------
// GET /api/ai/context-preview
// Previews retrieved invariants for any topic or query
// -------------------------------------------------------------
app.get('/api/ai/context-preview', (req, res) => {
  const query = String(req.query.q || '');
  const domain = req.query.domain ? String(req.query.domain) : undefined;
  const retrieved = retrieveSecurityContext(query, domain, 5);

  return res.json({
    matchedTopic: retrieved.matchedTopic ? {
      id: retrieved.matchedTopic.id,
      name: retrieved.matchedTopic.name,
      primaryStandard: retrieved.matchedTopic.primaryStandard,
      rarityLevel: retrieved.matchedTopic.rarityLevel,
    } : null,
    invariants: retrieved.invariants.map(inv => ({
      id: inv.id,
      ruleNumber: inv.ruleNumber,
      title: inv.title,
      domain: inv.domain,
      domainName: inv.domainName,
      subdomain: inv.subdomain,
      standards: inv.standards,
      formalInvariant: inv.formalInvariant,
      plainEnglish: inv.plainEnglish,
      isRareRule: inv.isRareRule,
    })),
  });
});

// -------------------------------------------------------------
// Vite middleware in dev, static files in production
// -------------------------------------------------------------
async function startServer() {
  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`Security Invariants Platform running on http://0.0.0.0:${port}`);
  });
}

startServer();
