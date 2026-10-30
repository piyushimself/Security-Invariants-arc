import { SecurityInvariant } from '../types/invariants';
import { convertLatexToUnicode } from './mathFormatter';

/**
 * Copies plain text to the clipboard with fallback for non-secure contexts
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    } else {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.left = '-999999px';
      textarea.style.top = '-999999px';
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      const successful = document.execCommand('copy');
      document.body.removeChild(textarea);
      return successful;
    }
  } catch (err) {
    console.error('Failed to copy to clipboard', err);
    return false;
  }
}

/**
 * Formats a single Security Invariant into a clean, comprehensive Markdown summary
 */
export function formatRuleAsMarkdown(inv: SecurityInvariant): string {
  const cleanMath = convertLatexToUnicode(inv.formalInvariant);

  return `# ${inv.id}: ${inv.title}
**Domain:** ${inv.domainName} (${inv.subdomain})
**Standards Grounding:** ${inv.standards.join(', ')}
**Classification:** ${inv.standardType} · Difficulty: ${inv.difficulty}

---

## 1. Formal Security Invariant
\`\`\`
${cleanMath}
\`\`\`

## 2. Plain English Explanation
${inv.plainEnglish}

## 3. Why It Matters in Production
${inv.whyItMatters}

---

## 4. Code Implementation Contrast

### ❌ Vulnerable Implementation (${inv.vulnerableExample.language})
\`\`\`${inv.vulnerableExample.language}
${inv.vulnerableExample.code}
\`\`\`
*Flaw Analysis:* ${inv.vulnerableExample.explanation}

### ✅ Hardened Defensive Implementation (${inv.secureExample.language})
\`\`\`${inv.secureExample.language}
${inv.secureExample.code}
\`\`\`
*Defensive Rationale:* ${inv.secureExample.explanation}

---

## 5. Automated Verification Procedure
${inv.howToTest.tools.length > 0 ? `**Required Tools:** ${inv.howToTest.tools.join(', ')}\n` : ''}
${inv.howToTest.steps.map((step, i) => `${i + 1}. ${step}`).join('\n')}

${inv.howToTest.commandExample ? `\`\`\`bash\n${inv.howToTest.commandExample}\n\`\`\`` : ''}

---

## 6. Staff-Level Whiteboard Interview Defense
**Scenario:** ${inv.interviewChallenge.scenario}
**Question:** ${inv.interviewChallenge.question}

> **Model Answer:**
> "${inv.interviewChallenge.sampleAnswer}"

**Core Architectural Takeaway:** ${inv.interviewChallenge.keyTakeaway}

---
*Source: Security Invariants Comprehensive Knowledge Base*`;
}

/**
 * Generates an optimized, highly detailed NotebookLM / AI Video Prompt
 * designed to produce an engaging, 6-7 minute animated cinematic explainer video.
 */
export function generateNotebookLMPrompt(inv: SecurityInvariant): string {
  const cleanMath = convertLatexToUnicode(inv.formalInvariant);

  return `Create a complete, cinematic 6 to 7-minute animated explainer video script and storyboard breakdown explaining the security invariant: "${inv.id}: ${inv.title}".

### GOAL:
Produce an engaging, visually compelling video (in the style of 3Blue1Brown meets a high-budget cybersecurity incident documentary) that demystifies this security invariant for software engineers and security architects.

### CORE SECURITY SUBJECT:
- **Rule ID & Title:** ${inv.id} — ${inv.title}
- **Domain & Scope:** ${inv.domainName} (${inv.subdomain})
- **Formal Mathematical Theorem:** ${cleanMath}
- **Standards & RFCs:** ${inv.standards.join(', ')}
- **Plain English Concept:** "${inv.plainEnglish}"
- **High-Impact Threat:** ${inv.whyItMatters}
- **Staff Interview Whiteboard Rule:** "${inv.interviewChallenge.keyTakeaway}"

---

### VISUAL STYLE & ART DIRECTION:
- **Aesthetic:** Dark-mode blueprint HUD with neon amber/cyan accents, volumetric 3D server racks, glowing data packet streams, dynamic split-screen code comparisons, and architectural schematic overlays.
- **Narrative Voice:** Clear, authoritative, engaging staff security engineer. Zero academic fluff—explain how real systems fail, how attackers exploit ambiguities, and how mathematical invariants guarantee defensive safety.

---

### TIMED 6-7 MINUTE VIDEO STRUCTURE:

#### [0:00 - 1:00] ACT 1: THE PRODUCTION OUTAGE (THE HOOK)
- **Visuals:** Dramatic red alert animation across a simulated distributed cloud topology. A request slips past the ingress proxy, triggering silent data leakage or unauthorized state mutation.
- **Narration:** Introduce the real-world catastrophe. Explain the exact ambiguity or missing precondition that allowed the breach, citing ${inv.standards.join(', ')}.
- **Anchor Question:** "Why do standard perimeter defenses fail here, and what mathematical invariant would have made this exploit impossible?"

#### [1:00 - 2:30] ACT 2: ANATOMY OF THE MECHANISM (THE DEEP DIVE)
- **Visuals:** 3D isometric animation dissecting the request lifecycle:
  - Header / payload parsing stages between proxy and backend.
  - The exact parser desynchronization or missing authorization predicate.
  - Animated byte sequence showing how the attacker payload is interpreted differently across system tiers.
- **Metaphor:** Use a concrete physical metaphor (e.g. dual inspection gates, cryptographic wax seals, unforgeable passport stamps) to illustrate why client-provided claims cannot be trusted without server verification.

#### [2:30 - 4:00] ACT 3: THE FORMAL INVARIANT (THE MATHEMATICAL PROOF)
- **Visuals:** Kinetic typography displaying the formal invariant:
  "${cleanMath}"
- **Narration:** Break down each symbol step-by-step in simple human terms:
  Explain the precondition, the invariant predicate, and the fail-closed postcondition.
- **Takeaway:** "Security is not a collection of patches; it is an invariant theorem that must hold true for every request without exception."

#### [4:00 - 5:15] ACT 4: CODE CRITIQUE: VULNERABLE VS. HARDENED
- **Visuals:** Split-screen glowing code terminal:
  - Left Screen (Red Tint): Naïve vulnerable code:
    \`\`\`${inv.vulnerableExample.language}
    ${inv.vulnerableExample.code}
    \`\`\`
    Highlight the exact vulnerable line: "${inv.vulnerableExample.explanation}"
  - Right Screen (Green Tint): Hardened, fail-closed implementation:
    \`\`\`${inv.secureExample.language}
    ${inv.secureExample.code}
    \`\`\`
    Highlight the fix: "${inv.secureExample.explanation}"

#### [5:15 - 6:15] ACT 5: AUTOMATED REGRESSION HARNESS (HOW TO TEST IT)
- **Visuals:** Terminal window executing the automated security verification harness:
  \`\`\`bash
  ${inv.howToTest.commandExample || '# Automated regression verification command'}
  \`\`\`
- **Narration:** Explain how to embed this verification check into modern CI/CD pipelines and IaC policy engines (OPA/Rego, Semgrep, or GitHub Actions) to prevent regressions.

#### [6:15 - 7:00] ACT 6: THE WHITEBOARD SCRIPT & STAFF ARCHITECT RECAP
- **Visuals:** Architectural whiteboard diagram showing the end-to-end hardened pattern with an animated green verification shield at the boundary.
- **Model Interview Answer:**
  > "${inv.interviewChallenge.sampleAnswer}"
- **Closing Punchline:** Recap the core takeaway: "${inv.interviewChallenge.keyTakeaway}". Call to action to enforce fail-closed invariants across all production endpoints.`;
}
