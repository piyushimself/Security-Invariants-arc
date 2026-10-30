/**
 * Mathematical LaTeX to Unicode & HTML Formatter
 * Converts LaTeX formulas ($$...$$ and $...$) and raw LaTeX symbols
 * into clean, readable Unicode notation styled in elegant callouts.
 */

/**
 * Replaces LaTeX symbols and commands with standard clean Unicode characters
 */
export function convertLatexToUnicode(str: string): string {
  if (!str) return '';

  return str
    // Common logic quantifiers & relations
    .replace(/\\forall\b/g, '∀')
    .replace(/\\exists\b/g, '∃')
    .replace(/\\nexists\b/g, '∄')
    .replace(/\\in\b/g, '∈')
    .replace(/\\notin\b/g, '∉')
    .replace(/\\ni\b/g, '∋')
    .replace(/\\subset\b/g, '⊂')
    .replace(/\\subseteq\b/g, '⊆')
    .replace(/\\supset\b/g, '⊃')
    .replace(/\\supseteq\b/g, '⊇')
    // Logical connectives
    .replace(/\\land\b/g, '∧')
    .replace(/\\wedge\b/g, '∧')
    .replace(/\\lor\b/g, '∨')
    .replace(/\\vee\b/g, '∨')
    .replace(/\\neg\b/g, '¬')
    .replace(/\\lnot\b/g, '¬')
    // Implications & Arrows
    .replace(/\\implies\b/g, '⇒')
    .replace(/\\Rightarrow\b/g, '⇒')
    .replace(/\\Leftarrow\b/g, '⇐')
    .replace(/\\iff\b/g, '⇔')
    .replace(/\\Leftrightarrow\b/g, '⇔')
    .replace(/\\rightarrow\b/g, '→')
    .replace(/\\leftarrow\b/g, '←')
    .replace(/\\leftrightarrow\b/g, '↔')
    .replace(/\\to\b/g, '→')
    // Relations & Operators
    .replace(/\\neq\b/g, '≠')
    .replace(/\\ne\b/g, '≠')
    .replace(/\\leq\b/g, '≤')
    .replace(/\\le\b/g, '≤')
    .replace(/\\geq\b/g, '≥')
    .replace(/\\ge\b/g, '≥')
    .replace(/\\times\b/g, '×')
    .replace(/\\div\b/g, '÷')
    .replace(/\\cdot\b/g, '·')
    .replace(/\\cap\b/g, '∩')
    .replace(/\\cup\b/g, '∪')
    .replace(/\\emptyset\b/g, '∅')
    .replace(/\\infty\b/g, '∞')
    .replace(/\\approx\b/g, '≈')
    .replace(/\\equiv\b/g, '≡')
    .replace(/\\sim\b/g, '~')
    // Text wrappers
    .replace(/\\text\{([^}]*)\}/g, '$1')
    .replace(/\\mathrm\{([^}]*)\}/g, '$1')
    .replace(/\\mathbf\{([^}]*)\}/g, '$1')
    .replace(/\\mathit\{([^}]*)\}/g, '$1')
    .replace(/\\operatorname\{([^}]*)\}/g, '$1')
    // Escaped characters in LaTeX like \_ \{ \}
    .replace(/\\_/g, '_')
    .replace(/\\\{/g, '{')
    .replace(/\\\}/g, '}')
    // Clean up residual LaTeX spacing
    .replace(/\\quad/g, '  ')
    .replace(/\\qquad/g, '    ')
    .replace(/\\,/g, ' ')
    .replace(/\\;/g, ' ');
}

/**
 * Formats a block math expression into a styled formula card
 */
export function formatBlockMath(formula: string): string {
  const clean = convertLatexToUnicode(formula.trim());
  return `<div class="my-3 p-3.5 rounded-xl bg-slate-950 border border-indigo-500/30 text-indigo-200 font-mono text-sm sm:text-base overflow-x-auto shadow-inner flex items-center gap-3"><span class="px-2 py-0.5 rounded text-[10px] uppercase font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 shrink-0">Rule Invariant</span><span class="tracking-wide">${clean}</span></div>`;
}

/**
 * Formats an inline math expression into a styled inline badge
 */
export function formatInlineMath(formula: string): string {
  const clean = convertLatexToUnicode(formula.trim());
  return `<span class="inline-flex items-center px-2 py-0.5 mx-0.5 rounded bg-slate-950 border border-indigo-500/30 text-indigo-300 font-mono text-xs font-semibold">${clean}</span>`;
}
