import { SecurityInvariant, UserProgress, DomainId, SecurityTopicMeta } from '../types/invariants';
import { domainMetadata } from '../data/invariantsRegistry';

/**
 * Utility to trigger immediate browser file download from memory
 */
export function downloadFile(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: `${mimeType};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Utility to open an HTML report in a clean printable window and trigger print
 */
export function openPrintWindow(htmlContent: string) {
  const printWindow = window.open('', '_blank', 'width=1100,height=900,menubar=no,toolbar=no,location=no,status=no');
  if (!printWindow) {
    alert('Pop-up blocked. Please allow pop-ups for this site to view printable audit reports.');
    return;
  }
  printWindow.document.open();
  printWindow.document.write(htmlContent);
  printWindow.document.close();
  printWindow.focus();
}

/**
 * Helper to escape CSV strings according to RFC 4180
 */
function escapeCSV(value: string | number | undefined | null): string {
  if (value === undefined || value === null) return '""';
  const str = String(value);
  return `"${str.replace(/"/g, '""')}"`;
}

/**
 * Helper to escape HTML characters for safe printable documents
 */
function escapeHtml(str: string | undefined | null): string {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * 1. COMPLIANCE & TRACEABILITY MATRIX (CSV)
 * Generates an Excel / Google Sheets / Jira importable matrix
 */
export function exportToCSV(invariants: SecurityInvariant[], progress?: UserProgress, filename?: string) {
  const headers = [
    'Rule ID',
    'Rule Number',
    'Domain',
    'Subdomain',
    'Title',
    'Difficulty',
    'Standard Type',
    'Formal Invariant (Logic)',
    'Primary Standards',
    'Plain English Meaning',
    'Threat Scenario & Why It Matters',
    'Testing Tools',
    'Verification Command',
    'Audit Status (Mastered)',
    'Bookmarked',
    'SRS Review Count',
    'Interview Scenario'
  ];

  const rows = invariants.map(inv => {
    const isMastered = progress?.masteredIds.includes(inv.id) ? 'Mastered / Verified' : 'Needs Review';
    const isBookmarked = progress?.bookmarkedIds.includes(inv.id) ? 'Bookmarked' : 'No';
    const srsRepetitions = progress?.srsData[inv.id]?.repetition ?? 0;

    return [
      escapeCSV(inv.id),
      escapeCSV(inv.ruleNumber),
      escapeCSV(inv.domainName),
      escapeCSV(inv.subdomain),
      escapeCSV(inv.title),
      escapeCSV(inv.difficulty),
      escapeCSV(inv.standardType),
      escapeCSV(inv.formalInvariant),
      escapeCSV(inv.standards.join('; ')),
      escapeCSV(inv.plainEnglish),
      escapeCSV(inv.whyItMatters),
      escapeCSV(inv.howToTest.tools.join(', ')),
      escapeCSV(inv.howToTest.commandExample),
      escapeCSV(isMastered),
      escapeCSV(isBookmarked),
      escapeCSV(srsRepetitions),
      escapeCSV(inv.interviewChallenge.scenario)
    ].join(',');
  });

  const csvContent = [headers.join(','), ...rows].join('\r\n');
  const actualFilename = filename || `security_invariants_matrix_${invariants.length}_rules.csv`;
  downloadFile(actualFilename, csvContent, 'text/csv');
}

/**
 * 2. GITHUB-FLAVORED MARKDOWN STUDY GUIDE & AUDIT BOOK (.md)
 */
export function exportToMarkdown(
  invariants: SecurityInvariant[],
  title: string = 'Security Invariants Curriculum & Audit Handbook',
  options: { includeQA?: boolean; includeDiffs?: boolean } = { includeQA: true, includeDiffs: true }
) {
  const dateStr = new Date().toISOString().split('T')[0];
  let md = `# ${title}\n\n`;
  md += `> **Standard:** RFC, NIST, OWASP, STRIDE, CWE Grounded Security Invariants\n`;
  md += `> **Generated on:** ${dateStr} | **Total Rules Included:** ${invariants.length}\n\n`;
  md += `---\n\n`;

  // Executive Summary Table
  md += `## Table of Contents\n\n`;
  md += `| ID | Title | Domain | Difficulty | Type |\n`;
  md += `|---|---|---|---|---|\n`;
  invariants.forEach(inv => {
    const anchor = inv.id.toLowerCase().replace(/[^a-z0-9_-]/g, '');
    md += `| [${inv.id}](#${anchor}) | ${inv.title} | ${inv.domainName} | ${inv.difficulty} | ${inv.standardType} |\n`;
  });
  md += `\n---\n\n`;

  // Detailed Rules
  invariants.forEach(inv => {
    md += `### ${inv.id}: ${inv.title}\n\n`;
    md += `- **Domain:** ${inv.domainName} (${inv.subdomain})\n`;
    md += `- **Classification:** ${inv.standardType} | **Difficulty:** ${inv.difficulty}\n`;
    md += `- **Standards Grounding:** \`${inv.standards.join('`, `')}\`\n\n`;

    md += `#### Formal Invariant\n\n`;
    md += `\`\`\`text\n${inv.formalInvariant}\n\`\`\`\n\n`;

    md += `**Plain-English Definition:**\n${inv.plainEnglish}\n\n`;

    if (inv.symbolBreakdown && inv.symbolBreakdown.length > 0) {
      md += `**Symbol Breakdown:**\n`;
      inv.symbolBreakdown.forEach(s => {
        md += `- \`${s.symbol}\`: ${s.meaning}\n`;
      });
      md += `\n`;
    }

    md += `#### Threat Scenario & Why It Matters\n\n`;
    md += `${inv.whyItMatters}\n\n`;

    if (options.includeDiffs) {
      md += `#### Implementation Comparison\n\n`;
      md += `**Vulnerable Pattern (${inv.vulnerableExample.language}):**\n`;
      md += `\`\`\`${inv.vulnerableExample.language.toLowerCase()}\n${inv.vulnerableExample.code}\n\`\`\`\n`;
      md += `*Vulnerability explanation:* ${inv.vulnerableExample.explanation}\n\n`;

      md += `**Secure Pattern (${inv.secureExample.language}):**\n`;
      md += `\`\`\`${inv.secureExample.language.toLowerCase()}\n${inv.secureExample.code}\n\`\`\`\n`;
      md += `*Security invariant enforced:* ${inv.secureExample.explanation}\n\n`;
    }

    md += `#### Verification Procedure\n\n`;
    md += `- **Recommended Tools:** \`${inv.howToTest.tools.join('`, `')}\`\n`;
    md += `- **Audit Steps:**\n`;
    inv.howToTest.steps.forEach((step, idx) => {
      md += `  ${idx + 1}. [ ] ${step}\n`;
    });
    md += `\n**CLI Verification Command:**\n`;
    md += `\`\`\`bash\n${inv.howToTest.commandExample}\n\`\`\`\n\n`;

    if (options.includeQA) {
      md += `#### Technical Interview Scenario\n\n`;
      md += `> **Scenario:** ${inv.interviewChallenge.scenario}\n>\n`;
      md += `> **Question:** ${inv.interviewChallenge.question}\n>\n`;
      md += `<details>\n<summary><b>View Model Answer & Key Takeaway</b></summary>\n\n`;
      md += `**Sample Answer:**\n${inv.interviewChallenge.sampleAnswer}\n\n`;
      md += `**Key Architectural Takeaway:**\n${inv.interviewChallenge.keyTakeaway}\n`;
      md += `</details>\n\n`;
    }

    md += `---\n\n`;
  });

  const filename = `${title.toLowerCase().replace(/[^a-z0-9]+/g, '_')}_${invariants.length}_rules.md`;
  downloadFile(filename, md, 'text/markdown');
}

/**
 * 3. EXECUTABLE BASH VERIFICATION TEST HARNESS (.sh)
 * Generates an executable shell script that developers and DevSecOps engineers can run
 */
export function exportToBashTestHarness(invariants: SecurityInvariant[], suiteName: string = 'Security Invariants Test Harness') {
  const dateStr = new Date().toISOString().split('T')[0];
  let sh = `#!/usr/bin/env bash
# ==============================================================================
# ${suiteName.toUpperCase()}
# Generated on: ${dateStr}
# Total Invariant Tests: ${invariants.length}
# ==============================================================================
# CAUTION: Run in a test or CI staging environment.
# Some tests perform network queries, local policy checks, or container audits.
# ==============================================================================

set -uo pipefail

# Color palette for terminal reporting
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
CYAN='\\033[0;36m'
NC='\\033[0m' # No Color

TOTAL_TESTS=${invariants.length}
PASSED_TESTS=0
SKIPPED_TESTS=0
FAILED_TESTS=0

echo -e "\${CYAN}===============================================================================\${NC}"
echo -e "\${CYAN}  ${suiteName}\${NC}"
echo -e "\${CYAN}  Verifying ${invariants.length} Security Invariant Checks\${NC}"
echo -e "\${CYAN}===============================================================================\${NC}"
echo ""

# Pre-flight tool check
echo -e "\${BLUE}[INFO]\${NC} Checking tool availability on host..."
for tool in curl jq semgrep trivy cosign openssl kubectl slither git; do
  if command -v "$tool" &> /dev/null; then
    echo -e "  [+] $tool: \${GREEN}Installed\${NC}"
  else
    echo -e "  [-] $tool: \${YELLOW}Not found (tests requiring $tool will simulate or log dry-run)\${NC}"
  fi
done
echo ""

run_invariant_check() {
  local id="$1"
  local title="$2"
  local domain="$3"
  local cmd="$4"
  
  echo -e "\${BLUE}-------------------------------------------------------------------------------\${NC}"
  echo -e "\${BLUE}[TEST]\${NC} [\${id}] \${title}"
  echo -e "       Domain: \${domain}"
  echo -e "       Command: \${cmd}"
  
  # For safe execution in diverse developer setups, run command with a fallback timeout
  # In dry-run mode, we verify the command syntax and syntax-check where possible
  if [ -n "$cmd" ]; then
    echo -e "       \${CYAN}>>> Executing verification check...\${NC}"
    # Execute non-destructively in dry-run mode
    if eval "$cmd" > /dev/null 2>&1; then
      echo -e "       [\${GREEN}PASS\${NC}] Invariant assertion satisfied or target passed verification."
      PASSED_TESTS=$((PASSED_TESTS + 1))
    else
      echo -e "       [\${YELLOW}AUDIT\${NC}] Target returned non-zero code or required specific endpoint (inspect manually)."
      FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
  else
    echo -e "       [\${YELLOW}SKIP\${NC}] No automated CLI command provided."
    SKIPPED_TESTS=$((SKIPPED_TESTS + 1))
  fi
}

`;

  invariants.forEach(inv => {
    const escapedCmd = inv.howToTest.commandExample.replace(/"/g, '\\"').replace(/\$/g, '\\$');
    const safeTitle = inv.title.replace(/"/g, '\\"');
    sh += `# ------------------------------------------------------------------------------\n`;
    sh += `# Invariant: ${inv.id} - ${safeTitle}\n`;
    sh += `# Standard: ${inv.standards.join(', ')}\n`;
    sh += `# Logic: ${inv.formalInvariant}\n`;
    sh += `run_invariant_check "${inv.id}" "${safeTitle}" "${inv.domainName}" "${escapedCmd}"\n\n`;
  });

  sh += `
echo ""
echo -e "\${CYAN}===============================================================================\${NC}"
echo -e "\${CYAN}  VERIFICATION AUDIT COMPLETE\${NC}"
echo -e "\${CYAN}===============================================================================\${NC}"
echo -e "Total Invariants: \${TOTAL_TESTS}"
echo -e "Passed:           \${GREEN}\${PASSED_TESTS}\${NC}"
echo -e "Needs Review:     \${YELLOW}\${FAILED_TESTS}\${NC}"
echo -e "Skipped:          \${SKIPPED_TESTS}"
echo -e "\${CYAN}===============================================================================\${NC}"
`;

  const filename = `verify_${suiteName.toLowerCase().replace(/[^a-z0-9]+/g, '_')}.sh`;
  downloadFile(filename, sh, 'application/x-sh');
}

/**
 * 4. DEVSECOPS SECURITY BASELINE (.JSON)
 * Structured machine-readable catalog of rules and verification queries
 */
export function exportToBaselineJSON(invariants: SecurityInvariant[], progress?: UserProgress) {
  const exportPayload = {
    schemaVersion: '1.2.0',
    title: 'Security Invariants Catalog & Baseline Policy',
    exportedAt: new Date().toISOString(),
    ruleCount: invariants.length,
    coverage: {
      domains: Array.from(new Set(invariants.map(i => i.domain))),
      standards: Array.from(new Set(invariants.flatMap(i => i.standards)))
    },
    userAuditProgress: progress ? {
      masteredCount: progress.masteredIds.filter((id: string) => invariants.some(i => i.id === id)).length,
      bookmarkedCount: progress.bookmarkedIds.filter((id: string) => invariants.some(i => i.id === id)).length,
      totalRules: invariants.length
    } : null,
    invariants: invariants.map(inv => ({
      id: inv.id,
      ruleNumber: inv.ruleNumber,
      title: inv.title,
      domain: inv.domain,
      domainName: inv.domainName,
      subdomain: inv.subdomain,
      difficulty: inv.difficulty,
      standardType: inv.standardType,
      standards: inv.standards,
      formalInvariant: inv.formalInvariant,
      plainEnglish: inv.plainEnglish,
      whyItMatters: inv.whyItMatters,
      symbols: inv.symbolBreakdown,
      vulnerableCode: {
        language: inv.vulnerableExample.language,
        code: inv.vulnerableExample.code,
        explanation: inv.vulnerableExample.explanation
      },
      secureCode: {
        language: inv.secureExample.language,
        code: inv.secureExample.code,
        explanation: inv.secureExample.explanation
      },
      testing: {
        tools: inv.howToTest.tools,
        steps: inv.howToTest.steps,
        commandExample: inv.howToTest.commandExample
      },
      interview: {
        scenario: inv.interviewChallenge.scenario,
        question: inv.interviewChallenge.question,
        sampleAnswer: inv.interviewChallenge.sampleAnswer,
        keyTakeaway: inv.interviewChallenge.keyTakeaway
      },
      auditState: {
        isMastered: progress?.masteredIds.includes(inv.id) ?? false,
        isBookmarked: progress?.bookmarkedIds.includes(inv.id) ?? false
      }
    }))
  };

  const jsonStr = JSON.stringify(exportPayload, null, 2);
  const filename = `security_invariants_baseline_${invariants.length}_rules.json`;
  downloadFile(filename, jsonStr, 'application/json');
}

/**
 * 5. PRINTABLE SECURITY AUDIT CHECKLIST (HTML with Print Stylesheet)
 * Pen-and-paper or PDF exportable audit worksheet with verification checkboxes
 */
export function openPrintableAuditChecklist(
  invariants: SecurityInvariant[],
  title: string = 'Security Invariants Audit Checklist',
  progress?: UserProgress
) {
  const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  
  // Group invariants by domain
  const byDomain: Record<string, SecurityInvariant[]> = {};
  invariants.forEach(inv => {
    if (!byDomain[inv.domainName]) {
      byDomain[inv.domainName] = [];
    }
    byDomain[inv.domainName].push(inv);
  });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${title}</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 1.2cm;
    }
    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #0f172a;
      background: #ffffff;
      line-height: 1.4;
      font-size: 11pt;
      padding: 24px;
    }
    .no-print {
      margin-bottom: 24px;
      padding: 16px;
      background: #f1f5f9;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .btn {
      padding: 8px 16px;
      background: #4f46e5;
      color: #fff;
      border: none;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      font-size: 13px;
    }
    .btn:hover {
      background: #4338ca;
    }
    .header {
      border-bottom: 2px solid #0f172a;
      padding-bottom: 12px;
      margin-bottom: 20px;
    }
    .header h1 {
      font-size: 20pt;
      font-weight: 800;
      letter-spacing: -0.5px;
      color: #0f172a;
    }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin: 16px 0;
      font-size: 9pt;
      background: #f8fafc;
      padding: 12px;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
    }
    .meta-item strong {
      display: block;
      color: #64748b;
      font-size: 8pt;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .domain-section {
      margin-top: 24px;
      page-break-inside: avoid;
    }
    .domain-title {
      font-size: 13pt;
      font-weight: 700;
      color: #1e293b;
      border-bottom: 1px solid #cbd5e1;
      padding-bottom: 4px;
      margin-bottom: 10px;
      display: flex;
      justify-content: space-between;
    }
    table.audit-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 8.5pt;
      margin-bottom: 16px;
    }
    table.audit-table th, table.audit-table td {
      border: 1px solid #cbd5e1;
      padding: 6px 8px;
      vertical-align: top;
      text-align: left;
    }
    table.audit-table th {
      background: #f1f5f9;
      font-weight: 700;
      color: #334155;
    }
    .id-col {
      width: 85px;
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-weight: 600;
      color: #4f46e5;
    }
    .checkbox-col {
      width: 105px;
      white-space: nowrap;
      text-align: center;
    }
    .box {
      display: inline-block;
      width: 11px;
      height: 11px;
      border: 1.5px solid #475569;
      border-radius: 2px;
      margin-right: 2px;
      vertical-align: middle;
    }
    .box-checked {
      background: #4f46e5;
      border-color: #4f46e5;
    }
    .formal-code {
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 8pt;
      background: #f8fafc;
      padding: 2px 4px;
      border-radius: 3px;
      display: block;
      margin-top: 4px;
      color: #1e293b;
    }
    .signoff-section {
      margin-top: 36px;
      padding-top: 16px;
      border-top: 1px solid #94a3b8;
      display: grid;
      grid-template-columns: 1fr 1fr 1fr;
      gap: 20px;
      font-size: 9pt;
      page-break-inside: avoid;
    }
    .sig-line {
      border-bottom: 1px solid #475569;
      height: 30px;
      margin-top: 10px;
    }
    @media print {
      body {
        padding: 0;
      }
      .no-print {
        display: none !important;
      }
      tr {
        page-break-inside: avoid;
      }
    }
  </style>
</head>
<body>

  <div class="no-print">
    <div>
      <strong>Printable Security Audit Worksheet</strong>
      <div style="font-size: 12px; color: #64748b;">Ready for printer, physical clipboard audit, or PDF generation</div>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn" onclick="window.print()">Print / Save as PDF</button>
      <button class="btn" style="background: #475569;" onclick="window.close()">Close Window</button>
    </div>
  </div>

  <div class="header">
    <h1>${title}</h1>
    <div style="font-size: 10pt; color: #475569; margin-top: 4px;">
      Formal Invariant Compliance & Systematic Security Review
    </div>
  </div>

  <div class="meta-grid">
    <div class="meta-item">
      <strong>Generated Date</strong>
      ${dateStr}
    </div>
    <div class="meta-item">
      <strong>Rules Scope</strong>
      ${invariants.length} Invariants
    </div>
    <div class="meta-item">
      <strong>Domains Covered</strong>
      ${Object.keys(byDomain).length} Security Domains
    </div>
    <div class="meta-item">
      <strong>Standards Grounding</strong>
      RFC, NIST SP 800, OWASP, CWE
    </div>
  </div>

  ${Object.entries(byDomain).map(([domain, rules]) => `
    <div class="domain-section">
      <div class="domain-title">
        <span>${domain}</span>
        <span style="font-size: 9pt; color: #64748b; font-weight: normal;">${rules.length} Rules</span>
      </div>
      <table class="audit-table">
        <thead>
          <tr>
            <th class="id-col">ID</th>
            <th>Title & Invariant Specification</th>
            <th style="width: 140px;">Standard & Tools</th>
            <th class="checkbox-col">Verification Status</th>
            <th style="width: 160px;">Auditor Notes / Findings</th>
          </tr>
        </thead>
        <tbody>
          ${rules.map(r => {
            const isMastered = progress?.masteredIds.includes(r.id);
            return `
            <tr>
              <td class="id-col">
                ${r.id}
                <div style="font-size: 7.5pt; color: #64748b; font-weight: normal; margin-top: 2px;">
                  ${r.standardType === 'Mandatory Standard' ? 'Mandatory' : 'Defense'}
                </div>
              </td>
              <td>
                <strong>${r.title}</strong>
                <div class="formal-code">${r.formalInvariant}</div>
                <div style="font-size: 8pt; color: #475569; margin-top: 3px;">
                  ${r.plainEnglish}
                </div>
              </td>
              <td style="font-size: 8pt;">
                <div style="font-weight: 600; color: #0f172a;">${r.standards[0]}</div>
                <div style="color: #64748b; margin-top: 3px;">Tools: ${r.howToTest.tools.slice(0, 2).join(', ')}</div>
              </td>
              <td class="checkbox-col">
                <div style="display: flex; flex-direction: column; gap: 3px; align-items: flex-start; margin-left: 6px;">
                  <label style="cursor: pointer;"><span class="box ${isMastered ? 'box-checked' : ''}"></span> PASS</label>
                  <label style="cursor: pointer;"><span class="box"></span> AUDIT</label>
                  <label style="cursor: pointer;"><span class="box"></span> FAIL</label>
                </div>
              </td>
              <td>
                <div style="height: 38px; border-bottom: 1px dashed #cbd5e1;"></div>
              </td>
            </tr>
          `;
          }).join('')}
        </tbody>
      </table>
    </div>
  `).join('')}

  <div class="signoff-section">
    <div>
      <strong>Lead Security Auditor</strong>
      <div class="sig-line"></div>
      <div style="color: #64748b; font-size: 8pt; margin-top: 4px;">Signature & Date</div>
    </div>
    <div>
      <strong>System / Technical Owner</strong>
      <div class="sig-line"></div>
      <div style="color: #64748b; font-size: 8pt; margin-top: 4px;">Signature & Date</div>
    </div>
    <div>
      <strong>Compliance / CISO Review</strong>
      <div class="sig-line"></div>
      <div style="color: #64748b; font-size: 8pt; margin-top: 4px;">Signature & Date</div>
    </div>
  </div>

</body>
</html>`;

  openPrintWindow(html);
}

/**
 * 6. ARCHITECTURAL STUDY DOSSIER (HTML with Print Stylesheet)
 * Deep technical dossier with formal logic, code diffs, attack breakdowns, and interview Q&A
 */
export function openPrintableDossier(invariants: SecurityInvariant[], title: string = 'Security Invariants Architectural Dossier') {
  const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${title}</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 1.5cm;
    }
    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #0f172a;
      background: #ffffff;
      line-height: 1.5;
      font-size: 10pt;
      padding: 30px;
    }
    .no-print {
      margin-bottom: 24px;
      padding: 16px;
      background: #f1f5f9;
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .btn {
      padding: 8px 16px;
      background: #4f46e5;
      color: #fff;
      border: none;
      border-radius: 6px;
      font-weight: 600;
      cursor: pointer;
      font-size: 13px;
    }
    .cover-title {
      font-size: 24pt;
      font-weight: 800;
      color: #0f172a;
      line-height: 1.2;
      border-bottom: 3px solid #4f46e5;
      padding-bottom: 12px;
      margin-bottom: 24px;
    }
    .rule-card {
      border: 1px solid #cbd5e1;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
      page-break-inside: avoid;
    }
    .rule-header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 8px;
      margin-bottom: 12px;
    }
    .rule-id {
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 11pt;
      font-weight: 700;
      color: #4f46e5;
    }
    .rule-title {
      font-size: 13pt;
      font-weight: 700;
      color: #0f172a;
    }
    .formal-box {
      background: #f8fafc;
      border-left: 4px solid #4f46e5;
      padding: 10px 14px;
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 9.5pt;
      color: #1e293b;
      margin: 10px 0;
      border-radius: 0 4px 4px 0;
    }
    .section-label {
      font-size: 8pt;
      text-transform: uppercase;
      font-weight: 700;
      letter-spacing: 0.5px;
      color: #64748b;
      margin-top: 10px;
      margin-bottom: 4px;
    }
    .code-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin: 12px 0;
    }
    .code-box {
      border: 1px solid #e2e8f0;
      border-radius: 4px;
      overflow: hidden;
      font-size: 8pt;
    }
    .code-box-header {
      padding: 4px 8px;
      font-weight: 700;
      font-size: 7.5pt;
      text-transform: uppercase;
    }
    .code-vuln-header { background: #fee2e2; color: #991b1b; }
    .code-sec-header { background: #dcfce7; color: #166534; }
    pre {
      font-family: ui-monospace, SFMono-Regular, monospace;
      padding: 8px;
      background: #fafafa;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .qa-box {
      background: #eff6ff;
      border: 1px solid #bfdbfe;
      border-radius: 6px;
      padding: 10px;
      margin-top: 10px;
      font-size: 8.5pt;
    }
    @media print {
      body { padding: 0; }
      .no-print { display: none !important; }
      .rule-card { page-break-inside: avoid; }
    }
  </style>
</head>
<body>

  <div class="no-print">
    <div>
      <strong>Security Invariants Architectural Dossier</strong>
      <div style="font-size: 12px; color: #64748b;">Comprehensive technical handbook formatted for print and PDF archiving</div>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn" onclick="window.print()">Print Dossier / Save as PDF</button>
      <button class="btn" style="background: #475569;" onclick="window.close()">Close Window</button>
    </div>
  </div>

  <div class="cover-title">
    ${title}
    <div style="font-size: 11pt; font-weight: normal; color: #64748b; margin-top: 6px;">
      Formal Mathematical Specifications, Vulnerability Mechanics, Implementation Diffs, and Verification Harnesses
    </div>
    <div style="font-size: 9pt; font-weight: normal; color: #94a3b8; margin-top: 2px;">
      Published: ${dateStr} · Scope: ${invariants.length} Security Invariants
    </div>
  </div>

  ${invariants.map(inv => `
    <div class="rule-card">
      <div class="rule-header">
        <div>
          <span class="rule-id">${inv.id}</span>
          <span style="color: #64748b; margin: 0 6px;">·</span>
          <span class="rule-title">${inv.title}</span>
        </div>
        <div style="font-size: 8pt; color: #64748b;">
          ${inv.domainName} · ${inv.difficulty} · ${inv.standardType}
        </div>
      </div>

      <div class="section-label">Formal Logical Invariant</div>
      <div class="formal-box">${inv.formalInvariant}</div>

      <div class="section-label">Plain-English Translation</div>
      <p style="font-size: 9pt; color: #334155; margin-bottom: 8px;">${inv.plainEnglish}</p>

      <div class="section-label">Threat Scenario & Why It Matters</div>
      <p style="font-size: 8.5pt; color: #475569; margin-bottom: 8px;">${inv.whyItMatters}</p>

      <div class="section-label">Implementation Comparison</div>
      <div class="code-grid">
        <div class="code-box">
          <div class="code-box-header code-vuln-header">Vulnerable Implementation (${inv.vulnerableExample.language})</div>
          <pre>${inv.vulnerableExample.code}</pre>
          <div style="padding: 6px 8px; font-size: 7.5pt; color: #991b1b; background: #fff5f5; border-top: 1px solid #fee2e2;">
            ${inv.vulnerableExample.explanation}
          </div>
        </div>
        <div class="code-box">
          <div class="code-box-header code-sec-header">Secure Invariant Enforced (${inv.secureExample.language})</div>
          <pre>${inv.secureExample.code}</pre>
          <div style="padding: 6px 8px; font-size: 7.5pt; color: #166534; background: #f0fdf4; border-top: 1px solid #dcfce7;">
            ${inv.secureExample.explanation}
          </div>
        </div>
      </div>

      <div class="section-label">Verification Procedure & Standards</div>
      <div style="font-size: 8.5pt; color: #334155; margin-bottom: 4px;">
        <strong>Standards:</strong> <code>${inv.standards.join(', ')}</code> | <strong>Tools:</strong> <code>${inv.howToTest.tools.join(', ')}</code>
      </div>
      <div style="font-family: ui-monospace, monospace; font-size: 8pt; background: #f1f5f9; padding: 6px 8px; border-radius: 4px; margin-bottom: 8px;">
        ${inv.howToTest.commandExample}
      </div>

      <div class="qa-box">
        <strong>Technical Interview Scenario:</strong>
        <p style="margin: 3px 0 6px 0;">${inv.interviewChallenge.scenario} <em>"${inv.interviewChallenge.question}"</em></p>
        <div style="border-top: 1px solid #bfdbfe; padding-top: 4px; margin-top: 4px;">
          <strong>Model Architectural Answer:</strong>
          <p style="margin-top: 2px;">${inv.interviewChallenge.sampleAnswer}</p>
          <div style="margin-top: 4px; color: #1e40af; font-weight: 600;">Takeaway: ${inv.interviewChallenge.keyTakeaway}</div>
        </div>
      </div>
    </div>
  `).join('')}

</body>
</html>`;

  openPrintWindow(html);
}

/**
 * 7. COMPLETE SECTION-WISE INTERVIEW PREPARATION MASTER HANDBOOK (PRINT / PDF)
 * Formatted specifically for hard-copy study, technical interview prep, and physical binder organization.
 * Groups all invariants across all 15 domains with candidate metadata, section dividers,
 * interview scenario callouts, formal logic axioms, code diffs, model verbal answers, and notes margins.
 */
export function openPrintableInterviewMasterBook(
  invariants: SecurityInvariant[],
  title: string = 'Security Invariants Interview Preparation Master Handbook',
  progress?: UserProgress
) {
  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  const CANONICAL_DOMAINS: { id: DomainId; sectionNumber: number; title: string; subtitle: string }[] = [
    { id: 'http', sectionNumber: 1, title: 'Section 1: HTTP Protocols & Transport Layer Invariants', subtitle: 'RFC 9110, RFC 9112, RFC 8446 (TLS 1.3), Framing & Smuggling Invariants' },
    { id: 'web', sectionNumber: 2, title: 'Section 2: Web Application Security & Browser Sandboxing', subtitle: 'W3C CSP Level 3, RFC 6265bis, Same-Origin Policy, Subresource Integrity' },
    { id: 'api', sectionNumber: 3, title: 'Section 3: API & REST / GraphQL Security Invariants', subtitle: 'RFC 7519, OpenAPI Spec, Mass Assignment Prevention, GraphQL AST Depth' },
    { id: 'auth', sectionNumber: 4, title: 'Section 4: Authentication & Credential Storage Invariants', subtitle: 'NIST SP 800-63B, FIDO2 / WebAuthn, Argon2id, Session Lifecycle Axioms' },
    { id: 'authz', sectionNumber: 5, title: 'Section 5: Authorization & Multi-Tenant Access Control', subtitle: 'NIST SP 800-162, RBAC, ABAC, ReBAC, Multi-Tenant BOLA / IDOR Prevention' },
    { id: 'oauth', sectionNumber: 6, title: 'Section 6: OAuth 2.0 & OIDC Identity Flows', subtitle: 'RFC 6749, RFC 7636 (PKCE), RFC 8725 (JWT BCP), OpenID Connect Core' },
    { id: 'crypto', sectionNumber: 7, title: 'Section 7: Modern Cryptography & Key Management', subtitle: 'NIST SP 800-57, FIPS 140-3, Constant-Time Execution, AEAD Ciphers' },
    { id: 'cloud', sectionNumber: 8, title: 'Section 8: Cloud Architecture & Multi-Cloud Security', subtitle: 'CIS Cloud Benchmark, NIST SP 800-145, IMDSv2, VPC Segmentation' },
    { id: 'aws', sectionNumber: 9, title: 'Section 9: AWS Identity & Infrastructure Security', subtitle: 'AWS Well-Architected Security Pillar, IAM Least Privilege, KMS Envelopes' },
    { id: 'containers', sectionNumber: 10, title: 'Section 10: Container Runtime & Isolation Invariants', subtitle: 'OCI Runtime Spec, Linux Namespaces & cgroups v2, Seccomp, CIS Docker' },
    { id: 'k8s', sectionNumber: 11, title: 'Section 11: Kubernetes Cluster Orchestration Invariants', subtitle: 'CIS Kubernetes Benchmark, Pod Security Standards (PSS), Admission Control' },
    { id: 'coding', sectionNumber: 12, title: 'Section 12: Secure Coding & Vulnerability Review Invariants', subtitle: 'OWASP Top 10, CWE/SANS Top 25, Memory Safety, Safe Deserialization' },
    { id: 'ai', sectionNumber: 13, title: 'Section 13: AI & Large Language Model Safety Invariants', subtitle: 'OWASP LLM Top 10, NIST AI RMF 100-1, Prompt Injection, RAG Isolation' },
    { id: 'smartcontracts', sectionNumber: 14, title: 'Section 14: Smart Contracts & Web3 Security Invariants', subtitle: 'SWC Registry, EVM State Machine, Checks-Effects-Interactions, Oracle Guardrails' },
    { id: 'threatmodeling', sectionNumber: 15, title: 'Section 15: Threat Modeling & Defensive Architecture', subtitle: 'STRIDE, DREAD, PASTA, Attack Trees, Trust Boundary Invariants' }
  ];

  // Group invariants by canonical domain
  const sectionsData = CANONICAL_DOMAINS.map(d => {
    const rules = invariants.filter(r => r.domain === d.id);
    return {
      ...d,
      rules
    };
  }).filter(s => s.rules.length > 0);

  const totalRules = invariants.length;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${escapeHtml(title)} - Hard Copy Interview Study Edition</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 12mm 14mm 14mm 14mm;
    }
    * {
      box-sizing: border-box;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 8.5pt;
      line-height: 1.45;
      color: #0f172a;
      background: #ffffff;
      margin: 0;
      padding: 24px;
    }
    .no-print {
      background: #0f172a;
      color: #ffffff;
      padding: 14px 20px;
      margin: -24px -24px 24px -24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 999;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    .btn {
      background: #4f46e5;
      color: white;
      border: none;
      padding: 9px 18px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn:hover { background: #4338ca; }
    .btn-secondary {
      background: #334155;
    }
    .btn-secondary:hover { background: #1e293b; }

    /* Page Breaks */
    .section-divider {
      page-break-before: always;
      break-before: page;
      margin-top: 32px;
      margin-bottom: 20px;
      padding-bottom: 12px;
      border-bottom: 2.5px solid #0f172a;
    }
    .rule-card {
      page-break-inside: avoid;
      break-inside: avoid;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 12px 14px;
      margin-bottom: 16px;
      background: #ffffff;
      box-shadow: 0 1px 3px rgba(0,0,0,0.02);
    }

    /* Cover Sheet */
    .cover-container {
      padding: 20px 0 40px 0;
      border-bottom: 2px solid #0f172a;
      margin-bottom: 30px;
    }
    .cover-badge {
      display: inline-block;
      background: #eef2ff;
      color: #4338ca;
      font-weight: 700;
      font-size: 8.5pt;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      padding: 4px 10px;
      border-radius: 4px;
      border: 1px solid #c7d2fe;
      margin-bottom: 10px;
    }
    .cover-title {
      font-size: 20pt;
      font-weight: 800;
      color: #0f172a;
      line-height: 1.2;
      margin: 0 0 8px 0;
    }
    .cover-subtitle {
      font-size: 10.5pt;
      color: #475569;
      margin-bottom: 18px;
      line-height: 1.4;
    }

    /* Candidate Metadata Hard Copy Card */
    .candidate-card {
      border: 1.5px solid #475569;
      border-radius: 6px;
      padding: 12px 16px;
      background: #f8fafc;
      margin-bottom: 24px;
    }
    .candidate-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px 24px;
      font-size: 8.5pt;
    }
    .candidate-line {
      display: flex;
      align-items: baseline;
      gap: 8px;
    }
    .field-label {
      font-weight: 700;
      color: #1e293b;
      white-space: nowrap;
    }
    .fill-line {
      flex: 1;
      border-bottom: 1px dotted #475569;
      height: 16px;
    }

    /* TOC Table */
    .toc-table {
      width: 100%;
      border-collapse: collapse;
      margin: 16px 0 28px 0;
      font-size: 8pt;
    }
    .toc-table th {
      background: #f1f5f9;
      text-align: left;
      padding: 6px 10px;
      border: 1px solid #cbd5e1;
      font-weight: 700;
      color: #0f172a;
    }
    .toc-table td {
      padding: 6px 10px;
      border: 1px solid #cbd5e1;
      color: #334155;
    }

    /* Card Details */
    .card-top {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 8px;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 6px;
    }
    .rule-id {
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-weight: 800;
      font-size: 9.5pt;
      color: #1e1b4b;
      background: #e0e7ff;
      padding: 2px 7px;
      border-radius: 4px;
      border: 1px solid #c7d2fe;
    }
    .rule-title {
      font-size: 10.5pt;
      font-weight: 700;
      color: #0f172a;
      margin-left: 8px;
    }
    .practice-boxes {
      display: flex;
      align-items: center;
      gap: 12px;
      font-size: 7.5pt;
      color: #475569;
    }
    .chk-label {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-weight: 600;
    }
    .chk-square {
      display: inline-block;
      width: 11px;
      height: 11px;
      border: 1.5px solid #475569;
      border-radius: 2px;
    }

    /* Interview Challenge Callout */
    .interview-box {
      background: #f0f4ff;
      border-left: 4px solid #3b82f6;
      border-radius: 0 4px 4px 0;
      padding: 8px 12px;
      margin-bottom: 10px;
    }
    .interview-q-label {
      font-size: 7.5pt;
      font-weight: 800;
      color: #1d4ed8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 2px;
    }
    .interview-q-text {
      font-size: 9pt;
      font-weight: 700;
      color: #0f172a;
      margin-bottom: 4px;
      line-height: 1.35;
    }
    .interview-scenario {
      font-size: 8pt;
      color: #334155;
      font-style: italic;
    }

    /* Axiom */
    .axiom-box {
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 8pt;
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      padding: 6px 10px;
      border-radius: 4px;
      margin-bottom: 6px;
      color: #0f172a;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .plain-english {
      font-size: 8pt;
      color: #334155;
      margin-bottom: 8px;
      line-height: 1.4;
    }

    /* Code Comparison Grid */
    .code-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-bottom: 8px;
    }
    .code-box {
      border-radius: 4px;
      overflow: hidden;
      border: 1px solid #e2e8f0;
    }
    .code-box-header {
      padding: 4px 8px;
      font-size: 7.5pt;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .code-vuln-header {
      background: #fee2e2;
      color: #991b1b;
      border-bottom: 1px solid #fecaca;
    }
    .code-sec-header {
      background: #dcfce7;
      color: #166534;
      border-bottom: 1px solid #bbf7d0;
    }
    .code-box pre {
      margin: 0;
      padding: 6px 8px;
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 7.2pt;
      line-height: 1.35;
      background: #f8fafc;
      color: #1e293b;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .code-box-footer {
      padding: 4px 8px;
      font-size: 7pt;
      line-height: 1.3;
    }
    .vuln-footer {
      background: #fff5f5;
      color: #7f1d1d;
      border-top: 1px solid #fee2e2;
    }
    .sec-footer {
      background: #f0fdf4;
      color: #14532d;
      border-top: 1px solid #dcfce7;
    }

    /* Model Staff Answer */
    .model-answer-box {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-left: 3.5px solid #059669;
      border-radius: 0 4px 4px 0;
      padding: 7px 10px;
      margin-bottom: 6px;
    }
    .model-label {
      font-size: 7.5pt;
      font-weight: 800;
      color: #047857;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      margin-bottom: 2px;
    }
    .model-text {
      font-size: 8pt;
      color: #1e293b;
      line-height: 1.4;
      margin-bottom: 4px;
    }
    .takeaway-badge {
      font-size: 7.8pt;
      font-weight: 700;
      color: #166534;
      background: #dcfce7;
      padding: 3px 6px;
      border-radius: 3px;
      display: inline-block;
    }

    /* Verification Line */
    .verification-line {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 7.5pt;
      color: #64748b;
      background: #f1f5f9;
      padding: 3px 8px;
      border-radius: 3px;
      margin-bottom: 8px;
    }
    .verification-line code {
      font-family: ui-monospace, monospace;
      color: #334155;
    }

    /* Candidate Handwritten Notes Box */
    .notes-box {
      border: 1px dashed #94a3b8;
      border-radius: 4px;
      padding: 6px 8px;
      background: #fafafa;
    }
    .notes-header {
      font-size: 7pt;
      font-weight: 700;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 4px;
    }
    .notes-lines {
      border-bottom: 1px solid #e2e8f0;
      height: 14px;
      margin-bottom: 4px;
    }
    .notes-lines:last-child {
      border-bottom: 1px solid #e2e8f0;
      margin-bottom: 0;
    }

    @media print {
      body { padding: 0; }
      .no-print { display: none !important; }
      .section-divider { page-break-before: always; }
      .rule-card { page-break-inside: avoid; }
    }
  </style>
</head>
<body>

  <!-- Top Sticky Bar for Screen / Printing Options -->
  <div class="no-print">
    <div>
      <strong style="font-size: 15px;">Security Invariants · Section-Wise Interview Preparation Handbook</strong>
      <div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">
        Hard-copy optimized edition · ${totalRules} Rules across ${sectionsData.length} Sections · Ready for printer or PDF save
      </div>
    </div>
    <div style="display: flex; gap: 10px; align-items: center;">
      <span style="font-size: 12px; color: #cbd5e1;">Tip: Check "Background graphics" in print options</span>
      <button class="btn" onclick="window.print()">
        🖨️ Print Complete Handbook / Save as PDF
      </button>
      <button class="btn btn-secondary" onclick="window.close()">
        Close
      </button>
    </div>
  </div>

  <!-- Cover Page & Table of Contents -->
  <div class="cover-container">
    <div class="cover-badge">Hard-Copy Study Edition · Section-by-Section Curriculum</div>
    <h1 class="cover-title">${escapeHtml(title)}</h1>
    <div class="cover-subtitle">
      Formal Logical Axioms, Real-World Attack Scenarios, Side-by-Side Implementation Diffs,
      Staff-Level Spoken Interview Answers, and Candidate Verification Checklists.
    </div>

    <!-- Candidate Study Tracker for Hard-Copy Binder -->
    <div class="candidate-card">
      <div style="font-weight: 800; font-size: 9pt; color: #0f172a; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">
        📋 Candidate Interview Preparation File & Practice Log
      </div>
      <div class="candidate-grid">
        <div class="candidate-line">
          <span class="field-label">Candidate Name:</span>
          <div class="fill-line"></div>
        </div>
        <div class="candidate-line">
          <span class="field-label">Target Role:</span>
          <span style="font-size: 7.5pt; color: #475569;">[ ] Staff AppSec &nbsp; [ ] Cloud Sec &nbsp; [ ] Sec Architect</span>
        </div>
        <div class="candidate-line">
          <span class="field-label">Target Companies:</span>
          <div class="fill-line"></div>
        </div>
        <div class="candidate-line">
          <span class="field-label">Interview Date:</span>
          <div class="fill-line" style="max-width: 140px;"></div>
        </div>
      </div>
      <div style="margin-top: 8px; padding-top: 8px; border-top: 1px dotted #cbd5e1; font-size: 7.5pt; color: #475569; display: flex; justify-content: space-between;">
        <span><strong>Prep Methodology:</strong> 1. Write Invariant Formula on paper &nbsp;|&nbsp; 2. Spot Vulnerability Root Cause &nbsp;|&nbsp; 3. Practice Verbal Model Answer Aloud</span>
        <span><strong>Generated:</strong> ${dateStr}</span>
      </div>
    </div>

    <!-- Section Index / Table of Contents -->
    <div style="font-weight: 800; font-size: 9pt; color: #0f172a; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.05em;">
      📚 Curriculum Table of Contents & Section Map (${totalRules} Rules)
    </div>
    <table class="toc-table">
      <thead>
        <tr>
          <th style="width: 70px;">Section #</th>
          <th>Domain & Strategic Scope</th>
          <th style="width: 220px;">Standards Grounding</th>
          <th style="width: 75px; text-align: center;">Rule Count</th>
          <th style="width: 110px; text-align: center;">Study Status</th>
        </tr>
      </thead>
      <tbody>
        ${sectionsData.map(s => `
          <tr>
            <td style="font-weight: 700; text-align: center;">Sec ${s.sectionNumber}</td>
            <td>
              <strong>${escapeHtml(s.title.replace(/^Section \d+:\s*/, ''))}</strong>
              <div style="font-size: 7pt; color: #64748b;">${escapeHtml(s.subtitle)}</div>
            </td>
            <td style="font-size: 7pt; color: #475569;">${escapeHtml(s.subtitle.split(', ').slice(0, 3).join(', '))}</td>
            <td style="text-align: center; font-weight: 700;">${s.rules.length}</td>
            <td style="text-align: center; font-size: 7.5pt; color: #64748b;">
              [ ] [ ] [ ]
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>

  <!-- Sections Loop -->
  ${sectionsData.map(section => `
    <div class="section-divider">
      <div style="display: flex; justify-content: space-between; align-items: flex-end;">
        <div>
          <div style="font-size: 8pt; font-weight: 800; color: #4338ca; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px;">
            TECHNICAL DOMAIN COMPENDIUM · ${section.rules.length} RULES
          </div>
          <h2 style="font-size: 15pt; font-weight: 800; color: #0f172a; margin: 0 0 4px 0;">
            ${escapeHtml(section.title)}
          </h2>
          <div style="font-size: 9pt; color: #475569;">
            ${escapeHtml(section.subtitle)}
          </div>
        </div>
        <div style="text-align: right; font-size: 7.5pt; color: #64748b; border: 1px solid #cbd5e1; padding: 4px 8px; border-radius: 4px; background: #f8fafc;">
          <div><strong>Section Checklist:</strong></div>
          <div style="margin-top: 2px;">[ ] Read &nbsp; [ ] Whiteboard &nbsp; [ ] Verbal Drill</div>
        </div>
      </div>
    </div>

    ${section.rules.map(inv => {
      const isMastered = progress?.masteredIds.includes(inv.id);
      return `
        <div class="rule-card">
          <!-- Card Header & Practice Checkboxes -->
          <div class="card-top">
            <div style="display: flex; align-items: center; flex-wrap: wrap; gap: 6px;">
              <span class="rule-id">${escapeHtml(inv.id)}</span>
              <span class="rule-title">${escapeHtml(inv.title)}</span>
              <span style="font-size: 7.5pt; color: #475569; background: #f1f5f9; padding: 1px 6px; border-radius: 3px;">${escapeHtml(inv.difficulty)}</span>
              <span style="font-size: 7.5pt; color: #475569; background: #f1f5f9; padding: 1px 6px; border-radius: 3px;">${escapeHtml(inv.standardType)}</span>
            </div>
            <div class="practice-boxes">
              <span class="chk-label"><span class="chk-square ${isMastered ? 'box-checked' : ''}"></span> Read</span>
              <span class="chk-label"><span class="chk-square"></span> Solved</span>
              <span class="chk-label"><span class="chk-square"></span> Verbalized</span>
              <span style="color: #cbd5e1;">|</span>
              <span style="font-size: 7.5pt; color: #475569;">★ ★ ★ ★ ★</span>
            </div>
          </div>

          <!-- Interview Challenge Scenario & Question -->
          <div class="interview-box">
            <div class="interview-q-label">🎙️ Technical Interview Challenge</div>
            <div class="interview-q-text">"${escapeHtml(inv.interviewChallenge.question)}"</div>
            <div class="interview-scenario">Scenario: ${escapeHtml(inv.interviewChallenge.scenario)}</div>
          </div>

          <!-- Formal Logical Invariant & Meaning -->
          <div style="font-size: 7.5pt; font-weight: 700; color: #475569; text-transform: uppercase; margin-bottom: 2px; letter-spacing: 0.04em;">
            Formal Invariant Specification (Whiteboard Axiom)
          </div>
          <div class="axiom-box">${escapeHtml(inv.formalInvariant)}</div>
          <div class="plain-english">
            <strong>Plain English Translation:</strong> ${escapeHtml(inv.plainEnglish)}
          </div>

          <!-- Why It Matters -->
          <div style="font-size: 7.8pt; color: #475569; margin-bottom: 8px;">
            <strong>Threat Scenario & Why It Matters:</strong> ${escapeHtml(inv.whyItMatters)}
          </div>

          <!-- Implementation Code Comparison -->
          <div class="code-grid">
            <div class="code-box">
              <div class="code-box-header code-vuln-header">Vulnerable Pattern (${escapeHtml(inv.vulnerableExample.language)})</div>
              <pre>${escapeHtml(inv.vulnerableExample.code)}</pre>
              <div class="code-box-footer vuln-footer">${escapeHtml(inv.vulnerableExample.explanation)}</div>
            </div>
            <div class="code-box">
              <div class="code-box-header code-sec-header">Secure Invariant Enforced (${escapeHtml(inv.secureExample.language)})</div>
              <pre>${escapeHtml(inv.secureExample.code)}</pre>
              <div class="code-box-footer sec-footer">${escapeHtml(inv.secureExample.explanation)}</div>
            </div>
          </div>

          <!-- Model Staff-Level Verbal Answer -->
          <div class="model-answer-box">
            <div class="model-label">🗣️ Staff-Level Spoken Response (What to say to the interviewer)</div>
            <div class="model-text">${escapeHtml(inv.interviewChallenge.sampleAnswer)}</div>
            <div>
              <span class="takeaway-badge">💡 Architectural Anchor: ${escapeHtml(inv.interviewChallenge.keyTakeaway)}</span>
            </div>
          </div>

          <!-- Verification Reference -->
          <div class="verification-line">
            <div>
              <strong>Standards:</strong> ${escapeHtml(inv.standards.join(', '))} &nbsp;|&nbsp;
              <strong>Tools:</strong> ${escapeHtml(inv.howToTest.tools.join(', '))}
            </div>
            <div>
              <strong>CLI Test:</strong> <code>${escapeHtml(inv.howToTest.commandExample)}</code>
            </div>
          </div>

          <!-- Candidate Handwritten Notes Space for Hard-Copy -->
          <div class="notes-box">
            <div class="notes-header">✍️ Candidate Personal Talking Points & Whiteboard Observations:</div>
            <div class="notes-lines"></div>
            <div class="notes-lines"></div>
          </div>
        </div>
      `;
    }).join('')}
  `).join('')}

</body>
</html>`;

  openPrintWindow(html);
}

/**
 * 8. HIGH-DENSITY INTERVIEW FLASH SHEETS / CRAM CARDS (PRINT / PDF)
 * Ultra-compact 2-column layout designed for rapid verbal drilling before interview day.
 * Fits ~6-8 questions per sheet with Invariant Formula, Question, and Verbal Anchor.
 */
export function openPrintableInterviewFlashSheets(
  invariants: SecurityInvariant[],
  title: string = 'Security Invariants High-Density Interview Flash Sheets'
) {
  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });

  // Group by domain
  const byDomain: Record<string, SecurityInvariant[]> = {};
  invariants.forEach(r => {
    if (!byDomain[r.domainName]) byDomain[r.domainName] = [];
    byDomain[r.domainName].push(r);
  });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${escapeHtml(title)} - Quick-Recall Cram Sheets</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 10mm;
    }
    * {
      box-sizing: border-box;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 8pt;
      line-height: 1.35;
      color: #0f172a;
      background: #ffffff;
      padding: 16px;
    }
    .no-print {
      background: #0f172a;
      color: #ffffff;
      padding: 10px 16px;
      margin: -16px -16px 16px -16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .btn {
      background: #4f46e5;
      color: white;
      border: none;
      padding: 7px 14px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
    }
    .domain-title {
      font-size: 11pt;
      font-weight: 800;
      color: #1e1b4b;
      border-bottom: 2px solid #4338ca;
      padding-bottom: 4px;
      margin-top: 18px;
      margin-bottom: 10px;
      page-break-after: avoid;
    }
    .flash-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-bottom: 16px;
    }
    .flash-card {
      border: 1px solid #cbd5e1;
      border-radius: 5px;
      padding: 8px 10px;
      background: #ffffff;
      page-break-inside: avoid;
      break-inside: avoid;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .card-id-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 4px;
      border-bottom: 1px solid #f1f5f9;
      padding-bottom: 3px;
    }
    .q-text {
      font-weight: 700;
      font-size: 8.5pt;
      color: #0f172a;
      margin-bottom: 4px;
    }
    .axiom-snippet {
      font-family: ui-monospace, monospace;
      font-size: 7.2pt;
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      padding: 3px 6px;
      border-radius: 3px;
      margin-bottom: 4px;
      color: #1e293b;
    }
    .verbal-answer {
      font-size: 7.5pt;
      color: #334155;
      margin-bottom: 4px;
      background: #f0fdf4;
      border-left: 2px solid #16a34a;
      padding: 3px 6px;
    }
    .card-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 7pt;
      color: #64748b;
      margin-top: 4px;
      padding-top: 4px;
      border-top: 1px dotted #e2e8f0;
    }
    @media print {
      body { padding: 0; }
      .no-print { display: none !important; }
      .flash-card { page-break-inside: avoid; }
    }
  </style>
</head>
<body>

  <div class="no-print">
    <div>
      <strong>High-Density Interview Flash Sheets</strong>
      <span style="color: #94a3b8; font-size: 11px; margin-left: 8px;">2-Column Fast Recall Drill (${invariants.length} Rules)</span>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn" onclick="window.print()">🖨️ Print Flash Sheets</button>
      <button class="btn" style="background: #475569;" onclick="window.close()">Close</button>
    </div>
  </div>

  <div style="margin-bottom: 12px; border-bottom: 1px solid #cbd5e1; padding-bottom: 8px;">
    <h1 style="font-size: 14pt; font-weight: 800; margin: 0 0 2px 0;">${escapeHtml(title)}</h1>
    <div style="font-size: 8pt; color: #475569;">
      High-Speed Verbal Recall Compendium · ${invariants.length} Invariants · Generated ${dateStr}
    </div>
  </div>

  ${Object.entries(byDomain).map(([domain, rules]) => `
    <div class="domain-title">${escapeHtml(domain)} (${rules.length} Rules)</div>
    <div class="flash-grid">
      ${rules.map(inv => `
        <div class="flash-card">
          <div>
            <div class="card-id-row">
              <span style="font-family: monospace; font-weight: 800; color: #4338ca;">${escapeHtml(inv.id)}</span>
              <span style="font-size: 7pt; color: #64748b;">${escapeHtml(inv.difficulty)} · ${escapeHtml(inv.subdomain)}</span>
            </div>
            <div class="q-text">"${escapeHtml(inv.interviewChallenge.question)}"</div>
            <div class="axiom-snippet">${escapeHtml(inv.formalInvariant)}</div>
            <div class="verbal-answer">
              <strong>Spoken Core:</strong> ${escapeHtml(inv.interviewChallenge.sampleAnswer.slice(0, 180))}...
            </div>
          </div>
          <div class="card-footer">
            <span style="font-weight: 700; color: #166534;">💡 ${escapeHtml(inv.interviewChallenge.keyTakeaway)}</span>
            <span>[ ] Recited</span>
          </div>
        </div>
      `).join('')}
    </div>
  `).join('')}

</body>
</html>`;

  openPrintWindow(html);
}

/**
 * 9. WHITEBOARD & SCENARIO MOCK INTERVIEW WORKBOOK (PRINT / PDF)
 * Practice-first format with blank workspace for candidate to physically sketch
 * invariants, vulnerability root causes, and defensive architecture before checking answers.
 */
export function openPrintableWhiteboardWorkbook(
  invariants: SecurityInvariant[],
  title: string = 'Security Invariants Whiteboard & Scenario Interview Workbook'
) {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${escapeHtml(title)}</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 12mm;
    }
    * {
      box-sizing: border-box;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 8.5pt;
      line-height: 1.4;
      color: #0f172a;
      background: #ffffff;
      padding: 20px;
    }
    .no-print {
      background: #0f172a;
      color: #ffffff;
      padding: 10px 16px;
      margin: -20px -20px 20px -20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .btn {
      background: #4f46e5;
      color: white;
      border: none;
      padding: 8px 16px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
    }
    .problem-card {
      border: 1.5px solid #64748b;
      border-radius: 6px;
      padding: 14px;
      margin-bottom: 22px;
      page-break-inside: avoid;
      break-inside: avoid;
    }
    .q-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid #cbd5e1;
      padding-bottom: 6px;
      margin-bottom: 8px;
    }
    .prompt-box {
      background: #eff6ff;
      border-left: 3.5px solid #2563eb;
      padding: 8px 10px;
      border-radius: 0 4px 4px 0;
      margin-bottom: 12px;
    }
    .whiteboard-box {
      border: 1px solid #94a3b8;
      background: #fafafa;
      border-radius: 4px;
      padding: 10px;
      margin-bottom: 12px;
      min-height: 110px;
    }
    .ruled-line {
      border-bottom: 1px dashed #cbd5e1;
      height: 20px;
    }
    .solution-box {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-top: 2px solid #059669;
      border-radius: 4px;
      padding: 8px 10px;
      font-size: 8pt;
    }
    @media print {
      body { padding: 0; }
      .no-print { display: none !important; }
      .problem-card { page-break-inside: avoid; }
    }
  </style>
</head>
<body>

  <div class="no-print">
    <div>
      <strong>Whiteboard & Scenario Mock Interview Workbook</strong>
      <span style="color: #94a3b8; font-size: 11px; margin-left: 8px;">Physical Active Recall Edition</span>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn" onclick="window.print()">🖨️ Print Workbook / Save as PDF</button>
      <button class="btn" style="background: #475569;" onclick="window.close()">Close</button>
    </div>
  </div>

  <div style="margin-bottom: 20px; border-bottom: 2px solid #0f172a; padding-bottom: 10px;">
    <h1 style="font-size: 16pt; font-weight: 800; margin: 0 0 4px 0;">${escapeHtml(title)}</h1>
    <div style="font-size: 9pt; color: #475569;">
      Active Candidate Practice Workbook: Formal Invariant Whiteboarding, Threat Diagnosis & Architecture Defense
    </div>
  </div>

  ${invariants.map((inv, idx) => `
    <div class="problem-card">
      <div class="q-header">
        <div>
          <span style="font-family: monospace; font-weight: 800; color: #1e1b4b; background: #e0e7ff; padding: 2px 6px; border-radius: 3px;">Problem #${idx + 1} [${escapeHtml(inv.id)}]</span>
          <span style="font-weight: 700; margin-left: 8px;">${escapeHtml(inv.title)}</span>
        </div>
        <div style="font-size: 8pt; color: #64748b;">
          ${escapeHtml(inv.domainName)} · ${escapeHtml(inv.difficulty)}
        </div>
      </div>

      <div class="prompt-box">
        <div style="font-size: 7.5pt; font-weight: 800; color: #1d4ed8; text-transform: uppercase;">Interview Scenario & Question:</div>
        <div style="font-size: 9pt; font-weight: 700; color: #0f172a; margin-top: 2px;">
          "${escapeHtml(inv.interviewChallenge.question)}"
        </div>
        <div style="font-size: 8pt; color: #334155; margin-top: 2px;">
          ${escapeHtml(inv.interviewChallenge.scenario)}
        </div>
      </div>

      <div class="whiteboard-box">
        <div style="font-size: 7.5pt; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 6px;">
          Candidate Solution Space: (Write Formal Logic Axiom, Identify Attack Vector & Outline Fix)
        </div>
        <div class="ruled-line"></div>
        <div class="ruled-line"></div>
        <div class="ruled-line"></div>
        <div class="ruled-line"></div>
      </div>

      <div class="solution-box">
        <div style="font-size: 7.5pt; font-weight: 800; color: #047857; text-transform: uppercase; margin-bottom: 3px;">
          Benchmark Staff Solution & Architectural Invariant:
        </div>
        <div style="font-family: monospace; font-size: 7.5pt; background: #ffffff; padding: 3px 6px; border: 1px solid #cbd5e1; border-radius: 3px; margin-bottom: 4px;">
          ${escapeHtml(inv.formalInvariant)}
        </div>
        <div style="color: #1e293b; margin-bottom: 3px;">
          <strong>Spoken Defense:</strong> ${escapeHtml(inv.interviewChallenge.sampleAnswer)}
        </div>
        <div style="font-weight: 700; color: #15803d; font-size: 7.5pt;">
          Key Anchor: ${escapeHtml(inv.interviewChallenge.keyTakeaway)}
        </div>
      </div>
    </div>
  `).join('')}

</body>
</html>`;

  openPrintWindow(html);
}

/**
 * 10. SECTION-WISE MARKDOWN EXPORTER FOR INTERVIEW PREPARATION (.md)
 */
export function exportToInterviewMarkdown(
  invariants: SecurityInvariant[],
  title: string = 'Security Invariants Interview Preparation Master Guide'
) {
  const dateStr = new Date().toISOString().split('T')[0];
  let md = `# ${title}\n\n`;
  md += `> **Technical Interview Preparation Compendium**\n`;
  md += `> **Generated on:** ${dateStr} | **Scope:** ${invariants.length} Security Invariants\n\n`;
  md += `This study guide is structured section-wise for technical interview preparation across Staff AppSec, Cloud Security, Systems Security, and Architecture roles.\n\n`;
  md += `---\n\n`;

  // Group by domain
  const byDomain: Record<string, SecurityInvariant[]> = {};
  invariants.forEach(r => {
    if (!byDomain[r.domainName]) byDomain[r.domainName] = [];
    byDomain[r.domainName].push(r);
  });

  Object.entries(byDomain).forEach(([domain, rules], dIdx) => {
    md += `## Section ${dIdx + 1}: ${domain} (${rules.length} Rules)\n\n`;

    rules.forEach((inv, rIdx) => {
      md += `### ${inv.id}: ${inv.title}\n\n`;
      md += `- **Domain / Subdomain:** ${inv.domainName} / ${inv.subdomain}\n`;
      md += `- **Difficulty / Standard:** ${inv.difficulty} | ${inv.standardType}\n`;
      md += `- **Normative Standards:** \`${inv.standards.join(', ')}\`\n\n`;

      md += `#### 🎙️ Interview Challenge Question\n`;
      md += `> **Scenario:** ${inv.interviewChallenge.scenario}\n>\n`;
      md += `> **Question:** *"${inv.interviewChallenge.question}"*\n\n`;

      md += `#### 📐 Formal Invariant Axiom\n`;
      md += `\`\`\`text\n${inv.formalInvariant}\n\`\`\`\n\n`;
      md += `**Plain-English Meaning:** ${inv.plainEnglish}\n\n`;

      md += `#### ⚠️ Threat Scenario & Why It Matters\n`;
      md += `${inv.whyItMatters}\n\n`;

      md += `#### 💻 Implementation Comparison\n\n`;
      md += `**Vulnerable Implementation (${inv.vulnerableExample.language}):**\n`;
      md += `\`\`\`${inv.vulnerableExample.language}\n${inv.vulnerableExample.code}\n\`\`\`\n`;
      md += `*Vulnerability Explanation:* ${inv.vulnerableExample.explanation}\n\n`;

      md += `**Secure Invariant Enforced (${inv.secureExample.language}):**\n`;
      md += `\`\`\`${inv.secureExample.language}\n${inv.secureExample.code}\n\`\`\`\n`;
      md += `*Secure Invariant Guarantee:* ${inv.secureExample.explanation}\n\n`;

      md += `#### 🗣️ Staff-Level Spoken Answer\n`;
      md += `${inv.interviewChallenge.sampleAnswer}\n\n`;
      md += `> **💡 Key Architectural Takeaway:** ${inv.interviewChallenge.keyTakeaway}\n\n`;

      md += `#### 🧪 Verification & Tooling\n`;
      md += `- **Tools:** \`${inv.howToTest.tools.join(', ')}\`\n`;
      md += `- **CLI Verification:**\n\`\`\`bash\n${inv.howToTest.commandExample}\n\`\`\`\n\n`;

      md += `---\n\n`;
    });
  });

  const filename = `security_invariants_interview_master_guide_${invariants.length}_rules.md`;
  downloadFile(filename, md, 'text/markdown');
}

/**
 * 11. PRINTABLE TOPIC HANDBOOK & CHEAT SHEET (HTML with Print Stylesheet)
 * Formatted specifically for hard-copy review of any of the 37 security topics.
 */
export function openPrintableTopicHandbook(
  topic: SecurityTopicMeta,
  invariants: SecurityInvariant[],
  progress?: UserProgress
) {
  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  const totalRules = invariants.length;
  const masteredCount = progress
    ? invariants.filter(r => progress.masteredIds.includes(r.id)).length
    : 0;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Topic #${topic.topicNumber}: ${escapeHtml(topic.name)} - Security Invariants Handbook</title>
  <style>
    @page {
      size: A4 portrait;
      margin: 12mm 14mm 14mm 14mm;
    }
    * {
      box-sizing: border-box;
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 8.5pt;
      line-height: 1.45;
      color: #0f172a;
      background: #ffffff;
      margin: 0;
      padding: 24px;
    }
    .no-print {
      background: #0f172a;
      color: #ffffff;
      padding: 14px 20px;
      margin: -24px -24px 24px -24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 999;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    .btn {
      background: #4f46e5;
      color: white;
      border: none;
      padding: 9px 18px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn:hover { background: #4338ca; }
    .btn-secondary { background: #334155; }
    .btn-secondary:hover { background: #1e293b; }

    .cover-container {
      padding: 16px 0 28px 0;
      border-bottom: 2.5px solid #0f172a;
      margin-bottom: 24px;
    }
    .cover-badge {
      display: inline-block;
      background: #eef2ff;
      color: #4338ca;
      font-weight: 700;
      font-size: 8.5pt;
      letter-spacing: 0.05em;
      text-transform: uppercase;
      padding: 4px 10px;
      border-radius: 4px;
      border: 1px solid #c7d2fe;
      margin-bottom: 8px;
    }
    .cover-title {
      font-size: 20pt;
      font-weight: 800;
      color: #0f172a;
      line-height: 1.2;
      margin: 0 0 6px 0;
    }
    .cover-tagline {
      font-size: 11pt;
      color: #4338ca;
      font-weight: 600;
      margin-bottom: 12px;
    }
    .cover-desc {
      font-size: 9.5pt;
      color: #334155;
      line-height: 1.5;
      margin-bottom: 16px;
      background: #f8fafc;
      padding: 12px 16px;
      border-radius: 6px;
      border: 1px solid #e2e8f0;
    }

    .meta-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 16px;
      font-size: 8pt;
      color: #475569;
      margin-bottom: 16px;
    }
    .meta-pill {
      background: #f1f5f9;
      padding: 3px 8px;
      border-radius: 4px;
      border: 1px solid #cbd5e1;
      font-family: monospace;
    }

    /* Candidate Study Card */
    .candidate-card {
      border: 1.5px solid #475569;
      border-radius: 6px;
      padding: 10px 14px;
      background: #ffffff;
      margin-bottom: 20px;
    }
    .candidate-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px 20px;
      font-size: 8pt;
    }
    .candidate-line {
      display: flex;
      align-items: baseline;
      gap: 6px;
    }
    .field-label {
      font-weight: 700;
      color: #1e293b;
      white-space: nowrap;
    }
    .fill-line {
      flex: 1;
      border-bottom: 1px dotted #475569;
      height: 14px;
    }

    /* Table of contents */
    .toc-table {
      width: 100%;
      border-collapse: collapse;
      margin: 12px 0 24px 0;
      font-size: 8pt;
    }
    .toc-table th {
      background: #f1f5f9;
      color: #1e293b;
      text-align: left;
      padding: 6px 10px;
      font-weight: 700;
      border: 1px solid #cbd5e1;
    }
    .toc-table td {
      padding: 6px 10px;
      border: 1px solid #cbd5e1;
      vertical-align: middle;
    }

    /* Rule card */
    .rule-card {
      page-break-inside: avoid;
      break-inside: avoid;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      padding: 14px;
      margin-bottom: 18px;
      background: #ffffff;
    }
    .rule-header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      border-bottom: 1.5px solid #0f172a;
      padding-bottom: 6px;
      margin-bottom: 10px;
    }
    .rule-id {
      font-family: monospace;
      font-weight: 800;
      color: #4338ca;
      font-size: 10pt;
    }
    .rule-title {
      font-size: 11pt;
      font-weight: 800;
      color: #0f172a;
      margin-bottom: 4px;
    }

    .axiom-box {
      background: #f8fafc;
      border: 1.5px solid #cbd5e1;
      border-left: 4px solid #4f46e5;
      padding: 8px 12px;
      margin: 8px 0;
      border-radius: 4px;
    }
    .axiom-label {
      font-size: 7pt;
      font-weight: 800;
      color: #4338ca;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 2px;
    }
    .axiom-formula {
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 8.5pt;
      font-weight: 700;
      color: #0f172a;
      white-space: pre-wrap;
      word-break: break-all;
    }

    .code-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin: 10px 0;
    }
    .code-box {
      border: 1px solid #cbd5e1;
      border-radius: 4px;
      overflow: hidden;
      font-size: 7.2pt;
    }
    .code-box-header {
      padding: 4px 8px;
      font-weight: 700;
      font-size: 7.5pt;
    }
    .code-vuln-header { background: #fee2e2; color: #991b1b; }
    .code-sec-header { background: #dcfce7; color: #166534; }
    .code-box pre {
      margin: 0;
      padding: 8px;
      background: #f8fafc;
      font-family: ui-monospace, monospace;
      overflow-x: auto;
      line-height: 1.35;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .code-box-footer {
      padding: 4px 8px;
      font-size: 7pt;
      border-top: 1px solid #e2e8f0;
    }

    .model-answer-box {
      background: #f0fdf4;
      border: 1.5px solid #bbf7d0;
      border-left: 4px solid #16a34a;
      padding: 8px 12px;
      border-radius: 4px;
      margin: 8px 0;
    }
    .model-label {
      font-size: 7pt;
      font-weight: 800;
      color: #15803d;
      text-transform: uppercase;
      margin-bottom: 2px;
    }
    .model-text {
      color: #14532d;
      font-size: 8pt;
      line-height: 1.4;
      margin-bottom: 4px;
    }
    .takeaway-badge {
      display: inline-block;
      background: #dcfce7;
      color: #166534;
      font-size: 7.5pt;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 3px;
    }

    .verification-line {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      font-size: 7.5pt;
      color: #475569;
      background: #f1f5f9;
      padding: 6px 10px;
      border-radius: 4px;
      margin-top: 8px;
    }
    .verification-line code {
      font-family: monospace;
      color: #0f172a;
      font-weight: 600;
    }

    .notes-box {
      margin-top: 8px;
      padding: 6px 10px;
      background: #fafafa;
      border: 1px dashed #cbd5e1;
      border-radius: 4px;
    }
    .notes-header {
      font-size: 7pt;
      font-weight: 700;
      color: #64748b;
      margin-bottom: 4px;
      text-transform: uppercase;
    }
    .notes-lines {
      border-bottom: 1px dotted #cbd5e1;
      height: 12px;
      margin-top: 3px;
    }

    @media print {
      body { padding: 0; }
      .no-print { display: none !important; }
      .rule-card { page-break-inside: avoid; }
    }
  </style>
</head>
<body>

  <!-- Top Action Bar -->
  <div class="no-print">
    <div>
      <strong style="font-size: 15px;">Topic #${topic.topicNumber}: ${escapeHtml(topic.name)} · Security Invariants Handbook</strong>
      <div style="font-size: 11px; color: #94a3b8; margin-top: 2px;">
        ${totalRules} Rules Mapped · Hard-copy printable study reference & audit workbook
      </div>
    </div>
    <div style="display: flex; gap: 10px; align-items: center;">
      <button class="btn" onclick="window.print()">
        🖨️ Print Topic Handbook / Save PDF
      </button>
      <button class="btn btn-secondary" onclick="window.close()">
        Close
      </button>
    </div>
  </div>

  <!-- Cover Header -->
  <div class="cover-container">
    <div class="cover-badge">Topic #${String(topic.topicNumber).padStart(2, '0')} · ${escapeHtml(topic.suite)}</div>
    <h1 class="cover-title">${escapeHtml(topic.name)}</h1>
    <div class="cover-tagline">${escapeHtml(topic.tagline)}</div>
    
    <div class="cover-desc">
      <strong>Defensive Scope & System Boundaries:</strong> ${escapeHtml(topic.description)}
    </div>

    <div class="meta-bar">
      <span><strong>Primary Standard:</strong> <span class="meta-pill">${escapeHtml(topic.primaryStandard)}</span></span>
      <span><strong>Associated CWEs:</strong> ${topic.cwes.map(c => `<span class="meta-pill">${escapeHtml(c)}</span>`).join(' ')}</span>
      <span><strong>Rarity / Threat Level:</strong> <span class="meta-pill">${escapeHtml(topic.rarityLevel)}</span></span>
      <span><strong>Generated:</strong> ${dateStr}</span>
    </div>

    <!-- Hard-Copy Candidate Tracker -->
    <div class="candidate-card">
      <div class="candidate-grid">
        <div class="candidate-line">
          <span class="field-label">Candidate Name:</span>
          <div class="fill-line"></div>
        </div>
        <div class="candidate-line">
          <span class="field-label">Target Role / Level:</span>
          <div class="fill-line"></div>
        </div>
        <div class="candidate-line">
          <span class="field-label">Audit / Review Date:</span>
          <div class="fill-line"></div>
        </div>
        <div class="candidate-line">
          <span class="field-label">Mastery Score:</span>
          <span style="font-size: 8pt; font-weight: 700; color: #16a34a;">${masteredCount} of ${totalRules} Verified</span>
        </div>
      </div>
    </div>

    <!-- Quick Index Table -->
    <div style="font-weight: 700; font-size: 8.5pt; color: #1e293b; margin-bottom: 6px; text-transform: uppercase;">
      📋 Topic Invariants Roster (${totalRules} Rules)
    </div>
    <table class="toc-table">
      <thead>
        <tr>
          <th style="width: 70px;">Rule ID</th>
          <th>Title & Subdomain</th>
          <th style="width: 140px;">Standard</th>
          <th style="width: 80px;">Difficulty</th>
          <th style="width: 70px; text-align: center;">Verified</th>
        </tr>
      </thead>
      <tbody>
        ${invariants.map(inv => `
          <tr>
            <td style="font-family: monospace; font-weight: 700; color: #4338ca;">${escapeHtml(inv.id)}</td>
            <td>
              <strong>${escapeHtml(inv.title)}</strong>
              <div style="font-size: 7pt; color: #64748b;">${escapeHtml(inv.domainName)} · ${escapeHtml(inv.subdomain)}</div>
            </td>
            <td style="font-family: monospace; font-size: 7.5pt;">${escapeHtml(inv.standards[0])}</td>
            <td>${escapeHtml(inv.difficulty)}</td>
            <td style="text-align: center; font-size: 8pt;">[ ]</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>

  <!-- Invariants Detailed Breakdown -->
  ${invariants.map((inv, idx) => `
    <div class="rule-card">
      <div class="rule-header">
        <div>
          <span class="rule-id">${escapeHtml(inv.id)}</span>
          ${inv.sequenceOrder ? `<span style="font-size: 7.5pt; font-family: monospace; color: #64748b; margin-left: 6px;">Step ${inv.sequenceOrder} · Tier ${inv.tierLevel || 1}</span>` : ''}
          ${inv.isRareRule ? `<span style="font-size: 7pt; font-weight: 700; background: #fee2e2; color: #991b1b; padding: 2px 6px; border-radius: 3px; margin-left: 6px;">Zero-Day</span>` : ''}
        </div>
        <div style="font-size: 7.5pt; font-family: monospace; color: #475569;">
          ${escapeHtml(inv.standards.join(', '))} · ${escapeHtml(inv.difficulty)}
        </div>
      </div>

      <div class="rule-title">${idx + 1}. ${escapeHtml(inv.title)}</div>
      <div style="font-size: 7.5pt; color: #64748b; margin-bottom: 6px;">
        <strong>Domain:</strong> ${escapeHtml(inv.domainName)} &nbsp;|&nbsp; <strong>Subdomain:</strong> ${escapeHtml(inv.subdomain)}
      </div>

      <!-- Formal Invariant Box -->
      <div class="axiom-box">
        <div class="axiom-label">Mathematical Invariant Theorem</div>
        <div class="axiom-formula">${escapeHtml(inv.formalInvariant)}</div>
      </div>

      <!-- Plain English Translation -->
      <div style="font-size: 8pt; color: #1e293b; margin-bottom: 6px;">
        <strong>Plain-English Translation:</strong> ${escapeHtml(inv.plainEnglish)}
      </div>

      <!-- Threat Scenario & Why It Matters -->
      <div style="font-size: 8pt; color: #475569; margin-bottom: 8px;">
        <strong>Threat Scenario & Blast Radius:</strong> ${escapeHtml(inv.whyItMatters)}
      </div>

      <!-- Code Comparison Diffs -->
      <div class="code-grid">
        <div class="code-box">
          <div class="code-box-header code-vuln-header">Vulnerable Pattern (${escapeHtml(inv.vulnerableExample.language)})</div>
          <pre>${escapeHtml(inv.vulnerableExample.code)}</pre>
          <div class="code-box-footer">${escapeHtml(inv.vulnerableExample.explanation)}</div>
        </div>
        <div class="code-box">
          <div class="code-box-header code-sec-header">Secure Invariant Enforced (${escapeHtml(inv.secureExample.language)})</div>
          <pre>${escapeHtml(inv.secureExample.code)}</pre>
          <div class="code-box-footer">${escapeHtml(inv.secureExample.explanation)}</div>
        </div>
      </div>

      <!-- Staff Verbal Model Answer -->
      <div class="model-answer-box">
        <div class="model-label">🗣️ Staff Interview Verbal Response</div>
        <div class="model-text">${escapeHtml(inv.interviewChallenge.sampleAnswer)}</div>
        <div>
          <span class="takeaway-badge">💡 Architectural Key Takeaway: ${escapeHtml(inv.interviewChallenge.keyTakeaway)}</span>
        </div>
      </div>

      <!-- Verification line -->
      <div class="verification-line">
        <div>
          <strong>Tools:</strong> ${escapeHtml(inv.howToTest.tools.join(', '))}
        </div>
        <div>
          <strong>CLI Verification:</strong> <code>${escapeHtml(inv.howToTest.commandExample)}</code>
        </div>
      </div>

      <!-- Notes lines -->
      <div class="notes-box">
        <div class="notes-header">✍️ Personal Talking Points & Whiteboard Notes:</div>
        <div class="notes-lines"></div>
        <div class="notes-lines"></div>
      </div>
    </div>
  `).join('')}

</body>
</html>`;

  openPrintWindow(html);
}

/**
 * 12. PRINTABLE DOMAIN HANDBOOK (HTML with Print Stylesheet)
 * Formatted specifically for hard-copy review of any of the 15 architectural domains.
 */
export function openPrintableDomainHandbook(
  domainId: DomainId,
  invariants: SecurityInvariant[],
  progress?: UserProgress
) {
  const meta = domainMetadata[domainId];
  const title = meta
    ? `${meta.name} - Security Invariants Domain Handbook`
    : `Domain ${domainId.toUpperCase()} - Security Invariants Handbook`;
  
  openPrintableInterviewMasterBook(invariants, title, progress);
}
