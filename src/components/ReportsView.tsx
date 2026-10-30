import React, { useState, useMemo } from 'react';
import { SecurityInvariant, DomainId, UserProgress, SecurityTopicId } from '../types/invariants';
import {
  allInvariants,
  domainMetadata,
  learningPaths,
  securityTopicsTaxonomy,
  getInvariantsForTopic
} from '../data/invariantsRegistry';
import {
  openPrintableInterviewMasterBook,
  openPrintableInterviewFlashSheets,
  openPrintableWhiteboardWorkbook,
  openPrintableTopicHandbook,
  openPrintableDomainHandbook,
  exportToInterviewMarkdown,
  exportToCSV,
  exportToMarkdown,
  exportToBashTestHarness,
  exportToBaselineJSON,
  openPrintableAuditChecklist,
  openPrintableDossier
} from '../utils/reportExporter';
import {
  GraduationCap,
  Printer,
  Download,
  BookOpen,
  Sparkles,
  Layers,
  Shield,
  FileText,
  Brain,
  CheckCircle2,
  Bookmark,
  ChevronRight,
  SlidersHorizontal,
  Table,
  Terminal,
  FileCode,
  Check,
  Eye,
  PenTool,
  Zap,
  Flame
} from 'lucide-react';

interface ReportsViewProps {
  progress: UserProgress;
  onOpenRule: (inv: SecurityInvariant) => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ progress, onOpenRule }) => {
  const [scopeType, setScopeType] = useState<'all' | 'domain' | 'topic' | 'track' | 'bookmarked' | 'mastered' | 'unmastered'>('all');
  const [selectedDomain, setSelectedDomain] = useState<DomainId>('containers');
  const [selectedTopicId, setSelectedTopicId] = useState<SecurityTopicId>(securityTopicsTaxonomy[0].id);
  const [selectedTrackId, setSelectedTrackId] = useState<string>(learningPaths[0].id);
  const [activePreviewTab, setActivePreviewTab] = useState<'handbook' | 'flashcards' | 'workbook' | 'matrix'>('handbook');
  const [recentlyDownloaded, setRecentlyDownloaded] = useState<string | null>(null);

  // Canonical list of all 15 sections with metadata
  const canonicalSections: { id: DomainId; sectionNum: number; name: string; rfc: string }[] = useMemo(() => [
    { id: 'http', sectionNum: 1, name: 'HTTP & Transport Security', rfc: 'RFC 9110 / TLS 1.3' },
    { id: 'web', sectionNum: 2, name: 'Web Security & Sandboxing', rfc: 'W3C CSP3 / SOP' },
    { id: 'api', sectionNum: 3, name: 'API & GraphQL Security', rfc: 'RFC 7519 / OpenAPI' },
    { id: 'auth', sectionNum: 4, name: 'Authentication & Credentials', rfc: 'NIST 800-63B / FIDO2' },
    { id: 'authz', sectionNum: 5, name: 'Authorization & Multi-Tenancy', rfc: 'NIST 800-162 / ReBAC' },
    { id: 'oauth', sectionNum: 6, name: 'OAuth 2.0 & OIDC Flows', rfc: 'RFC 6749 / PKCE' },
    { id: 'crypto', sectionNum: 7, name: 'Modern Cryptography', rfc: 'NIST 800-57 / FIPS' },
    { id: 'cloud', sectionNum: 8, name: 'Cloud Architecture & VPC', rfc: 'CIS Cloud / IMDSv2' },
    { id: 'aws', sectionNum: 9, name: 'AWS Identity & Infrastructure', rfc: 'AWS Well-Architected' },
    { id: 'containers', sectionNum: 10, name: 'Container Runtime & Isolation', rfc: 'OCI Spec / Linux cgroups' },
    { id: 'k8s', sectionNum: 11, name: 'Kubernetes Orchestration', rfc: 'CIS K8s / PSS Standards' },
    { id: 'coding', sectionNum: 12, name: 'Secure Coding & Code Review', rfc: 'OWASP Top 10 / CWE-25' },
    { id: 'ai', sectionNum: 13, name: 'AI & Large Language Model Safety', rfc: 'OWASP LLM / NIST AI RMF' },
    { id: 'smartcontracts', sectionNum: 14, name: 'Smart Contracts & Web3', rfc: 'SWC / EVM Semantics' },
    { id: 'threatmodeling', sectionNum: 15, name: 'Threat Modeling & Architecture', rfc: 'STRIDE / DREAD / PASTA' }
  ], []);

  // Compute selected invariants based on scope
  const scopedInvariants = useMemo(() => {
    switch (scopeType) {
      case 'all':
        return allInvariants;
      case 'domain':
        return allInvariants.filter(r => r.domain === selectedDomain);
      case 'topic':
        return getInvariantsForTopic(selectedTopicId, allInvariants);
      case 'track': {
        const track = learningPaths.find(t => t.id === selectedTrackId);
        if (!track) return allInvariants;
        return allInvariants.filter(r => track.domainIds.includes(r.domain) || track.ruleIds.includes(r.id));
      }
      case 'bookmarked':
        return allInvariants.filter(r => progress.bookmarkedIds.includes(r.id));
      case 'mastered':
        return allInvariants.filter(r => progress.masteredIds.includes(r.id));
      case 'unmastered':
        return allInvariants.filter(r => !progress.masteredIds.includes(r.id));
      default:
        return allInvariants;
    }
  }, [scopeType, selectedDomain, selectedTopicId, selectedTrackId, progress]);

  // Scope title
  const scopeTitle = useMemo(() => {
    switch (scopeType) {
      case 'all':
        return `Complete Section-Wise Curriculum (${allInvariants.length} Invariants)`;
      case 'domain': {
        const sec = canonicalSections.find(s => s.id === selectedDomain);
        return sec ? `Section ${sec.sectionNum}: ${sec.name}` : `${domainMetadata[selectedDomain]?.name} Invariants`;
      }
      case 'topic': {
        const topic = securityTopicsTaxonomy.find(t => t.id === selectedTopicId);
        return topic ? `Topic #${topic.topicNumber}: ${topic.name}` : 'Security Topic';
      }
      case 'track': {
        const track = learningPaths.find(t => t.id === selectedTrackId);
        return track ? track.title : 'Interview Track';
      }
      case 'bookmarked':
        return 'Bookmarked Interview Questions & Axioms';
      case 'mastered':
        return 'Mastered Invariants Review Set';
      case 'unmastered':
        return 'Unmastered Practice Questions';
      default:
        return 'Security Invariants';
    }
  }, [scopeType, selectedDomain, selectedTopicId, selectedTrackId, canonicalSections]);

  const triggerFeedback = (formatName: string) => {
    setRecentlyDownloaded(formatName);
    setTimeout(() => setRecentlyDownloaded(null), 3500);
  };

  // Handlers
  const handlePrintMasterBook = (customInvariants?: SecurityInvariant[], customTitle?: string) => {
    const list = customInvariants || scopedInvariants;
    const title = customTitle || (scopeType === 'all' 
      ? 'Security Invariants Technical Interview Preparation Master Handbook' 
      : `${scopeTitle} - Interview Preparation Handbook`);
    openPrintableInterviewMasterBook(list, title, progress);
    triggerFeedback('Master Handbook (Print / PDF)');
  };

  const handlePrintFlashSheets = () => {
    openPrintableInterviewFlashSheets(scopedInvariants, `${scopeTitle} - Fast-Recall Flash Sheets`);
    triggerFeedback('Flash Sheets (Print / PDF)');
  };

  const handlePrintWorkbook = () => {
    openPrintableWhiteboardWorkbook(scopedInvariants, `${scopeTitle} - Whiteboard & Scenario Workbook`);
    triggerFeedback('Workbook (Print / PDF)');
  };

  const handleDownloadInterviewMarkdown = () => {
    exportToInterviewMarkdown(scopedInvariants, `${scopeTitle} - Technical Interview Master Guide`);
    triggerFeedback('Interview Markdown (.md)');
  };

  const handleDownloadCSV = () => {
    const filename = `security_invariants_interview_matrix_${scopedInvariants.length}_rules.csv`;
    exportToCSV(scopedInvariants, progress, filename);
    triggerFeedback('Study Matrix (CSV)');
  };

  const handleDownloadBashHarness = () => {
    exportToBashTestHarness(scopedInvariants, scopeTitle);
    triggerFeedback('Test Harness (Bash .sh)');
  };

  const handlePrintAuditWorksheet = () => {
    openPrintableAuditChecklist(scopedInvariants, `${scopeTitle} - Audit Worksheet`, progress);
    triggerFeedback('Audit Checklist');
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8 space-y-10">
      {/* 1. HERO: Interview Preparation Hard-Copy Center */}
      <div className="bg-gradient-to-br from-indigo-950/40 via-slate-900/60 to-slate-950 border border-indigo-500/30 rounded-2xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 -mt-12 -mr-12 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs font-mono font-medium mb-3">
              <GraduationCap className="w-4 h-4 text-indigo-400" />
              <span>Complete Section-Wise Hard-Copy Study Edition</span>
              <span className="text-slate-600">·</span>
              <span>1,036 Invariants Across 15 Sections</span>
            </div>
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-white tracking-tight leading-tight">
              Technical Interview Preparation & Print Center
            </h1>
            <p className="text-sm sm:text-base text-slate-300 mt-2.5 leading-relaxed">
              Designed specifically for <strong>hard-copy physical study</strong>, binder organization, and <strong>senior/staff security interview drills</strong>.
              Print the complete 1,036-rule curriculum section-by-section, complete with real-world scenarios, whiteboard invariant formulas,
              vulnerable vs secure code diffs, model verbal answers, and lined space for handwritten notes.
            </p>
          </div>

          {/* Master 1-Click Action */}
          <div className="shrink-0 flex flex-col sm:flex-row lg:flex-col gap-3">
            <button
              onClick={() => handlePrintMasterBook(allInvariants, 'Security Invariants Technical Interview Preparation Master Handbook')}
              className="px-5 py-3.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-sm font-bold transition-all flex items-center justify-center gap-2.5 shadow-lg shadow-indigo-600/30 hover:scale-[1.02] active:scale-[0.98]"
              title="Prints the complete 1,036 invariants organized by Section 1 to 15"
            >
              <Printer className="w-5 h-5 text-indigo-200" />
              <span>Print Complete 1,036-Rule Handbook</span>
            </button>
            <button
              onClick={() => handlePrintMasterBook(scopedInvariants)}
              className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-xl text-xs font-semibold transition-colors flex items-center justify-center gap-2"
              title="Print current selected scope"
            >
              <BookOpen className="w-4 h-4 text-indigo-400" />
              <span>Print Current Selection ({scopedInvariants.length} Rules)</span>
            </button>
          </div>
        </div>

        {/* Feedback pill */}
        {recentlyDownloaded && (
          <div className="mt-4 inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-xs font-medium animate-fadeIn">
            <Check className="w-4 h-4 text-emerald-400" />
            <span>Generated & opened <strong>{recentlyDownloaded}</strong> for printing or download!</span>
          </div>
        )}
      </div>

      {/* 2. FOUR CORE PRINTABLE STUDY FORMATS (INTERVIEW PREP FOCUSED) */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Sparkles className="w-5 h-5 text-indigo-400" />
              <span>Dedicated Interview Preparation Print Formats</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Choose the learning modality that fits your interview study schedule.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Format 1: Master Handbook */}
          <div className="bg-slate-900/80 border border-slate-800 hover:border-indigo-500/40 rounded-xl p-5 flex flex-col justify-between transition-all group">
            <div>
              <div className="w-10 h-10 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 mb-3 group-hover:scale-105 transition-transform">
                <BookOpen className="w-5 h-5" />
              </div>
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-bold text-white text-sm">Master Handbook</h3>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  Full Dossier
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed mb-4">
                Section-wise compendium with candidate study log, TOC, formal logic whiteboard axioms, code diffs, model verbal answers, and ruled notes margins.
              </p>
            </div>
            <div className="space-y-2 pt-3 border-t border-slate-800/80">
              <button
                onClick={() => handlePrintMasterBook()}
                className="w-full py-2 px-3 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-sm shadow-indigo-600/20"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print Handbook / PDF</span>
              </button>
              <button
                onClick={handleDownloadInterviewMarkdown}
                className="w-full py-1.5 px-3 bg-slate-800/80 hover:bg-slate-800 text-slate-300 rounded-lg text-[11px] font-medium flex items-center justify-center gap-1.5 transition-colors border border-slate-700/60"
              >
                <Download className="w-3 h-3 text-indigo-400" />
                <span>Download Markdown (.md)</span>
              </button>
            </div>
          </div>

          {/* Format 2: Fast-Recall Flash Sheets */}
          <div className="bg-slate-900/80 border border-slate-800 hover:border-amber-500/40 rounded-xl p-5 flex flex-col justify-between transition-all group">
            <div>
              <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 mb-3 group-hover:scale-105 transition-transform">
                <Zap className="w-5 h-5" />
              </div>
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-bold text-white text-sm">Flash Sheets</h3>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  2-Column Cram
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed mb-4">
                High-density 2-column format (~6-8 rules per page) with scenario questions, mathematical formulas, and verbal takeaway anchors for rapid pre-interview drills.
              </p>
            </div>
            <div className="space-y-2 pt-3 border-t border-slate-800/80">
              <button
                onClick={handlePrintFlashSheets}
                className="w-full py-2 px-3 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-sm shadow-amber-600/20"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print Flash Sheets</span>
              </button>
              <div className="text-[11px] text-center text-slate-500">
                Optimized for fast verbal recitation
              </div>
            </div>
          </div>

          {/* Format 3: Whiteboard & Scenario Practice Workbook */}
          <div className="bg-slate-900/80 border border-slate-800 hover:border-emerald-500/40 rounded-xl p-5 flex flex-col justify-between transition-all group">
            <div>
              <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 mb-3 group-hover:scale-105 transition-transform">
                <PenTool className="w-5 h-5" />
              </div>
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-bold text-white text-sm">Practice Workbook</h3>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Active Recall
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed mb-4">
                Active problem sheets with real-world scenarios and blank ruled workspace for handwriting formal axioms and architectural fixes before checking model answers.
              </p>
            </div>
            <div className="space-y-2 pt-3 border-t border-slate-800/80">
              <button
                onClick={handlePrintWorkbook}
                className="w-full py-2 px-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-sm shadow-emerald-600/20"
              >
                <Printer className="w-3.5 h-3.5" />
                <span>Print Workbook / Exam</span>
              </button>
              <div className="text-[11px] text-center text-slate-500">
                Self-test before revealing answers
              </div>
            </div>
          </div>

          {/* Format 4: Study Matrix & Automation */}
          <div className="bg-slate-900/80 border border-slate-800 hover:border-sky-500/40 rounded-xl p-5 flex flex-col justify-between transition-all group">
            <div>
              <div className="w-10 h-10 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400 mb-3 group-hover:scale-105 transition-transform">
                <Table className="w-5 h-5" />
              </div>
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-bold text-white text-sm">Matrix & Automation</h3>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
                  CSV + Bash
                </span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed mb-4">
                Excel/Sheets matrix with mastery tracking columns, RFC mappings, testing tools, and executable CLI verification test scripts for DevSecOps pipelines.
              </p>
            </div>
            <div className="space-y-2 pt-3 border-t border-slate-800/80">
              <button
                onClick={handleDownloadCSV}
                className="w-full py-2 px-3 bg-sky-600 hover:bg-sky-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors shadow-sm shadow-sky-600/20"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Matrix (CSV)</span>
              </button>
              <button
                onClick={handleDownloadBashHarness}
                className="w-full py-1.5 px-3 bg-slate-800/80 hover:bg-slate-800 text-slate-300 rounded-lg text-[11px] font-medium flex items-center justify-center gap-1.5 transition-colors border border-slate-700/60"
              >
                <Terminal className="w-3 h-3 text-sky-400" />
                <span>Download Test Script (.sh)</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* 3. SECTION-BY-SECTION DIRECT PRINT BINDERS */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-5">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" />
              <span>Section-by-Section Study Booklets (All 15 Domains)</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Print a clean, standalone booklet for any specific technical domain to master one topic at a time.
            </p>
          </div>
          <span className="text-xs text-slate-500 font-mono">15 Standard Sections Available</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {canonicalSections.map(sec => {
            const rules = allInvariants.filter(r => r.domain === sec.id);
            const masteredCount = rules.filter(r => progress.masteredIds.includes(r.id)).length;
            const percent = Math.round((masteredCount / rules.length) * 100);

            return (
              <div
                key={sec.id}
                className="bg-slate-950/70 border border-slate-800/90 hover:border-indigo-500/50 rounded-xl p-3.5 flex items-center justify-between gap-3 transition-colors group"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="font-mono text-[11px] font-bold text-indigo-400 bg-indigo-500/10 px-1.5 py-0.2 rounded border border-indigo-500/20">
                      Sec {sec.sectionNum}
                    </span>
                    <span className="text-xs font-bold text-slate-200 truncate group-hover:text-white">
                      {sec.name}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-slate-400">
                    <span>{rules.length} Rules</span>
                    <span className="text-slate-600">·</span>
                    <span className="truncate text-slate-500 font-mono text-[10px]">{sec.rfc}</span>
                  </div>
                  <div className="mt-1.5 flex items-center gap-1.5">
                    <div className="flex-1 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div
                        className="bg-indigo-500 h-full rounded-full transition-all"
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                    <span className="text-[10px] font-mono text-slate-400">{percent}%</span>
                  </div>
                </div>

                <div className="flex flex-col gap-1 shrink-0">
                  <button
                    onClick={() => handlePrintMasterBook(rules, `Section ${sec.sectionNum}: ${sec.name} - Interview Handbook`)}
                    className="p-2 bg-indigo-600/20 hover:bg-indigo-600 text-indigo-300 hover:text-white rounded-lg transition-colors border border-indigo-500/30"
                    title={`Print Section ${sec.sectionNum} Handbook (${rules.length} Rules)`}
                  >
                    <Printer className="w-4 h-4" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 3b. TOPIC-BY-TOPIC DIRECT PRINT BINDERS (ALL 37 TOPICS) */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-5">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Flame className="w-4 h-4 text-amber-400" />
              <span>Topic-by-Topic Study Booklets (All 37 Vulnerability Categories)</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Print dedicated cheat sheets and interview workbooks for each of the 37 security categories (Request Smuggling, SQLi, LLM Safety, DeFi, etc.).
            </p>
          </div>
          <span className="text-xs text-slate-500 font-mono">37 Topics Available</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 max-h-96 overflow-y-auto pr-1">
          {securityTopicsTaxonomy.map(topic => {
            const rules = getInvariantsForTopic(topic.id, allInvariants);
            const masteredCount = rules.filter(r => progress.masteredIds.includes(r.id)).length;
            const percent = rules.length > 0 ? Math.round((masteredCount / rules.length) * 100) : 0;

            return (
              <div
                key={topic.id}
                className="bg-slate-950/70 border border-slate-800/90 hover:border-amber-500/50 rounded-xl p-3 flex items-center justify-between gap-3 transition-colors group"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="font-mono text-[10px] font-bold text-amber-400 bg-amber-500/10 px-1.5 py-0.2 rounded border border-amber-500/20">
                      #{String(topic.topicNumber).padStart(2, '0')}
                    </span>
                    <span className="text-xs font-bold text-slate-200 truncate group-hover:text-white">
                      {topic.name}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-slate-400">
                    <span>{rules.length} Rules</span>
                    <span className="text-slate-600">·</span>
                    <span className="truncate text-slate-500 font-mono text-[10px]">{topic.primaryStandard}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-1.5">
                    <div className="flex-1 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div
                        className="bg-amber-500 h-full rounded-full transition-all"
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                    <span className="text-[10px] font-mono text-slate-400">{percent}%</span>
                  </div>
                </div>

                <div className="flex flex-col gap-1 shrink-0">
                  <button
                    onClick={() => openPrintableTopicHandbook(topic, rules, progress)}
                    className="p-2 bg-amber-600/20 hover:bg-amber-600 text-amber-300 hover:text-white rounded-lg transition-colors border border-amber-500/30"
                    title={`Print Topic #${topic.topicNumber}: ${topic.name} Handbook (${rules.length} Rules)`}
                  >
                    <Printer className="w-4 h-4" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 4. SCOPE SELECTOR & FILTER DECK */}
      <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-5 space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <SlidersHorizontal className="w-4 h-4 text-indigo-400" />
            <h3 className="font-bold text-white text-sm">Scope & Custom Filter For Printing</h3>
          </div>
          <div className="text-xs font-mono text-indigo-300 bg-indigo-500/10 px-2.5 py-1 rounded-md border border-indigo-500/20">
            Selected Scope: <strong>{scopedInvariants.length}</strong> of <strong>{allInvariants.length}</strong> rules
          </div>
        </div>

        {/* Scope Type Selector */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-2">
          <button
            onClick={() => setScopeType('all')}
            className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-colors ${
              scopeType === 'all'
                ? 'bg-indigo-600 text-white border-indigo-500 font-semibold'
                : 'bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            All 15 Sections ({allInvariants.length})
          </button>
          <button
            onClick={() => setScopeType('domain')}
            className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-colors ${
              scopeType === 'domain'
                ? 'bg-indigo-600 text-white border-indigo-500 font-semibold'
                : 'bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            By Section / Domain
          </button>
          <button
            onClick={() => setScopeType('topic')}
            className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-colors ${
              scopeType === 'topic'
                ? 'bg-indigo-600 text-white border-indigo-500 font-semibold'
                : 'bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            By Topic (37 Topics)
          </button>
          <button
            onClick={() => setScopeType('track')}
            className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-colors ${
              scopeType === 'track'
                ? 'bg-indigo-600 text-white border-indigo-500 font-semibold'
                : 'bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            By Career Track
          </button>
          <button
            onClick={() => setScopeType('unmastered')}
            className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-colors ${
              scopeType === 'unmastered'
                ? 'bg-indigo-600 text-white border-indigo-500 font-semibold'
                : 'bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            Need Practice ({allInvariants.length - progress.masteredIds.length})
          </button>
          <button
            onClick={() => setScopeType('bookmarked')}
            className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-colors ${
              scopeType === 'bookmarked'
                ? 'bg-indigo-600 text-white border-indigo-500 font-semibold'
                : 'bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            Bookmarked ({progress.bookmarkedIds.length})
          </button>
          <button
            onClick={() => setScopeType('mastered')}
            className={`px-3 py-2 rounded-lg text-xs font-medium border text-center transition-colors ${
              scopeType === 'mastered'
                ? 'bg-indigo-600 text-white border-indigo-500 font-semibold'
                : 'bg-slate-900 text-slate-300 border-slate-800 hover:border-slate-700'
            }`}
          >
            Mastered ({progress.masteredIds.length})
          </button>
        </div>

        {/* Sub-selectors */}
        {scopeType === 'domain' && (
          <div className="pt-2 flex flex-wrap items-center gap-2.5">
            <span className="text-xs text-slate-400 font-medium">Select Section:</span>
            <select
              value={selectedDomain}
              onChange={(e) => setSelectedDomain(e.target.value as DomainId)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium"
            >
              {canonicalSections.map(sec => {
                const count = allInvariants.filter(r => r.domain === sec.id).length;
                return (
                  <option key={sec.id} value={sec.id}>
                    Section {sec.sectionNum}: {sec.name} ({count} Invariants)
                  </option>
                );
              })}
            </select>
            <button
              onClick={() => openPrintableDomainHandbook(selectedDomain, scopedInvariants, progress)}
              className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
              title="Print or Save PDF Handbook for this Domain"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print Domain Handbook</span>
            </button>
          </div>
        )}

        {scopeType === 'topic' && (
          <div className="pt-2 flex flex-wrap items-center gap-2.5">
            <span className="text-xs text-slate-400 font-medium">Select Topic:</span>
            <select
              value={selectedTopicId}
              onChange={(e) => setSelectedTopicId(e.target.value as SecurityTopicId)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium"
            >
              {securityTopicsTaxonomy.map(topic => {
                const count = getInvariantsForTopic(topic.id, allInvariants).length;
                return (
                  <option key={topic.id} value={topic.id}>
                    Topic #{String(topic.topicNumber).padStart(2, '0')}: {topic.name} ({count} Invariants)
                  </option>
                );
              })}
            </select>
            <button
              onClick={() => {
                const topic = securityTopicsTaxonomy.find(t => t.id === selectedTopicId);
                if (topic) {
                  openPrintableTopicHandbook(topic, scopedInvariants, progress);
                }
              }}
              className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm"
              title="Print or Save PDF Handbook for this Topic"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print Topic Handbook</span>
            </button>
          </div>
        )}

        {scopeType === 'track' && (
          <div className="pt-2 flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-400 font-medium">Select Career Track:</span>
            <select
              value={selectedTrackId}
              onChange={(e) => setSelectedTrackId(e.target.value)}
              className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium"
            >
              {learningPaths.map(track => (
                <option key={track.id} value={track.id}>
                  {track.title} ({track.difficulty} · {track.ruleIds.length} Key Rules)
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* 5. INTERACTIVE IN-APP HARD-COPY PREVIEW (SIMULATED PRINT EXPERIENCE) */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        {/* Preview Tab Header */}
        <div className="border-b border-slate-800 px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-950/60">
          <div className="flex items-center gap-3">
            <Eye className="w-4 h-4 text-indigo-400" />
            <span className="text-xs font-bold text-white uppercase tracking-wider">
              Interactive Print Preview ({scopeTitle})
            </span>
          </div>

          <div className="flex items-center gap-1.5 bg-slate-900 p-1 rounded-lg border border-slate-800 self-start sm:self-auto">
            <button
              onClick={() => setActivePreviewTab('handbook')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                activePreviewTab === 'handbook' ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              📖 Master Handbook
            </button>
            <button
              onClick={() => setActivePreviewTab('flashcards')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                activePreviewTab === 'flashcards' ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              ⚡ Flash Sheets
            </button>
            <button
              onClick={() => setActivePreviewTab('workbook')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                activePreviewTab === 'workbook' ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              📝 Workbook
            </button>
            <button
              onClick={() => setActivePreviewTab('matrix')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                activePreviewTab === 'matrix' ? 'bg-indigo-600 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              📊 Matrix
            </button>
          </div>
        </div>

        {/* Realistic Simulated Paper Viewer */}
        <div className="p-4 sm:p-6 bg-slate-950 overflow-x-auto">
          <div className="max-w-4xl mx-auto bg-white text-slate-900 rounded-lg shadow-2xl p-6 sm:p-10 font-sans text-xs border border-slate-300">
            {/* 5A. MASTER HANDBOOK PREVIEW */}
            {activePreviewTab === 'handbook' && (
              <div className="space-y-6">
                {/* Paper Header / Cover */}
                <div className="border-b-2 border-slate-900 pb-4">
                  <div className="inline-block bg-indigo-50 border border-indigo-200 text-indigo-700 font-bold text-[10px] uppercase px-2 py-0.5 rounded tracking-wider mb-2">
                    Official Technical Interview Preparation Handbook
                  </div>
                  <h3 className="text-xl font-extrabold text-slate-950 tracking-tight">
                    {scopeTitle}
                  </h3>
                  <div className="text-xs text-slate-600 mt-1">
                    Formal Mathematical Axioms, Real-World Attack Scenarios, Implementation Diffs & Staff-Level Spoken Answers
                  </div>

                  {/* Candidate practice card mockup */}
                  <div className="mt-4 border border-slate-400 rounded p-3 bg-slate-50 text-[11px] grid grid-cols-2 gap-3">
                    <div>
                      <span className="font-bold text-slate-800">Candidate:</span> __________________________
                    </div>
                    <div>
                      <span className="font-bold text-slate-800">Target Role:</span> [✓] Staff AppSec [ ] Cloud Sec [ ] Architect
                    </div>
                    <div>
                      <span className="font-bold text-slate-800">Interview Target:</span> __________________________
                    </div>
                    <div>
                      <span className="font-bold text-slate-800">Scope:</span> {scopedInvariants.length} Invariants Section-Wise
                    </div>
                  </div>
                </div>

                {/* Sample Rule Cards */}
                <div className="space-y-4">
                  {scopedInvariants.slice(0, 3).map((rule, idx) => (
                    <div key={rule.id} className="border border-slate-300 rounded-lg p-4 bg-white shadow-sm space-y-3">
                      <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-xs bg-indigo-100 text-indigo-900 px-2 py-0.5 rounded border border-indigo-200">
                            {rule.id}
                          </span>
                          <span className="font-bold text-slate-900 text-sm">{rule.title}</span>
                          <span className="text-[10px] bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded">{rule.difficulty}</span>
                        </div>
                        <div className="flex items-center gap-2 text-[10px] text-slate-500 font-mono">
                          <span>[ ] Read</span>
                          <span>[ ] Whiteboard</span>
                          <span>[ ] Spoken</span>
                          <span className="text-amber-500 font-bold">★★★★★</span>
                        </div>
                      </div>

                      {/* Technical Interview Scenario Box */}
                      <div className="bg-blue-50 border-l-4 border-blue-600 p-2.5 rounded-r">
                        <div className="text-[10px] font-extrabold text-blue-700 uppercase tracking-wider">
                          🎙️ Interview Challenge Question:
                        </div>
                        <div className="font-bold text-slate-900 text-xs mt-0.5">
                          "{rule.interviewChallenge.question}"
                        </div>
                        <div className="text-[11px] text-slate-600 italic mt-1">
                          Scenario Context: {rule.interviewChallenge.scenario}
                        </div>
                      </div>

                      {/* Formal Axiom */}
                      <div>
                        <div className="text-[10px] font-bold text-slate-500 uppercase">Formal Invariant Axiom (Whiteboard Logic)</div>
                        <div className="font-mono text-[11px] bg-slate-50 border border-slate-200 p-2 rounded text-slate-900 mt-1">
                          {rule.formalInvariant}
                        </div>
                        <div className="text-[11px] text-slate-700 mt-1">
                          <strong>Plain-English Translation:</strong> {rule.plainEnglish}
                        </div>
                      </div>

                      {/* Code Diffs */}
                      <div className="grid grid-cols-2 gap-2 text-[10px]">
                        <div className="border border-red-200 rounded overflow-hidden">
                          <div className="bg-red-100 text-red-900 font-bold px-2 py-0.5">Vulnerable Code Pattern</div>
                          <pre className="p-2 font-mono text-[10px] bg-slate-50 overflow-x-auto text-slate-800">
                            {rule.vulnerableExample.code.slice(0, 140)}...
                          </pre>
                        </div>
                        <div className="border border-emerald-200 rounded overflow-hidden">
                          <div className="bg-emerald-100 text-emerald-900 font-bold px-2 py-0.5">Secure Invariant Enforced</div>
                          <pre className="p-2 font-mono text-[10px] bg-slate-50 overflow-x-auto text-slate-800">
                            {rule.secureExample.code.slice(0, 140)}...
                          </pre>
                        </div>
                      </div>

                      {/* Model Staff Spoken Answer */}
                      <div className="bg-emerald-50 border-l-4 border-emerald-600 p-2.5 rounded-r">
                        <div className="text-[10px] font-extrabold text-emerald-800 uppercase tracking-wider">
                          🗣️ Staff-Level Spoken Answer (Script for Candidate)
                        </div>
                        <div className="text-[11px] text-slate-800 mt-0.5">
                          {rule.interviewChallenge.sampleAnswer}
                        </div>
                        <div className="mt-1.5 inline-block text-[10px] font-bold text-emerald-800 bg-emerald-100 px-2 py-0.5 rounded">
                          💡 Key Architectural Takeaway: {rule.interviewChallenge.keyTakeaway}
                        </div>
                      </div>

                      {/* Handwritten Notes Space */}
                      <div className="border border-dashed border-slate-300 rounded p-2 bg-slate-50/50">
                        <div className="text-[9px] font-bold text-slate-400 uppercase">
                          ✍️ Candidate Notes & Whiteboard Talking Points:
                        </div>
                        <div className="border-b border-slate-200 h-4"></div>
                        <div className="border-b border-slate-200 h-4"></div>
                      </div>
                    </div>
                  ))}
                </div>

                {scopedInvariants.length > 3 && (
                  <div className="text-center py-3 border-t border-slate-200 text-slate-500 font-mono text-xs">
                    ... + {scopedInvariants.length - 3} additional security invariant cards formatted across printed pages ...
                  </div>
                )}
              </div>
            )}

            {/* 5B. FLASH SHEETS PREVIEW */}
            {activePreviewTab === 'flashcards' && (
              <div className="space-y-4">
                <div className="border-b border-slate-300 pb-2">
                  <h3 className="font-extrabold text-base text-slate-900">
                    High-Density Interview Flash Sheets (2-Column Fast Drill)
                  </h3>
                  <div className="text-xs text-slate-500">
                    Optimized for rapid verbal review before interview day
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  {scopedInvariants.slice(0, 4).map((rule) => (
                    <div key={rule.id} className="border border-slate-300 rounded p-3 bg-white space-y-2">
                      <div className="flex items-center justify-between text-[10px] border-b border-slate-100 pb-1">
                        <span className="font-mono font-bold text-indigo-700">{rule.id}</span>
                        <span className="text-slate-500">{rule.difficulty}</span>
                      </div>
                      <div className="font-bold text-slate-900 text-xs">
                        "{rule.interviewChallenge.question}"
                      </div>
                      <div className="font-mono text-[10px] bg-slate-100 p-1.5 rounded text-slate-800">
                        {rule.formalInvariant}
                      </div>
                      <div className="text-[10px] bg-emerald-50 text-emerald-900 p-1.5 rounded border-l-2 border-emerald-500">
                        <strong>Anchor:</strong> {rule.interviewChallenge.sampleAnswer.slice(0, 120)}...
                      </div>
                      <div className="flex items-center justify-between text-[9px] text-slate-400 pt-1 border-t border-slate-100">
                        <span className="text-emerald-700 font-semibold truncate max-w-[150px]">
                          💡 {rule.interviewChallenge.keyTakeaway}
                        </span>
                        <span>[ ] Recited</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 5C. WORKBOOK PREVIEW */}
            {activePreviewTab === 'workbook' && (
              <div className="space-y-4">
                <div className="border-b border-slate-300 pb-2">
                  <h3 className="font-extrabold text-base text-slate-900">
                    Whiteboard & Scenario Mock Interview Workbook
                  </h3>
                  <div className="text-xs text-slate-500">
                    Active recall testing format with handwritten workspace
                  </div>
                </div>

                {scopedInvariants.slice(0, 2).map((rule, idx) => (
                  <div key={rule.id} className="border-2 border-slate-400 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-sm text-slate-900">Problem #{idx + 1} [{rule.id}]: {rule.title}</span>
                      <span className="text-xs text-slate-500">{rule.domainName}</span>
                    </div>

                    <div className="bg-blue-50 border-l-4 border-blue-600 p-2.5 rounded">
                      <div className="text-[10px] font-bold text-blue-700 uppercase">Scenario & Question:</div>
                      <div className="font-bold text-slate-900 text-xs mt-0.5">"{rule.interviewChallenge.question}"</div>
                      <div className="text-[11px] text-slate-600 mt-1">{rule.interviewChallenge.scenario}</div>
                    </div>

                    <div className="border border-slate-300 rounded p-3 bg-slate-50/60 min-h-[90px]">
                      <div className="text-[10px] font-bold text-slate-400 uppercase mb-2">
                        Candidate Solution Space (Draw Architecture & Write Formal Invariant Formula):
                      </div>
                      <div className="border-b border-dashed border-slate-300 h-5"></div>
                      <div className="border-b border-dashed border-slate-300 h-5"></div>
                      <div className="border-b border-dashed border-slate-300 h-5"></div>
                    </div>

                    <div className="bg-slate-50 border border-slate-300 p-2.5 rounded text-[11px]">
                      <div className="text-[10px] font-bold text-emerald-700 uppercase">Benchmark Staff Solution:</div>
                      <div className="font-mono text-[10px] bg-white p-1 border border-slate-200 rounded mt-0.5">
                        {rule.formalInvariant}
                      </div>
                      <div className="mt-1 text-slate-700">
                        <strong>Spoken Core:</strong> {rule.interviewChallenge.sampleAnswer}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* 5D. SPREADSHEET MATRIX PREVIEW */}
            {activePreviewTab === 'matrix' && (
              <div className="space-y-4">
                <div className="border-b border-slate-300 pb-2">
                  <h3 className="font-extrabold text-base text-slate-900">
                    Compliance, Traceability & Interview Matrix (CSV)
                  </h3>
                  <div className="text-xs text-slate-500">
                    Import ready for Google Sheets, Microsoft Excel, or Airtable
                  </div>
                </div>

                <div className="overflow-x-auto border border-slate-300 rounded">
                  <table className="w-full text-left text-[10px] border-collapse">
                    <thead className="bg-slate-100 border-b border-slate-300 font-bold text-slate-800">
                      <tr>
                        <th className="p-2 border-r border-slate-200">Rule ID</th>
                        <th className="p-2 border-r border-slate-200">Domain / Section</th>
                        <th className="p-2 border-r border-slate-200">Title & Invariant Axiom</th>
                        <th className="p-2 border-r border-slate-200">Standards</th>
                        <th className="p-2">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 font-mono">
                      {scopedInvariants.slice(0, 5).map(r => (
                        <tr key={r.id}>
                          <td className="p-2 border-r border-slate-200 font-bold text-indigo-700">{r.id}</td>
                          <td className="p-2 border-r border-slate-200">{r.domainName}</td>
                          <td className="p-2 border-r border-slate-200 font-sans">
                            <div className="font-bold">{r.title}</div>
                            <div className="font-mono text-[9px] text-slate-600">{r.formalInvariant}</div>
                          </td>
                          <td className="p-2 border-r border-slate-200">{r.standards.join(', ')}</td>
                          <td className="p-2 font-sans">
                            <span className="px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-800 text-[9px]">
                              {progress.masteredIds.includes(r.id) ? 'Mastered' : 'Needs Practice'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Bottom Print Button on Paper Mockup */}
            <div className="mt-8 pt-4 border-t-2 border-slate-900 flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="text-slate-500 text-[11px]">
                Showing preview of <strong>{scopeTitle}</strong> ({scopedInvariants.length} Rules).
              </div>
              <button
                onClick={() => {
                  if (activePreviewTab === 'flashcards') handlePrintFlashSheets();
                  else if (activePreviewTab === 'workbook') handlePrintWorkbook();
                  else if (activePreviewTab === 'matrix') handleDownloadCSV();
                  else handlePrintMasterBook();
                }}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-bold rounded shadow flex items-center gap-2 transition-colors"
              >
                <Printer className="w-4 h-4" />
                <span>Print This Format Now</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
