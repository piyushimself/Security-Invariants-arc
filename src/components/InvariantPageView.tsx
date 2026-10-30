import React, { useState, useEffect, useMemo } from 'react';
import { SecurityInvariant } from '../types/invariants';
import { InteractiveSimulator } from './InteractiveSimulator';
import {
  ArrowLeft,
  ArrowRight,
  Bookmark,
  BookmarkCheck,
  CheckCircle2,
  Copy,
  Check,
  Code2,
  Terminal,
  AlertOctagon,
  ShieldCheck,
  HelpCircle,
  BookOpen,
  ChevronRight,
  ExternalLink,
  Layers,
  Sparkles,
  Share2,
  Printer,
  ChevronDown,
  Info,
  CheckCircle,
  FileCode,
  Shield,
  Compass,
  Download,
  Table,
  FileText,
  Brain,
  Film
} from 'lucide-react';
import {
  formatRuleAsMarkdown,
  generateNotebookLMPrompt,
  copyToClipboard
} from '../utils/ruleExportHelpers';
import {
  exportToCSV,
  exportToMarkdown,
  exportToInterviewMarkdown,
  exportToBashTestHarness,
  exportToBaselineJSON,
  openPrintableAuditChecklist,
  openPrintableDossier,
  openPrintableInterviewMasterBook,
  openPrintableInterviewFlashSheets,
  openPrintableTopicHandbook,
  openPrintableDomainHandbook
} from '../utils/reportExporter';
import { securityTopicsTaxonomy, getInvariantsForTopic } from '../data/invariantsRegistry';

interface InvariantPageViewProps {
  invariant: SecurityInvariant;
  allInvariants: SecurityInvariant[];
  onSelectInvariant: (inv: SecurityInvariant) => void;
  onBack: () => void;
  isBookmarked: boolean;
  isMastered: boolean;
  onToggleBookmark: (id: string) => void;
  onToggleMastered: (id: string) => void;
}

export const InvariantPageView: React.FC<InvariantPageViewProps> = ({
  invariant,
  allInvariants,
  onSelectInvariant,
  onBack,
  isBookmarked,
  isMastered,
  onToggleBookmark,
  onToggleMastered
}) => {
  const [codeTab, setCodeTab] = useState<'side-by-side' | 'vulnerable' | 'secure'>('side-by-side');
  const [showHint, setShowHint] = useState(false);
  const [showAnswer, setShowAnswer] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedRule, setCopiedRule] = useState(false);
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [selectedSymbol, setSelectedSymbol] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<string>('formal');

  const handleCopyRule = async () => {
    const md = formatRuleAsMarkdown(invariant);
    const ok = await copyToClipboard(md);
    if (ok) {
      setCopiedRule(true);
      setTimeout(() => setCopiedRule(false), 2000);
    }
  };

  const handleCopyPrompt = async () => {
    const prompt = generateNotebookLMPrompt(invariant);
    const ok = await copyToClipboard(prompt);
    if (ok) {
      setCopiedPrompt(true);
      setTimeout(() => setCopiedPrompt(false), 2000);
    }
  };

  // Find index in global list and domain list for linear navigation
  const currentIndex = useMemo(
    () => allInvariants.findIndex(r => r.id === invariant.id),
    [allInvariants, invariant.id]
  );

  const prevInvariant = currentIndex > 0 ? allInvariants[currentIndex - 1] : null;
  const nextInvariant = currentIndex < allInvariants.length - 1 ? allInvariants[currentIndex + 1] : null;

  const domainInvariants = useMemo(
    () => allInvariants.filter(r => r.domain === invariant.domain),
    [allInvariants, invariant.domain]
  );
  const domainIndex = useMemo(
    () => domainInvariants.findIndex(r => r.id === invariant.id) + 1,
    [domainInvariants, invariant.id]
  );

  const associatedTopic = useMemo(() => {
    return securityTopicsTaxonomy.find(t =>
      getInvariantsForTopic(t.id, allInvariants).some(r => r.id === invariant.id)
    );
  }, [allInvariants, invariant.id]);

  // Keyboard navigation: Left/Right arrows to flip rules, Escape to go back
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't trigger if user is typing in a textarea or input
      const target = e.target as HTMLElement;
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA') return;

      if (e.key === 'ArrowLeft' && prevInvariant) {
        onSelectInvariant(prevInvariant);
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } else if (e.key === 'ArrowRight' && nextInvariant) {
        onSelectInvariant(nextInvariant);
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } else if (e.key === 'Escape') {
        onBack();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [prevInvariant, nextInvariant, onSelectInvariant, onBack]);

  // Reset answer/hint state when switching invariants
  useEffect(() => {
    setShowHint(false);
    setShowAnswer(false);
    setSelectedSymbol(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, [invariant.id]);

  const handleCopyCommand = () => {
    navigator.clipboard.writeText(invariant.howToTest.commandExample);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  const handleCopyLink = () => {
    const url = `${window.location.origin}${window.location.pathname}#rule=${invariant.id}`;
    navigator.clipboard.writeText(url);
    setCopiedLink(true);
    setTimeout(() => setCopiedLink(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  const scrollToSection = (id: string) => {
    setActiveSection(id);
    const element = document.getElementById(id);
    if (element) {
      const yOffset = -90;
      const y = element.getBoundingClientRect().top + window.pageYOffset + yOffset;
      window.scrollTo({ top: y, behavior: 'smooth' });
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Top Sticky Navigation Bar */}
      <div className="sticky top-0 z-40 bg-slate-950/95 backdrop-blur-md border-b border-slate-800 shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between gap-4">
          {/* Breadcrumbs & Back */}
          <div className="flex items-center gap-2 text-xs truncate">
            <button
              onClick={onBack}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors font-medium shrink-0"
              title="Return to curriculum index"
            >
              <ArrowLeft className="w-3.5 h-3.5 text-indigo-400" />
              <span>Back to Curriculum</span>
            </button>
            <ChevronRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />
            <span className="text-slate-400 hidden sm:inline">{invariant.domainName}</span>
            <ChevronRight className="w-3.5 h-3.5 text-slate-600 shrink-0 hidden sm:inline" />
            <span className="font-mono text-indigo-400 font-bold">{invariant.id}</span>
          </div>

          {/* Previous / Next Page Controls & Actions */}
          <div className="flex items-center gap-2 shrink-0">
            {/* Rule Jump Dropdown */}
            <div className="hidden lg:flex items-center gap-1 text-xs text-slate-400 font-mono mr-2">
              <span>Rule {domainIndex} of {domainInvariants.length} in domain</span>
            </div>

            {/* Prev Rule */}
            <button
              onClick={() => {
                if (prevInvariant) {
                  onSelectInvariant(prevInvariant);
                  window.scrollTo({ top: 0, behavior: 'smooth' });
                }
              }}
              disabled={!prevInvariant}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed text-xs font-medium flex items-center gap-1 transition-colors"
              title={prevInvariant ? `Previous: ${prevInvariant.id} - ${prevInvariant.title}` : 'No previous rule'}
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span className="hidden md:inline">Prev</span>
            </button>

            {/* Next Rule */}
            <button
              onClick={() => {
                if (nextInvariant) {
                  onSelectInvariant(nextInvariant);
                  window.scrollTo({ top: 0, behavior: 'smooth' });
                }
              }}
              disabled={!nextInvariant}
              className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed text-xs font-medium flex items-center gap-1 transition-colors"
              title={nextInvariant ? `Next: ${nextInvariant.id} - ${nextInvariant.title}` : 'No next rule'}
            >
              <span className="hidden md:inline">Next</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>

            <div className="h-4 w-px bg-slate-800 mx-1 hidden sm:block" />

            {/* Bookmark Action */}
            <button
              onClick={() => onToggleBookmark(invariant.id)}
              className={`p-2 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-colors ${
                isBookmarked
                  ? 'border-amber-500/40 text-amber-300 bg-amber-500/10'
                  : 'border-slate-800 text-slate-400 hover:text-white bg-slate-900'
              }`}
              title={isBookmarked ? 'Remove bookmark' : 'Bookmark this rule'}
            >
              {isBookmarked ? (
                <BookmarkCheck className="w-4 h-4 fill-amber-400/20 text-amber-400" />
              ) : (
                <Bookmark className="w-4 h-4" />
              )}
            </button>

            {/* Mastered Action */}
            <button
              onClick={() => onToggleMastered(invariant.id)}
              className={`p-2 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-colors ${
                isMastered
                  ? 'border-emerald-500/40 text-emerald-300 bg-emerald-500/10'
                  : 'border-slate-800 text-slate-400 hover:text-white bg-slate-900'
              }`}
              title={isMastered ? 'Mark as unmastered' : 'Mark as mastered'}
            >
              <CheckCircle2
                className={`w-4 h-4 ${
                  isMastered ? 'text-emerald-400 fill-emerald-400/20' : ''
                }`}
              />
            </button>

            {/* Copy Full Rule */}
            <button
              onClick={handleCopyRule}
              className="px-2.5 py-1.5 rounded-lg border border-slate-800 bg-slate-900 text-slate-300 hover:text-white hover:border-slate-700 transition-colors flex items-center gap-1.5 text-xs font-medium"
              title="Copy complete rule Markdown"
            >
              {copiedRule ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-300 font-semibold">Rule Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-slate-400" />
                  <span className="hidden sm:inline">Copy Rule</span>
                </>
              )}
            </button>

            {/* Copy Video Prompt (NotebookLM) */}
            <button
              onClick={handleCopyPrompt}
              className="px-2.5 py-1.5 rounded-lg border border-indigo-500/30 bg-indigo-950/40 text-indigo-300 hover:text-white hover:border-indigo-500/50 transition-colors flex items-center gap-1.5 text-xs font-medium"
              title="Copy 6-7 min NotebookLM / Video prompt for cinematic explainer"
            >
              {copiedPrompt ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span className="text-emerald-300 font-semibold">Prompt Copied!</span>
                </>
              ) : (
                <>
                  <Film className="w-3.5 h-3.5 text-amber-400" />
                  <span className="hidden sm:inline">Video Prompt</span>
                </>
              )}
            </button>

            {/* Share / Copy Link */}
            <button
              onClick={handleCopyLink}
              className="p-2 rounded-lg border border-slate-800 bg-slate-900 text-slate-400 hover:text-white transition-colors"
              title="Copy shareable link"
            >
              {copiedLink ? (
                <Check className="w-4 h-4 text-emerald-400" />
              ) : (
                <Share2 className="w-4 h-4" />
              )}
            </button>

            {/* Multi-Format Export & Print Dropdown */}
            <div className="relative">
              <button
                onClick={() => setExportMenuOpen(!exportMenuOpen)}
                className="px-2.5 py-2 rounded-lg border border-slate-800 bg-slate-900 text-slate-300 hover:text-white hover:border-slate-700 transition-colors flex items-center gap-1.5 text-xs font-medium"
                title="Export or print this security invariant in multiple formats"
              >
                <Download className="w-3.5 h-3.5 text-indigo-400" />
                <span className="hidden sm:inline">Export / Print</span>
                <ChevronDown className={`w-3 h-3 text-slate-500 transition-transform ${exportMenuOpen ? 'rotate-180' : ''}`} />
              </button>

              {exportMenuOpen && (
                <>
                  <div
                    className="fixed inset-0 z-40"
                    onClick={() => setExportMenuOpen(false)}
                  />
                  <div className="absolute right-0 mt-1.5 w-64 bg-slate-900 border border-slate-800 rounded-xl shadow-xl shadow-black/60 py-1.5 z-50 text-xs">
                    <div className="px-3 py-1.5 text-[10px] uppercase font-mono text-indigo-400 font-semibold border-b border-slate-800/80 flex items-center justify-between">
                      <span>Interview Prep & Hard Copy</span>
                    </div>

                    <button
                      onClick={() => {
                        const domainRules = allInvariants.filter(r => r.domain === invariant.domain);
                        openPrintableInterviewMasterBook(
                          domainRules,
                          `${invariant.domainName} - Complete Section Interview Handbook`
                        );
                        setExportMenuOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 text-indigo-300 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-colors border-b border-slate-800/60"
                    >
                      <Printer className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                      <div>
                        <div className="font-bold">Print Complete Section Handbook</div>
                        <div className="text-[10px] text-slate-400">All {allInvariants.filter(r => r.domain === invariant.domain).length} rules in {invariant.domainName}</div>
                      </div>
                    </button>

                    {associatedTopic && (
                      <button
                        onClick={() => {
                          const topicRules = getInvariantsForTopic(associatedTopic.id, allInvariants);
                          openPrintableTopicHandbook(associatedTopic, topicRules);
                          setExportMenuOpen(false);
                        }}
                        className="w-full text-left px-3 py-2 text-amber-300 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-colors border-b border-slate-800/60"
                      >
                        <Printer className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                        <div>
                          <div className="font-bold">Print Topic #{associatedTopic.topicNumber} Handbook</div>
                          <div className="text-[10px] text-slate-400">{associatedTopic.name} ({getInvariantsForTopic(associatedTopic.id, allInvariants).length} rules)</div>
                        </div>
                      </button>
                    )}

                    <button
                      onClick={() => {
                        openPrintableInterviewMasterBook([invariant], `${invariant.id} Interview Challenge Sheet`);
                        setExportMenuOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-colors"
                    >
                      <FileText className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                      <div>
                        <div className="font-medium">Print This Interview Sheet</div>
                        <div className="text-[10px] text-slate-500">Scenario, formula, diffs & spoken answer</div>
                      </div>
                    </button>

                    <button
                      onClick={() => {
                        const domainRules = allInvariants.filter(r => r.domain === invariant.domain);
                        openPrintableInterviewFlashSheets(domainRules, `${invariant.domainName} Flash Sheets`);
                        setExportMenuOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-colors"
                    >
                      <Printer className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <div>
                        <div className="font-medium">Print Section Flash Sheets</div>
                        <div className="text-[10px] text-slate-500">2-column rapid verbal recall</div>
                      </div>
                    </button>

                    <button
                      onClick={() => {
                        exportToInterviewMarkdown([invariant], `${invariant.id} Interview Guide`);
                        setExportMenuOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-colors"
                    >
                      <FileCode className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <div>
                        <div className="font-medium">Download Interview Markdown (.md)</div>
                        <div className="text-[10px] text-slate-500">Obsidian / GitHub / Notion ready</div>
                      </div>
                    </button>

                    <button
                      onClick={() => {
                        exportToBashTestHarness([invariant], `${invariant.id} Verification`);
                        setExportMenuOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-colors"
                    >
                      <Terminal className="w-3.5 h-3.5 text-violet-400 shrink-0" />
                      <div>
                        <div className="font-medium">Download Bash Test (.sh)</div>
                        <div className="text-[10px] text-slate-500">Runnable CLI test runner</div>
                      </div>
                    </button>

                    <button
                      onClick={() => {
                        exportToBaselineJSON([invariant]);
                        setExportMenuOpen(false);
                      }}
                      className="w-full text-left px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 transition-colors"
                    >
                      <Table className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                      <div>
                        <div className="font-medium">Download JSON Baseline</div>
                        <div className="text-[10px] text-slate-500">DevSecOps policy schema</div>
                      </div>
                    </button>

                    <div className="border-t border-slate-800/80 my-1" />

                    <button
                      onClick={() => {
                        window.print();
                        setExportMenuOpen(false);
                      }}
                      className="w-full text-left px-3 py-1.5 text-slate-400 hover:text-white hover:bg-slate-800 flex items-center gap-2.5 text-[11px] transition-colors"
                    >
                      <Printer className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                      <span>Browser Quick Print</span>
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Main Webpage Container */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          
          {/* Main Article Stream (Left/Center: 8 cols or 9 cols) */}
          <article className="lg:col-span-9 space-y-10 min-w-0">
            
            {/* 1. Header Banner & Identity */}
            <header className="space-y-4 pb-6 border-b border-slate-800">
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2.5 py-1 bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 rounded-md font-mono text-xs font-bold">
                  {invariant.id}
                </span>
                {invariant.sequenceOrder && (
                  <span className="px-2.5 py-1 bg-gradient-to-r from-indigo-500/20 via-purple-500/20 to-indigo-500/20 text-indigo-300 border border-indigo-500/30 rounded-md font-mono text-xs font-bold flex items-center gap-1.5 shadow-sm">
                    <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
                    Step {invariant.sequenceOrder} of 1036 · {invariant.tier} (Tier {invariant.tierLevel || 1})
                  </span>
                )}
                <span className="px-2.5 py-1 bg-slate-900 text-slate-300 border border-slate-800 rounded-md text-xs font-medium">
                  {invariant.domainName}
                </span>
                <span className="px-2.5 py-1 bg-slate-900 text-slate-400 border border-slate-800 rounded-md font-mono text-xs">
                  {invariant.subdomain}
                </span>
                <span
                  className={`px-2.5 py-1 rounded-md text-xs font-semibold ${
                    invariant.standardType === 'Mandatory Standard'
                      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  }`}
                >
                  {invariant.standardType}
                </span>
                <span className="px-2.5 py-1 bg-slate-900 text-slate-400 border border-slate-800 rounded-md text-xs font-mono">
                  Difficulty: {invariant.difficulty}
                </span>
              </div>

              <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-white tracking-tight leading-tight">
                {invariant.title}
              </h1>

              {/* Standards Grounding Badges */}
              <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                <span className="text-slate-500 font-mono">Governing Standards:</span>
                {invariant.standards.map((std, idx) => (
                  <span
                    key={idx}
                    className="px-2.5 py-0.5 rounded-full bg-slate-900 border border-indigo-500/30 text-indigo-300 font-mono text-xs"
                  >
                    {std}
                  </span>
                ))}
              </div>
            </header>

            {/* 2. Formal Invariant Section */}
            <section id="formal" className="scroll-mt-28 space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-indigo-500" />
                  <span>1. Formal Security Invariant Specification</span>
                </h2>
                <span className="text-xs text-slate-500 font-mono">
                  First-Order Logic / Mathematical Predicate
                </span>
              </div>

              <div className="bg-slate-900/90 border border-indigo-500/30 rounded-2xl p-5 sm:p-6 shadow-xl relative overflow-hidden">
                <div className="absolute top-0 right-0 px-3 py-1 bg-indigo-500/10 text-indigo-400 text-[10px] font-mono border-b border-l border-indigo-500/20 rounded-bl-lg">
                  FORMAL SPECIFICATION
                </div>
                
                <div className="p-4 bg-slate-950/90 border border-indigo-500/20 rounded-xl font-mono text-sm sm:text-base lg:text-lg text-indigo-200 overflow-x-auto leading-relaxed shadow-inner">
                  {invariant.formalInvariant}
                </div>

                {/* Symbol & Predicate Breakdown Cards */}
                <div className="mt-5 pt-4 border-t border-slate-800/80">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                      Mathematical Symbol Breakdown
                    </span>
                    <span className="text-[11px] text-slate-500">
                      Click any symbol to isolate
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs font-mono">
                    {invariant.symbolBreakdown.map((item, idx) => (
                      <div
                        key={idx}
                        onClick={() =>
                          setSelectedSymbol(selectedSymbol === item.symbol ? null : item.symbol)
                        }
                        className={`p-3 rounded-xl border transition-all cursor-pointer ${
                          selectedSymbol === item.symbol
                            ? 'bg-indigo-500/15 border-indigo-500/50 text-indigo-200 shadow-md ring-1 ring-indigo-500/30'
                            : 'bg-slate-950/70 border-slate-800 text-slate-300 hover:border-slate-700 hover:bg-slate-900'
                        }`}
                      >
                        <div className="font-bold text-indigo-400 mb-1">
                          {item.symbol}
                        </div>
                        <div className="font-sans text-slate-300 text-xs leading-relaxed">
                          {item.meaning}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </section>

            {/* 3. Plain-English Meaning */}
            <section id="plain" className="scroll-mt-28 space-y-3">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-sky-500" />
                <span>2. Plain-English Meaning & Concept Breakdown</span>
              </h2>
              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 sm:p-6 text-sm text-slate-200 leading-relaxed space-y-3">
                <p>{invariant.plainEnglish}</p>
                <div className="flex items-center gap-2 text-xs text-slate-400 pt-2 border-t border-slate-800 font-mono">
                  <Info className="w-4 h-4 text-sky-400 shrink-0" />
                  <span>
                    Translates the mathematical conditions into practical systems architecture requirements.
                  </span>
                </div>
              </div>
            </section>

            {/* 4. Why It Matters & Real-World Attack Scenario */}
            <section id="threat" className="scroll-mt-28 space-y-3">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-rose-500" />
                <span>3. Why It Matters: Real-World Exploit Scenario & Blast Radius</span>
              </h2>
              <div className="bg-rose-950/15 border border-rose-500/25 rounded-2xl p-5 sm:p-6 text-sm text-rose-100/90 leading-relaxed space-y-3 shadow-lg">
                <div className="flex items-center gap-2 text-rose-400 font-semibold text-xs tracking-wider uppercase font-mono">
                  <AlertOctagon className="w-4 h-4 text-rose-400 shrink-0" />
                  <span>Threat Model & Vulnerability Mechanics</span>
                </div>
                <p className="text-slate-200 text-sm leading-relaxed">
                  {invariant.whyItMatters}
                </p>
              </div>
            </section>

            {/* 5. Implementation: Vulnerable vs Secure Code */}
            <section id="code" className="scroll-mt-28 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  <span>4. Implementation: Vulnerable Pattern vs. Secure Defense</span>
                </h2>

                {/* View switcher: side-by-side vs tabs */}
                <div className="flex items-center p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs self-start sm:self-auto">
                  <button
                    onClick={() => setCodeTab('side-by-side')}
                    className={`px-3 py-1 rounded-md font-medium transition-colors ${
                      codeTab === 'side-by-side'
                        ? 'bg-indigo-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Side-by-Side
                  </button>
                  <button
                    onClick={() => setCodeTab('vulnerable')}
                    className={`px-3 py-1 rounded-md font-medium transition-colors ${
                      codeTab === 'vulnerable'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Vulnerable
                  </button>
                  <button
                    onClick={() => setCodeTab('secure')}
                    className={`px-3 py-1 rounded-md font-medium transition-colors ${
                      codeTab === 'secure'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Secure
                  </button>
                </div>
              </div>

              {/* Side by side grid on wide screens, stacked on small */}
              {codeTab === 'side-by-side' ? (
                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                  {/* Vulnerable Block */}
                  <div className="bg-slate-900/90 border border-rose-500/30 rounded-2xl overflow-hidden flex flex-col shadow-lg">
                    <div className="px-4 py-2.5 bg-rose-950/30 border-b border-rose-500/20 flex items-center justify-between text-xs font-mono text-rose-300">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-rose-500" />
                        <span className="font-bold">VULNERABLE CODE (VIOLATION)</span>
                      </div>
                      <span className="text-slate-400 text-[11px]">{invariant.vulnerableExample.language}</span>
                    </div>
                    <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed flex-1 bg-slate-950/60">
                      <code>{invariant.vulnerableExample.code}</code>
                    </pre>
                    <div className="p-3.5 bg-rose-950/20 border-t border-rose-500/20 text-xs text-rose-200/90">
                      <span className="font-semibold text-rose-300">Defect Analysis: </span>
                      {invariant.vulnerableExample.explanation}
                    </div>
                  </div>

                  {/* Secure Block */}
                  <div className="bg-slate-900/90 border border-emerald-500/30 rounded-2xl overflow-hidden flex flex-col shadow-lg">
                    <div className="px-4 py-2.5 bg-emerald-950/30 border-b border-emerald-500/20 flex items-center justify-between text-xs font-mono text-emerald-300">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-500" />
                        <span className="font-bold">HARDENED SECURE CODE (ENFORCED)</span>
                      </div>
                      <span className="text-slate-400 text-[11px]">{invariant.secureExample.language}</span>
                    </div>
                    <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed flex-1 bg-slate-950/60">
                      <code>{invariant.secureExample.code}</code>
                    </pre>
                    <div className="p-3.5 bg-emerald-950/20 border-t border-emerald-500/20 text-xs text-emerald-200/90">
                      <span className="font-semibold text-emerald-300">Defense Mechanism: </span>
                      {invariant.secureExample.explanation}
                    </div>
                  </div>
                </div>
              ) : codeTab === 'vulnerable' ? (
                <div className="bg-slate-900/90 border border-rose-500/30 rounded-2xl overflow-hidden shadow-lg">
                  <div className="px-4 py-2.5 bg-rose-950/30 border-b border-rose-500/20 flex items-center justify-between text-xs font-mono text-rose-300">
                    <span className="font-bold">FAILING INVARIANT PATTERN</span>
                    <span className="text-slate-400">{invariant.vulnerableExample.language}</span>
                  </div>
                  <pre className="p-4 sm:p-5 text-xs sm:text-sm font-mono text-slate-200 overflow-x-auto leading-relaxed bg-slate-950/60">
                    <code>{invariant.vulnerableExample.code}</code>
                  </pre>
                  <div className="p-4 bg-rose-950/20 border-t border-rose-500/20 text-xs sm:text-sm text-rose-200/90">
                    <span className="font-semibold text-rose-300">Defect Analysis: </span>
                    {invariant.vulnerableExample.explanation}
                  </div>
                </div>
              ) : (
                <div className="bg-slate-900/90 border border-emerald-500/30 rounded-2xl overflow-hidden shadow-lg">
                  <div className="px-4 py-2.5 bg-emerald-950/30 border-b border-emerald-500/20 flex items-center justify-between text-xs font-mono text-emerald-300">
                    <span className="font-bold">SECURE INVARIANT IMPLEMENTATION</span>
                    <span className="text-slate-400">{invariant.secureExample.language}</span>
                  </div>
                  <pre className="p-4 sm:p-5 text-xs sm:text-sm font-mono text-slate-200 overflow-x-auto leading-relaxed bg-slate-950/60">
                    <code>{invariant.secureExample.code}</code>
                  </pre>
                  <div className="p-4 bg-emerald-950/20 border-t border-emerald-500/20 text-xs sm:text-sm text-emerald-200/90">
                    <span className="font-semibold text-emerald-300">Defense Mechanism: </span>
                    {invariant.secureExample.explanation}
                  </div>
                </div>
              )}
            </section>

            {/* 6. Interactive Invariant Verifier */}
            <section id="verifier" className="scroll-mt-28 space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-purple-500" />
                  <span>5. Interactive Invariant Verifier & Live Testbench</span>
                </h2>
                <span className="text-xs text-slate-500 font-mono hidden sm:inline">
                  Interactive Evaluation Engine
                </span>
              </div>
              
              {/* Simulator Component */}
              <InteractiveSimulator invariant={invariant} />
            </section>

            {/* 7. How to Test & Concrete Validation Steps */}
            <section id="testing" className="scroll-mt-28 space-y-3">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-amber-500" />
                <span>6. How to Test: Validation Tools & Reproduction Procedure</span>
              </h2>

              <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 sm:p-6 space-y-4">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-slate-400 font-medium">Recommended Validation Tools:</span>
                  <div className="flex flex-wrap gap-1.5 font-mono">
                    {invariant.howToTest.tools.map((tool, idx) => (
                      <span
                        key={idx}
                        className="px-2.5 py-0.5 bg-slate-950 text-indigo-300 rounded border border-slate-800 text-xs"
                      >
                        {tool}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="space-y-2 pt-2 border-t border-slate-800">
                  <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono block">
                    Step-by-Step Validation Procedure:
                  </span>
                  <ol className="list-decimal list-inside space-y-2 text-xs sm:text-sm text-slate-300 leading-relaxed">
                    {invariant.howToTest.steps.map((step, idx) => (
                      <li key={idx} className="pl-1">
                        {step}
                      </li>
                    ))}
                  </ol>
                </div>

                <div className="pt-3 border-t border-slate-800">
                  <span className="text-xs text-slate-400 font-medium block mb-2 font-mono">
                    Reproduction / Audit CLI Command:
                  </span>
                  <div className="flex items-center justify-between gap-3 p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-indigo-200">
                    <code className="break-all">{invariant.howToTest.commandExample}</code>
                    <button
                      onClick={handleCopyCommand}
                      className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg shrink-0 transition-colors"
                      title="Copy command to clipboard"
                    >
                      {copiedCmd ? (
                        <Check className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </section>

            {/* 8. Interview Scenario Challenge */}
            <section id="interview" className="scroll-mt-28 space-y-3">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-indigo-500" />
                <span>7. Technical Interview Scenario & Systems Defense Challenge</span>
              </h2>

              <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 sm:p-6 space-y-5">
                {/* Scenario Description */}
                <div>
                  <span className="text-xs font-semibold text-indigo-400 uppercase tracking-wider font-mono block mb-1">
                    Scenario Context:
                  </span>
                  <p className="text-xs sm:text-sm text-slate-300 leading-relaxed bg-slate-950/60 p-4 rounded-xl border border-slate-800/80">
                    {invariant.interviewChallenge.scenario}
                  </p>
                </div>

                {/* Challenge Question */}
                <div>
                  <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider font-mono block mb-1">
                    Interview Challenge Question:
                  </span>
                  <p className="text-sm sm:text-base font-semibold text-white leading-relaxed">
                    {invariant.interviewChallenge.question}
                  </p>
                </div>

                {/* Hint Toggle */}
                <div>
                  <button
                    onClick={() => setShowHint(!showHint)}
                    className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1.5 font-medium transition-colors"
                  >
                    <HelpCircle className="w-3.5 h-3.5 text-amber-400" />
                    <span>{showHint ? 'Hide Hint' : 'Reveal Conceptual Hint'}</span>
                  </button>
                  {showHint && (
                    <div className="mt-2 p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl text-xs text-amber-200/90 leading-relaxed animate-in fade-in duration-200">
                      <span className="font-bold text-amber-300">Hint: </span>
                      {invariant.interviewChallenge.hint}
                    </div>
                  )}
                </div>

                {/* Answer Reveal Button */}
                <div className="pt-2 border-t border-slate-800">
                  {!showAnswer ? (
                    <button
                      onClick={() => setShowAnswer(true)}
                      className="px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs sm:text-sm font-semibold transition-colors flex items-center gap-2 shadow-sm"
                    >
                      <ShieldCheck className="w-4 h-4" />
                      <span>Reveal Technical Sample Answer & Key Takeaway</span>
                    </button>
                  ) : (
                    <div className="space-y-4 animate-in fade-in duration-200">
                      <div className="p-4 sm:p-5 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                        <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider font-mono block">
                          Comprehensive Technical Solution:
                        </span>
                        <p className="text-xs sm:text-sm text-slate-200 leading-relaxed">
                          {invariant.interviewChallenge.sampleAnswer}
                        </p>
                      </div>

                      <div className="p-3.5 bg-indigo-950/30 border border-indigo-500/25 rounded-xl text-xs text-indigo-200">
                        <span className="font-bold text-indigo-300 font-mono">Key Takeaway: </span>
                        {invariant.interviewChallenge.keyTakeaway}
                      </div>

                      <button
                        onClick={() => setShowAnswer(false)}
                        className="text-xs text-slate-500 hover:text-slate-400"
                      >
                        Hide Answer
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </section>

            {/* 9. Previous & Next Invariant Cards Footer */}
            <footer className="pt-8 border-t border-slate-800">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {prevInvariant ? (
                  <button
                    onClick={() => {
                      onSelectInvariant(prevInvariant);
                      window.scrollTo({ top: 0, behavior: 'smooth' });
                    }}
                    className="p-4 bg-slate-900/60 hover:bg-slate-900 border border-slate-800 hover:border-indigo-500/40 rounded-2xl text-left transition-all group"
                  >
                    <div className="flex items-center gap-1.5 text-xs text-slate-500 font-mono mb-1">
                      <ArrowLeft className="w-3.5 h-3.5 group-hover:-translate-x-1 transition-transform" />
                      <span>Previous Rule #{prevInvariant.ruleNumber}</span>
                    </div>
                    <div className="font-mono text-xs text-indigo-400 font-bold mb-1">
                      {prevInvariant.id}
                    </div>
                    <div className="text-sm font-semibold text-white group-hover:text-indigo-300 truncate">
                      {prevInvariant.title}
                    </div>
                  </button>
                ) : (
                  <div className="p-4 bg-slate-900/20 border border-slate-900 rounded-2xl opacity-40 text-xs text-slate-600">
                    Start of curriculum
                  </div>
                )}

                {nextInvariant ? (
                  <button
                    onClick={() => {
                      onSelectInvariant(nextInvariant);
                      window.scrollTo({ top: 0, behavior: 'smooth' });
                    }}
                    className="p-4 bg-slate-900/60 hover:bg-slate-900 border border-slate-800 hover:border-indigo-500/40 rounded-2xl text-right transition-all group"
                  >
                    <div className="flex items-center justify-end gap-1.5 text-xs text-slate-500 font-mono mb-1">
                      <span>Next Rule #{nextInvariant.ruleNumber}</span>
                      <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
                    </div>
                    <div className="font-mono text-xs text-indigo-400 font-bold mb-1">
                      {nextInvariant.id}
                    </div>
                    <div className="text-sm font-semibold text-white group-hover:text-indigo-300 truncate">
                      {nextInvariant.title}
                    </div>
                  </button>
                ) : (
                  <div className="p-4 bg-slate-900/20 border border-slate-900 rounded-2xl opacity-40 text-xs text-slate-600 text-right">
                    End of curriculum (Rule 511)
                  </div>
                )}
              </div>

              {/* Back to top button */}
              <div className="text-center mt-6">
                <button
                  onClick={onBack}
                  className="px-6 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white text-xs font-semibold transition-colors inline-flex items-center gap-2"
                >
                  <ArrowLeft className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Return to Full Invariants Directory</span>
                </button>
              </div>
            </footer>
          </article>

          {/* Table of Contents & Quick Jump Sidebar (Right: 3 cols on desktop) */}
          <aside className="hidden lg:block lg:col-span-3 sticky top-20 space-y-6">
            
            {/* Table of Contents Box */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 shadow-sm space-y-3">
              <span className="text-xs font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                <Compass className="w-3.5 h-3.5 text-indigo-400" />
                <span>On This Webpage</span>
              </span>

              <nav className="space-y-1 text-xs font-medium text-slate-400">
                <button
                  onClick={() => scrollToSection('formal')}
                  className={`w-full text-left px-2.5 py-1.5 rounded-lg transition-colors flex items-center gap-2 ${
                    activeSection === 'formal'
                      ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-500/20'
                      : 'hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-500" />
                  <span>1. Formal Invariant</span>
                </button>

                <button
                  onClick={() => scrollToSection('plain')}
                  className={`w-full text-left px-2.5 py-1.5 rounded-lg transition-colors flex items-center gap-2 ${
                    activeSection === 'plain'
                      ? 'bg-sky-600/10 text-sky-400 border border-sky-500/20'
                      : 'hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-sky-500" />
                  <span>2. Plain English</span>
                </button>

                <button
                  onClick={() => scrollToSection('threat')}
                  className={`w-full text-left px-2.5 py-1.5 rounded-lg transition-colors flex items-center gap-2 ${
                    activeSection === 'threat'
                      ? 'bg-rose-600/10 text-rose-400 border border-rose-500/20'
                      : 'hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                  <span>3. Attack Scenario</span>
                </button>

                <button
                  onClick={() => scrollToSection('code')}
                  className={`w-full text-left px-2.5 py-1.5 rounded-lg transition-colors flex items-center gap-2 ${
                    activeSection === 'code'
                      ? 'bg-emerald-600/10 text-emerald-400 border border-emerald-500/20'
                      : 'hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                  <span>4. Code Diffs</span>
                </button>

                <button
                  onClick={() => scrollToSection('verifier')}
                  className={`w-full text-left px-2.5 py-1.5 rounded-lg transition-colors flex items-center gap-2 ${
                    activeSection === 'verifier'
                      ? 'bg-purple-600/10 text-purple-400 border border-purple-500/20'
                      : 'hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-purple-500" />
                  <span>5. Live Verifier</span>
                </button>

                <button
                  onClick={() => scrollToSection('testing')}
                  className={`w-full text-left px-2.5 py-1.5 rounded-lg transition-colors flex items-center gap-2 ${
                    activeSection === 'testing'
                      ? 'bg-amber-600/10 text-amber-400 border border-amber-500/20'
                      : 'hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                  <span>6. How to Test</span>
                </button>

                <button
                  onClick={() => scrollToSection('interview')}
                  className={`w-full text-left px-2.5 py-1.5 rounded-lg transition-colors flex items-center gap-2 ${
                    activeSection === 'interview'
                      ? 'bg-indigo-600/10 text-indigo-400 border border-indigo-500/20'
                      : 'hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-500" />
                  <span>7. Interview Challenge</span>
                </button>
              </nav>
            </div>

            {/* Quick Domain Navigator */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 shadow-sm space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                  {invariant.domainName} Rules
                </span>
                <span className="text-[11px] font-mono text-indigo-400">
                  {domainIndex}/{domainInvariants.length}
                </span>
              </div>

              {/* Scrollable list of rules in this domain */}
              <div className="max-h-60 overflow-y-auto space-y-1 pr-1 font-mono text-[11px] scrollbar-thin">
                {domainInvariants.map(r => (
                  <button
                    key={r.id}
                    onClick={() => {
                      onSelectInvariant(r);
                      window.scrollTo({ top: 0, behavior: 'smooth' });
                    }}
                    className={`w-full text-left px-2 py-1.5 rounded truncate transition-colors flex items-center gap-1.5 ${
                      r.id === invariant.id
                        ? 'bg-indigo-600 text-white font-bold'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800'
                    }`}
                  >
                    <span className="shrink-0">{r.id}:</span>
                    <span className="truncate font-sans">{r.title}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Reading Status Card */}
            <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-2xl space-y-3 text-xs">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider font-mono block">
                Study Status
              </span>
              <div className="flex items-center justify-between text-slate-300">
                <span>Bookmarked:</span>
                <span className={isBookmarked ? 'text-amber-400 font-bold' : 'text-slate-500'}>
                  {isBookmarked ? 'Yes' : 'No'}
                </span>
              </div>
              <div className="flex items-center justify-between text-slate-300">
                <span>Mastered:</span>
                <span className={isMastered ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                  {isMastered ? 'Yes' : 'Not yet'}
                </span>
              </div>
              <div className="pt-2 border-t border-slate-800 flex gap-2">
                <button
                  onClick={() => onToggleBookmark(invariant.id)}
                  className="flex-1 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-300 hover:text-white transition-colors text-center"
                >
                  {isBookmarked ? 'Unbookmark' : 'Bookmark'}
                </button>
                <button
                  onClick={() => onToggleMastered(invariant.id)}
                  className="flex-1 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-slate-300 hover:text-white transition-colors text-center"
                >
                  {isMastered ? 'Unmaster' : 'Master'}
                </button>
              </div>
            </div>

          </aside>
        </div>
      </div>
    </div>
  );
};
