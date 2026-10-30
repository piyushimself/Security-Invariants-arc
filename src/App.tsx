import React, { useState, useMemo, useEffect } from 'react';
import { DomainId, SecurityInvariant, Difficulty, StandardType, SecurityTopicId, SecurityTopicMeta } from './types/invariants';
import { allInvariants, domainMetadata, searchInvariants, securityTopicsTaxonomy, getInvariantsForTopic } from './data/invariantsRegistry';
import { useUserProgress } from './hooks/useUserProgress';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { InvariantCard } from './components/InvariantCard';
import { InvariantPageView } from './components/InvariantPageView';
import { FlashcardsView } from './components/FlashcardsView';
import { QuizView } from './components/QuizView';
import { LearningPathsView } from './components/LearningPathsView';
import { MicroSessionsView } from './components/MicroSessionsView';
import { DashboardView } from './components/DashboardView';
import { ReportsView } from './components/ReportsView';
import { TopicsTaxonomyView } from './components/TopicsTaxonomyView';
import { AICopilotModal } from './components/AICopilotModal';
import {
  formatRuleAsMarkdown,
  generateNotebookLMPrompt,
  copyToClipboard
} from './utils/ruleExportHelpers';
import {
  openPrintableInterviewMasterBook,
  openPrintableDomainHandbook,
  openPrintableTopicHandbook
} from './utils/reportExporter';
import {
  Search,
  SlidersHorizontal,
  LayoutGrid,
  List,
  CheckCircle2,
  Bookmark,
  Award,
  BookOpen,
  ArrowRight,
  Shield,
  Sparkles,
  ChevronLeft,
  ChevronRight,
  X,
  Printer,
  FileText,
  Brain,
  Layers,
  Flame,
  Copy,
  Check,
  Film,
  Globe,
  Server,
  Code,
  Key,
  Lock,
  Fingerprint,
  Binary,
  Cloud,
  Cpu,
  Box,
  Boxes,
  Target,
  RotateCcw,
  ChevronDown,
  ChevronUp,
  Filter,
  CheckCircle,
  Eye,
  AlertTriangle,
  FolderOpen
} from 'lucide-react';

export default function App() {
  const {
    progress,
    toggleBookmark,
    toggleMastered,
    recordSRSReview,
    recordQuizResult,
    resetAllProgress
  } = useUserProgress();

  const [copiedRuleId, setCopiedRuleId] = useState<string | null>(null);
  const [copiedPromptId, setCopiedPromptId] = useState<string | null>(null);

  const handleCopyRule = async (inv: SecurityInvariant, e: React.MouseEvent) => {
    e.stopPropagation();
    const markdown = formatRuleAsMarkdown(inv);
    const success = await copyToClipboard(markdown);
    if (success) {
      setCopiedRuleId(inv.id);
      setTimeout(() => setCopiedRuleId(null), 2000);
    }
  };

  const handleCopyPrompt = async (inv: SecurityInvariant, e: React.MouseEvent) => {
    e.stopPropagation();
    const prompt = generateNotebookLMPrompt(inv);
    const success = await copyToClipboard(prompt);
    if (success) {
      setCopiedPromptId(inv.id);
      setTimeout(() => setCopiedPromptId(null), 2000);
    }
  };

  const handlePrintDomain = (domainId: DomainId | 'all') => {
    if (domainId === 'all') {
      openPrintableInterviewMasterBook(
        allInvariants,
        'Complete Security Invariants Master Handbook (All 15 Domains)',
        progress
      );
    } else {
      const domainRules = allInvariants.filter(r => r.domain === domainId);
      openPrintableDomainHandbook(domainId, domainRules, progress);
    }
  };

  const handlePrintTopic = (topicId: SecurityTopicId | 'all') => {
    if (topicId === 'all') {
      openPrintableInterviewMasterBook(
        allInvariants,
        'Complete 37 Security Topics Master Reference Handbook',
        progress
      );
    } else {
      const topic = securityTopicsTaxonomy.find(t => t.id === topicId);
      if (topic) {
        const topicRules = getInvariantsForTopic(topicId, allInvariants);
        openPrintableTopicHandbook(topic, topicRules, progress);
      }
    }
  };

  const [currentTab, setCurrentTab] = useState<
    'curriculum' | 'taxonomy' | 'tracks' | 'sessions' | 'flashcards' | 'quiz' | 'dashboard' | 'reports'
  >('curriculum');

const CANONICAL_DOMAINS: Array<{
  id: DomainId;
  index: number;
  name: string;
  clusterId: 'web_app' | 'identity' | 'cloud_infra' | 'frontier';
  icon: React.ComponentType<{ className?: string }>;
  accentColor: string;
  badgeStyle: string;
}> = [
  { id: 'http', index: 1, name: 'HTTP Protocols', clusterId: 'web_app', icon: Globe, accentColor: 'text-sky-400', badgeStyle: 'bg-sky-500/10 text-sky-400 border-sky-500/20' },
  { id: 'web', index: 2, name: 'Web Security', clusterId: 'web_app', icon: Shield, accentColor: 'text-indigo-400', badgeStyle: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20' },
  { id: 'api', index: 3, name: 'API Security', clusterId: 'web_app', icon: Server, accentColor: 'text-cyan-400', badgeStyle: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20' },
  { id: 'coding', index: 4, name: 'Secure Coding', clusterId: 'web_app', icon: Code, accentColor: 'text-emerald-400', badgeStyle: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' },
  { id: 'auth', index: 5, name: 'Authentication', clusterId: 'identity', icon: Key, accentColor: 'text-amber-400', badgeStyle: 'bg-amber-500/10 text-amber-400 border-amber-500/20' },
  { id: 'authz', index: 6, name: 'Authorization', clusterId: 'identity', icon: Lock, accentColor: 'text-rose-400', badgeStyle: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
  { id: 'oauth', index: 7, name: 'OAuth 2.0 & OIDC', clusterId: 'identity', icon: Fingerprint, accentColor: 'text-teal-400', badgeStyle: 'bg-teal-500/10 text-teal-400 border-teal-500/20' },
  { id: 'crypto', index: 8, name: 'Cryptography', clusterId: 'identity', icon: Binary, accentColor: 'text-violet-400', badgeStyle: 'bg-violet-500/10 text-violet-400 border-violet-500/20' },
  { id: 'cloud', index: 9, name: 'Cloud Security', clusterId: 'cloud_infra', icon: Cloud, accentColor: 'text-blue-400', badgeStyle: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
  { id: 'aws', index: 10, name: 'AWS Security', clusterId: 'cloud_infra', icon: Cpu, accentColor: 'text-orange-400', badgeStyle: 'bg-orange-500/10 text-orange-400 border-orange-500/20' },
  { id: 'containers', index: 11, name: 'Containers', clusterId: 'cloud_infra', icon: Box, accentColor: 'text-teal-400', badgeStyle: 'bg-teal-500/10 text-teal-400 border-teal-500/20' },
  { id: 'k8s', index: 12, name: 'Kubernetes', clusterId: 'cloud_infra', icon: Boxes, accentColor: 'text-blue-500', badgeStyle: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
  { id: 'ai', index: 13, name: 'AI & LLM Security', clusterId: 'frontier', icon: Sparkles, accentColor: 'text-fuchsia-400', badgeStyle: 'bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/20' },
  { id: 'smartcontracts', index: 14, name: 'Smart Contracts', clusterId: 'frontier', icon: Layers, accentColor: 'text-yellow-400', badgeStyle: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' },
  { id: 'threatmodeling', index: 15, name: 'Threat Modeling', clusterId: 'frontier', icon: Target, accentColor: 'text-pink-400', badgeStyle: 'bg-pink-500/10 text-pink-400 border-pink-500/20' },
];

const ARCHITECTURAL_CLUSTERS = [
  {
    id: 'web_app',
    title: 'Web & Application Security',
    description: 'HTTP framing, browser boundaries, API protocols & secure coding',
    domainIds: ['http', 'web', 'api', 'coding'] as DomainId[]
  },
  {
    id: 'identity',
    title: 'Identity, Access & Cryptography',
    description: 'Authentication secrets, authorization policies, OAuth/OIDC & primitives',
    domainIds: ['auth', 'authz', 'oauth', 'crypto'] as DomainId[]
  },
  {
    id: 'cloud_infra',
    title: 'Cloud & Infrastructure',
    description: 'Cloud perimeters, AWS IAM, container sandboxes & Kubernetes orchestrations',
    domainIds: ['cloud', 'aws', 'containers', 'k8s'] as DomainId[]
  },
  {
    id: 'frontier',
    title: 'Frontier, AI & Architecture',
    description: 'LLM guardrails, smart contract DeFi logic & formal threat modeling',
    domainIds: ['ai', 'smartcontracts', 'threatmodeling'] as DomainId[]
  }
];

  // Search & Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [filterMode, setFilterMode] = useState<'domains' | 'topics'>('domains');
  const [selectedDomain, setSelectedDomain] = useState<DomainId | 'all'>('all');
  const [selectedTopicId, setSelectedTopicId] = useState<SecurityTopicId | 'all'>('all');
  const [topicForCopilot, setTopicForCopilot] = useState<SecurityTopicMeta | null>(null);
  const [selectedDifficulty, setSelectedDifficulty] = useState<Difficulty | 'All'>('All');
  const [selectedStandardType, setSelectedStandardType] = useState<StandardType | 'All' | 'Rare'>('All');
  const [selectedPathway, setSelectedPathway] = useState<'all' | 'sequential' | 'tier1' | 'tier2' | 'tier3' | 'tier4'>('all');
  const [selectedStatus, setSelectedStatus] = useState<'all' | 'bookmarked' | 'mastered' | 'unmastered'>('all');
  const [domainLayout, setDomainLayout] = useState<'grid' | 'clusters' | 'compact'>('grid');
  const [isDomainSectionCollapsed, setIsDomainSectionCollapsed] = useState(false);
  const [viewMode, setViewMode] = useState<'grid' | 'table'>('grid');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 24;

  // Selected invariant for full webpage view (no popup modal)
  const [selectedInvariant, setSelectedInvariant] = useState<SecurityInvariant | null>(null);

  // AI Copilot Modal open state
  const [isAIChatOpen, setIsAIChatOpen] = useState(false);

  // Synchronize URL hash with selected invariant for direct deep-linking
  useEffect(() => {
    const handleHash = () => {
      const hash = window.location.hash;
      if (hash.startsWith('#rule=')) {
        const id = hash.replace('#rule=', '').trim();
        const found = allInvariants.find(
          r => r.id.toLowerCase() === id.toLowerCase() || r.ruleNumber.toString() === id
        );
        if (found) {
          setSelectedInvariant(found);
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }
      } else if (!hash && selectedInvariant) {
        setSelectedInvariant(null);
      }
    };

    handleHash();
    window.addEventListener('hashchange', handleHash);
    return () => window.removeEventListener('hashchange', handleHash);
  }, []);

  const handleOpenInvariant = (inv: SecurityInvariant | null) => {
    setSelectedInvariant(inv);
    if (inv) {
      window.location.hash = `rule=${inv.id}`;
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      if (window.location.hash.startsWith('#rule=')) {
        history.pushState('', document.title, window.location.pathname + window.location.search);
      }
    }
  };

  // Initial domain for flashcard practice
  const [flashcardDomain, setFlashcardDomain] = useState<DomainId | undefined>(undefined);
  // Initial domain for quiz practice
  const [quizDomain, setQuizDomain] = useState<DomainId | undefined>(undefined);

  // Quick reset all filters
  const handleResetFilters = () => {
    setSearchQuery('');
    setSelectedDomain('all');
    setSelectedTopicId('all');
    setSelectedDifficulty('All');
    setSelectedStandardType('All');
    setSelectedPathway('all');
    setSelectedStatus('all');
    setCurrentPage(1);
  };

  const hasActiveFilters = Boolean(
    searchQuery.trim() ||
    selectedDomain !== 'all' ||
    selectedTopicId !== 'all' ||
    selectedDifficulty !== 'All' ||
    selectedStandardType !== 'All' ||
    selectedPathway !== 'all' ||
    selectedStatus !== 'all'
  );

  // Filtered invariants (supports 15 Domains and 37 Vulnerability Topics)
  const filteredInvariants = useMemo(() => {
    let pool = allInvariants;

    // Pathway Filter
    if (selectedPathway === 'sequential') {
      pool = pool.filter(r => r.sequenceOrder !== undefined).sort((a, b) => (a.sequenceOrder || 0) - (b.sequenceOrder || 0));
    } else if (selectedPathway === 'tier1') {
      pool = pool.filter(r => r.tierLevel === 1);
    } else if (selectedPathway === 'tier2') {
      pool = pool.filter(r => r.tierLevel === 2);
    } else if (selectedPathway === 'tier3') {
      pool = pool.filter(r => r.tierLevel === 3);
    } else if (selectedPathway === 'tier4') {
      pool = pool.filter(r => r.tierLevel === 4);
    }

    // Study Status Filter
    if (selectedStatus === 'bookmarked') {
      const bSet = new Set(progress.bookmarkedIds);
      pool = pool.filter(r => bSet.has(r.id));
    } else if (selectedStatus === 'mastered') {
      const mSet = new Set(progress.masteredIds);
      pool = pool.filter(r => mSet.has(r.id));
    } else if (selectedStatus === 'unmastered') {
      const mSet = new Set(progress.masteredIds);
      pool = pool.filter(r => !mSet.has(r.id));
    }

    // Domain Filter
    if (selectedDomain !== 'all') {
      pool = pool.filter(r => r.domain === selectedDomain);
    }

    // Vulnerability Topic Filter
    if (selectedTopicId !== 'all') {
      pool = getInvariantsForTopic(selectedTopicId, pool);
    }

    // Difficulty Filter
    if (selectedDifficulty !== 'All') {
      pool = pool.filter(r => r.difficulty === selectedDifficulty);
    }

    // Standard Type & Rarity Filter
    if (selectedStandardType === 'Rare') {
      pool = pool.filter(r => r.isRareRule === true || r.tierLevel === 4);
    } else if (selectedStandardType !== 'All') {
      pool = pool.filter(r => r.standardType === selectedStandardType);
    }

    // Search Query Filter
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      pool = pool.filter(rule => {
        return (
          rule.id.toLowerCase().includes(q) ||
          String(rule.ruleNumber).includes(q) ||
          rule.title.toLowerCase().includes(q) ||
          rule.subdomain.toLowerCase().includes(q) ||
          rule.formalInvariant.toLowerCase().includes(q) ||
          rule.plainEnglish.toLowerCase().includes(q) ||
          rule.standards.some(s => s.toLowerCase().includes(q))
        );
      });
    }

    return pool;
  }, [
    searchQuery,
    selectedDomain,
    selectedTopicId,
    selectedDifficulty,
    selectedStandardType,
    selectedPathway,
    selectedStatus,
    progress.bookmarkedIds,
    progress.masteredIds
  ]);

  // Pagination slice
  const totalPages = Math.ceil(filteredInvariants.length / pageSize) || 1;
  const paginatedInvariants = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredInvariants.slice(start, start + pageSize);
  }, [filteredInvariants, currentPage]);

  const handleDomainFilter = (domainId: DomainId | 'all') => {
    setSelectedDomain(domainId);
    setCurrentPage(1);
  };

  const handleTopicFilter = (topicId: SecurityTopicId | 'all') => {
    setSelectedTopicId(topicId);
    setCurrentPage(1);
  };

  const handleSearchChange = (q: string) => {
    setSearchQuery(q);
    setCurrentPage(1);
  };

  const now = Date.now();
  const dueCount = allInvariants.filter(rule => {
    const srs = progress.srsData[rule.id];
    return srs ? srs.nextDueDate <= now : false;
  }).length;

  const handleStartTrackFlashcards = (domainIds: string[]) => {
    if (domainIds.length > 0) {
      setFlashcardDomain(domainIds[0] as DomainId);
    }
    handleOpenInvariant(null);
    setCurrentTab('flashcards');
  };

  const handleStartTrackQuiz = (domainIds?: string[]) => {
    if (domainIds && domainIds.length > 0) {
      setQuizDomain(domainIds[0] as DomainId);
    }
    handleOpenInvariant(null);
    setCurrentTab('quiz');
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 font-sans selection:bg-indigo-500/30 selection:text-indigo-200 w-full max-w-full overflow-x-hidden">
      {/* 3-Zone Top Bar */}
      <Header
        currentTab={currentTab}
        onSelectTab={tab => {
          handleOpenInvariant(null);
          setCurrentTab(tab);
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }}
        dueCount={dueCount}
        bookmarkedCount={progress.bookmarkedIds.length}
      />

      {/* Main Content Area */}
      <main className="flex-1 pb-16 w-full max-w-full overflow-x-hidden">
        {selectedInvariant ? (
          <InvariantPageView
            invariant={selectedInvariant}
            allInvariants={allInvariants}
            onSelectInvariant={handleOpenInvariant}
            onBack={() => handleOpenInvariant(null)}
            isBookmarked={progress.bookmarkedIds.includes(selectedInvariant.id)}
            isMastered={progress.masteredIds.includes(selectedInvariant.id)}
            onToggleBookmark={toggleBookmark}
            onToggleMastered={toggleMastered}
          />
        ) : (
          <>
            {currentTab === 'curriculum' && (
          <div className="max-w-7xl mx-auto px-3 sm:px-6 py-6 sm:py-8 space-y-6 sm:space-y-8 w-full max-w-full min-w-0">
            {/* Hero / Header Section */}
            <div className="border-b border-slate-800/80 pb-6 sm:pb-8">
              <div className="flex flex-col md:flex-row md:items-end justify-between gap-5">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-indigo-400 mb-2">
                    <span>{allInvariants.length} Formal Rules</span>
                    <span aria-hidden="true" className="text-slate-600">·</span>
                    <span>{Object.keys(domainMetadata).length} Security Domains</span>
                    <span aria-hidden="true" className="text-slate-600">·</span>
                    <span>RFC, NIST, OWASP & STRIDE Grounded</span>
                  </div>
                  <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-white tracking-tight">
                    Security Invariants Curriculum
                  </h1>
                  <p className="text-xs sm:text-sm text-slate-400 mt-2 max-w-2xl leading-relaxed">
                    Master essential formal invariants governing modern software systems. Each rule pairs mathematical logic with real-world exploit mechanics, secure code diffs, verification commands, and interview scenarios.
                  </p>
                </div>

                {/* Quick Action Badges */}
                <div className="flex flex-wrap sm:flex-nowrap items-center gap-2.5 shrink-0">
                  <button
                    onClick={() => setCurrentTab('flashcards')}
                    className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-200 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 shadow-sm"
                  >
                    <BookOpen className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Practice Cards</span>
                  </button>
                  <button
                    onClick={() => setCurrentTab('quiz')}
                    className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-200 rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 shadow-sm"
                  >
                    <Award className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Scenario Quiz</span>
                  </button>
                  <button
                    onClick={() => setCurrentTab('reports')}
                    className="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition-colors flex items-center gap-2 shadow-sm shadow-indigo-600/20"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    <span>Print Center</span>
                  </button>
                </div>
              </div>

              {/* Filter Mode Switcher: 15 Architecture Domains vs 37 Vulnerability Topics */}
              <div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-4 border-t border-slate-800/80">
                <div className="flex items-center gap-1.5 p-1 bg-slate-900 border border-slate-800 rounded-xl w-fit">
                  <button
                    onClick={() => {
                      setFilterMode('domains');
                      setCurrentPage(1);
                    }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                      filterMode === 'domains'
                        ? 'bg-indigo-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    <Layers className="w-3.5 h-3.5" />
                    <span>15 Architectural Domains</span>
                  </button>
                  <button
                    onClick={() => {
                      setFilterMode('topics');
                      setCurrentPage(1);
                    }}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                      filterMode === 'topics'
                        ? 'bg-indigo-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    <Flame className="w-3.5 h-3.5 text-amber-400" />
                    <span>37 Vulnerability Topics</span>
                  </button>
                </div>

                <div className="flex items-center gap-2">
                  {filterMode === 'domains' ? (
                    <>
                      {/* Domain View Layout Switcher */}
                      <div className="flex items-center p-0.5 bg-slate-900 border border-slate-800 rounded-lg text-xs">
                        <button
                          onClick={() => setDomainLayout('grid')}
                          className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors flex items-center gap-1 ${
                            domainLayout === 'grid'
                              ? 'bg-slate-800 text-white shadow-sm font-semibold'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                          title="Grid view: All 15 domains visible on screen"
                        >
                          <LayoutGrid className="w-3 h-3 text-indigo-400" />
                          <span className="hidden sm:inline">All 15 Grid</span>
                        </button>
                        <button
                          onClick={() => setDomainLayout('clusters')}
                          className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors flex items-center gap-1 ${
                            domainLayout === 'clusters'
                              ? 'bg-slate-800 text-white shadow-sm font-semibold'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                          title="Architectural clusters view"
                        >
                          <Boxes className="w-3 h-3 text-emerald-400" />
                          <span className="hidden sm:inline">Clusters</span>
                        </button>
                        <button
                          onClick={() => setDomainLayout('compact')}
                          className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors flex items-center gap-1 ${
                            domainLayout === 'compact'
                              ? 'bg-slate-800 text-white shadow-sm font-semibold'
                              : 'text-slate-400 hover:text-slate-200'
                          }`}
                          title="Compact wrap pills"
                        >
                          <List className="w-3 h-3 text-amber-400" />
                          <span className="hidden sm:inline">Tags</span>
                        </button>
                      </div>

                      <button
                        onClick={() => setIsDomainSectionCollapsed(c => !c)}
                        className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-white rounded-lg text-xs font-medium transition-colors flex items-center gap-1 shrink-0"
                        title={isDomainSectionCollapsed ? 'Expand Domain Panel' : 'Collapse Domain Panel'}
                      >
                        {isDomainSectionCollapsed ? (
                          <>
                            <ChevronDown className="w-3.5 h-3.5" />
                            <span className="text-[11px]">Show Domains</span>
                          </>
                        ) : (
                          <>
                            <ChevronUp className="w-3.5 h-3.5" />
                            <span className="text-[11px]">Collapse</span>
                          </>
                        )}
                      </button>

                      <button
                        onClick={() => handlePrintDomain('all')}
                        className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-indigo-300 hover:text-white border border-indigo-500/30 rounded-lg text-[11px] font-medium transition-colors flex items-center gap-1 shrink-0"
                        title="Print Complete 15 Domains Master Handbook"
                      >
                        <Printer className="w-3 h-3 text-indigo-400" />
                        <span className="hidden sm:inline">Print Master Book</span>
                      </button>
                    </>
                  ) : (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handlePrintTopic('all')}
                        className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 text-indigo-300 hover:text-white border border-indigo-500/30 rounded-lg text-[11px] font-medium transition-colors flex items-center gap-1 shrink-0"
                        title="Print Complete 37 Topics Master Handbook"
                      >
                        <Printer className="w-3 h-3 text-indigo-400" />
                        <span className="hidden sm:inline">Print All 37 Topics</span>
                      </button>
                      <button
                        onClick={() => setCurrentTab('taxonomy')}
                        className="text-xs text-indigo-400 hover:text-indigo-300 font-semibold flex items-center gap-1 shrink-0"
                      >
                        <span>Full Taxonomy Grid</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                </div>
              </div>

              {/* DOMAINS SECTION: ALL 15 DOMAINS ARE FULLY VISIBLE WITHOUT CLIPPING */}
              {filterMode === 'domains' && !isDomainSectionCollapsed && (
                <div className="mt-4 space-y-3">
                  {/* Grid Layout: Displays all 15 domains simultaneously in clean columns */}
                  {domainLayout === 'grid' && (
                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-5 gap-2.5 sm:gap-3">
                      {/* Tile 0: All Domains */}
                      <div
                        onClick={() => handleDomainFilter('all')}
                        className={`group relative p-2.5 sm:p-3 rounded-xl border text-left cursor-pointer transition-all flex flex-col justify-between ${
                          selectedDomain === 'all'
                            ? 'bg-indigo-950/60 border-indigo-500 ring-2 ring-indigo-500/30 shadow-lg shadow-indigo-950/50'
                            : 'bg-slate-900/60 border-slate-800/80 hover:bg-slate-900 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1.5 mb-1.5">
                          <span className="font-mono text-[10px] font-bold text-indigo-400 bg-indigo-500/10 px-1.5 py-0.5 rounded border border-indigo-500/20">
                            ALL 15
                          </span>
                          <button
                            onClick={e => {
                              e.stopPropagation();
                              handlePrintDomain('all');
                            }}
                            className="p-1 text-slate-500 hover:text-indigo-300 transition-colors rounded"
                            title="Print Master Invariants Handbook (All 15 Domains)"
                          >
                            <Printer className="w-3 h-3" />
                          </button>
                        </div>
                        <div>
                          <div className="text-xs font-bold text-white group-hover:text-indigo-200 line-clamp-1">
                            All Security Domains
                          </div>
                          <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                            {allInvariants.length} formal rules
                          </div>
                        </div>
                        <div className="mt-2 pt-1.5 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                          <span>{progress.masteredIds.length} mastered</span>
                          {selectedDomain === 'all' && (
                            <span className="text-indigo-400 font-bold flex items-center gap-0.5">
                              <CheckCircle className="w-3 h-3" /> Active
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Canonical 15 Domains */}
                      {CANONICAL_DOMAINS.map(dom => {
                        const meta = domainMetadata[dom.id];
                        const count = meta?.count || 0;
                        const masteredCount = allInvariants.filter(
                          r => r.domain === dom.id && progress.masteredIds.includes(r.id)
                        ).length;
                        const isSelected = selectedDomain === dom.id;
                        const IconComponent = dom.icon;

                        return (
                          <div
                            key={dom.id}
                            onClick={() => handleDomainFilter(dom.id)}
                            className={`group relative p-2.5 sm:p-3 rounded-xl border text-left cursor-pointer transition-all flex flex-col justify-between ${
                              isSelected
                                ? 'bg-indigo-950/60 border-indigo-500 ring-2 ring-indigo-500/30 shadow-lg shadow-indigo-950/50'
                                : 'bg-slate-900/60 border-slate-800/80 hover:bg-slate-900 hover:border-slate-700'
                            }`}
                          >
                            <div className="flex items-center justify-between gap-1.5 mb-1.5">
                              <div className="flex items-center gap-1.5">
                                <span className="font-mono text-[10px] font-bold text-slate-400 bg-slate-800/80 px-1.5 py-0.5 rounded">
                                  #{String(dom.index).padStart(2, '0')}
                                </span>
                                <IconComponent className={`w-3.5 h-3.5 ${dom.accentColor}`} />
                              </div>
                              <button
                                onClick={e => {
                                  e.stopPropagation();
                                  handlePrintDomain(dom.id);
                                }}
                                className="p-1 text-slate-500 hover:text-indigo-300 transition-colors rounded"
                                title={`Print ${dom.name} Handbook`}
                              >
                                <Printer className="w-3 h-3" />
                              </button>
                            </div>

                            <div>
                              <div className={`text-xs font-bold line-clamp-1 ${isSelected ? 'text-white' : 'text-slate-200 group-hover:text-white'}`}>
                                {dom.name}
                              </div>
                              <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                                {count} rules
                              </div>
                            </div>

                            <div className="mt-2 pt-1.5 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                              <span>
                                {masteredCount > 0 ? `${masteredCount}/${count}` : '0 mastered'}
                              </span>
                              {isSelected ? (
                                <span className="text-indigo-400 font-bold flex items-center gap-0.5">
                                  <CheckCircle className="w-3 h-3" /> Active
                                </span>
                              ) : (
                                <span className="text-slate-600 group-hover:text-slate-400">View</span>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* Clusters View: 4 Architectural Pillars */}
                  {domainLayout === 'clusters' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {ARCHITECTURAL_CLUSTERS.map(cluster => (
                        <div
                          key={cluster.id}
                          className="p-3.5 rounded-xl border border-slate-800/80 bg-slate-900/40 space-y-2.5"
                        >
                          <div className="flex items-center justify-between">
                            <div>
                              <div className="text-xs font-bold text-white flex items-center gap-1.5">
                                <Boxes className="w-3.5 h-3.5 text-indigo-400" />
                                <span>{cluster.title}</span>
                              </div>
                              <p className="text-[11px] text-slate-400">{cluster.description}</p>
                            </div>
                          </div>

                          <div className="grid grid-cols-2 gap-2">
                            {cluster.domainIds.map(domId => {
                              const dom = CANONICAL_DOMAINS.find(d => d.id === domId);
                              if (!dom) return null;
                              const meta = domainMetadata[domId];
                              const isSelected = selectedDomain === domId;
                              const IconComponent = dom.icon;
                              return (
                                <button
                                  key={domId}
                                  onClick={() => handleDomainFilter(domId)}
                                  className={`p-2 rounded-lg border text-left flex items-center justify-between transition-colors ${
                                    isSelected
                                      ? 'bg-indigo-950/70 border-indigo-500 text-white'
                                      : 'bg-slate-950/60 border-slate-800 text-slate-300 hover:bg-slate-900 hover:text-white'
                                  }`}
                                >
                                  <div className="flex items-center gap-2 min-w-0">
                                    <IconComponent className={`w-3.5 h-3.5 shrink-0 ${dom.accentColor}`} />
                                    <div className="min-w-0">
                                      <div className="text-xs font-semibold truncate">{dom.name}</div>
                                      <div className="text-[10px] text-slate-500 font-mono">{meta?.count || 0} rules</div>
                                    </div>
                                  </div>
                                  <span
                                    onClick={e => {
                                      e.stopPropagation();
                                      handlePrintDomain(domId);
                                    }}
                                    className="p-1 text-slate-500 hover:text-indigo-300 shrink-0"
                                    title={`Print ${dom.name}`}
                                  >
                                    <Printer className="w-3 h-3" />
                                  </span>
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Compact Tags View: Clean Wrapping Flex Badges (No horizontal clipping) */}
                  {domainLayout === 'compact' && (
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        onClick={() => handleDomainFilter('all')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
                          selectedDomain === 'all'
                            ? 'bg-indigo-600 text-white shadow-sm'
                            : 'bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800'
                        }`}
                      >
                        <span>All Domains ({allInvariants.length})</span>
                      </button>

                      {CANONICAL_DOMAINS.map(dom => {
                        const count = domainMetadata[dom.id]?.count || 0;
                        const isSelected = selectedDomain === dom.id;
                        const IconComponent = dom.icon;
                        return (
                          <button
                            key={dom.id}
                            onClick={() => handleDomainFilter(dom.id)}
                            className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
                              isSelected
                                ? 'bg-indigo-600 text-white shadow-sm'
                                : 'bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800'
                            }`}
                          >
                            <span className="font-mono text-[10px] opacity-70">#{String(dom.index).padStart(2, '0')}</span>
                            <IconComponent className={`w-3.5 h-3.5 ${isSelected ? 'text-white' : dom.accentColor}`} />
                            <span>{dom.name}</span>
                            <span className="text-[10px] opacity-70 font-mono">({count})</span>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* TOPICS SECTION: ALL 37 TOPICS ORGANIZED CLEANLY WITHOUT CLIPPING */}
              {filterMode === 'topics' && (
                <div className="mt-4 p-3 bg-slate-900/40 border border-slate-800/80 rounded-xl space-y-3">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="font-semibold text-slate-300">
                      Select any of the 37 Vulnerability Topics to filter curriculum:
                    </span>
                    <button
                      onClick={() => handleTopicFilter('all')}
                      className={`px-2.5 py-1 rounded text-xs transition-colors ${
                        selectedTopicId === 'all'
                          ? 'bg-indigo-600 text-white font-bold'
                          : 'text-indigo-400 hover:text-white'
                      }`}
                    >
                      Show All 37 Topics ({allInvariants.length} rules)
                    </button>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    {securityTopicsTaxonomy.map(topic => {
                      const isSelected = selectedTopicId === topic.id;
                      const count = getInvariantsForTopic(topic.id, allInvariants).length;
                      return (
                        <button
                          key={topic.id}
                          onClick={() => handleTopicFilter(topic.id)}
                          className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
                            isSelected
                              ? 'bg-indigo-600 text-white shadow-sm'
                              : 'bg-slate-950 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-900'
                          }`}
                        >
                          <span className="font-mono text-[10px] font-bold text-indigo-400">
                            #{String(topic.topicNumber).padStart(2, '0')}
                          </span>
                          <span>{topic.name.split('(')[0].split('&')[0].trim()}</span>
                          <span className="text-[10px] opacity-70 font-mono">({count})</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            {/* SENSEFUL MULTI-DIMENSIONAL FILTER CONTROL DASHBOARD */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 sm:p-4 space-y-3.5 shadow-sm">
              {/* Row 1: Comprehensive Search + Direct Domain Selector + Direct Topic Selector + Quick Reset */}
              <div className="flex flex-col lg:flex-row items-stretch lg:items-center gap-2.5 min-w-0">
                {/* Search input with count & clear */}
                <div className="relative flex-1 min-w-0">
                  <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={e => handleSearchChange(e.target.value)}
                    placeholder="Search rules, formal logic, CVE, standards (e.g. RFC 9112, BOLA, Argon2, reentrancy)..."
                    className="w-full pl-10 pr-9 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
                  />
                  {searchQuery && (
                    <button
                      onClick={() => handleSearchChange('')}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 p-0.5"
                      title="Clear search"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                {/* Direct Domain Select Dropdown */}
                <div className="relative shrink-0 sm:w-56">
                  <select
                    value={selectedDomain}
                    onChange={e => handleDomainFilter(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500 transition-colors appearance-none pr-8 cursor-pointer"
                  >
                    <option value="all">🌐 All 15 Domains ({allInvariants.length} Rules)</option>
                    {CANONICAL_DOMAINS.map(d => (
                      <option key={d.id} value={d.id}>
                        #{String(d.index).padStart(2, '0')}. {d.name} ({domainMetadata[d.id]?.count || 0})
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
                </div>

                {/* Direct Topic Select Dropdown */}
                <div className="relative shrink-0 sm:w-56">
                  <select
                    value={selectedTopicId}
                    onChange={e => handleTopicFilter(e.target.value as any)}
                    className="w-full bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500 transition-colors appearance-none pr-8 cursor-pointer"
                  >
                    <option value="all">🔥 All 37 Topics</option>
                    {securityTopicsTaxonomy.map(t => (
                      <option key={t.id} value={t.id}>
                        #{String(t.topicNumber).padStart(2, '0')} {t.name.split('(')[0].trim()}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500 pointer-events-none" />
                </div>

                {/* Reset All Filters Button */}
                {hasActiveFilters && (
                  <button
                    onClick={handleResetFilters}
                    className="px-3 py-2 bg-rose-950/40 hover:bg-rose-900/50 border border-rose-800/60 text-rose-300 hover:text-white rounded-lg text-xs font-semibold transition-colors flex items-center justify-center gap-1.5 shrink-0 shadow-sm"
                    title="Reset all search, domain, topic, and status filters"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Reset Filters</span>
                  </button>
                )}
              </div>

              {/* Row 2: Study Status Pills + Seniority + Standard & Rarity + Pathway + View Mode Switch */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800/60">
                {/* Study Status Pills */}
                <div className="flex items-center gap-1.5 p-1 bg-slate-950 border border-slate-800 rounded-lg text-xs">
                  <button
                    onClick={() => {
                      setSelectedStatus('all');
                      setCurrentPage(1);
                    }}
                    className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                      selectedStatus === 'all'
                        ? 'bg-slate-800 text-white font-semibold shadow-sm'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    All Rules
                  </button>
                  <button
                    onClick={() => {
                      setSelectedStatus('bookmarked');
                      setCurrentPage(1);
                    }}
                    className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors flex items-center gap-1 ${
                      selectedStatus === 'bookmarked'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold'
                        : 'text-slate-400 hover:text-amber-300'
                    }`}
                  >
                    <Bookmark className="w-3 h-3 text-amber-400" />
                    <span>Bookmarked ({progress.bookmarkedIds.length})</span>
                  </button>
                  <button
                    onClick={() => {
                      setSelectedStatus('mastered');
                      setCurrentPage(1);
                    }}
                    className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors flex items-center gap-1 ${
                      selectedStatus === 'mastered'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-semibold'
                        : 'text-slate-400 hover:text-emerald-300'
                    }`}
                  >
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                    <span>Mastered ({progress.masteredIds.length})</span>
                  </button>
                  <button
                    onClick={() => {
                      setSelectedStatus('unmastered');
                      setCurrentPage(1);
                    }}
                    className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                      selectedStatus === 'unmastered'
                        ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 font-semibold'
                        : 'text-slate-400 hover:text-indigo-300'
                    }`}
                  >
                    <span>Needs Practice</span>
                  </button>
                </div>

                {/* Dropdowns Group */}
                <div className="flex flex-wrap items-center gap-2">
                  {/* Seniority / Level Dropdown */}
                  <select
                    value={selectedDifficulty}
                    onChange={e => {
                      setSelectedDifficulty(e.target.value as any);
                      setCurrentPage(1);
                    }}
                    className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-indigo-500 shrink-0 cursor-pointer"
                  >
                    <option value="All">All Seniority Levels</option>
                    <option value="Beginner">Beginner (Foundations)</option>
                    <option value="Intermediate">Intermediate (Applied)</option>
                    <option value="Advanced">Advanced (Senior / Distributed)</option>
                    <option value="Expert">Expert (Staff / Principal)</option>
                  </select>

                  {/* Standard Type & Rarity Dropdown */}
                  <select
                    value={selectedStandardType}
                    onChange={e => {
                      setSelectedStandardType(e.target.value as any);
                      setCurrentPage(1);
                    }}
                    className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-indigo-500 shrink-0 cursor-pointer"
                  >
                    <option value="All">All Standards & Rarity</option>
                    <option value="Mandatory Standard">Mandatory Standards</option>
                    <option value="Defense-in-Depth">Defense-in-Depth</option>
                    <option value="Rare">🚨 Zero-Day & Rare Vectors</option>
                  </select>

                  {/* Learning Pathway Dropdown */}
                  <select
                    value={selectedPathway}
                    onChange={e => {
                      setSelectedPathway(e.target.value as any);
                      setCurrentPage(1);
                    }}
                    className="bg-slate-950 border border-indigo-500/30 text-indigo-300 font-medium text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-indigo-400 shrink-0 cursor-pointer max-w-[190px] truncate"
                  >
                    <option value="all">Full Database (2,146 Rules)</option>
                    <option value="sequential">Sequential Steps (1–1036)</option>
                    <option value="tier1">Tier 1: Foundations (1–259)</option>
                    <option value="tier2">Tier 2: Applied Defense (260–518)</option>
                    <option value="tier3">Tier 3: Distributed Systems (519–777)</option>
                    <option value="tier4">Tier 4: Staff Frontier (778–1036)</option>
                  </select>

                  {/* View Mode Switcher */}
                  <div className="flex items-center p-0.5 bg-slate-950 border border-slate-800 rounded-lg shrink-0">
                    <button
                      onClick={() => setViewMode('grid')}
                      className={`p-1.5 rounded transition-colors ${
                        viewMode === 'grid' ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-slate-300'
                      }`}
                      title="Grid Card View"
                    >
                      <LayoutGrid className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => setViewMode('table')}
                      className={`p-1.5 rounded transition-colors ${
                        viewMode === 'table' ? 'bg-slate-800 text-white' : 'text-slate-500 hover:text-slate-300'
                      }`}
                      title="Compact Table View"
                    >
                      <List className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>

              {/* Row 3: Active Filters Summary Chips (Dismissable) */}
              {hasActiveFilters && (
                <div className="flex flex-wrap items-center justify-between gap-2 pt-2.5 border-t border-slate-800/50 text-xs">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-slate-400 font-medium text-[11px] mr-1">Active filters:</span>

                    {searchQuery.trim() && (
                      <span className="px-2 py-0.5 rounded-md bg-indigo-500/20 text-indigo-200 border border-indigo-500/30 text-[11px] flex items-center gap-1">
                        Search: "{searchQuery}"
                        <button onClick={() => handleSearchChange('')} className="hover:text-white">
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    )}

                    {selectedDomain !== 'all' && (
                      <span className="px-2 py-0.5 rounded-md bg-sky-500/20 text-sky-200 border border-sky-500/30 text-[11px] flex items-center gap-1">
                        Domain: {domainMetadata[selectedDomain]?.name}
                        <button onClick={() => handleDomainFilter('all')} className="hover:text-white">
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    )}

                    {selectedTopicId !== 'all' && (
                      <span className="px-2 py-0.5 rounded-md bg-amber-500/20 text-amber-200 border border-amber-500/30 text-[11px] flex items-center gap-1">
                        Topic: #{securityTopicsTaxonomy.find(t => t.id === selectedTopicId)?.topicNumber}
                        <button onClick={() => handleTopicFilter('all')} className="hover:text-white">
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    )}

                    {selectedStatus !== 'all' && (
                      <span className="px-2 py-0.5 rounded-md bg-emerald-500/20 text-emerald-200 border border-emerald-500/30 text-[11px] flex items-center gap-1">
                        Status: {selectedStatus}
                        <button onClick={() => setSelectedStatus('all')} className="hover:text-white">
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    )}

                    {selectedDifficulty !== 'All' && (
                      <span className="px-2 py-0.5 rounded-md bg-violet-500/20 text-violet-200 border border-violet-500/30 text-[11px] flex items-center gap-1">
                        Level: {selectedDifficulty}
                        <button onClick={() => setSelectedDifficulty('All')} className="hover:text-white">
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    )}

                    {selectedStandardType !== 'All' && (
                      <span className="px-2 py-0.5 rounded-md bg-rose-500/20 text-rose-200 border border-rose-500/30 text-[11px] flex items-center gap-1">
                        Type: {selectedStandardType === 'Rare' ? 'Zero-Day / Rare' : selectedStandardType}
                        <button onClick={() => setSelectedStandardType('All')} className="hover:text-white">
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    )}

                    {selectedPathway !== 'all' && (
                      <span className="px-2 py-0.5 rounded-md bg-indigo-500/20 text-indigo-200 border border-indigo-500/30 text-[11px] flex items-center gap-1">
                        Pathway: {selectedPathway}
                        <button onClick={() => setSelectedPathway('all')} className="hover:text-white">
                          <X className="w-3 h-3" />
                        </button>
                      </span>
                    )}

                    <button
                      onClick={handleResetFilters}
                      className="text-xs text-rose-400 hover:text-rose-300 hover:underline ml-1 font-medium"
                    >
                      Clear all
                    </button>
                  </div>

                  <div className="text-[11px] font-mono text-slate-400">
                    {filteredInvariants.length} rules matched
                  </div>
                </div>
              )}
            </div>

            {/* Results count & Pagination stats */}
            <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
              <span>
                Showing {paginatedInvariants.length > 0 ? (currentPage - 1) * pageSize + 1 : 0}–
                {Math.min(currentPage * pageSize, filteredInvariants.length)} of {filteredInvariants.length} rules
                {filteredInvariants.length !== allInvariants.length && (
                  <span className="text-slate-500 ml-1">(filtered from {allInvariants.length} total)</span>
                )}
              </span>
              <span>
                Page {currentPage} of {totalPages}
              </span>
            </div>

            {/* Invariants Grid / Table */}
            {filteredInvariants.length === 0 ? (
              <div className="text-center py-16 bg-slate-900/40 border border-slate-800 rounded-xl p-8 space-y-3">
                <p className="text-sm text-slate-300">No security invariants match your current filter criteria.</p>
                <p className="text-xs text-slate-500 max-w-md mx-auto">
                  Try clearing specific filters or click below to restore the full curriculum of 2,146 rules.
                </p>
                <button
                  onClick={handleResetFilters}
                  className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition-colors inline-flex items-center gap-1.5 shadow-sm"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Reset All Filters (2,146 Rules)</span>
                </button>
              </div>
            ) : viewMode === 'grid' ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {paginatedInvariants.map(inv => (
                  <InvariantCard
                    key={inv.id}
                    invariant={inv}
                    isBookmarked={progress.bookmarkedIds.includes(inv.id)}
                    isMastered={progress.masteredIds.includes(inv.id)}
                    onToggleBookmark={toggleBookmark}
                    onToggleMastered={toggleMastered}
                    onOpenDetails={handleOpenInvariant}
                  />
                ))}
              </div>
            ) : (
              /* Compact Table View */
              <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/40">
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase font-mono text-[11px]">
                      <tr>
                        <th className="py-3 px-4">ID</th>
                        <th className="py-3 px-4">Title & Subdomain</th>
                        <th className="py-3 px-4">Formal Invariant</th>
                        <th className="py-3 px-4">Standard</th>
                        <th className="py-3 px-4">Type</th>
                        <th className="py-3 px-4 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80 font-sans">
                      {paginatedInvariants.map(inv => (
                        <tr
                          key={inv.id}
                          onClick={() => handleOpenInvariant(inv)}
                          className="hover:bg-slate-900/80 transition-colors cursor-pointer group"
                        >
                          <td className="py-3 px-4 font-mono text-indigo-400 font-semibold whitespace-nowrap">
                            {inv.id}
                          </td>
                          <td className="py-3 px-4">
                            <div className="font-semibold text-white group-hover:text-indigo-300">
                              {inv.title}
                            </div>
                            <div className="text-[11px] text-slate-400 font-mono">
                              {inv.domainName} · {inv.subdomain}
                            </div>
                          </td>
                          <td className="py-3 px-4 font-mono text-indigo-200/90 text-[11px] max-w-xs truncate">
                            {inv.formalInvariant}
                          </td>
                          <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                            {inv.standards[0]}
                          </td>
                          <td className="py-3 px-4 whitespace-nowrap">
                            <span
                              className={`text-[11px] ${
                                inv.standardType === 'Mandatory Standard'
                                  ? 'text-rose-400'
                                  : 'text-emerald-400'
                              }`}
                            >
                              {inv.standardType === 'Mandatory Standard' ? 'Mandatory' : 'Defense'}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-right whitespace-nowrap">
                            <button
                              onClick={e => handleCopyRule(inv, e)}
                              title="Copy complete rule Markdown"
                              className="p-1 text-slate-400 hover:text-white mr-1 transition-colors"
                            >
                              {copiedRuleId === inv.id ? (
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                            <button
                              onClick={e => handleCopyPrompt(inv, e)}
                              title="Copy 6-7 min NotebookLM / Video prompt"
                              className="p-1 text-slate-400 hover:text-amber-400 mr-1.5 transition-colors"
                            >
                              {copiedPromptId === inv.id ? (
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <Film className="w-3.5 h-3.5 text-amber-400/80" />
                              )}
                            </button>
                            <button
                              onClick={e => {
                                e.stopPropagation();
                                toggleBookmark(inv.id);
                              }}
                              className="p-1 text-slate-400 hover:text-amber-400 mr-1"
                            >
                              <Bookmark
                                className={`w-3.5 h-3.5 ${
                                  progress.bookmarkedIds.includes(inv.id)
                                    ? 'text-amber-400 fill-amber-400/20'
                                    : ''
                                }`}
                              />
                            </button>
                            <button
                              onClick={e => {
                                e.stopPropagation();
                                toggleMastered(inv.id);
                              }}
                              className="p-1 text-slate-400 hover:text-emerald-400"
                            >
                              <CheckCircle2
                                className={`w-3.5 h-3.5 ${
                                  progress.masteredIds.includes(inv.id)
                                    ? 'text-emerald-400 fill-emerald-400/20'
                                    : ''
                                }`}
                              />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between pt-6 border-t border-slate-800">
                <button
                  onClick={() => {
                    setCurrentPage(p => Math.max(1, p - 1));
                    window.scrollTo({ top: 300, behavior: 'smooth' });
                  }}
                  disabled={currentPage === 1}
                  className="px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed text-xs font-medium flex items-center gap-1.5 transition-colors"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                  <span>Previous</span>
                </button>

                <div className="flex items-center gap-1 text-xs font-mono">
                  {Array.from({ length: Math.min(7, totalPages) }, (_, i) => {
                    let pageNum = i + 1;
                    if (totalPages > 7 && currentPage > 4) {
                      pageNum = Math.min(totalPages - 6 + i, currentPage - 3 + i);
                    }
                    return (
                      <button
                        key={pageNum}
                        onClick={() => {
                          setCurrentPage(pageNum);
                          window.scrollTo({ top: 300, behavior: 'smooth' });
                        }}
                        className={`w-7 h-7 rounded text-xs transition-colors ${
                          currentPage === pageNum
                            ? 'bg-indigo-600 text-white font-bold'
                            : 'text-slate-400 hover:text-white hover:bg-slate-900'
                        }`}
                      >
                        {pageNum}
                      </button>
                    );
                  })}
                </div>

                <button
                  onClick={() => {
                    setCurrentPage(p => Math.min(totalPages, p + 1));
                    window.scrollTo({ top: 300, behavior: 'smooth' });
                  }}
                  disabled={currentPage === totalPages}
                  className="px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed text-xs font-medium flex items-center gap-1.5 transition-colors"
                >
                  <span>Next</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        )}

        {currentTab === 'taxonomy' && (
          <div className="max-w-7xl mx-auto px-4 sm:px-6 pt-6">
            <TopicsTaxonomyView
              onOpenRule={handleOpenInvariant}
              onFilterCurriculumTopic={topicId => {
                setFilterMode('topics');
                setSelectedTopicId(topicId);
                setCurrentTab('curriculum');
                window.scrollTo({ top: 300, behavior: 'smooth' });
              }}
              masteredIds={progress.masteredIds}
            />
          </div>
        )}

        {currentTab === 'tracks' && (
          <LearningPathsView
            masteredIds={progress.masteredIds}
            bookmarkedIds={progress.bookmarkedIds}
            onOpenRule={handleOpenInvariant}
            onStartTrackFlashcards={handleStartTrackFlashcards}
            onStartTrackQuiz={handleStartTrackQuiz}
          />
        )}

        {currentTab === 'sessions' && (
          <MicroSessionsView
            progress={progress}
            onOpenRule={handleOpenInvariant}
            onToggleBookmark={toggleBookmark}
            onToggleMastered={toggleMastered}
            onRecordSRS={recordSRSReview}
          />
        )}

        {currentTab === 'flashcards' && (
          <FlashcardsView
            bookmarkedIds={progress.bookmarkedIds}
            masteredIds={progress.masteredIds}
            srsData={progress.srsData}
            onToggleBookmark={toggleBookmark}
            onToggleMastered={toggleMastered}
            onRecordSRS={recordSRSReview}
            initialDomain={flashcardDomain}
          />
        )}

        {currentTab === 'quiz' && (
          <QuizView
            key={quizDomain || 'all'}
            initialDomain={quizDomain}
            onRecordQuizResult={recordQuizResult}
            onOpenDetails={handleOpenInvariant}
          />
        )}

        {currentTab === 'dashboard' && (
          <DashboardView
            progress={progress}
            onOpenRule={handleOpenInvariant}
            onStartDueReview={() => setCurrentTab('flashcards')}
            onResetProgress={resetAllProgress}
            onOpenReports={() => setCurrentTab('reports')}
          />
        )}

        {currentTab === 'reports' && (
          <ReportsView
            progress={progress}
            onOpenRule={handleOpenInvariant}
          />
        )}
          </>
        )}
      </main>

      {/* Sleek Floating AI Security Chat Bubble */}
      <button
        onClick={() => {
          setTopicForCopilot(null);
          setIsAIChatOpen(true);
        }}
        className="fixed bottom-6 right-6 z-40 px-3.5 py-3 bg-gradient-to-r from-indigo-600 via-indigo-500 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white rounded-full shadow-2xl shadow-indigo-600/40 hover:scale-105 active:scale-95 transition-all flex items-center gap-2 border border-indigo-400/30 group ring-4 ring-indigo-500/10"
        title="Chat with Security AI Assistant & Build Custom Reports"
        aria-label="Open Security AI Assistant"
      >
        <div className="relative">
          <Brain className="w-5 h-5 text-indigo-100" />
          <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-emerald-400 rounded-full border-2 border-indigo-900 animate-pulse" />
        </div>
        <span className="font-bold text-xs tracking-wide">Ask AI</span>
        <Sparkles className="w-3.5 h-3.5 text-amber-300" />
      </button>

      {/* AI Copilot & Custom Report Generator Modal */}
      <AICopilotModal
        isOpen={isAIChatOpen}
        onClose={() => {
          setIsAIChatOpen(false);
          setTopicForCopilot(null);
        }}
        activeInvariant={selectedInvariant}
        initialTopic={topicForCopilot}
        onOpenInvariant={handleOpenInvariant}
        userMasteredCount={progress.masteredIds.length}
        userTotalCount={allInvariants.length}
      />

      {/* Clean Footer */}
      <Footer />
    </div>
  );
}
