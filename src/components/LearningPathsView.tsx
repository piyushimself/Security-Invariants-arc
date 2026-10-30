import React, { useState, useMemo } from 'react';
import { LearningPath, SecurityInvariant, Difficulty, DomainId } from '../types/invariants';
import {
  sectionLearningPaths,
  curatedLearningPaths,
  learningPaths,
  allInvariants,
  domainMetadata
} from '../data/invariantsRegistry';
import {
  openPrintableInterviewMasterBook,
  openPrintableInterviewFlashSheets,
  exportToInterviewMarkdown
} from '../utils/reportExporter';
import {
  Compass,
  CheckCircle2,
  Clock,
  Briefcase,
  ChevronRight,
  ArrowRight,
  BookOpen,
  Award,
  Layers,
  Sparkles,
  Shield,
  Zap,
  Printer,
  Target,
  GraduationCap,
  Search,
  Check,
  TrendingUp,
  Brain,
  Download,
  Code2,
  FileText,
  Lock,
  Server,
  Cpu,
  FileCheck
} from 'lucide-react';

interface LearningPathsViewProps {
  masteredIds: string[];
  bookmarkedIds: string[];
  onOpenRule: (invariant: SecurityInvariant) => void;
  onStartTrackFlashcards: (domainIds: string[]) => void;
  onStartTrackQuiz?: (domainIds: string[]) => void;
}

export const LearningPathsView: React.FC<LearningPathsViewProps> = ({
  masteredIds,
  bookmarkedIds,
  onOpenRule,
  onStartTrackFlashcards,
  onStartTrackQuiz
}) => {
  // Top-level Navigation Mode: Progressive Domain Curricula (1-15) vs Career/Sprint Tracks
  const [learningMode, setLearningMode] = useState<'sections' | 'tracks'>('sections');

  // Progressive Domain Curricula State
  const [activeSectionId, setActiveSectionId] = useState<string>(sectionLearningPaths[0].id);
  const [selectedStage, setSelectedStage] = useState<'all' | 'stage1' | 'stage2' | 'stage3'>('all');
  const [sectionSearchQuery, setSectionSearchQuery] = useState('');

  // Career / Curated Tracks State
  const [activeTrackId, setActiveTrackId] = useState<string>(curatedLearningPaths[0].id);
  const [selectedCategory, setSelectedCategory] = useState<'All' | 'Career-Role' | 'Foundational-Tier' | 'Interview-Sprint' | 'Specialized'>('All');
  const [selectedDifficulty, setSelectedDifficulty] = useState<Difficulty | 'All'>('All');
  const [trackSearchQuery, setTrackSearchQuery] = useState('');
  const [showAdvisorModal, setShowAdvisorModal] = useState(false);

  // Guided Decision Advisor State
  const [advisorGoal, setAdvisorGoal] = useState<'interview' | 'cloud' | 'ai' | 'appsec' | 'foundations' | 'crypto'>('interview');
  const [advisorTime, setAdvisorTime] = useState<'sprint' | 'targeted' | 'deep'>('sprint');

  // Filtered Progressive Sections
  const filteredSections = useMemo(() => {
    return sectionLearningPaths.filter(sec => {
      const num = sec.sectionNumber || 0;
      if (selectedStage === 'stage1' && (num < 1 || num > 6)) return false;
      if (selectedStage === 'stage2' && (num < 7 || num > 11)) return false;
      if (selectedStage === 'stage3' && (num < 12 || num > 15)) return false;

      if (sectionSearchQuery.trim()) {
        const q = sectionSearchQuery.toLowerCase();
        const matchesTitle = sec.title.toLowerCase().includes(q);
        const matchesTagline = sec.tagline.toLowerCase().includes(q);
        const matchesSkills = sec.keySkills.some(s => s.toLowerCase().includes(q));
        const matchesDesc = sec.description.toLowerCase().includes(q);
        if (!matchesTitle && !matchesTagline && !matchesSkills && !matchesDesc) return false;
      }
      return true;
    });
  }, [selectedStage, sectionSearchQuery]);

  // Active Section
  const activeSection = useMemo(() => {
    return sectionLearningPaths.find(s => s.id === activeSectionId) || sectionLearningPaths[0];
  }, [activeSectionId]);

  // Invariants in Active Section
  const sectionInvariants = useMemo(() => {
    return allInvariants.filter(r => activeSection.domainIds.includes(r.domain));
  }, [activeSection]);

  const masteredInSection = useMemo(() => {
    return sectionInvariants.filter(r => masteredIds.includes(r.id)).length;
  }, [sectionInvariants, masteredIds]);

  const sectionProgressPercent = Math.round((masteredInSection / (sectionInvariants.length || 1)) * 100);

  // Search inside Active Section
  const [sectionRuleSearch, setSectionRuleSearch] = useState('');
  const displayedRulesInSection = useMemo(() => {
    if (!sectionRuleSearch.trim()) return sectionInvariants;
    const q = sectionRuleSearch.toLowerCase();
    return sectionInvariants.filter(r =>
      r.id.toLowerCase().includes(q) ||
      r.title.toLowerCase().includes(q) ||
      r.subdomain.toLowerCase().includes(q) ||
      r.formalInvariant.toLowerCase().includes(q) ||
      r.plainEnglish.toLowerCase().includes(q)
    );
  }, [sectionInvariants, sectionRuleSearch]);

  // Filtered Curated Tracks
  const filteredCuratedTracks = useMemo(() => {
    return curatedLearningPaths.filter(path => {
      if (selectedCategory !== 'All' && path.category !== selectedCategory) return false;
      if (selectedDifficulty !== 'All' && path.difficulty !== selectedDifficulty) return false;
      if (trackSearchQuery.trim()) {
        const q = trackSearchQuery.toLowerCase();
        const matchesTitle = path.title.toLowerCase().includes(q);
        const matchesTagline = path.tagline.toLowerCase().includes(q);
        const matchesRole = path.targetRole.toLowerCase().includes(q);
        const matchesSkills = path.keySkills.some(s => s.toLowerCase().includes(q));
        if (!matchesTitle && !matchesTagline && !matchesRole && !matchesSkills) return false;
      }
      return true;
    });
  }, [selectedCategory, selectedDifficulty, trackSearchQuery]);

  // Active Curated Track
  const activeTrack = useMemo(() => {
    return curatedLearningPaths.find(p => p.id === activeTrackId) || curatedLearningPaths[0];
  }, [activeTrackId]);

  // Invariants in Active Track
  const trackInvariants = useMemo(() => {
    return allInvariants.filter(r => activeTrack.domainIds.includes(r.domain));
  }, [activeTrack]);

  const masteredInTrack = useMemo(() => {
    return trackInvariants.filter(r => masteredIds.includes(r.id)).length;
  }, [trackInvariants, masteredIds]);

  const trackProgressPercent = Math.round((masteredInTrack / (trackInvariants.length || 1)) * 100);

  // Search inside Active Track
  const [trackRuleSearch, setTrackRuleSearch] = useState('');
  const displayedRulesInTrack = useMemo(() => {
    if (!trackRuleSearch.trim()) return trackInvariants;
    const q = trackRuleSearch.toLowerCase();
    return trackInvariants.filter(r =>
      r.id.toLowerCase().includes(q) ||
      r.title.toLowerCase().includes(q) ||
      r.subdomain.toLowerCase().includes(q) ||
      r.formalInvariant.toLowerCase().includes(q) ||
      r.plainEnglish.toLowerCase().includes(q)
    );
  }, [trackInvariants, trackRuleSearch]);

  // Advisor recommendation resolver
  const recommendedPathId = useMemo(() => {
    if (advisorGoal === 'interview') {
      return advisorTime === 'sprint' ? 'path-sprint-faang-interview' : 'path-role-staff-appsec';
    }
    if (advisorGoal === 'cloud') {
      return advisorTime === 'sprint' ? 'path-sprint-cloud-devsecops-interview' : 'path-role-cloud-infra-sec';
    }
    if (advisorGoal === 'ai') {
      return advisorTime === 'sprint' ? 'path-tier6-ai-llm-security' : 'path-role-ai-security-lead';
    }
    if (advisorGoal === 'appsec') {
      return 'path-role-staff-appsec';
    }
    if (advisorGoal === 'crypto') {
      return 'path-role-crypto-identity';
    }
    return 'path-tier1-foundations';
  }, [advisorGoal, advisorTime]);

  // Print Handlers for Section
  const handlePrintSectionBook = (section: LearningPath) => {
    const list = allInvariants.filter(r => section.domainIds.includes(r.domain));
    openPrintableInterviewMasterBook(
      list,
      `${section.title} - Complete Section Study Booklet`
    );
  };

  const handlePrintSectionFlashSheets = (section: LearningPath) => {
    const list = allInvariants.filter(r => section.domainIds.includes(r.domain));
    openPrintableInterviewFlashSheets(
      list,
      `${section.title} - Fast-Recall Flash Sheets`
    );
  };

  const handleDownloadSectionMarkdown = (section: LearningPath) => {
    const list = allInvariants.filter(r => section.domainIds.includes(r.domain));
    exportToInterviewMarkdown(
      list,
      `${section.title} - Technical Study Guide`
    );
  };

  // Print Handlers for Track
  const handlePrintTrackBook = (track: LearningPath) => {
    const list = allInvariants.filter(r => track.domainIds.includes(r.domain));
    openPrintableInterviewMasterBook(
      list,
      `${track.title} - Career Track Study Handbook`
    );
  };

  const handlePrintTrackFlashSheets = (track: LearningPath) => {
    const list = allInvariants.filter(r => track.domainIds.includes(r.domain));
    openPrintableInterviewFlashSheets(
      list,
      `${track.title} - Fast-Recall Flash Sheets`
    );
  };

  const handleDownloadTrackMarkdown = (track: LearningPath) => {
    const list = allInvariants.filter(r => track.domainIds.includes(r.domain));
    exportToInterviewMarkdown(
      list,
      `${track.title} - Technical Study Guide`
    );
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8 space-y-10">
      {/* 1. HERO & TOP BANNER */}
      <div className="bg-gradient-to-br from-indigo-950/50 via-slate-900 to-slate-950 border border-indigo-500/30 rounded-2xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 -mt-10 -mr-10 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="max-w-3xl">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-xs font-mono font-medium mb-3">
              <Compass className="w-4 h-4 text-indigo-400" />
              <span>Progressive Security Learning Paths & Curricula</span>
              <span className="text-slate-600">·</span>
              <span>15 Canonical Sections + 16 Curated Career Tracks</span>
            </div>
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-white tracking-tight leading-tight">
              Progressive Security Learning Paths
            </h1>
            <p className="text-sm sm:text-base text-slate-300 mt-2.5 leading-relaxed">
              Master the security invariants in <strong>structured, progressive order</strong>.
              Follow the <strong>15 Section-by-Section Curricula</strong> exactly matching the hard-copy study books,
              or select <strong>Career Role & Interview Sprints</strong> tailored to your next promotion or FAANG loop.
            </p>
          </div>

          {/* Quick Guided Decision Button */}
          <div className="shrink-0 flex flex-col sm:flex-row lg:flex-col gap-3">
            <button
              onClick={() => setShowAdvisorModal(true)}
              className="px-5 py-3 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 text-white rounded-xl text-xs sm:text-sm font-bold transition-all flex items-center justify-center gap-2.5 shadow-lg shadow-indigo-600/30 hover:scale-[1.02] active:scale-[0.98]"
            >
              <Brain className="w-4 h-4 text-indigo-200" />
              <span>Help Me Choose My Path</span>
            </button>
            <div className="text-center text-[11px] text-slate-400 font-mono">
              15 Sections · 16 Tracks · Hard-Copy Ready
            </div>
          </div>
        </div>

        {/* Global Statistics Bar */}
        <div className="mt-6 pt-6 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3">
            <span className="text-slate-400 block font-mono text-[11px]">Section Curricula</span>
            <span className="text-lg font-bold text-white font-mono mt-0.5 block">15 Sequential Domains</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3">
            <span className="text-slate-400 block font-mono text-[11px]">Total Invariants Covered</span>
            <span className="text-lg font-bold text-indigo-400 font-mono mt-0.5 block">{allInvariants.length} Formal Rules</span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3">
            <span className="text-slate-400 block font-mono text-[11px]">Your Verified Mastery</span>
            <span className="text-lg font-bold text-emerald-400 font-mono mt-0.5 block">
              {masteredIds.length} / {allInvariants.length} ({Math.round((masteredIds.length / allInvariants.length) * 100)}%)
            </span>
          </div>
          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3">
            <span className="text-slate-400 block font-mono text-[11px]">Curated Career Tracks</span>
            <span className="text-lg font-bold text-amber-400 font-mono mt-0.5 block">16 Career & Sprints</span>
          </div>
        </div>
      </div>

      {/* 2. PRIMARY VIEW MODE SELECTOR (15 Sections vs Career Tracks) */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center gap-2 p-1 bg-slate-900 border border-slate-800 rounded-xl max-w-fit">
          <button
            onClick={() => setLearningMode('sections')}
            className={`px-4 py-2.5 rounded-lg text-xs sm:text-sm font-bold transition-all flex items-center gap-2.5 ${
              learningMode === 'sections'
                ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <BookOpen className="w-4 h-4 text-indigo-300" />
            <span>15 Progressive Domain Curricula (Sec 1–15)</span>
            <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono ${
              learningMode === 'sections' ? 'bg-indigo-700 text-indigo-100' : 'bg-slate-800 text-slate-400'
            }`}>
              1,036 Rules
            </span>
          </button>

          <button
            onClick={() => setLearningMode('tracks')}
            className={`px-4 py-2.5 rounded-lg text-xs sm:text-sm font-bold transition-all flex items-center gap-2.5 ${
              learningMode === 'tracks'
                ? 'bg-indigo-600 text-white shadow-md shadow-indigo-600/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Briefcase className="w-4 h-4 text-amber-300" />
            <span>Career Roles & Interview Sprints</span>
            <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono ${
              learningMode === 'tracks' ? 'bg-indigo-700 text-indigo-100' : 'bg-slate-800 text-slate-400'
            }`}>
              16 Tracks
            </span>
          </button>
        </div>

        <div className="text-xs text-slate-400 font-mono">
          {learningMode === 'sections'
            ? 'Matching Print Center Hard-Copy Booklets'
            : 'Tailored for Promotions & FAANG Interview Loops'}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* MODE A: 15 PROGRESSIVE DOMAIN CURRICULA (SECTION 1 TO 15)                  */}
      {/* ========================================================================= */}
      {learningMode === 'sections' && (
        <div className="space-y-8 animate-fadeIn">
          {/* Stage Progression Filter & Search */}
          <div className="space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              {/* Stage Pills */}
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none">
                <button
                  onClick={() => setSelectedStage('all')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
                    selectedStage === 'all'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  All 15 Sections (1,036 Rules)
                </button>
                <button
                  onClick={() => setSelectedStage('stage1')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors flex items-center gap-1.5 ${
                    selectedStage === 'stage1'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-cyan-400" />
                  <span>Stage 1: Web & Identity Foundations (Sec 1–6 · 221 Rules)</span>
                </button>
                <button
                  onClick={() => setSelectedStage('stage2')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors flex items-center gap-1.5 ${
                    selectedStage === 'stage2'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-blue-400" />
                  <span>Stage 2: Crypto & Cloud Infra (Sec 7–11 · 285 Rules)</span>
                </button>
                <button
                  onClick={() => setSelectedStage('stage3')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors flex items-center gap-1.5 ${
                    selectedStage === 'stage3'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-fuchsia-400" />
                  <span>Stage 3: Secure Code, AI & Systems (Sec 12–15 · 530 Rules)</span>
                </button>
              </div>
            </div>

            {/* Section Search input */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={sectionSearchQuery}
                onChange={(e) => setSectionSearchQuery(e.target.value)}
                placeholder="Search across all 15 sections by domain, RFC, skill (e.g. RFC 9110, Containers, Zanzibar, Prompt Injection, TWAP, STRIDE)..."
                className="w-full pl-9 pr-4 py-2 bg-slate-900/80 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          {/* Section Grid (All 15 Sections in Progressive Numerical Sequence) */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3.5">
            {filteredSections.map(sec => {
              const isSelected = sec.id === activeSectionId;
              const secRules = allInvariants.filter(r => sec.domainIds.includes(r.domain));
              const secMastered = secRules.filter(r => masteredIds.includes(r.id)).length;
              const secPercent = Math.round((secMastered / (secRules.length || 1)) * 100);
              const num = sec.sectionNumber || 0;

              return (
                <div
                  key={sec.id}
                  onClick={() => setActiveSectionId(sec.id)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer flex flex-col justify-between group relative overflow-hidden ${
                    isSelected
                      ? 'bg-slate-900 border-indigo-500 shadow-xl ring-2 ring-indigo-500/40 scale-[1.01]'
                      : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900/90'
                  }`}
                >
                  <div>
                    {/* Top Section Tag & Level */}
                    <div className="flex items-center justify-between text-[10px] text-slate-400 mb-2 font-mono">
                      <span className={`px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
                        num <= 6 ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' :
                        num <= 11 ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20' :
                        'bg-fuchsia-500/10 text-fuchsia-400 border border-fuchsia-500/20'
                      }`}>
                        SEC {num < 10 ? `0${num}` : num}
                      </span>
                      <span className="font-semibold">{sec.difficulty}</span>
                    </div>

                    <h3 className="text-sm font-bold text-white mb-1 leading-snug group-hover:text-indigo-300 transition-colors">
                      {sec.title}
                    </h3>
                    <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed mb-3">
                      {sec.tagline}
                    </p>

                    {/* Standard Tag */}
                    <div className="text-[10px] font-mono text-indigo-300 bg-indigo-950/40 border border-indigo-900/50 px-2 py-1 rounded mb-3 truncate">
                      {sec.milestones[0]?.focus || sec.keySkills[0]}
                    </div>
                  </div>

                  {/* Progress & Rules count */}
                  <div className="pt-3 border-t border-slate-800/80 space-y-2">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="font-mono text-slate-400">{secRules.length} Rules</span>
                      <span className="font-mono font-semibold text-slate-300">
                        {secMastered}/{secRules.length} ({secPercent}%)
                      </span>
                    </div>

                    {/* Mini Progress Bar */}
                    <div className="w-full h-1.5 bg-slate-950 rounded-full overflow-hidden border border-slate-800/60">
                      <div
                        className={`h-full transition-all duration-300 ${
                          secPercent === 100
                            ? 'bg-emerald-400'
                            : secPercent > 0
                            ? 'bg-indigo-500'
                            : 'bg-transparent'
                        }`}
                        style={{ width: `${secPercent}%` }}
                      />
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-indigo-400 font-semibold pt-1">
                      <span>{isSelected ? '✓ Active Syllabus' : 'Inspect Section'}</span>
                      <ChevronRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* ACTIVE SECTION DETAILED CURRICULUM STUDIO */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-8 shadow-2xl relative">
            {/* Header info */}
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6 pb-6 border-b border-slate-800">
              <div className="max-w-3xl space-y-2">
                <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                  <span className="px-2.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-bold border border-indigo-500/30">
                    SECTION {activeSection.sectionNumber} OF 15
                  </span>
                  <span className="text-slate-500">·</span>
                  <span className="text-slate-300">{activeSection.difficulty} Level</span>
                  <span className="text-slate-500">·</span>
                  <span className="text-slate-300">Est. {activeSection.estimatedHours} Hours</span>
                  <span className="text-slate-500">·</span>
                  <span className="text-indigo-400 font-semibold">{sectionInvariants.length} Formal Rules</span>
                </div>

                <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                  {activeSection.title}
                </h2>
                <p className="text-xs sm:text-sm text-indigo-300 font-medium font-mono">
                  {activeSection.tagline}
                </p>
                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed pt-1">
                  {activeSection.description}
                </p>

                {/* Prerequisites & Target Role */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-3 text-xs">
                  <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3">
                    <span className="text-slate-500 font-mono text-[11px] block mb-1">Target Roles & Evaluators</span>
                    <span className="text-slate-300 font-medium">{activeSection.targetRole}</span>
                  </div>
                  <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3">
                    <span className="text-slate-500 font-mono text-[11px] block mb-1">Recommended Pace</span>
                    <span className="text-slate-300 font-medium">{activeSection.recommendedPace}</span>
                  </div>
                </div>
              </div>

              {/* Progress & Quick Action Buttons */}
              <div className="lg:w-80 shrink-0 bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4">
                <div>
                  <div className="flex items-center justify-between text-xs mb-1.5 font-mono">
                    <span className="text-slate-400">Section Mastery</span>
                    <span className="text-white font-bold">{masteredInSection} / {sectionInvariants.length} ({sectionProgressPercent}%)</span>
                  </div>
                  <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                    <div
                      className={`h-full transition-all duration-500 ${
                        sectionProgressPercent === 100 ? 'bg-emerald-400' : 'bg-indigo-500'
                      }`}
                      style={{ width: `${sectionProgressPercent}%` }}
                    />
                  </div>
                </div>

                {/* Primary Study Actions */}
                <div className="space-y-2 pt-2">
                  <button
                    onClick={() => onStartTrackFlashcards(activeSection.domainIds)}
                    className="w-full px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold transition-colors flex items-center justify-center gap-2 shadow-sm shadow-indigo-600/30"
                  >
                    <BookOpen className="w-4 h-4" />
                    <span>Practice Section Flashcards</span>
                  </button>

                  {onStartTrackQuiz && (
                    <button
                      onClick={() => onStartTrackQuiz(activeSection.domainIds)}
                      className="w-full px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors flex items-center justify-center gap-2"
                    >
                      <Award className="w-4 h-4 text-indigo-400" />
                      <span>Take Section Scenario Quiz</span>
                    </button>
                  )}

                  {/* Print & Download Options */}
                  <div className="pt-2 border-t border-slate-800/80 flex items-center gap-2">
                    <button
                      onClick={() => handlePrintSectionBook(activeSection)}
                      className="flex-1 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white rounded-lg text-[11px] font-semibold transition-colors flex items-center justify-center gap-1.5"
                      title="Print Section Booklet"
                    >
                      <Printer className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Print Booklet</span>
                    </button>

                    <button
                      onClick={() => handlePrintSectionFlashSheets(activeSection)}
                      className="flex-1 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white rounded-lg text-[11px] font-semibold transition-colors flex items-center justify-center gap-1.5"
                      title="Print Fast-Recall Flash Sheets"
                    >
                      <FileCheck className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Flash Sheets</span>
                    </button>

                    <button
                      onClick={() => handleDownloadSectionMarkdown(activeSection)}
                      className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white rounded-lg transition-colors"
                      title="Download Section Study Guide (.md)"
                    >
                      <Download className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* 3 Progressive Milestones */}
            <div className="space-y-3">
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Target className="w-4 h-4 text-indigo-400" />
                <span>3 Progressive Milestones in This Section</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {activeSection.milestones.map((m, idx) => (
                  <div
                    key={idx}
                    className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-4 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between text-xs font-mono text-indigo-400 mb-1.5">
                        <span className="font-bold">Milestone {idx + 1}</span>
                        <span className="text-slate-400">{m.rulesCount} Rules</span>
                      </div>
                      <h4 className="text-sm font-bold text-white mb-1">{m.title}</h4>
                      <p className="text-xs text-slate-400 leading-relaxed">{m.focus}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Key Skills & Spoken Interview Axioms */}
            <div className="space-y-3">
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                <span>Key Competencies & Whiteboard Axioms</span>
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
                {activeSection.keySkills.map((skill, sIdx) => (
                  <div
                    key={sIdx}
                    className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl text-xs text-slate-300 flex items-start gap-2"
                  >
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span className="leading-snug">{skill}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Invariants Search & Interactive Rules List */}
            <div className="space-y-4 pt-4 border-t border-slate-800">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <FileText className="w-4 h-4 text-indigo-400" />
                    <span>All {sectionInvariants.length} Formal Invariants in {activeSection.title}</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Click any invariant to inspect its formal notation, exploit mechanics, code diff, and interview challenges.
                  </p>
                </div>

                <div className="relative w-full sm:w-72">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={sectionRuleSearch}
                    onChange={(e) => setSectionRuleSearch(e.target.value)}
                    placeholder="Search in this section..."
                    className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              {/* Rules List Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {displayedRulesInSection.map(inv => {
                  const isRuleMastered = masteredIds.includes(inv.id);
                  const isRuleBookmarked = bookmarkedIds.includes(inv.id);

                  return (
                    <div
                      key={inv.id}
                      onClick={() => onOpenRule(inv)}
                      className="p-3.5 bg-slate-950/70 border border-slate-800/80 hover:border-indigo-500/60 hover:bg-slate-950 rounded-xl transition-all cursor-pointer flex flex-col justify-between group"
                    >
                      <div>
                        <div className="flex items-center justify-between text-[10px] font-mono mb-1.5">
                          <span className="text-indigo-400 font-bold">{inv.id}</span>
                          <div className="flex items-center gap-1.5">
                            {isRuleMastered && (
                              <span className="text-emerald-400 flex items-center gap-0.5">
                                <Check className="w-3 h-3" />
                                <span>Mastered</span>
                              </span>
                            )}
                            <span className="text-slate-500">{inv.difficulty}</span>
                          </div>
                        </div>

                        <h4 className="text-xs font-bold text-slate-200 group-hover:text-white transition-colors line-clamp-1 mb-1">
                          {inv.title}
                        </h4>

                        <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed mb-2">
                          {inv.plainEnglish}
                        </p>

                        <div className="p-1.5 bg-slate-900 border border-slate-800/80 rounded font-mono text-[10px] text-indigo-300 truncate">
                          {inv.formalInvariant}
                        </div>
                      </div>

                      <div className="pt-2.5 mt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                        <span className="truncate max-w-[160px]">{inv.subdomain}</span>
                        <span className="text-indigo-400 group-hover:translate-x-0.5 transition-transform flex items-center gap-0.5 font-sans font-semibold">
                          <span>Study</span>
                          <ChevronRight className="w-3 h-3" />
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODE B: CAREER ROLES & INTERVIEW ROADMAPS (16 CURATED TRACKS)              */}
      {/* ========================================================================= */}
      {learningMode === 'tracks' && (
        <div className="space-y-8 animate-fadeIn">
          {/* Category Tabs & Search */}
          <div className="space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              {/* Category Tabs */}
              <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none">
                <button
                  onClick={() => setSelectedCategory('All')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors ${
                    selectedCategory === 'All'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  All Curated Tracks ({curatedLearningPaths.length})
                </button>
                <button
                  onClick={() => setSelectedCategory('Career-Role')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors flex items-center gap-1.5 ${
                    selectedCategory === 'Career-Role'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <Briefcase className="w-3.5 h-3.5" />
                  <span>Career Roles (5)</span>
                </button>
                <button
                  onClick={() => setSelectedCategory('Foundational-Tier')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors flex items-center gap-1.5 ${
                    selectedCategory === 'Foundational-Tier'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <Layers className="w-3.5 h-3.5" />
                  <span>Progressive Tiers (4)</span>
                </button>
                <button
                  onClick={() => setSelectedCategory('Interview-Sprint')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors flex items-center gap-1.5 ${
                    selectedCategory === 'Interview-Sprint'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <Zap className="w-3.5 h-3.5 text-amber-400" />
                  <span>Interview Sprints (3)</span>
                </button>
                <button
                  onClick={() => setSelectedCategory('Specialized')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-colors flex items-center gap-1.5 ${
                    selectedCategory === 'Specialized'
                      ? 'bg-indigo-600 text-white shadow-sm'
                      : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                  }`}
                >
                  <Sparkles className="w-3.5 h-3.5 text-fuchsia-400" />
                  <span>Specialized Deep-Dives (4)</span>
                </button>
              </div>

              {/* Difficulty Filter */}
              <div className="flex items-center gap-2 self-start md:self-auto">
                <span className="text-xs text-slate-400 font-medium">Difficulty:</span>
                <select
                  value={selectedDifficulty}
                  onChange={(e) => setSelectedDifficulty(e.target.value as any)}
                  className="bg-slate-900 border border-slate-700 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-indigo-500 font-medium"
                >
                  <option value="All">All Difficulties</option>
                  <option value="Beginner">Beginner</option>
                  <option value="Intermediate">Intermediate</option>
                  <option value="Advanced">Advanced</option>
                  <option value="Expert">Expert</option>
                </select>
              </div>
            </div>

            {/* Track Search input */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={trackSearchQuery}
                onChange={(e) => setTrackSearchQuery(e.target.value)}
                placeholder="Search career roadmaps by role, keywords (e.g. Staff AppSec, FAANG Whiteboard, ReBAC, Container Breakout)..."
                className="w-full pl-9 pr-4 py-2 bg-slate-900/80 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>

          {/* Curated Track Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5">
            {filteredCuratedTracks.map(track => {
              const isSelected = track.id === activeTrackId;
              const trackRules = allInvariants.filter(r => track.domainIds.includes(r.domain));
              const trackMastered = trackRules.filter(r => masteredIds.includes(r.id)).length;
              const trackPercent = Math.round((trackMastered / (trackRules.length || 1)) * 100);

              return (
                <div
                  key={track.id}
                  onClick={() => setActiveTrackId(track.id)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer flex flex-col justify-between group relative overflow-hidden ${
                    isSelected
                      ? 'bg-slate-900 border-indigo-500 shadow-xl ring-2 ring-indigo-500/40'
                      : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900/90'
                  }`}
                >
                  <div>
                    {/* Category badge */}
                    <div className="flex items-center justify-between text-[10px] text-slate-400 mb-2 font-mono">
                      <span className={`px-2 py-0.5 rounded font-semibold ${
                        track.category === 'Career-Role' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' :
                        track.category === 'Interview-Sprint' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                        track.category === 'Specialized' ? 'bg-fuchsia-500/10 text-fuchsia-400 border border-fuchsia-500/20' :
                        'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                      }`}>
                        {track.category.replace('-', ' ')}
                      </span>
                      <span className="font-semibold">{track.difficulty}</span>
                    </div>

                    <h3 className="text-sm font-bold text-white mb-1 leading-snug group-hover:text-indigo-300 transition-colors">
                      {track.title}
                    </h3>
                    <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed mb-3">
                      {track.tagline}
                    </p>

                    {/* Key skills pills */}
                    <div className="flex flex-wrap gap-1 mb-3">
                      {track.keySkills.slice(0, 2).map((skill, sIdx) => (
                        <span
                          key={sIdx}
                          className="text-[10px] bg-slate-950 px-1.5 py-0.5 rounded text-slate-400 border border-slate-800 truncate max-w-[140px]"
                        >
                          {skill}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Progress & Actions */}
                  <div className="pt-3 border-t border-slate-800/80 space-y-2">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="font-mono text-slate-400">{trackRules.length} Rules · ~{track.estimatedHours}h</span>
                      <span className="font-mono font-semibold text-slate-300">
                        {trackMastered}/{trackRules.length} ({trackPercent}%)
                      </span>
                    </div>

                    <div className="w-full h-1.5 bg-slate-950 rounded-full overflow-hidden border border-slate-800/60">
                      <div
                        className={`h-full transition-all duration-300 ${
                          trackPercent === 100
                            ? 'bg-emerald-400'
                            : trackPercent > 0
                            ? 'bg-indigo-500'
                            : 'bg-transparent'
                        }`}
                        style={{ width: `${trackPercent}%` }}
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* ACTIVE CURATED TRACK DETAILED STUDIO */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-8 shadow-2xl relative">
            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6 pb-6 border-b border-slate-800">
              <div className="max-w-3xl space-y-2">
                <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
                  <span className="px-2.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-bold border border-indigo-500/30">
                    {activeTrack.category.replace('-', ' ')}
                  </span>
                  <span className="text-slate-500">·</span>
                  <span className="text-slate-300">{activeTrack.difficulty} Level</span>
                  <span className="text-slate-500">·</span>
                  <span className="text-slate-300">Est. {activeTrack.estimatedHours} Hours</span>
                  <span className="text-slate-500">·</span>
                  <span className="text-indigo-400 font-semibold">{trackInvariants.length} Rules</span>
                </div>

                <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                  {activeTrack.title}
                </h2>
                <p className="text-xs sm:text-sm text-indigo-300 font-medium font-mono">
                  {activeTrack.tagline}
                </p>
                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed pt-1">
                  {activeTrack.description}
                </p>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-3 text-xs">
                  <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3">
                    <span className="text-slate-500 font-mono text-[11px] block mb-1">Target Roles</span>
                    <span className="text-slate-300 font-medium">{activeTrack.targetRole}</span>
                  </div>
                  <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3">
                    <span className="text-slate-500 font-mono text-[11px] block mb-1">Recommended Pace</span>
                    <span className="text-slate-300 font-medium">{activeTrack.recommendedPace}</span>
                  </div>
                </div>
              </div>

              {/* Progress & Quick Action Buttons */}
              <div className="lg:w-80 shrink-0 bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4">
                <div>
                  <div className="flex items-center justify-between text-xs mb-1.5 font-mono">
                    <span className="text-slate-400">Track Mastery</span>
                    <span className="text-white font-bold">{masteredInTrack} / {trackInvariants.length} ({trackProgressPercent}%)</span>
                  </div>
                  <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                    <div
                      className={`h-full transition-all duration-500 ${
                        trackProgressPercent === 100 ? 'bg-emerald-400' : 'bg-indigo-500'
                      }`}
                      style={{ width: `${trackProgressPercent}%` }}
                    />
                  </div>
                </div>

                <div className="space-y-2 pt-2">
                  <button
                    onClick={() => onStartTrackFlashcards(activeTrack.domainIds)}
                    className="w-full px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold transition-colors flex items-center justify-center gap-2 shadow-sm shadow-indigo-600/30"
                  >
                    <BookOpen className="w-4 h-4" />
                    <span>Practice Track Flashcards</span>
                  </button>

                  {onStartTrackQuiz && (
                    <button
                      onClick={() => onStartTrackQuiz(activeTrack.domainIds)}
                      className="w-full px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors flex items-center justify-center gap-2"
                    >
                      <Award className="w-4 h-4 text-indigo-400" />
                      <span>Take Track Scenario Quiz</span>
                    </button>
                  )}

                  <div className="pt-2 border-t border-slate-800/80 flex items-center gap-2">
                    <button
                      onClick={() => handlePrintTrackBook(activeTrack)}
                      className="flex-1 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white rounded-lg text-[11px] font-semibold transition-colors flex items-center justify-center gap-1.5"
                    >
                      <Printer className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Print Handbook</span>
                    </button>

                    <button
                      onClick={() => handlePrintTrackFlashSheets(activeTrack)}
                      className="flex-1 px-3 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white rounded-lg text-[11px] font-semibold transition-colors flex items-center justify-center gap-1.5"
                    >
                      <FileCheck className="w-3.5 h-3.5 text-indigo-400" />
                      <span>Flash Sheets</span>
                    </button>

                    <button
                      onClick={() => handleDownloadTrackMarkdown(activeTrack)}
                      className="p-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white rounded-lg transition-colors"
                      title="Download Markdown Guide"
                    >
                      <Download className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Milestones */}
            <div className="space-y-3">
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Target className="w-4 h-4 text-indigo-400" />
                <span>Track Milestones & Phases</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {activeTrack.milestones.map((m, idx) => (
                  <div
                    key={idx}
                    className="bg-slate-950/80 border border-slate-800/80 rounded-xl p-4 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between text-xs font-mono text-indigo-400 mb-1.5">
                        <span className="font-bold">Phase {idx + 1}</span>
                        <span className="text-slate-400">{m.rulesCount} Rules</span>
                      </div>
                      <h4 className="text-sm font-bold text-white mb-1">{m.title}</h4>
                      <p className="text-xs text-slate-400 leading-relaxed">{m.focus}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Key Skills */}
            <div className="space-y-3">
              <h3 className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                <span>Target Interview Skills</span>
              </h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
                {activeTrack.keySkills.map((skill, sIdx) => (
                  <div
                    key={sIdx}
                    className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-xl text-xs text-slate-300 flex items-start gap-2"
                  >
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span className="leading-snug">{skill}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Track Invariants Search & List */}
            <div className="space-y-4 pt-4 border-t border-slate-800">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <FileText className="w-4 h-4 text-indigo-400" />
                    <span>Invariants in {activeTrack.title}</span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Click any invariant to study full proofs, vulnerable code diffs, and interview challenges.
                  </p>
                </div>

                <div className="relative w-full sm:w-72">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={trackRuleSearch}
                    onChange={(e) => setTrackRuleSearch(e.target.value)}
                    placeholder="Search in this track..."
                    className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                  />
                </div>
              </div>

              {/* Rules List Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {displayedRulesInTrack.slice(0, 36).map(inv => {
                  const isRuleMastered = masteredIds.includes(inv.id);

                  return (
                    <div
                      key={inv.id}
                      onClick={() => onOpenRule(inv)}
                      className="p-3.5 bg-slate-950/70 border border-slate-800/80 hover:border-indigo-500/60 hover:bg-slate-950 rounded-xl transition-all cursor-pointer flex flex-col justify-between group"
                    >
                      <div>
                        <div className="flex items-center justify-between text-[10px] font-mono mb-1.5">
                          <span className="text-indigo-400 font-bold">{inv.id}</span>
                          <div className="flex items-center gap-1.5">
                            {isRuleMastered && (
                              <span className="text-emerald-400 flex items-center gap-0.5">
                                <Check className="w-3 h-3" />
                                <span>Mastered</span>
                              </span>
                            )}
                            <span className="text-slate-500">{inv.difficulty}</span>
                          </div>
                        </div>

                        <h4 className="text-xs font-bold text-slate-200 group-hover:text-white transition-colors line-clamp-1 mb-1">
                          {inv.title}
                        </h4>

                        <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed mb-2">
                          {inv.plainEnglish}
                        </p>

                        <div className="p-1.5 bg-slate-900 border border-slate-800/80 rounded font-mono text-[10px] text-indigo-300 truncate">
                          {inv.formalInvariant}
                        </div>
                      </div>

                      <div className="pt-2.5 mt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-400 font-mono">
                        <span className="truncate max-w-[160px]">{inv.domainName}</span>
                        <span className="text-indigo-400 group-hover:translate-x-0.5 transition-transform flex items-center gap-0.5 font-sans font-semibold">
                          <span>Study</span>
                          <ChevronRight className="w-3 h-3" />
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {displayedRulesInTrack.length > 36 && (
                <div className="text-center pt-2">
                  <span className="text-xs text-slate-500 font-mono">
                    Showing first 36 of {displayedRulesInTrack.length} rules in this track.
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* 3. GUIDED DECISION ADVISOR MODAL */}
      {showAdvisorModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 sm:p-8 shadow-2xl relative space-y-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2.5">
                <div className="p-2 bg-indigo-500/20 text-indigo-400 rounded-lg">
                  <Brain className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-lg font-bold text-white">Path Finder & Learning Decision Advisor</h3>
                  <p className="text-xs text-slate-400">Answer 2 questions to receive your tailored progressive security roadmap.</p>
                </div>
              </div>
              <button
                onClick={() => setShowAdvisorModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                ✕
              </button>
            </div>

            {/* Question 1: What is your primary objective? */}
            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
                1. What is your primary goal right now?
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => setAdvisorGoal('interview')}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    advisorGoal === 'interview'
                      ? 'bg-indigo-600/20 border-indigo-500 text-white font-semibold ring-1 ring-indigo-500'
                      : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="font-bold flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-amber-400" />
                    <span>Pass Staff / Senior Interviews</span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">High-frequency whiteboard axioms, scenarios & spoken scripts</div>
                </button>

                <button
                  type="button"
                  onClick={() => setAdvisorGoal('cloud')}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    advisorGoal === 'cloud'
                      ? 'bg-indigo-600/20 border-indigo-500 text-white font-semibold ring-1 ring-indigo-500'
                      : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="font-bold flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 text-blue-400" />
                    <span>Cloud, Containers & K8s</span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">IMDSv2, AWS IAM, Linux namespaces, Seccomp & PSS</div>
                </button>

                <button
                  type="button"
                  onClick={() => setAdvisorGoal('ai')}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    advisorGoal === 'ai'
                      ? 'bg-indigo-600/20 border-indigo-500 text-white font-semibold ring-1 ring-indigo-500'
                      : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="font-bold flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-fuchsia-400" />
                    <span>AI & LLM System Safety</span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">Prompt injection defense, autonomous agent guardrails & RAG</div>
                </button>

                <button
                  type="button"
                  onClick={() => setAdvisorGoal('appsec')}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    advisorGoal === 'appsec'
                      ? 'bg-indigo-600/20 border-indigo-500 text-white font-semibold ring-1 ring-indigo-500'
                      : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="font-bold flex items-center gap-1.5">
                    <Briefcase className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Staff AppSec Engineer Career</span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">End-to-end web, API, code review & threat modeling mastery</div>
                </button>

                <button
                  type="button"
                  onClick={() => setAdvisorGoal('foundations')}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    advisorGoal === 'foundations'
                      ? 'bg-indigo-600/20 border-indigo-500 text-white font-semibold ring-1 ring-indigo-500'
                      : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="font-bold flex items-center gap-1.5">
                    <GraduationCap className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Start with Core Foundations</span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">HTTP protocol framing, CSP, Cookies, CORS & parameter binding</div>
                </button>

                <button
                  type="button"
                  onClick={() => setAdvisorGoal('crypto')}
                  className={`p-3 rounded-xl border text-left transition-all ${
                    advisorGoal === 'crypto'
                      ? 'bg-indigo-600/20 border-indigo-500 text-white font-semibold ring-1 ring-indigo-500'
                      : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="font-bold flex items-center gap-1.5">
                    <Code2 className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Cryptography & Zero-Trust Identity</span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">AEAD ciphers, constant-time algorithms, OAuth PKCE & ReBAC</div>
                </button>
              </div>
            </div>

            {/* Question 2: What is your timeline / commitment? */}
            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
                2. How much time do you have?
              </label>
              <div className="grid grid-cols-3 gap-2 text-xs">
                <button
                  type="button"
                  onClick={() => setAdvisorTime('sprint')}
                  className={`p-2.5 rounded-xl border text-center transition-all ${
                    advisorTime === 'sprint'
                      ? 'bg-indigo-600/20 border-indigo-500 text-white font-semibold ring-1 ring-indigo-500'
                      : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="font-bold">⚡ Sprint</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">1–2 Weeks</div>
                </button>

                <button
                  type="button"
                  onClick={() => setAdvisorTime('targeted')}
                  className={`p-2.5 rounded-xl border text-center transition-all ${
                    advisorTime === 'targeted'
                      ? 'bg-indigo-600/20 border-indigo-500 text-white font-semibold ring-1 ring-indigo-500'
                      : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="font-bold">🎯 Targeted</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">3–4 Weeks</div>
                </button>

                <button
                  type="button"
                  onClick={() => setAdvisorTime('deep')}
                  className={`p-2.5 rounded-xl border text-center transition-all ${
                    advisorTime === 'deep'
                      ? 'bg-indigo-600/20 border-indigo-500 text-white font-semibold ring-1 ring-indigo-500'
                      : 'bg-slate-950 border-slate-800 text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <div className="font-bold">🏛️ Comprehensive</div>
                  <div className="text-[10px] text-slate-400 mt-0.5">6–8+ Weeks</div>
                </button>
              </div>
            </div>

            {/* Recommendation Result */}
            {(() => {
              const rec = curatedLearningPaths.find(p => p.id === recommendedPathId) || curatedLearningPaths[0];
              return (
                <div className="bg-indigo-950/40 border border-indigo-500/40 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 text-indigo-400 font-mono text-[11px] font-semibold mb-1">
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Recommended Path for Your Goal</span>
                    </div>
                    <h4 className="text-sm font-bold text-white">{rec.title}</h4>
                    <p className="text-xs text-slate-300 mt-0.5">{rec.tagline}</p>
                    <div className="text-[11px] text-slate-400 mt-1 font-mono">
                      ~{rec.estimatedHours} Hours · {rec.difficulty} · {rec.category}
                    </div>
                  </div>

                  <button
                    onClick={() => {
                      setLearningMode('tracks');
                      setActiveTrackId(rec.id);
                      setShowAdvisorModal(false);
                    }}
                    className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-bold transition-colors whitespace-nowrap shadow-sm shadow-indigo-600/20"
                  >
                    Select This Path →
                  </button>
                </div>
              );
            })()}
          </div>
        </div>
      )}
    </div>
  );
};
