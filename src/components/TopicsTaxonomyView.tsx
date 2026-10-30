import React, { useState, useMemo } from 'react';
import {
  SecurityTopicId,
  SecurityTopicMeta,
  SecurityInvariant,
  SecurityTopicSuite
} from '../types/invariants';
import {
  securityTopicsTaxonomy,
  getInvariantsForTopic,
  allInvariants
} from '../data/invariantsRegistry';
import {
  Globe,
  Database,
  Terminal,
  Code,
  ShieldAlert,
  Radio,
  FolderLock,
  Binary,
  Compass,
  KeyRound,
  Fingerprint,
  FileKey,
  Lock,
  GitBranch,
  ShieldCheck,
  Cpu,
  Zap,
  Activity,
  Layers,
  Server,
  Layers2,
  Share2,
  Boxes,
  Cloud,
  Smartphone,
  HardDrive,
  Award,
  Package,
  CreditCard,
  Bot,
  Coins,
  Mail,
  Sparkles,
  Container,
  FileSearch,
  Crosshair,
  Search,
  Filter,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  Flame,
  FileText,
  Printer,
  X,
  BookOpen,
  Copy,
  Check,
  Film
} from 'lucide-react';
import {
  formatRuleAsMarkdown,
  generateNotebookLMPrompt,
  copyToClipboard
} from '../utils/ruleExportHelpers';
import { openPrintableTopicHandbook } from '../utils/reportExporter';

interface TopicsTaxonomyViewProps {
  onOpenRule: (inv: SecurityInvariant) => void;
  onFilterCurriculumTopic: (topicId: SecurityTopicId) => void;
  masteredIds: string[];
}

const SUITES: SecurityTopicSuite[] = [
  'Application & Injection',
  'Identity, Auth & Tokens',
  'Systems, Concurrency & Crypto',
  'Cloud, Infrastructure & Ops',
  'AI & LLM System Safety',
  'Web3, Smart Contracts & DeFi'
];

const ICON_MAP: Record<string, React.ElementType> = {
  Globe,
  Database,
  Terminal,
  Code,
  ShieldAlert,
  Radio,
  FolderLock,
  Binary,
  Compass,
  KeyRound,
  Fingerprint,
  FileKey,
  Lock,
  GitBranch,
  ShieldCheck,
  Cpu,
  Zap,
  Activity,
  Layers,
  Server,
  Layers2,
  Share2,
  Boxes,
  Cloud,
  Smartphone,
  HardDrive,
  Award,
  Package,
  CreditCard,
  Bot,
  Coins,
  Mail,
  Sparkles,
  Container,
  FileSearch,
  Crosshair
};

export const TopicsTaxonomyView: React.FC<TopicsTaxonomyViewProps> = ({
  onOpenRule,
  onFilterCurriculumTopic,
  masteredIds
}) => {
  const [selectedSuite, setSelectedSuite] = useState<SecurityTopicSuite | 'all'>('all');
  const [selectedRarity, setSelectedRarity] = useState<'all' | 'Common' | 'Advanced' | 'Rare & Subtle Zero-Day'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [inspectedTopic, setInspectedTopic] = useState<SecurityTopicMeta | null>(null);

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

  // Filter topics
  const filteredTopics = useMemo(() => {
    return securityTopicsTaxonomy.filter(topic => {
      if (selectedSuite !== 'all' && topic.suite !== selectedSuite) return false;
      if (selectedRarity !== 'all' && topic.rarityLevel !== selectedRarity) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesName = topic.name.toLowerCase().includes(q);
        const matchesTagline = topic.tagline.toLowerCase().includes(q);
        const matchesDesc = topic.description.toLowerCase().includes(q);
        const matchesStandard = topic.primaryStandard.toLowerCase().includes(q);
        const matchesCwe = topic.cwes.some(c => c.toLowerCase().includes(q));
        const matchesNumber = String(topic.topicNumber).includes(q);
        return matchesName || matchesTagline || matchesDesc || matchesStandard || matchesCwe || matchesNumber;
      }
      return true;
    });
  }, [selectedSuite, selectedRarity, searchQuery]);

  // Topic metrics
  const inspectedTopicRules = useMemo(() => {
    if (!inspectedTopic) return [];
    return getInvariantsForTopic(inspectedTopic.id, allInvariants);
  }, [inspectedTopic]);

  const suiteColors: Record<SecurityTopicSuite, { border: string; badge: string; text: string }> = {
    'Application & Injection': {
      border: 'border-rose-500/20 hover:border-rose-500/50',
      badge: 'bg-rose-500/10 text-rose-300 border-rose-500/30',
      text: 'text-rose-400'
    },
    'Identity, Auth & Tokens': {
      border: 'border-amber-500/20 hover:border-amber-500/50',
      badge: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
      text: 'text-amber-400'
    },
    'Systems, Concurrency & Crypto': {
      border: 'border-purple-500/20 hover:border-purple-500/50',
      badge: 'bg-purple-500/10 text-purple-300 border-purple-500/30',
      text: 'text-purple-400'
    },
    'Cloud, Infrastructure & Ops': {
      border: 'border-blue-500/20 hover:border-blue-500/50',
      badge: 'bg-blue-500/10 text-blue-300 border-blue-500/30',
      text: 'text-blue-400'
    },
    'AI & LLM System Safety': {
      border: 'border-emerald-500/20 hover:border-emerald-500/50',
      badge: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
      text: 'text-emerald-400'
    },
    'Web3, Smart Contracts & DeFi': {
      border: 'border-cyan-500/20 hover:border-cyan-500/50',
      badge: 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30',
      text: 'text-cyan-400'
    }
  };

  return (
    <div className="space-y-8 animate-fadeIn pb-12">
      {/* Top Banner / Hero */}
      <div className="rounded-2xl border border-indigo-500/20 bg-gradient-to-br from-slate-900 via-indigo-950/20 to-slate-900 p-6 sm:p-8 relative overflow-hidden shadow-2xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        
        <div className="relative z-10 max-w-4xl space-y-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-semibold bg-indigo-500/10 border border-indigo-500/30 text-indigo-300">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>Complete 37 Security Topics & Vulnerability Taxonomy</span>
          </div>

          <h1 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-white">
            37 Security Domains & Attack Surface Taxonomy
          </h1>

          <p className="text-slate-300 text-sm sm:text-base leading-relaxed">
            Every category from Request Smuggling and SQLi to LLMs, DeFi economic security, and Threat Modeling.
            Explore both <strong className="text-emerald-400">Common Standards</strong> and <strong className="text-rose-400">Rare &amp; Subtle Zero-Day</strong> invariants with formal logic, exploit proofs, and whiteboard interview challenges.
          </p>

          {/* Stats Ribbon */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-4 border-t border-slate-800/80">
            <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800">
              <div className="text-2xl font-black text-indigo-400">37</div>
              <div className="text-xs text-slate-400 font-medium">Distinct Domains</div>
            </div>
            <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800">
              <div className="text-2xl font-black text-white">{allInvariants.length}</div>
              <div className="text-xs text-slate-400 font-medium">Formal Invariants</div>
            </div>
            <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800">
              <div className="text-2xl font-black text-amber-400">6</div>
              <div className="text-xs text-slate-400 font-medium">Architectural Suites</div>
            </div>
            <div className="bg-slate-950/60 rounded-xl p-3 border border-slate-800">
              <div className="text-2xl font-black text-rose-400">37</div>
              <div className="text-xs text-slate-400 font-medium">Rare Zero-Day Rules</div>
            </div>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="space-y-4">
        {/* Search Input */}
        <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center justify-between">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search 37 topics by name, CWE, RFC (e.g. 'smuggling', 'CWE-89', 'IMDSv2', 'TWAP', 'LLM')..."
              className="w-full pl-10 pr-4 py-2.5 bg-slate-900 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Rarity Filter */}
          <div className="flex items-center gap-1.5 p-1 bg-slate-900 rounded-xl border border-slate-800 shrink-0">
            <span className="text-xs text-slate-400 px-2 font-medium">Rarity:</span>
            {(['all', 'Common', 'Advanced', 'Rare & Subtle Zero-Day'] as const).map(rarity => (
              <button
                key={rarity}
                onClick={() => setSelectedRarity(rarity)}
                className={`px-2.5 py-1 text-xs rounded-lg font-medium transition-colors ${
                  selectedRarity === rarity
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                {rarity === 'all' ? 'All Rules' : rarity}
              </button>
            ))}
          </div>
        </div>

        {/* Suites Selector Tabs */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 no-scrollbar">
          <button
            onClick={() => setSelectedSuite('all')}
            className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-colors border ${
              selectedSuite === 'all'
                ? 'bg-indigo-600 border-indigo-500 text-white shadow-sm'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            All Suites ({securityTopicsTaxonomy.length})
          </button>
          {SUITES.map(suite => {
            const count = securityTopicsTaxonomy.filter(t => t.suite === suite).length;
            const isSelected = selectedSuite === suite;
            return (
              <button
                key={suite}
                onClick={() => setSelectedSuite(suite)}
                className={`px-3.5 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-colors border ${
                  isSelected
                    ? 'bg-indigo-600 border-indigo-500 text-white shadow-sm'
                    : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                {suite} ({count})
              </button>
            );
          })}
        </div>
      </div>

      {/* Topics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
        {filteredTopics.map(topic => {
          const IconComponent = ICON_MAP[topic.iconName] || Globe;
          const matchingInvariants = getInvariantsForTopic(topic.id, allInvariants);
          const masteredCount = matchingInvariants.filter(r => masteredIds.includes(r.id)).length;
          const suiteStyle = suiteColors[topic.suite] || suiteColors['Application & Injection'];
          const isRare = topic.rarityLevel === 'Rare & Subtle Zero-Day';

          return (
            <div
              key={topic.id}
              className={`rounded-2xl bg-slate-900/90 border ${suiteStyle.border} p-5 flex flex-col justify-between transition-all hover:shadow-xl hover:-translate-y-0.5 group`}
            >
              <div className="space-y-3.5">
                {/* Header row: Number + Suite Badge + Rarity */}
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className="w-7 h-7 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-center font-mono font-bold text-xs text-indigo-400">
                      #{String(topic.topicNumber).padStart(2, '0')}
                    </span>
                    <span className={`px-2 py-0.5 rounded-md text-[10px] font-semibold border ${suiteStyle.badge}`}>
                      {topic.suite}
                    </span>
                  </div>

                  <span
                    className={`px-2 py-0.5 rounded-md text-[10px] font-semibold border ${
                      isRare
                        ? 'bg-rose-500/10 text-rose-300 border-rose-500/30 animate-pulse'
                        : topic.rarityLevel === 'Advanced'
                        ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                        : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                    }`}
                  >
                    {topic.rarityLevel}
                  </span>
                </div>

                {/* Title & Icon */}
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-center shrink-0 group-hover:border-indigo-500/40 transition-colors">
                    <IconComponent className={`w-5 h-5 ${suiteStyle.text}`} />
                  </div>
                  <div>
                    <h3 className="font-bold text-base text-white group-hover:text-indigo-300 transition-colors">
                      {topic.name}
                    </h3>
                    <p className="text-xs text-slate-400 font-mono line-clamp-1 mt-0.5">
                      {topic.tagline}
                    </p>
                  </div>
                </div>

                {/* Description */}
                <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed">
                  {topic.description}
                </p>

                {/* CWEs & Standards */}
                <div className="flex flex-wrap items-center gap-1.5 pt-1">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-indigo-300 border border-slate-800">
                    {topic.primaryStandard}
                  </span>
                  {topic.cwes.slice(0, 3).map(cwe => (
                    <span
                      key={cwe}
                      className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-950/80 text-slate-400 border border-slate-800/80"
                    >
                      {cwe}
                    </span>
                  ))}
                </div>
              </div>

              {/* Bottom Actions & Progress */}
              <div className="pt-4 mt-4 border-t border-slate-800/80 space-y-3">
                <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                  <span>{matchingInvariants.length} Invariants Mapped</span>
                  <span className="text-emerald-400 font-semibold">
                    {masteredCount}/{matchingInvariants.length} Mastered
                  </span>
                </div>

                {/* Mini progress bar */}
                <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden border border-slate-800">
                  <div
                    className="bg-indigo-500 h-full rounded-full transition-all"
                    style={{
                      width: `${matchingInvariants.length ? (masteredCount / matchingInvariants.length) * 100 : 0}%`
                    }}
                  />
                </div>

                <div className="flex items-center gap-1.5 pt-1">
                  <button
                    onClick={() => setInspectedTopic(topic)}
                    className="flex-1 py-1.5 px-2.5 bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold rounded-lg transition-colors flex items-center justify-center gap-1.5 border border-slate-700"
                  >
                    <BookOpen className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Deep Dive</span>
                  </button>

                  <button
                    onClick={() => onFilterCurriculumTopic(topic.id)}
                    className="py-1.5 px-2 bg-indigo-600/20 hover:bg-indigo-600 text-indigo-300 hover:text-white text-xs font-semibold rounded-lg transition-all border border-indigo-500/30 flex items-center justify-center gap-1"
                    title="View all invariants in Curriculum"
                  >
                    <span>Curriculum</span>
                    <ChevronRight className="w-3 h-3" />
                  </button>

                  <button
                    onClick={e => {
                      e.stopPropagation();
                      openPrintableTopicHandbook(topic, matchingInvariants);
                    }}
                    className="py-1.5 px-2 bg-slate-950 hover:bg-slate-800 text-slate-300 hover:text-white text-xs font-semibold rounded-lg transition-colors border border-slate-800 flex items-center justify-center gap-1"
                    title={`Print Topic #${topic.topicNumber}: ${topic.name} Handbook & Study Sheet`}
                  >
                    <Printer className="w-3.5 h-3.5 text-indigo-400" />
                    <span className="hidden sm:inline">Print</span>
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Deep-Dive Inspection Modal */}
      {inspectedTopic && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-950/80 backdrop-blur-md animate-fadeIn">
          <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden min-w-0">
            {/* Modal Header */}
            <div className="p-4 sm:p-6 border-b border-slate-800 flex items-start justify-between gap-3 bg-slate-950/50">
              <div className="space-y-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="px-2 py-0.5 rounded font-mono font-bold text-xs bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                    Topic #{String(inspectedTopic.topicNumber).padStart(2, '0')}
                  </span>
                  <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                    {inspectedTopic.suite}
                  </span>
                  <span className="px-2 py-0.5 rounded text-xs font-semibold bg-rose-500/10 text-rose-300 border border-rose-500/30">
                    {inspectedTopic.rarityLevel}
                  </span>
                </div>
                <h2 className="text-xl sm:text-2xl font-black text-white truncate">
                  {inspectedTopic.name}
                </h2>
                <p className="text-xs text-indigo-300 font-mono line-clamp-1">
                  {inspectedTopic.tagline}
                </p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => openPrintableTopicHandbook(inspectedTopic, inspectedTopicRules)}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-sm shadow-indigo-600/20 transition-colors"
                  title="Print or Save PDF Topic Handbook"
                >
                  <Printer className="w-3.5 h-3.5" />
                  <span className="hidden sm:inline">Print Topic Handbook</span>
                  <span className="sm:hidden">Print</span>
                </button>
                <button
                  onClick={() => setInspectedTopic(null)}
                  className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white flex items-center justify-center transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-6">
              {/* Scope & Description */}
              <div className="bg-slate-950 rounded-xl p-4 border border-slate-800 space-y-2">
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">
                  Domain Scope & Defensive Boundary
                </h4>
                <p className="text-sm text-slate-200 leading-relaxed">
                  {inspectedTopic.description}
                </p>
                <div className="flex flex-wrap items-center gap-2 pt-2">
                  <span className="text-xs font-mono text-amber-400 bg-amber-500/10 px-2.5 py-1 rounded border border-amber-500/20">
                    Standard: {inspectedTopic.primaryStandard}
                  </span>
                  {inspectedTopic.cwes.map(cwe => (
                    <span
                      key={cwe}
                      className="text-xs font-mono text-slate-300 bg-slate-900 px-2 py-1 rounded border border-slate-800"
                    >
                      {cwe}
                    </span>
                  ))}
                </div>
              </div>

              {/* Invariants in this Topic */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    <span>Invariants Mapped to this Category ({inspectedTopicRules.length})</span>
                  </h4>
                  <button
                    onClick={() => {
                      onFilterCurriculumTopic(inspectedTopic.id);
                      setInspectedTopic(null);
                    }}
                    className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
                  >
                    <span>View all in Curriculum</span>
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>

                <div className="space-y-2.5 max-h-96 overflow-y-auto pr-1">
                  {inspectedTopicRules.map(rule => (
                    <div
                      key={rule.id}
                      onClick={() => {
                        onOpenRule(rule);
                        setInspectedTopic(null);
                      }}
                      className="p-3.5 rounded-xl bg-slate-950 hover:bg-slate-800/80 border border-slate-800 hover:border-indigo-500/40 cursor-pointer transition-all group flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                    >
                      <div className="space-y-1 flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-indigo-400">
                            {rule.id}
                          </span>
                          {rule.sequenceOrder && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
                              Step {rule.sequenceOrder} · Tier {rule.tierLevel || 1}
                            </span>
                          )}
                          {rule.isRareRule && (
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                              Subtle Zero-Day
                            </span>
                          )}
                          <span className="text-[10px] font-mono text-slate-500">
                            {rule.standards[0]}
                          </span>
                        </div>
                        <div className="text-sm font-semibold text-white group-hover:text-indigo-300 transition-colors">
                          {rule.title}
                        </div>
                        <div className="text-xs font-mono text-indigo-200/80 line-clamp-1">
                          {rule.formalInvariant}
                        </div>
                      </div>

                      {/* Action buttons: Copy Rule & Video Prompt */}
                      <div className="flex items-center gap-1.5 shrink-0" onClick={e => e.stopPropagation()}>
                        <button
                          onClick={e => handleCopyRule(rule, e)}
                          title="Copy rule details as Markdown"
                          className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-[11px] font-medium text-slate-300 hover:text-white flex items-center gap-1.5 transition-colors"
                        >
                          {copiedRuleId === rule.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                              <span className="text-emerald-300">Copied!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5 text-slate-400" />
                              <span>Copy Rule</span>
                            </>
                          )}
                        </button>
                        <button
                          onClick={e => handleCopyPrompt(rule, e)}
                          title="Copy 6-7 min NotebookLM / Video prompt for cinematic explainer"
                          className="px-2.5 py-1 rounded-lg bg-indigo-950/40 hover:bg-indigo-900/50 border border-indigo-500/30 text-[11px] font-medium text-indigo-300 hover:text-white flex items-center gap-1.5 transition-colors"
                        >
                          {copiedPromptId === rule.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                              <span className="text-emerald-300">Prompt!</span>
                            </>
                          ) : (
                            <>
                              <Film className="w-3.5 h-3.5 text-amber-400" />
                              <span>Video Prompt</span>
                            </>
                          )}
                        </button>
                        <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-indigo-400 ml-1 hidden sm:block" />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/70 flex flex-wrap items-center justify-between gap-3">
              <button
                onClick={() => {
                  onFilterCurriculumTopic(inspectedTopic.id);
                  setInspectedTopic(null);
                }}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold rounded-xl transition-all flex items-center gap-2 shadow-lg shadow-indigo-600/20"
              >
                <span>Filter Curriculum for {inspectedTopic.name}</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => openPrintableTopicHandbook(inspectedTopic, inspectedTopicRules)}
                  className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-white text-xs font-semibold rounded-xl transition-colors flex items-center gap-1.5"
                >
                  <Printer className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Print Topic Handbook</span>
                </button>
                <button
                  onClick={() => setInspectedTopic(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-xl transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
