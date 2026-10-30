import React, { useState } from 'react';
import { UserProgress, SecurityInvariant } from '../types/invariants';
import { allInvariants, domainMetadata } from '../data/invariantsRegistry';
import {
  Award,
  BookOpen,
  Bookmark,
  BookmarkCheck,
  CheckCircle2,
  Clock,
  Download,
  Flame,
  RotateCcw,
  Shield,
  Upload,
  ArrowRight,
  TrendingUp,
  BrainCircuit,
  Trash2,
  Printer
} from 'lucide-react';

interface DashboardViewProps {
  progress: UserProgress;
  onOpenRule: (invariant: SecurityInvariant) => void;
  onStartDueReview: () => void;
  onResetProgress: () => void;
  onOpenReports?: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  progress,
  onOpenRule,
  onStartDueReview,
  onResetProgress,
  onOpenReports
}) => {
  const [showConfirmReset, setShowConfirmReset] = useState(false);

  const now = Date.now();
  const dueRules = allInvariants.filter(rule => {
    const srs = progress.srsData[rule.id];
    if (!srs) return false;
    return srs.nextDueDate <= now;
  });

  const masteredCount = progress.masteredIds.length;
  const reviewedCount = progress.reviewedIds.length;
  const totalCount = allInvariants.length;
  const unseenCount = totalCount - reviewedCount;
  const overallMasteryPct = Math.round((masteredCount / totalCount) * 100);

  // Bookmarked list
  const bookmarkedRules = allInvariants.filter(r => progress.bookmarkedIds.includes(r.id));

  // Export JSON
  const handleExport = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(progress, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `security_invariants_progress_${new Date().toISOString().split('T')[0]}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8 space-y-8">
      {/* Top Banner and Summary Stats */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Revision & Mastery Dashboard
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Track your spaced repetition review queue, retention trajectory, and cross-domain proficiency.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {onOpenReports && (
            <button
              onClick={onOpenReports}
              className="px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
              title="Open the Reports & Audit Hub"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Audit & Reports Hub</span>
            </button>
          )}

          <button
            onClick={handleExport}
            className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5"
            title="Export study data as JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Backup</span>
          </button>

          {dueRules.length > 0 && (
            <button
              onClick={onStartDueReview}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Review {dueRules.length} Due Cards</span>
            </button>
          )}
        </div>
      </div>

      {/* KPI Cards Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Mastered Invariants</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-extrabold text-white font-mono tabular-nums">
            {masteredCount}
            <span className="text-xs text-slate-500 font-sans font-normal ml-2">/ {totalCount}</span>
          </div>
          <div className="text-xs text-emerald-400/90 mt-1 font-mono">
            {overallMasteryPct}% Curriculum Mastery
          </div>
        </div>

        {/* Metric 2 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Due For Review</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-extrabold text-white font-mono tabular-nums">
            {dueRules.length}
          </div>
          <div className="text-xs text-amber-400/90 mt-1 font-mono">
            {dueRules.length === 0 ? 'Queue Clear' : 'SRS Spaced Repetition Due'}
          </div>
        </div>

        {/* Metric 3 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Study Streak</span>
            <Flame className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-extrabold text-white font-mono tabular-nums">
            {progress.studyStreakDays} <span className="text-sm font-normal text-slate-400">days</span>
          </div>
          <div className="text-xs text-orange-400/90 mt-1">
            Active Continuous Learning
          </div>
        </div>

        {/* Metric 4 */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
            <span>Bookmarked Rules</span>
            <Bookmark className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-extrabold text-white font-mono tabular-nums">
            {bookmarkedRules.length}
          </div>
          <div className="text-xs text-indigo-400/90 mt-1 font-mono">
            Personal Study List
          </div>
        </div>
      </div>

      {/* Domain Proficiency Breakdown across all 14 Domains */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-6">
        <div>
          <h2 className="text-lg font-bold text-white tracking-tight">
            Curriculum Domain Proficiency (14 Core Domains)
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Progress measured by 3 consecutive successful spaced-repetition ratings per invariant.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {Object.values(domainMetadata).map(domain => {
            const domainInvariants = allInvariants.filter(r => r.domain === domain.id);
            const masteredInDomain = domainInvariants.filter(r => progress.masteredIds.includes(r.id)).length;
            const pct = Math.round((masteredInDomain / (domainInvariants.length || 1)) * 100);

            return (
              <div
                key={domain.id}
                className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2"
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-white">{domain.name}</span>
                  <span className="font-mono text-slate-400">
                    {masteredInDomain} / {domainInvariants.length} ({pct}%)
                  </span>
                </div>
                <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden">
                  <div
                    className="bg-indigo-500 h-full transition-all duration-300"
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span>{domain.primaryStandard}</span>
                  <span>{domainInvariants.length} Rules</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Bookmarked Invariants Table / List */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
            <BookmarkCheck className="w-4 h-4 text-amber-400" />
            <span>Bookmarked Study List ({bookmarkedRules.length})</span>
          </h3>
          <span className="text-xs text-slate-500 font-mono">Click to review formal invariant</span>
        </div>

        {bookmarkedRules.length === 0 ? (
          <p className="text-xs text-slate-500 py-6 text-center">
            No bookmarked rules yet. Click the bookmark icon on any card to save it here for targeted revision.
          </p>
        ) : (
          <div className="divide-y divide-slate-800 border border-slate-800 rounded-xl overflow-hidden bg-slate-950/60 max-h-[360px] overflow-y-auto">
            {bookmarkedRules.map(rule => (
              <div
                key={rule.id}
                onClick={() => onOpenRule(rule)}
                className="p-3.5 hover:bg-slate-900 transition-colors flex items-center justify-between gap-4 cursor-pointer"
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
                    <span className="text-indigo-400 font-semibold">{rule.id}</span>
                    <span>·</span>
                    <span className="text-slate-300">{rule.domainName}</span>
                    <span>·</span>
                    <span className="text-slate-500 truncate">{rule.subdomain}</span>
                  </div>
                  <h4 className="text-xs sm:text-sm font-semibold text-white truncate mt-0.5">
                    {rule.title}
                  </h4>
                </div>
                <ArrowRight className="w-4 h-4 text-slate-500 shrink-0" />
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Reset progress safety latch */}
      <div className="pt-6 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500">
        <span>Curriculum Grounding: OWASP, RFCs, NIST, CWE, and ISO/IEC</span>
        {!showConfirmReset ? (
          <button
            onClick={() => setShowConfirmReset(true)}
            className="text-slate-500 hover:text-rose-400 transition-colors flex items-center gap-1"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Reset Local Progress</span>
          </button>
        ) : (
          <div className="flex items-center gap-2">
            <span className="text-rose-400">Confirm reset all review data?</span>
            <button
              onClick={() => {
                onResetProgress();
                setShowConfirmReset(false);
              }}
              className="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded text-[11px]"
            >
              Yes, Reset
            </button>
            <button
              onClick={() => setShowConfirmReset(false)}
              className="px-2.5 py-1 bg-slate-800 text-slate-300 hover:text-white rounded text-[11px]"
            >
              Cancel
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
