import React, { useState } from 'react';
import { SecurityInvariant } from '../types/invariants';
import { Bookmark, BookmarkCheck, CheckCircle2, ArrowRight, Copy, Check, Film } from 'lucide-react';
import { formatRuleAsMarkdown, generateNotebookLMPrompt, copyToClipboard } from '../utils/ruleExportHelpers';

interface InvariantCardProps {
  invariant: SecurityInvariant;
  isBookmarked: boolean;
  isMastered: boolean;
  onToggleBookmark: (id: string) => void;
  onToggleMastered: (id: string) => void;
  onOpenDetails: (invariant: SecurityInvariant) => void;
}

export const InvariantCard: React.FC<InvariantCardProps> = ({
  invariant,
  isBookmarked,
  isMastered,
  onToggleBookmark,
  onToggleMastered,
  onOpenDetails
}) => {
  const [copiedRule, setCopiedRule] = useState(false);
  const [copiedPrompt, setCopiedPrompt] = useState(false);

  const handleCopyRule = async (e: React.MouseEvent) => {
    e.stopPropagation();
    const markdown = formatRuleAsMarkdown(invariant);
    const success = await copyToClipboard(markdown);
    if (success) {
      setCopiedRule(true);
      setTimeout(() => setCopiedRule(false), 2000);
    }
  };

  const handleCopyPrompt = async (e: React.MouseEvent) => {
    e.stopPropagation();
    const prompt = generateNotebookLMPrompt(invariant);
    const success = await copyToClipboard(prompt);
    if (success) {
      setCopiedPrompt(true);
      setTimeout(() => setCopiedPrompt(false), 2000);
    }
  };

  return (
    <div
      onClick={() => onOpenDetails(invariant)}
      className="group relative flex flex-col justify-between bg-slate-900/70 hover:bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all duration-200 rounded-xl p-5 cursor-pointer shadow-sm hover:shadow-md"
    >
      <div>
        {/* Unboxed Metadata Line with typographic separators */}
        <div className="flex items-center justify-between gap-2 text-xs text-slate-400 mb-2.5">
          <div className="flex items-center gap-1.5 font-mono text-[11px] truncate">
            <span className="text-indigo-400 font-semibold">{invariant.id}</span>
            <span aria-hidden="true" className="text-slate-600">·</span>
            <span className="text-slate-300 font-sans font-medium">{invariant.domainName}</span>
            <span aria-hidden="true" className="text-slate-600">·</span>
            <span className="text-slate-400 truncate">{invariant.subdomain}</span>
          </div>

          <div className="flex items-center gap-2 shrink-0" onClick={e => e.stopPropagation()}>
            <button
              onClick={() => onToggleBookmark(invariant.id)}
              title={isBookmarked ? 'Remove bookmark' : 'Bookmark rule'}
              className="p-1 rounded text-slate-400 hover:text-amber-400 hover:bg-slate-800 transition-colors"
            >
              {isBookmarked ? (
                <BookmarkCheck className="w-4 h-4 text-amber-400 fill-amber-400/20" />
              ) : (
                <Bookmark className="w-4 h-4" />
              )}
            </button>
            <button
              onClick={() => onToggleMastered(invariant.id)}
              title={isMastered ? 'Marked as Mastered' : 'Mark as Mastered'}
              className="p-1 rounded text-slate-400 hover:text-emerald-400 hover:bg-slate-800 transition-colors"
            >
              <CheckCircle2
                className={`w-4 h-4 transition-colors ${
                  isMastered ? 'text-emerald-400 fill-emerald-400/20' : 'text-slate-500'
                }`}
              />
            </button>
          </div>
        </div>

        {/* Sequential Learning Path Step & Tier Badge */}
        {invariant.sequenceOrder && (
          <div className="flex items-center gap-1.5 mb-2">
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
              Step {invariant.sequenceOrder} · Tier {invariant.tierLevel || 1}
            </span>
            <span className="text-[10px] font-sans text-slate-400 truncate">
              {invariant.tier}
            </span>
          </div>
        )}

        {/* Title */}
        <h3 className="text-base font-semibold text-white group-hover:text-indigo-300 transition-colors line-clamp-1 mb-2">
          {invariant.title}
        </h3>

        {/* Formal Invariant Math Expression */}
        <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-2.5 mb-3 overflow-x-auto">
          <p className="font-mono text-xs text-indigo-300 tracking-tight whitespace-nowrap overflow-hidden text-ellipsis">
            {invariant.formalInvariant}
          </p>
        </div>

        {/* Plain English Summary */}
        <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed mb-3">
          {invariant.plainEnglish}
        </p>

        {/* Quick Action Bar: Copy Rule & Video Prompt */}
        <div className="flex items-center gap-2 mb-3 pt-1" onClick={e => e.stopPropagation()}>
          <button
            onClick={handleCopyRule}
            className="flex-1 py-1.5 px-2 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-medium text-slate-300 hover:text-white flex items-center justify-center gap-1.5 transition-colors"
            title="Copy complete rule summary as Markdown"
          >
            {copiedRule ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-300 font-semibold">Rule Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-slate-400" />
                <span>Copy Rule</span>
              </>
            )}
          </button>

          <button
            onClick={handleCopyPrompt}
            className="flex-1 py-1.5 px-2 rounded-lg bg-indigo-950/40 hover:bg-indigo-900/50 border border-indigo-500/30 text-[11px] font-medium text-indigo-300 hover:text-white flex items-center justify-center gap-1.5 transition-colors"
            title="Copy 6-7 min NotebookLM / Video prompt for cinematic animation"
          >
            {copiedPrompt ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-300 font-semibold">Prompt Copied!</span>
              </>
            ) : (
              <>
                <Film className="w-3.5 h-3.5 text-amber-400" />
                <span>Video Prompt</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Footer info: Standards & Action */}
      <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
        <div className="flex items-center gap-1.5 truncate pr-2">
          <span className="text-slate-400 truncate font-mono text-[11px]">
            {invariant.standards[0]}
          </span>
          <span aria-hidden="true" className="text-slate-700">·</span>
          <span className={`${
            invariant.standardType === 'Mandatory Standard' ? 'text-rose-400/90' : 'text-emerald-400/90'
          }`}>
            {invariant.standardType === 'Mandatory Standard' ? 'Mandatory' : 'Defense-in-Depth'}
          </span>
        </div>

        <div className="flex items-center gap-1 text-slate-400 group-hover:text-indigo-400 font-medium text-[11px] whitespace-nowrap shrink-0 transition-colors">
          <span>Explore</span>
          <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
        </div>
      </div>
    </div>
  );
};
