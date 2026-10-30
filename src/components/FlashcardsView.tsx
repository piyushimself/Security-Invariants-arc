import React, { useState, useEffect } from 'react';
import { SecurityInvariant, DomainId } from '../types/invariants';
import { allInvariants, domainMetadata } from '../data/invariantsRegistry';
import {
  RotateCcw,
  CheckCircle2,
  Bookmark,
  BookmarkCheck,
  ChevronLeft,
  ChevronRight,
  Filter,
  Eye,
  Terminal,
  Code2,
  Sparkles,
  Info
} from 'lucide-react';

interface FlashcardsViewProps {
  bookmarkedIds: string[];
  masteredIds: string[];
  srsData: Record<string, any>;
  onToggleBookmark: (id: string) => void;
  onToggleMastered: (id: string) => void;
  onRecordSRS: (id: string, rating: 'again' | 'hard' | 'good' | 'easy') => void;
  initialDomain?: DomainId;
}

export const FlashcardsView: React.FC<FlashcardsViewProps> = ({
  bookmarkedIds,
  masteredIds,
  srsData,
  onToggleBookmark,
  onToggleMastered,
  onRecordSRS,
  initialDomain
}) => {
  const [selectedDomain, setSelectedDomain] = useState<DomainId | 'all'>(initialDomain || 'all');
  const [filterMode, setFilterMode] = useState<'all' | 'due' | 'bookmarked'>('all');
  const [isFlipped, setIsFlipped] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(0);

  // Filter cards
  const now = Date.now();
  const filteredCards = allInvariants.filter(card => {
    if (selectedDomain !== 'all' && card.domain !== selectedDomain) return false;
    if (filterMode === 'bookmarked' && !bookmarkedIds.includes(card.id)) return false;
    if (filterMode === 'due') {
      const srs = srsData[card.id];
      if (!srs) return true; // Unreviewed are due
      return srs.nextDueDate <= now;
    }
    return true;
  });

  const currentCard: SecurityInvariant | undefined = filteredCards[currentIndex];

  useEffect(() => {
    setIsFlipped(false);
    setCurrentIndex(0);
  }, [selectedDomain, filterMode]);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;

      if (e.code === 'Space') {
        e.preventDefault();
        setIsFlipped(prev => !prev);
      } else if (e.code === 'ArrowRight') {
        e.preventDefault();
        handleNext();
      } else if (e.code === 'ArrowLeft') {
        e.preventDefault();
        handlePrev();
      } else if (isFlipped && currentCard) {
        if (e.key === '1') handleRate('again');
        else if (e.key === '2') handleRate('hard');
        else if (e.key === '3') handleRate('good');
        else if (e.key === '4') handleRate('easy');
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isFlipped, currentCard, currentIndex, filteredCards.length]);

  const handleNext = () => {
    if (currentIndex < filteredCards.length - 1) {
      setCurrentIndex(prev => prev + 1);
      setIsFlipped(false);
    }
  };

  const handlePrev = () => {
    if (currentIndex > 0) {
      setCurrentIndex(prev => prev - 1);
      setIsFlipped(false);
    }
  };

  const handleRate = (rating: 'again' | 'hard' | 'good' | 'easy') => {
    if (!currentCard) return;
    onRecordSRS(currentCard.id, rating);
    if (currentIndex < filteredCards.length - 1) {
      setCurrentIndex(prev => prev + 1);
      setIsFlipped(false);
    } else {
      setIsFlipped(false);
    }
  };

  if (filteredCards.length === 0) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-16 text-center">
        <div className="w-16 h-16 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto mb-4 text-slate-400">
          <CheckCircle2 className="w-8 h-8 text-emerald-400" />
        </div>
        <h2 className="text-xl font-bold text-white mb-2">All Caught Up!</h2>
        <p className="text-sm text-slate-400 max-w-md mx-auto mb-6">
          No cards match your current filter. You have reviewed all scheduled invariants for this selection.
        </p>
        <button
          onClick={() => {
            setFilterMode('all');
            setSelectedDomain('all');
          }}
          className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-semibold transition-colors"
        >
          Reset Filters & Explore All 500 Cards
        </button>
      </div>
    );
  }

  const isBookmarked = currentCard ? bookmarkedIds.includes(currentCard.id) : false;
  const isMastered = currentCard ? masteredIds.includes(currentCard.id) : false;
  const currentSrs = currentCard ? srsData[currentCard.id] : null;

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Top Filter Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-4">
        {/* Domain selection */}
        <div className="flex items-center gap-2 overflow-x-auto w-full sm:w-auto">
          <label htmlFor="flashcard-domain-select" className="text-xs text-slate-400 shrink-0 font-medium">Domain:</label>
          <select
            id="flashcard-domain-select"
            value={selectedDomain}
            onChange={e => setSelectedDomain(e.target.value as any)}
            className="bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">All Domains (511 Invariants)</option>
            {Object.values(domainMetadata).map(d => (
              <option key={d.id} value={d.id}>
                {d.name} ({d.count})
              </option>
            ))}
          </select>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-2 shrink-0">
          <div className="flex items-center p-1 bg-slate-950 rounded-lg border border-slate-800 text-xs">
            <button
              onClick={() => setFilterMode('all')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                filterMode === 'all'
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setFilterMode('due')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                filterMode === 'due'
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Due for Review
            </button>
            <button
              onClick={() => setFilterMode('bookmarked')}
              className={`px-3 py-1 rounded font-medium transition-colors ${
                filterMode === 'bookmarked'
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Bookmarked
            </button>
          </div>
        </div>
      </div>

      {/* Progress & Counter */}
      <div className="flex items-center justify-between text-xs text-slate-400 px-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-slate-300 font-semibold">
            Card {currentIndex + 1} of {filteredCards.length}
          </span>
          {currentSrs && (
            <span className="text-slate-500">
              · Interval: {currentSrs.interval}d · Ease: {currentSrs.easeFactor}
            </span>
          )}
        </div>
        <div className="text-slate-500 hidden sm:block">
          Press <kbd className="px-1.5 py-0.5 bg-slate-800 rounded text-slate-300 font-mono">Space</kbd> to flip, <kbd className="px-1.5 py-0.5 bg-slate-800 rounded text-slate-300 font-mono">←</kbd> <kbd className="px-1.5 py-0.5 bg-slate-800 rounded text-slate-300 font-mono">→</kbd> to navigate
        </div>
      </div>

      {/* 3D Flashcard Container */}
      {currentCard && (
        <div
          onClick={() => setIsFlipped(!isFlipped)}
          className="relative w-full min-h-[420px] bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-2xl p-6 sm:p-8 cursor-pointer shadow-xl transition-all duration-300 flex flex-col justify-between select-none group"
        >
          {/* Top metadata of card */}
          <div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
              <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
                <span className="text-indigo-400 font-semibold">{currentCard.id}</span>
                <span className="text-slate-600">·</span>
                <span className="text-slate-300">{currentCard.domainName}</span>
                <span className="text-slate-600">·</span>
                <span className="text-slate-400">{currentCard.subdomain}</span>
              </div>

              <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
                <button
                  onClick={() => onToggleBookmark(currentCard.id)}
                  className="p-1 text-slate-400 hover:text-amber-400 rounded transition-colors"
                >
                  {isBookmarked ? (
                    <BookmarkCheck className="w-4 h-4 text-amber-400 fill-amber-400/20" />
                  ) : (
                    <Bookmark className="w-4 h-4" />
                  )}
                </button>
                <button
                  onClick={() => onToggleMastered(currentCard.id)}
                  className="p-1 text-slate-400 hover:text-emerald-400 rounded transition-colors"
                >
                  <CheckCircle2
                    className={`w-4 h-4 ${isMastered ? 'text-emerald-400 fill-emerald-400/20' : ''}`}
                  />
                </button>
              </div>
            </div>

            {/* Front of Card */}
            {!isFlipped ? (
              <div className="space-y-6 py-4">
                <div>
                  <span className="text-xs uppercase tracking-wider text-slate-500 font-semibold">
                    Security Rule #{currentCard.ruleNumber}
                  </span>
                  <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight mt-1 mb-3">
                    {currentCard.title}
                  </h2>
                  <div className="flex items-center gap-2 text-xs text-slate-400 font-mono mb-6">
                    <span className="text-indigo-300">{currentCard.standards.join(', ')}</span>
                    <span>·</span>
                    <span className={currentCard.standardType === 'Mandatory Standard' ? 'text-rose-400' : 'text-emerald-400'}>
                      {currentCard.standardType}
                    </span>
                  </div>
                </div>

                {/* Mathematical Invariant */}
                <div className="bg-slate-950 border border-slate-800 rounded-xl p-5 shadow-inner">
                  <div className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold mb-2">
                    Formal Mathematical Invariant:
                  </div>
                  <div className="font-mono text-sm sm:text-base text-indigo-300 leading-relaxed overflow-x-auto">
                    {currentCard.formalInvariant}
                  </div>
                </div>

                <div className="text-center pt-8">
                  <div className="inline-flex items-center gap-2 text-xs text-indigo-400 bg-indigo-500/10 px-4 py-2 rounded-full border border-indigo-500/20 group-hover:bg-indigo-500/20 transition-colors">
                    <Eye className="w-3.5 h-3.5" />
                    <span>Click card or press Space to reveal explanation & code</span>
                  </div>
                </div>
              </div>
            ) : (
              /* Back of Card */
              <div className="space-y-5 py-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs uppercase tracking-wider text-emerald-400 font-semibold">
                    Explanation & Validation
                  </span>
                  <span className="text-xs text-slate-500 font-mono">
                    {currentCard.standards[0]}
                  </span>
                </div>

                <div className="space-y-1.5">
                  <h4 className="text-xs font-semibold text-white uppercase tracking-wider text-slate-400">
                    Plain-English Meaning
                  </h4>
                  <p className="text-sm text-slate-200 leading-relaxed bg-slate-950/60 p-3.5 rounded-xl border border-slate-800">
                    {currentCard.plainEnglish}
                  </p>
                </div>

                <div className="space-y-1.5">
                  <h4 className="text-xs font-semibold text-rose-400 uppercase tracking-wider">
                    Attack Scenario & Threat
                  </h4>
                  <p className="text-xs text-slate-300 leading-relaxed bg-rose-500/5 p-3 rounded-lg border border-rose-500/20">
                    {currentCard.whyItMatters}
                  </p>
                </div>

                <div className="space-y-1.5">
                  <h4 className="text-xs font-semibold text-indigo-400 uppercase tracking-wider">
                    Key Interview Takeaway
                  </h4>
                  <p className="text-xs text-indigo-200 leading-relaxed bg-indigo-500/10 p-3 rounded-lg border border-indigo-500/20">
                    {currentCard.interviewChallenge.keyTakeaway}
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Footer of Card */}
          <div className="pt-4 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
            <span>Difficulty: {currentCard.difficulty}</span>
            <span>{isFlipped ? 'Click to show front' : 'Click to flip'}</span>
          </div>
        </div>
      )}

      {/* SRS Rating Bar (When Flipped) */}
      {isFlipped && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
          <p className="text-xs text-slate-400 text-center mb-3 font-medium">
            How well did you know this invariant? (Press 1 - 4)
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <button
              onClick={() => handleRate('again')}
              className="py-2.5 px-3 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/30 text-rose-300 text-xs font-semibold transition-colors flex flex-col items-center gap-0.5"
            >
              <span>1. Again</span>
              <span className="text-[10px] text-rose-400/80 font-normal">Repeat in 1 day</span>
            </button>
            <button
              onClick={() => handleRate('hard')}
              className="py-2.5 px-3 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-300 text-xs font-semibold transition-colors flex flex-col items-center gap-0.5"
            >
              <span>2. Hard</span>
              <span className="text-[10px] text-amber-400/80 font-normal">+2-3 days</span>
            </button>
            <button
              onClick={() => handleRate('good')}
              className="py-2.5 px-3 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 text-xs font-semibold transition-colors flex flex-col items-center gap-0.5"
            >
              <span>3. Good</span>
              <span className="text-[10px] text-indigo-400/80 font-normal">+4-6 days</span>
            </button>
            <button
              onClick={() => handleRate('easy')}
              className="py-2.5 px-3 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-300 text-xs font-semibold transition-colors flex flex-col items-center gap-0.5"
            >
              <span>4. Easy</span>
              <span className="text-[10px] text-emerald-400/80 font-normal">+7-14 days</span>
            </button>
          </div>
        </div>
      )}

      {/* Navigation Controls */}
      <div className="flex items-center justify-between">
        <button
          onClick={handlePrev}
          disabled={currentIndex === 0}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-xs font-medium transition-colors"
        >
          <ChevronLeft className="w-4 h-4" />
          <span>Previous Card</span>
        </button>

        <button
          onClick={() => setIsFlipped(!isFlipped)}
          className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5 inline mr-1.5" />
          Flip Card
        </button>

        <button
          onClick={handleNext}
          disabled={currentIndex === filteredCards.length - 1}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:border-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-xs font-medium transition-colors"
        >
          <span>Next Card</span>
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  );
};
