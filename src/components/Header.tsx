import React from 'react';
import { ShieldCheck, BookOpen, BrainCircuit, Award, Compass, Bookmark, Sparkles, Brain } from 'lucide-react';

interface HeaderProps {
  currentTab: 'curriculum' | 'taxonomy' | 'tracks' | 'sessions' | 'flashcards' | 'quiz' | 'dashboard' | 'reports';
  onSelectTab: (tab: 'curriculum' | 'taxonomy' | 'tracks' | 'sessions' | 'flashcards' | 'quiz' | 'dashboard' | 'reports') => void;
  dueCount: number;
  bookmarkedCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  currentTab,
  onSelectTab,
  dueCount,
  bookmarkedCount
}) => {
  return (
    <header className="sticky top-0 z-40 bg-slate-950/95 backdrop-blur-md border-b border-slate-800 w-full max-w-full">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-3 sm:gap-6 px-3 sm:px-6 py-3">
        {/* Zone 1: Brand Title */}
        <button
          onClick={() => onSelectTab('curriculum')}
          className="flex items-center gap-2 text-left group transition-opacity hover:opacity-95 shrink-0"
        >
          <div className="w-8 h-8 rounded-lg bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 group-hover:border-indigo-400 transition-colors">
            <ShieldCheck className="w-5 h-5 text-indigo-400" />
          </div>
          <span className="font-bold text-sm sm:text-base lg:text-lg tracking-tight text-white whitespace-nowrap">
            Security Invariants
          </span>
        </button>

        {/* Zone 2: Clean Responsive Navigation Links */}
        <nav className="hidden md:flex items-center gap-2 lg:gap-4 xl:gap-5 text-xs lg:text-sm font-medium text-slate-300">
          <button
            onClick={() => onSelectTab('curriculum')}
            className={`whitespace-nowrap transition-colors hover:text-white px-1.5 py-1 rounded ${
              currentTab === 'curriculum' ? 'text-indigo-400 font-semibold' : 'text-slate-400'
            }`}
          >
            Curriculum
          </button>
          <button
            onClick={() => onSelectTab('taxonomy')}
            className={`whitespace-nowrap transition-colors hover:text-white flex items-center gap-1 px-1.5 py-1 rounded ${
              currentTab === 'taxonomy' ? 'text-indigo-400 font-semibold' : 'text-slate-400'
            }`}
          >
            <span>37 Topics</span>
            <span className="px-1 py-0.2 bg-indigo-500/20 text-indigo-300 rounded text-[10px] font-mono border border-indigo-500/30">
              New
            </span>
          </button>
          <button
            onClick={() => onSelectTab('tracks')}
            className={`whitespace-nowrap transition-colors hover:text-white px-1.5 py-1 rounded ${
              currentTab === 'tracks' ? 'text-indigo-400 font-semibold' : 'text-slate-400'
            }`}
          >
            <span className="hidden xl:inline">Learning </span>Paths
          </button>
          <button
            onClick={() => onSelectTab('sessions')}
            className={`whitespace-nowrap transition-colors hover:text-white flex items-center gap-1 px-1.5 py-1 rounded ${
              currentTab === 'sessions' ? 'text-indigo-400 font-semibold' : 'text-slate-400'
            }`}
          >
            <span>Sprints</span>
            <span className="px-1 py-0.2 bg-amber-500/20 text-amber-300 rounded text-[10px] font-mono border border-amber-500/30">
              5m
            </span>
          </button>
          <button
            onClick={() => onSelectTab('flashcards')}
            className={`whitespace-nowrap transition-colors hover:text-white flex items-center gap-1 px-1.5 py-1 rounded ${
              currentTab === 'flashcards' ? 'text-indigo-400 font-semibold' : 'text-slate-400'
            }`}
          >
            <span>Cards</span>
            {dueCount > 0 && (
              <span className="px-1.5 py-0.2 bg-amber-500/20 text-amber-300 rounded text-xs font-mono">
                {dueCount}
              </span>
            )}
          </button>
          <button
            onClick={() => onSelectTab('quiz')}
            className={`whitespace-nowrap transition-colors hover:text-white px-1.5 py-1 rounded ${
              currentTab === 'quiz' ? 'text-indigo-400 font-semibold' : 'text-slate-400'
            }`}
          >
            Quiz
          </button>
          <button
            onClick={() => onSelectTab('dashboard')}
            className={`whitespace-nowrap transition-colors hover:text-white flex items-center gap-1 px-1.5 py-1 rounded ${
              currentTab === 'dashboard' ? 'text-indigo-400 font-semibold' : 'text-slate-400'
            }`}
          >
            <span>Dashboard</span>
            {bookmarkedCount > 0 && (
              <span className="px-1.5 py-0.2 bg-slate-800 text-slate-300 rounded text-xs font-mono">
                {bookmarkedCount}
              </span>
            )}
          </button>
          <button
            onClick={() => onSelectTab('reports')}
            className={`whitespace-nowrap transition-colors hover:text-white flex items-center gap-1 px-1.5 py-1 rounded ${
              currentTab === 'reports' ? 'text-indigo-400 font-semibold' : 'text-slate-400'
            }`}
          >
            <span>Print Center</span>
          </button>
        </nav>

        {/* Zone 3: Primary Action */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => onSelectTab('flashcards')}
            className="px-2.5 sm:px-3 py-1.5 sm:py-2 text-xs font-semibold text-slate-200 hover:text-white bg-slate-900 border border-slate-800 rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap flex items-center gap-1.5 shadow-sm"
          >
            <Award className="w-3.5 h-3.5 text-amber-400" />
            <span>{dueCount > 0 ? `Due (${dueCount})` : 'Practice Cards'}</span>
          </button>
        </div>
      </div>

      {/* Mobile sub-bar */}
      <div className="md:hidden flex items-center gap-1 border-t border-slate-800/80 px-2 py-2 text-xs bg-slate-950/95 overflow-x-auto no-scrollbar w-full">
        <button
          onClick={() => onSelectTab('curriculum')}
          className={`px-2.5 py-1 rounded whitespace-nowrap shrink-0 ${currentTab === 'curriculum' ? 'text-indigo-400 font-semibold bg-indigo-500/10' : 'text-slate-400'}`}
        >
          Curriculum
        </button>
        <button
          onClick={() => onSelectTab('taxonomy')}
          className={`px-2.5 py-1 rounded whitespace-nowrap shrink-0 ${currentTab === 'taxonomy' ? 'text-indigo-400 font-semibold bg-indigo-500/10' : 'text-slate-400'}`}
        >
          37 Topics
        </button>
        <button
          onClick={() => onSelectTab('tracks')}
          className={`px-2.5 py-1 rounded whitespace-nowrap shrink-0 ${currentTab === 'tracks' ? 'text-indigo-400 font-semibold bg-indigo-500/10' : 'text-slate-400'}`}
        >
          Paths
        </button>
        <button
          onClick={() => onSelectTab('sessions')}
          className={`px-2.5 py-1 rounded whitespace-nowrap shrink-0 ${currentTab === 'sessions' ? 'text-indigo-400 font-semibold bg-indigo-500/10' : 'text-slate-400'}`}
        >
          Sprints (5m)
        </button>
        <button
          onClick={() => onSelectTab('flashcards')}
          className={`px-2.5 py-1 rounded whitespace-nowrap shrink-0 ${currentTab === 'flashcards' ? 'text-indigo-400 font-semibold bg-indigo-500/10' : 'text-slate-400'}`}
        >
          Cards {dueCount > 0 && `(${dueCount})`}
        </button>
        <button
          onClick={() => onSelectTab('quiz')}
          className={`px-2.5 py-1 rounded whitespace-nowrap shrink-0 ${currentTab === 'quiz' ? 'text-indigo-400 font-semibold bg-indigo-500/10' : 'text-slate-400'}`}
        >
          Quiz
        </button>
        <button
          onClick={() => onSelectTab('reports')}
          className={`px-2.5 py-1 rounded whitespace-nowrap shrink-0 ${currentTab === 'reports' ? 'text-indigo-400 font-semibold bg-indigo-500/10' : 'text-slate-400'}`}
        >
          Print Center
        </button>
      </div>
    </header>
  );
};
