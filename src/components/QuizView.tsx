import React, { useState } from 'react';
import { SecurityInvariant, DomainId } from '../types/invariants';
import { allInvariants, domainMetadata } from '../data/invariantsRegistry';
import {
  Award,
  HelpCircle,
  CheckCircle2,
  XCircle,
  ArrowRight,
  RotateCcw,
  Lightbulb,
  ShieldAlert,
  Terminal,
  ChevronRight
} from 'lucide-react';

interface QuizViewProps {
  initialDomain?: DomainId;
  onRecordQuizResult: (result: {
    totalQuestions: number;
    score: number;
    domainBreakdown: Record<string, number>;
  }) => void;
  onOpenDetails: (invariant: SecurityInvariant) => void;
}

interface GeneratedQuestion {
  invariant: SecurityInvariant;
  questionText: string;
  scenarioText: string;
  hintText: string;
  options: { text: string; isCorrect: boolean }[];
  explanation: string;
  formalProof: string;
}

export const QuizView: React.FC<QuizViewProps> = ({ initialDomain, onRecordQuizResult, onOpenDetails }) => {
  const [selectedDomain, setSelectedDomain] = useState<DomainId | 'all'>(initialDomain || 'all');
  const [questionCount, setQuestionCount] = useState<number>(5);
  const [quizState, setQuizState] = useState<'idle' | 'active' | 'finished'>('idle');

  const [questions, setQuestions] = useState<GeneratedQuestion[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [selectedOption, setSelectedOption] = useState<number | null>(null);
  const [isAnswerSubmitted, setIsAnswerSubmitted] = useState(false);
  const [showHint, setShowHint] = useState(false);
  const [score, setScore] = useState(0);
  const [domainBreakdown, setDomainBreakdown] = useState<Record<string, number>>({});

  const startQuiz = () => {
    // Select eligible pool based on domain
    const pool = allInvariants.filter(
      r => selectedDomain === 'all' || r.domain === selectedDomain
    );

    // Shuffle and pick
    const shuffled = [...pool].sort(() => Math.random() - 0.5).slice(0, questionCount);

    const generated: GeneratedQuestion[] = shuffled.map(inv => {
      const correctAns = inv.interviewChallenge.sampleAnswer;

      // Generate plausible distractors based on common security anti-patterns
      const distractorA = `Rely on client-side regex or perimeter WAF rules without verifying server-side state or changing internal architecture.`;
      const distractorB = `Permit the operation by default and log the transaction to SIEM for post-mortem manual audit inspection.`;
      const distractorC = `Disable protocol negotiation or downgrade to HTTP/1.0 without enforcing complete mediation.`;

      const options = [
        { text: correctAns, isCorrect: true },
        { text: distractorA, isCorrect: false },
        { text: distractorB, isCorrect: false },
        { text: distractorC, isCorrect: false }
      ].sort(() => Math.random() - 0.5);

      return {
        invariant: inv,
        scenarioText: inv.interviewChallenge.scenario,
        questionText: inv.interviewChallenge.question,
        hintText: inv.interviewChallenge.hint,
        options,
        explanation: inv.interviewChallenge.keyTakeaway,
        formalProof: inv.formalInvariant
      };
    });

    setQuestions(generated);
    setCurrentIndex(0);
    setSelectedOption(null);
    setIsAnswerSubmitted(false);
    setShowHint(false);
    setScore(0);
    setDomainBreakdown({});
    setQuizState('active');
  };

  const handleSelectOption = (idx: number) => {
    if (isAnswerSubmitted) return;
    setSelectedOption(idx);
  };

  const handleSubmitAnswer = () => {
    if (selectedOption === null || isAnswerSubmitted) return;

    setIsAnswerSubmitted(true);
    const curr = questions[currentIndex];
    const isCorrect = curr.options[selectedOption].isCorrect;

    if (isCorrect) {
      setScore(prev => prev + 1);
      setDomainBreakdown(prev => ({
        ...prev,
        [curr.invariant.domain]: (prev[curr.invariant.domain] || 0) + 1
      }));
    }
  };

  const handleNextQuestion = () => {
    if (currentIndex < questions.length - 1) {
      setCurrentIndex(prev => prev + 1);
      setSelectedOption(null);
      setIsAnswerSubmitted(false);
      setShowHint(false);
    } else {
      // Finish quiz
      onRecordQuizResult({
        totalQuestions: questions.length,
        score: score + (questions[currentIndex].options[selectedOption!]?.isCorrect ? 1 : 0),
        domainBreakdown
      });
      setQuizState('finished');
    }
  };

  if (quizState === 'idle') {
    return (
      <div className="max-w-3xl mx-auto px-4 py-12">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-10 shadow-xl text-center space-y-6">
          <div className="w-16 h-16 rounded-2xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center mx-auto text-indigo-400">
            <Award className="w-8 h-8" />
          </div>

          <div>
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Security Invariants Scenario Quiz
            </h1>
            <p className="text-sm text-slate-400 max-w-lg mx-auto mt-2 leading-relaxed">
              Test your ability to solve real-world system design security challenges, debug vulnerabilities, and enforce formal invariants under interview conditions.
            </p>
          </div>

          {/* Config options */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 max-w-md mx-auto text-left pt-2">
            <div>
              <label htmlFor="quiz-track-domain-select" className="block text-xs font-medium text-slate-400 mb-1.5">
                Target Domain:
              </label>
              <select
                id="quiz-track-domain-select"
                value={selectedDomain}
                onChange={e => setSelectedDomain(e.target.value as any)}
                className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
              >
                <option value="all">All 14 Domains (511 Invariants)</option>
                {Object.values(domainMetadata).map(d => (
                  <option key={d.id} value={d.id}>
                    {d.name} ({d.count})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="quiz-question-count-select" className="block text-xs font-medium text-slate-400 mb-1.5">
                Question Count:
              </label>
              <select
                id="quiz-question-count-select"
                value={questionCount}
                onChange={e => setQuestionCount(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 focus:outline-none focus:border-indigo-500"
              >
                <option value={5}>5 Questions (Rapid Assessment)</option>
                <option value={10}>10 Questions (Standard Drill)</option>
                <option value={20}>20 Questions (Comprehensive Exam)</option>
              </select>
            </div>
          </div>

          <div className="pt-4">
            <button
              onClick={startQuiz}
              className="px-6 py-3 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm rounded-xl shadow-lg shadow-indigo-600/30 transition-all hover:scale-[1.02]"
            >
              Start Scenario Quiz
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (quizState === 'finished') {
    const finalScore = score;
    const percentage = Math.round((finalScore / questions.length) * 100);

    const getRank = () => {
      if (percentage >= 90) return 'Principal Security Architect';
      if (percentage >= 75) return 'Staff Security Engineer';
      if (percentage >= 60) return 'Senior AppSec Engineer';
      return 'Security Engineer Candidate';
    };

    return (
      <div className="max-w-2xl mx-auto px-4 py-12">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-10 text-center space-y-6 shadow-2xl">
          <div className="w-20 h-20 rounded-full bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center mx-auto text-indigo-400">
            <Award className="w-10 h-10" />
          </div>

          <div>
            <div className="text-xs font-mono text-indigo-400 uppercase tracking-wider font-semibold mb-1">
              Assessment Completed
            </div>
            <h2 className="text-2xl font-bold text-white">{getRank()}</h2>
            <p className="text-4xl font-extrabold text-white font-mono mt-3 tabular-nums">
              {finalScore} / {questions.length} ({percentage}%)
            </p>
          </div>

          <p className="text-sm text-slate-400 max-w-md mx-auto leading-relaxed">
            {percentage >= 75
              ? 'Outstanding performance. You have demonstrated rigorous understanding of security invariant boundaries and defensive architectural patterns.'
              : 'Good effort. Review the missed invariants in the curriculum to reinforce the formal logic and attack scenarios.'}
          </p>

          <div className="pt-4 flex flex-wrap items-center justify-center gap-3">
            <button
              onClick={startQuiz}
              className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs rounded-lg transition-colors flex items-center gap-2"
            >
              <RotateCcw className="w-4 h-4" />
              <span>Retry Quiz</span>
            </button>
            <button
              onClick={() => setQuizState('idle')}
              className="px-5 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg transition-colors"
            >
              Configure New Quiz
            </button>
          </div>
        </div>
      </div>
    );
  }

  const currentQ = questions[currentIndex];

  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-8 space-y-6">
      {/* Progress bar and counter */}
      <div className="flex items-center justify-between text-xs text-slate-400">
        <div className="flex items-center gap-2 font-mono">
          <span className="text-indigo-400 font-semibold">Question {currentIndex + 1} of {questions.length}</span>
          <span>·</span>
          <span>Score: {score}</span>
        </div>
        <span className="text-slate-500 font-mono">{currentQ.invariant.standards[0]}</span>
      </div>

      <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
        <div
          className="bg-indigo-500 h-full transition-all duration-300"
          style={{ width: `${((currentIndex + 1) / questions.length) * 100}%` }}
        />
      </div>

      {/* Question Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-5 shadow-xl">
        {/* Scenario */}
        <div className="p-3.5 bg-slate-950/80 rounded-xl border border-slate-800 text-xs text-slate-300 leading-relaxed">
          <span className="font-semibold text-indigo-400 block mb-1 uppercase tracking-wider text-[11px]">
            Real-World Scenario:
          </span>
          {currentQ.scenarioText}
        </div>

        {/* Question */}
        <h3 className="text-base sm:text-lg font-bold text-white tracking-tight leading-snug">
          {currentQ.questionText}
        </h3>

        {/* Options */}
        <div className="space-y-2.5 pt-2">
          {currentQ.options.map((opt, idx) => {
            let optionStyles = 'border-slate-800 bg-slate-950/50 hover:bg-slate-950 hover:border-slate-700 text-slate-300';
            if (selectedOption === idx) {
              optionStyles = 'border-indigo-500 bg-indigo-500/10 text-white';
            }
            if (isAnswerSubmitted) {
              if (opt.isCorrect) {
                optionStyles = 'border-emerald-500/60 bg-emerald-500/10 text-emerald-200';
              } else if (selectedOption === idx && !opt.isCorrect) {
                optionStyles = 'border-rose-500/60 bg-rose-500/10 text-rose-200';
              }
            }

            return (
              <div
                key={idx}
                onClick={() => handleSelectOption(idx)}
                className={`p-4 rounded-xl border text-xs sm:text-sm transition-all cursor-pointer flex items-start gap-3 ${optionStyles}`}
              >
                <div className="w-5 h-5 rounded-full border border-current flex items-center justify-center shrink-0 mt-0.5 text-xs font-mono font-bold">
                  {String.fromCharCode(65 + idx)}
                </div>
                <div className="leading-relaxed flex-1">{opt.text}</div>
                {isAnswerSubmitted && opt.isCorrect && (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                )}
                {isAnswerSubmitted && selectedOption === idx && !opt.isCorrect && (
                  <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                )}
              </div>
            );
          })}
        </div>

        {/* Hint toggle */}
        <div className="pt-2">
          <button
            onClick={() => setShowHint(!showHint)}
            className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1.5 font-medium"
          >
            <Lightbulb className="w-3.5 h-3.5" />
            <span>{showHint ? 'Hide Hint' : 'Need a hint?'}</span>
          </button>
          {showHint && (
            <p className="mt-2 text-xs text-amber-300/90 bg-amber-500/10 border border-amber-500/20 p-3 rounded-lg leading-relaxed">
              {currentQ.hintText}
            </p>
          )}
        </div>

        {/* Explanation when submitted */}
        {isAnswerSubmitted && (
          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 space-y-2 text-xs text-slate-300 leading-relaxed mt-4">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-indigo-400 uppercase tracking-wider text-[11px]">
                Architectural Invariant Proof:
              </span>
              <button
                onClick={() => onOpenDetails(currentQ.invariant)}
                className="text-indigo-400 hover:underline flex items-center gap-1"
              >
                <span>View Full Rule Details</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            </div>
            <p className="font-mono text-indigo-200 text-xs bg-slate-900 p-2.5 rounded border border-slate-800 overflow-x-auto">
              {currentQ.formalProof}
            </p>
            <p className="pt-1">
              <span className="font-semibold text-white">Core Principle: </span>
              {currentQ.explanation}
            </p>
          </div>
        )}

        {/* Action button */}
        <div className="pt-4 flex justify-end">
          {!isAnswerSubmitted ? (
            <button
              onClick={handleSubmitAnswer}
              disabled={selectedOption === null}
              className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-semibold rounded-xl transition-colors shadow-sm"
            >
              Submit Answer
            </button>
          ) : (
            <button
              onClick={handleNextQuestion}
              className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-xl transition-colors shadow-sm flex items-center gap-2"
            >
              <span>{currentIndex === questions.length - 1 ? 'Finish Quiz' : 'Next Question'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
