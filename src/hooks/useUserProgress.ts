import { useState, useEffect, useCallback } from 'react';
import { UserProgress } from '../types/invariants';

const STORAGE_KEY = 'sec_invariants_progress_v1';

const getInitialProgress = (): UserProgress => {
  const today = new Date().toISOString().split('T')[0];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return {
        bookmarkedIds: parsed.bookmarkedIds || [],
        masteredIds: parsed.masteredIds || [],
        reviewedIds: parsed.reviewedIds || [],
        srsData: parsed.srsData || {},
        quizHistory: parsed.quizHistory || [],
        notes: parsed.notes || {},
        studyStreakDays: parsed.studyStreakDays || 1,
        lastActiveDate: parsed.lastActiveDate || today
      };
    }
  } catch (e) {
    console.error('Failed to parse stored user progress', e);
  }

  return {
    bookmarkedIds: ['SEC-HTTP-001', 'SEC-WEB-001', 'SEC-API-001', 'SEC-AUTH-001'],
    masteredIds: [],
    reviewedIds: ['SEC-HTTP-001', 'SEC-WEB-001'],
    srsData: {},
    quizHistory: [],
    notes: {},
    studyStreakDays: 1,
    lastActiveDate: today
  };
};

export function useUserProgress() {
  const [progress, setProgress] = useState<UserProgress>(getInitialProgress);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(progress));
    } catch (e) {
      console.error('Failed to save user progress', e);
    }
  }, [progress]);

  // Update study streak if active on a new calendar day
  useEffect(() => {
    const today = new Date().toISOString().split('T')[0];
    if (progress.lastActiveDate !== today) {
      const last = new Date(progress.lastActiveDate);
      const curr = new Date(today);
      const diffDays = Math.round((curr.getTime() - last.getTime()) / (1000 * 3600 * 24));
      
      setProgress(prev => ({
        ...prev,
        lastActiveDate: today,
        studyStreakDays: diffDays === 1 ? prev.studyStreakDays + 1 : 1
      }));
    }
  }, [progress.lastActiveDate]);

  const toggleBookmark = useCallback((ruleId: string) => {
    setProgress(prev => {
      const exists = prev.bookmarkedIds.includes(ruleId);
      return {
        ...prev,
        bookmarkedIds: exists
          ? prev.bookmarkedIds.filter(id => id !== ruleId)
          : [...prev.bookmarkedIds, ruleId]
      };
    });
  }, []);

  const toggleMastered = useCallback((ruleId: string) => {
    setProgress(prev => {
      const exists = prev.masteredIds.includes(ruleId);
      return {
        ...prev,
        masteredIds: exists
          ? prev.masteredIds.filter(id => id !== ruleId)
          : [...prev.masteredIds, ruleId]
      };
    });
  }, []);

  const recordSRSReview = useCallback((ruleId: string, rating: 'again' | 'hard' | 'good' | 'easy') => {
    const now = Date.now();
    setProgress(prev => {
      const current = prev.srsData[ruleId] || {
        interval: 1,
        repetition: 0,
        easeFactor: 2.5,
        nextDueDate: now,
        lastReviewed: now,
        consecutiveCorrect: 0
      };

      let nextInterval = 1;
      let newRep = current.repetition + 1;
      let newConsecutive = current.consecutiveCorrect;
      let newEase = current.easeFactor;

      if (rating === 'again') {
        nextInterval = 1;
        newConsecutive = 0;
        newEase = Math.max(1.3, newEase - 0.2);
      } else if (rating === 'hard') {
        nextInterval = Math.max(1, Math.round(current.interval * 1.2));
        newConsecutive = Math.max(0, newConsecutive);
        newEase = Math.max(1.3, newEase - 0.15);
      } else if (rating === 'good') {
        nextInterval = current.interval === 1 ? 3 : Math.round(current.interval * newEase);
        newConsecutive += 1;
      } else if (rating === 'easy') {
        nextInterval = current.interval === 1 ? 5 : Math.round(current.interval * newEase * 1.3);
        newConsecutive += 2;
        newEase = Math.min(3.0, newEase + 0.15);
      }

      const nextDueDate = now + nextInterval * 24 * 60 * 60 * 1000;

      const reviewedSet = new Set(prev.reviewedIds);
      reviewedSet.add(ruleId);

      const masteredSet = new Set(prev.masteredIds);
      if (newConsecutive >= 3) {
        masteredSet.add(ruleId);
      }

      return {
        ...prev,
        reviewedIds: Array.from(reviewedSet),
        masteredIds: Array.from(masteredSet),
        srsData: {
          ...prev.srsData,
          [ruleId]: {
            interval: nextInterval,
            repetition: newRep,
            easeFactor: Number(newEase.toFixed(2)),
            nextDueDate,
            lastReviewed: now,
            consecutiveCorrect: newConsecutive
          }
        }
      };
    });
  }, []);

  const recordQuizResult = useCallback((result: { totalQuestions: number; score: number; domainBreakdown: Record<string, number> }) => {
    setProgress(prev => ({
      ...prev,
      quizHistory: [
        {
          id: 'quiz_' + Date.now(),
          date: Date.now(),
          totalQuestions: result.totalQuestions,
          score: result.score,
          domainBreakdown: result.domainBreakdown
        },
        ...prev.quizHistory
      ].slice(0, 50)
    }));
  }, []);

  const saveRuleNote = useCallback((ruleId: string, note: string) => {
    setProgress(prev => ({
      ...prev,
      notes: {
        ...prev.notes,
        [ruleId]: note
      }
    }));
  }, []);

  const resetAllProgress = useCallback(() => {
    const today = new Date().toISOString().split('T')[0];
    const fresh: UserProgress = {
      bookmarkedIds: [],
      masteredIds: [],
      reviewedIds: [],
      srsData: {},
      quizHistory: [],
      notes: {},
      studyStreakDays: 1,
      lastActiveDate: today
    };
    setProgress(fresh);
  }, []);

  return {
    progress,
    toggleBookmark,
    toggleMastered,
    recordSRSReview,
    recordQuizResult,
    saveRuleNote,
    resetAllProgress
  };
}
