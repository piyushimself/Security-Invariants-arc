import React from 'react';
import { ShieldCheck, BookOpen, ExternalLink } from 'lucide-react';

export const Footer: React.FC = () => {
  return (
    <footer className="mt-auto border-t border-slate-800 bg-slate-950 py-8 px-4 sm:px-6">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-indigo-400" />
          <span className="text-slate-400 font-medium">Security Invariants Library</span>
          <span>·</span>
          <span>511 Formal Rules Across 14 Engineering Domains</span>
        </div>

        <div className="flex flex-wrap items-center gap-4 text-slate-400">
          <span>Standards: RFCs, NIST SP 800, OWASP, CWE, W3C, CIS</span>
          <span>·</span>
          <span>Fail-Closed Formal Verification</span>
        </div>
      </div>
    </footer>
  );
};
