import React, { useState, useEffect } from 'react';
import { SecurityInvariant } from '../types/invariants';
import { getSimulationProfileForInvariant } from '../utils/invariantVerificationEngine';
import {
  Play,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Terminal,
  ShieldAlert,
  ShieldCheck,
  Zap
} from 'lucide-react';

interface InteractiveSimulatorProps {
  invariant: SecurityInvariant;
}

export const InteractiveSimulator: React.FC<InteractiveSimulatorProps> = ({ invariant }) => {
  const profile = getSimulationProfileForInvariant(invariant);

  const [inputVal, setInputVal] = useState<string>(profile.attackInput);
  const [activePreset, setActivePreset] = useState<'attack' | 'hardened'>('attack');
  const [testResult, setTestResult] = useState<{
    status: 'pass' | 'fail' | 'warn';
    message: string;
    details: string;
    predicateEvaluated: string;
    formalViolation: boolean;
  } | null>(null);

  // Sync state whenever invariant changes
  useEffect(() => {
    const newProfile = getSimulationProfileForInvariant(invariant);
    setInputVal(newProfile.attackInput);
    setActivePreset('attack');
    setTestResult(null);
  }, [invariant.id]);

  const handleLoadPreset = (type: 'attack' | 'hardened') => {
    setActivePreset(type);
    if (type === 'attack') {
      setInputVal(profile.attackInput);
    } else {
      setInputVal(profile.hardenedInput);
    }
    setTestResult(null);
  };

  const handleRunSimulation = () => {
    const result = profile.evaluate(inputVal);
    setTestResult(result);
  };

  return (
    <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 sm:p-5 space-y-4">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-indigo-400 shrink-0" />
          <h4 className="text-sm font-semibold text-white tracking-tight">
            {profile.label}
          </h4>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 font-mono">Preset:</span>
          <button
            onClick={() => handleLoadPreset('attack')}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors flex items-center gap-1.5 ${
              activePreset === 'attack'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                : 'text-slate-400 hover:text-white bg-slate-900 border border-slate-800'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            <span>Attack Payload</span>
          </button>
          <button
            onClick={() => handleLoadPreset('hardened')}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors flex items-center gap-1.5 ${
              activePreset === 'hardened'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                : 'text-slate-400 hover:text-white bg-slate-900 border border-slate-800'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            <span>Hardened Input</span>
          </button>
        </div>
      </div>

      <p className="text-xs text-slate-400 leading-relaxed">
        {profile.description}
      </p>

      {/* Editor & Execution Area */}
      <div className="space-y-3">
        <div className="relative">
          <textarea
            value={inputVal}
            onChange={e => {
              setInputVal(e.target.value);
              setActivePreset('attack'); // User customized
            }}
            rows={4}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors leading-relaxed"
            placeholder="Enter configuration, headers, code, or payload to verify..."
          />
        </div>

        <div className="flex items-center justify-between">
          <span className="text-[11px] text-slate-500 font-mono">
            Grounding: {invariant.standards[0]}
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setInputVal(profile.attackInput);
                setActivePreset('attack');
                setTestResult(null);
              }}
              className="text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1 transition-colors px-2.5 py-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Reset</span>
            </button>

            <button
              onClick={handleRunSimulation}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition-colors shadow-sm"
            >
              <Play className="w-3.5 h-3.5 fill-white" />
              <span>Verify Invariant Logic</span>
            </button>
          </div>
        </div>

        {/* Verification Outcome Card */}
        {testResult && (
          <div
            className={`mt-4 p-4 rounded-xl border text-xs space-y-2 transition-all ${
              testResult.status === 'fail'
                ? 'bg-rose-950/20 border-rose-500/40 text-rose-200'
                : testResult.status === 'warn'
                ? 'bg-amber-950/20 border-amber-500/40 text-amber-200'
                : 'bg-emerald-950/20 border-emerald-500/40 text-emerald-200'
            }`}
          >
            <div className="flex items-center justify-between border-b border-current/20 pb-2">
              <div className="flex items-center gap-2 font-bold text-sm">
                {testResult.status === 'fail' ? (
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                ) : (
                  <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                )}
                <span>{testResult.message}</span>
              </div>
              <span className="font-mono text-[11px] uppercase tracking-wider font-semibold">
                {testResult.status === 'fail' ? 'FAIL / REJECT' : 'PASS / ENFORCED'}
              </span>
            </div>

            <div className="p-2.5 bg-slate-950/60 rounded border border-current/20 font-mono text-xs overflow-x-auto">
              <span className="text-slate-400">Formal Predicate Evaluation: </span>
              <span className="font-semibold text-white">{testResult.predicateEvaluated}</span>
            </div>

            <p className="text-slate-300 leading-relaxed pt-1">
              {testResult.details}
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
