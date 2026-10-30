import React, { useState, useEffect, useRef } from 'react';
import { SecurityInvariant, DomainId, SecurityTopicMeta } from '../types/invariants';
import { domainMetadata, allInvariants } from '../data/invariantsRegistry';
import { convertLatexToUnicode, formatBlockMath, formatInlineMath } from '../utils/mathFormatter';
import {
  Sparkles,
  Send,
  Printer,
  Download,
  Copy,
  Check,
  RotateCcw,
  BookOpen,
  FileText,
  Shield,
  Layers,
  Brain,
  MessageSquare,
  ChevronRight,
  X,
  ExternalLink,
  Code2,
  FileCheck,
  AlertCircle,
  HelpCircle,
  Flame,
  Award,
  Terminal
} from 'lucide-react';

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
  retrievedInvariants?: Array<{
    id: string;
    title: string;
    domainName?: string;
    subdomain?: string;
    standards?: string[];
  }>;
}

interface AICopilotModalProps {
  isOpen: boolean;
  onClose: () => void;
  activeInvariant?: SecurityInvariant | null;
  initialTopic?: SecurityTopicMeta | null;
  onOpenInvariant?: (inv: SecurityInvariant) => void;
  userMasteredCount?: number;
  userTotalCount?: number;
}

export const AICopilotModal: React.FC<AICopilotModalProps> = ({
  isOpen,
  onClose,
  activeInvariant,
  initialTopic,
  onOpenInvariant,
  userMasteredCount = 0,
  userTotalCount = allInvariants.length,
}) => {
  const [activeTab, setActiveTab] = useState<'chat' | 'report'>('chat');

  // Chat State
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'assistant',
      content: `👋 **Hi there! Welcome to your Security Invariants AI Copilot.**

I'm your interactive security mentor. Whether you're getting ready for a senior or staff security interview, reviewing code, or trying to understand tricky vulnerabilities (like request smuggling, ReBAC, or container breakouts), I'm here to walk through them with you in plain, practical terms.

**Things we can do together:**
- 💡 **Ask any security question:** I'll explain how vulnerabilities happen in the real world and how to stop them—no academic fluff.
- 📐 **Understand the security formulas:** I'll break down the mathematical invariants into simple, logical rules.
- 🎙️ **Whiteboard interview practice:** Let's run realistic interview scenarios so you can practice explaining defensive designs out loud.
- 🛡️ **Review code:** Look at vulnerable code vs. production-hardened implementations in Go, TypeScript, Python, and more.
- 📑 **Build custom study sheets:** Switch to the **Custom Report Builder** tab above to generate a tailored workbook ready to print.

What would you like to explore today?`,
      timestamp: Date.now(),
    },
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isChatLoading, setIsChatLoading] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Custom Report Generator State
  const [reportPrompt, setReportPrompt] = useState('');
  const [selectedDomains, setSelectedDomains] = useState<DomainId[]>(
    activeInvariant ? [activeInvariant.domain] : ['coding', 'cloud', 'threatmodeling']
  );
  const [reportType, setReportType] = useState('Staff Interview Whiteboard Workbook');
  const [targetAudience, setTargetAudience] = useState('Senior / Staff Security Engineers');
  const [codeLanguage, setCodeLanguage] = useState('TypeScript & Go');
  const [customInstructions, setCustomInstructions] = useState('');
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  const [previewInvariants, setPreviewInvariants] = useState<any[]>([]);
  const [generatedReport, setGeneratedReport] = useState<{
    title: string;
    reportType: string;
    generatedAt: string;
    markdownContent: string;
    retrievedInvariantsCount?: number;
  } | null>(null);
  const [copiedCode, setCopiedCode] = useState<string | null>(null);

  // Auto-scroll chat
  useEffect(() => {
    if (activeTab === 'chat' && isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, activeTab, isOpen]);

  // Contextual initial message when activeInvariant changes
  useEffect(() => {
    if (activeInvariant && isOpen) {
      setSelectedDomains([activeInvariant.domain]);
    }
  }, [activeInvariant, isOpen]);

  // Pre-fill when opened from 37 Topics Taxonomy
  useEffect(() => {
    if (initialTopic && isOpen) {
      setActiveTab('report');
      setReportPrompt(`${initialTopic.name}: Comprehensive Threat Modeling, Formal Invariants, and Staff Interview Whiteboard Defense (${initialTopic.primaryStandard})`);
      setSelectedDomains([initialTopic.domainId]);
      setReportType('Staff Interview Whiteboard Workbook');
    }
  }, [initialTopic, isOpen]);

  // Live context preview when typing report prompt
  useEffect(() => {
    if (!reportPrompt.trim()) {
      setPreviewInvariants([]);
      return;
    }
    const timer = setTimeout(async () => {
      try {
        const res = await fetch(`/api/ai/context-preview?q=${encodeURIComponent(reportPrompt)}`);
        if (res.ok) {
          const data = await res.json();
          setPreviewInvariants(data.invariants || []);
        }
      } catch {
        // Ignore preview fetch errors
      }
    }, 400);

    return () => clearTimeout(timer);
  }, [reportPrompt]);

  if (!isOpen) return null;

  // Send Chat message
  const handleSendMessage = async (customText?: string) => {
    const textToSend = customText || inputMessage.trim();
    if (!textToSend || isChatLoading) return;

    const userMsg: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: textToSend,
      timestamp: Date.now(),
    };

    setMessages(prev => [...prev, userMsg]);
    if (!customText) setInputMessage('');
    setIsChatLoading(true);
    setChatError(null);

    try {
      const response = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: [...messages, userMsg].map(m => ({
            role: m.role,
            content: m.content,
          })),
          currentInvariant: activeInvariant
            ? {
                id: activeInvariant.id,
                title: activeInvariant.title,
                domain: activeInvariant.domain,
                domainName: activeInvariant.domainName,
                formalInvariant: activeInvariant.formalInvariant,
                standards: activeInvariant.standards,
                plainEnglish: activeInvariant.plainEnglish,
              }
            : null,
          domain: activeInvariant?.domain,
          userContext: {
            masteredCount: userMasteredCount,
            totalCount: userTotalCount,
          },
        }),
      });

      if (!response.ok) {
        throw new Error(`Server returned status ${response.status}`);
      }

      const data = await response.json();
      const assistantMsg: ChatMessage = {
        id: `msg-${Date.now()}`,
        role: 'assistant',
        content: data.reply || 'No response returned.',
        timestamp: Date.now(),
        retrievedInvariants: data.retrievedInvariants || [],
      };

      setMessages(prev => [...prev, assistantMsg]);
    } catch (err: any) {
      console.error('Chat error:', err);
      setChatError(err.message || 'Failed to communicate with AI server.');
      setMessages(prev => [
        ...prev,
        {
          id: `msg-err-${Date.now()}`,
          role: 'assistant',
          content: `⚠️ **Connection Notice:** Unable to reach the AI model service. Please check your network or ensure the server is running. (${err.message})`,
          timestamp: Date.now(),
        },
      ]);
    } finally {
      setIsChatLoading(false);
    }
  };

  // Generate Custom Report
  const handleGenerateReport = async () => {
    if (!reportPrompt.trim()) return;

    setIsGeneratingReport(true);
    setReportError(null);

    try {
      const response = await fetch('/api/ai/generate-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          topicPrompt: reportPrompt,
          reportType,
          domains: selectedDomains,
          targetAudience,
          codeLanguage,
          customRequirements: customInstructions,
          userMasteryContext: {
            masteredCount: userMasteredCount,
            totalCount: userTotalCount,
          },
        }),
      });

      if (!response.ok) {
        throw new Error(`Report generation failed: status ${response.status}`);
      }

      const data = await response.json();
      setGeneratedReport(data);
    } catch (err: any) {
      console.error('Report generation error:', err);
      setReportError(err.message || 'Failed to generate report.');
    } finally {
      setIsGeneratingReport(false);
    }
  };

  // Print Report Handler
  const handlePrintReport = () => {
    if (!generatedReport) return;

    const printWin = window.open('', '_blank');
    if (!printWin) return;

    printWin.document.write(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>${generatedReport.title}</title>
          <meta charset="utf-8" />
          <style>
            @page { size: letter portrait; margin: 18mm 16mm 18mm 16mm; }
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.5; color: #0f172a; padding: 20px; }
            h1 { font-size: 22pt; font-weight: 800; border-bottom: 2pt solid #4338ca; padding-bottom: 8px; margin-bottom: 12px; }
            h2 { font-size: 14pt; font-weight: 700; color: #1e1b4b; border-bottom: 1pt solid #cbd5e1; padding-bottom: 4px; margin-top: 20pt; page-break-after: avoid; }
            h3 { font-size: 11pt; font-weight: 600; color: #312e81; margin-top: 14pt; }
            pre { background: #f8fafc; border: 1pt solid #cbd5e1; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 9pt; white-space: pre-wrap; page-break-inside: avoid; }
            code { font-family: monospace; font-size: 9.5pt; background: #f1f5f9; padding: 2px 4px; border-radius: 4px; }
            blockquote { border-left: 3pt solid #6366f1; padding-left: 12px; color: #334155; margin-left: 0; }
            ul, ol { padding-left: 20px; }
            li { margin-bottom: 4px; }
            .header-meta { font-family: monospace; font-size: 9pt; color: #64748b; margin-bottom: 20px; }
            .font-mono { font-family: monospace; }
            div[class*="bg-slate-950"] { background: #0f172a !important; color: #c7d2fe !important; border: 1pt solid #312e81 !important; padding: 8px 12px; border-radius: 6px; margin: 10px 0; }
            span[class*="bg-slate-950"] { background: #0f172a !important; color: #c7d2fe !important; border: 1pt solid #312e81 !important; padding: 2px 6px; border-radius: 4px; }
            span[class*="bg-indigo-500"] { background: #312e81 !important; color: #e0e7ff !important; padding: 2px 5px; border-radius: 4px; font-size: 8pt; font-weight: 700; }
            @media print {
              body { padding: 0; }
              .no-print { display: none !important; }
            }
          </style>
        </head>
        <body>
          <div class="header-meta">
            SECURITY INVARIANTS TECHNICAL STUDY SYSTEM · CUSTOM AI GENERATED REPORT
          </div>
          <div>${formatMarkdownToHTML(generatedReport.markdownContent)}</div>
          <script>
            window.onload = function() { window.print(); };
          </script>
        </body>
      </html>
    `);
    printWin.document.close();
  };

  // Download Markdown file
  const handleDownloadMarkdown = () => {
    if (!generatedReport) return;
    const blob = new Blob([generatedReport.markdownContent], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${generatedReport.title.toLowerCase().replace(/[^a-z0-9]+/g, '_')}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Copy helper
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  // Quick Preset Prompts for Custom Reports
  const reportPresets = [
    {
      title: 'Path Traversal & File Uploads (CWE-22 / 434)',
      prompt: 'Path Traversal, Arbitrary File Uploads, and Zip Slip Symlink Dereferences: Canonical Confinement and Object Storage Sandboxing',
      domains: ['coding', 'web'] as DomainId[],
      type: 'Staff Interview Whiteboard Workbook',
    },
    {
      title: 'HTTP Smuggling & Framing Desync (RFC 9112)',
      prompt: 'HTTP Request Smuggling, CL.TE / TE.CL Desynchronization, and H2.CL Protocol Downgrades: RFC 9112 Strict Framing Invariants',
      domains: ['http', 'api'] as DomainId[],
      type: 'Staff Interview Whiteboard Workbook',
    },
    {
      title: 'Container & Kubernetes Breakout Audit',
      prompt: 'Production Container Runtime & Kubernetes Isolation: Linux Namespaces, Seccomp-BPF Syscall Filtering, and Pod Security Standards (PSS Restricted)',
      domains: ['containers', 'k8s', 'cloud'] as DomainId[],
      type: 'Defensive Infrastructure Audit Guide',
    },
    {
      title: 'Generative AI & LLM Agent Security',
      prompt: 'Generative AI & LLM Agent Safety: Indirect Prompt Injection Quarantines, Dual-LLM Supervisor Validation, and Tool Authorization Envelopes',
      domains: ['ai', 'coding'] as DomainId[],
      type: 'Comprehensive Architecture Deep-Dive',
    },
    {
      title: 'Threat Modeling: STRIDE & PASTA Framework',
      prompt: 'Production Threat Modeling: STRIDE Trust Boundaries, PASTA Attack Trees, Data Flow Diagrams (DFDs), and Automated Cut Set Elimination',
      domains: ['threatmodeling', 'cloud', 'coding'] as DomainId[],
      type: 'Architectural Defense & Threat Modeling Audit',
    },
    {
      title: 'Web3 & Smart Contract Audit Playbook',
      prompt: 'Web3 & DeFi Economic Security: Checks-Effects-Interactions (CEI), TWAP Oracle Manipulation, ERC-4626 Vault Inflation, and Signature Malleability',
      domains: ['smartcontracts', 'crypto'] as DomainId[],
      type: 'CWE & OWASP Vulnerability Elimination Guide',
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-md animate-fadeIn">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-5xl h-[90vh] flex flex-col shadow-2xl overflow-hidden relative">
        {/* Top Header */}
        <div className="px-6 py-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-indigo-600 to-violet-600 flex items-center justify-center text-white shadow-md shadow-indigo-600/30">
              <Brain className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-white text-base">
                  Security Invariants AI Copilot
                </h3>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span>Full Document Grounding (1,110 Rules)</span>
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Senior & Staff architect assistant for clearing doubts, formal proofs, code reviews, and bespoke reports
              </p>
            </div>
          </div>

          {/* Close & Tabs */}
          <div className="flex items-center gap-3">
            <div className="flex items-center p-1 bg-slate-900 border border-slate-800 rounded-xl text-xs">
              <button
                onClick={() => setActiveTab('chat')}
                className={`px-3 py-1.5 rounded-lg font-semibold flex items-center gap-1.5 transition-colors ${
                  activeTab === 'chat'
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <MessageSquare className="w-3.5 h-3.5" />
                <span>Discussion & Help</span>
              </button>
              <button
                onClick={() => setActiveTab('report')}
                className={`px-3 py-1.5 rounded-lg font-semibold flex items-center gap-1.5 transition-colors ${
                  activeTab === 'report'
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                <span>Generate Custom Report</span>
              </button>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              title="Close modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* TAB 1: CHAT DISCUSSION */}
        {activeTab === 'chat' && (
          <div className="flex-1 flex flex-col overflow-hidden bg-slate-950/60">
            {/* Active invariant banner if studying one */}
            {activeInvariant && (
              <div className="px-6 py-2.5 bg-indigo-950/40 border-b border-indigo-900/50 flex items-center justify-between gap-4 text-xs">
                <div className="flex items-center gap-2 truncate">
                  <span className="font-mono font-bold text-indigo-400 shrink-0">
                    {activeInvariant.id}
                  </span>
                  <span className="text-slate-200 font-medium truncate">
                    {activeInvariant.title}
                  </span>
                  <span className="text-slate-500 font-mono hidden sm:inline">
                    ({activeInvariant.subdomain})
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() =>
                      handleSendMessage(
                        `Can you explain the mathematical logic formula and real-world attack scenario for rule ${activeInvariant.id}: "${activeInvariant.title}"?`
                      )
                    }
                    className="text-[11px] text-indigo-300 hover:text-white bg-indigo-500/20 px-2 py-1 rounded transition-colors"
                  >
                    Explain Formal Logic
                  </button>
                  <button
                    onClick={() =>
                      handleSendMessage(
                        `How would you defend ${activeInvariant.id} in a Staff AppSec interview? Give me the model spoken answer.`
                      )
                    }
                    className="text-[11px] text-indigo-300 hover:text-white bg-indigo-500/20 px-2 py-1 rounded transition-colors"
                  >
                    Mock Interview
                  </button>
                </div>
              </div>
            )}

            {/* Messages Scroll Area */}
            <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
              {messages.map(msg => (
                <div
                  key={msg.id}
                  className={`flex gap-3 max-w-4xl ${
                    msg.role === 'user' ? 'ml-auto flex-row-reverse' : 'mr-auto'
                  }`}
                >
                  <div
                    className={`w-7 h-7 rounded-lg shrink-0 flex items-center justify-center text-xs font-bold ${
                      msg.role === 'user'
                        ? 'bg-slate-800 text-slate-300 border border-slate-700'
                        : 'bg-indigo-600 text-white shadow-sm'
                    }`}
                  >
                    {msg.role === 'user' ? 'You' : <Brain className="w-4 h-4" />}
                  </div>

                  <div
                    className={`p-4 rounded-2xl text-xs sm:text-sm leading-relaxed ${
                      msg.role === 'user'
                        ? 'bg-indigo-600 text-white rounded-tr-none'
                        : 'bg-slate-900 border border-slate-800 text-slate-200 rounded-tl-none shadow-md'
                    }`}
                  >
                    {/* Grounded Invariants Pills (if assistant message returned them) */}
                    {msg.role === 'assistant' && msg.retrievedInvariants && msg.retrievedInvariants.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5 mb-3 pb-2.5 border-b border-slate-800">
                        <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1 font-semibold">
                          <BookOpen className="w-3 h-3 text-indigo-400" />
                          <span>Grounded In {msg.retrievedInvariants.length} Curriculum Rules:</span>
                        </span>
                        {msg.retrievedInvariants.map(inv => (
                          <button
                            key={inv.id}
                            onClick={() => {
                              const found = allInvariants.find(r => r.id === inv.id);
                              if (found && onOpenInvariant) onOpenInvariant(found);
                            }}
                            className="px-2 py-0.5 rounded bg-slate-950 hover:bg-slate-800 text-[10px] font-mono text-indigo-300 hover:text-white border border-slate-800 hover:border-indigo-500/50 transition-colors flex items-center gap-1 group"
                            title={`Click to open full page for ${inv.title}`}
                          >
                            <span>{inv.id}</span>
                            <span className="text-slate-500 group-hover:text-slate-300 truncate max-w-[130px]">
                              {inv.title}
                            </span>
                            <ExternalLink className="w-2.5 h-2.5 opacity-60" />
                          </button>
                        ))}
                      </div>
                    )}

                    <div
                      className="prose prose-invert prose-xs max-w-none space-y-2.5"
                      dangerouslySetInnerHTML={{
                        __html: formatMarkdownToHTML(msg.content),
                      }}
                    />

                    {msg.role === 'assistant' && msg.id !== 'welcome' && (
                      <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                        <span>Grounded Security Architect Response</span>
                        <button
                          onClick={() => handleCopy(msg.content, msg.id)}
                          className="flex items-center gap-1 hover:text-slate-300 transition-colors"
                        >
                          {copiedCode === msg.id ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" />
                              <span className="text-emerald-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy Answer</span>
                            </>
                          )}
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))}

              {isChatLoading && (
                <div className="flex gap-3 mr-auto">
                  <div className="w-7 h-7 rounded-lg bg-indigo-600 text-white shrink-0 flex items-center justify-center">
                    <Brain className="w-4 h-4 animate-spin" />
                  </div>
                  <div className="bg-slate-900 border border-slate-800 rounded-2xl rounded-tl-none p-4 text-xs text-slate-400 flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse" />
                    <span>Analyzing 1,110 invariants and synthesizing architectural response...</span>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Quick Action Suggestion Chips */}
            <div className="px-4 sm:px-6 py-2.5 bg-slate-950/90 border-t border-slate-800/80 flex items-center gap-2 overflow-x-auto scrollbar-none text-[11px]">
              <span className="text-slate-500 font-mono text-[10px] shrink-0 font-semibold uppercase">
                Explore & Drill:
              </span>
              <button
                onClick={() => handleSendMessage('Explain how path canonicalization and symlink dereferencing prevent Zip Slip RCE.')}
                className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 shrink-0 transition-colors flex items-center gap-1"
              >
                <HelpCircle className="w-3 h-3 text-indigo-400" />
                <span>Zip Slip & Symlinks</span>
              </button>
              <button
                onClick={() => handleSendMessage('Explain how Google Zanzibar ReBAC evaluates transitive access permissions with zero privilege leakage.')}
                className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 shrink-0 transition-colors flex items-center gap-1"
              >
                <Layers className="w-3 h-3 text-amber-400" />
                <span>Zanzibar ReBAC Invariant</span>
              </button>
              <button
                onClick={() => handleSendMessage('What is the formal theorem preventing HTTP request smuggling in RFC 9112 CL.TE desynchronization?')}
                className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 shrink-0 transition-colors flex items-center gap-1"
              >
                <Flame className="w-3 h-3 text-rose-400" />
                <span>HTTP Smuggling Formula</span>
              </button>
              <button
                onClick={() => handleSendMessage('Simulate a Staff Security Engineer interview scenario on distributed rate limiting and token bucket invariants.')}
                className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 shrink-0 transition-colors flex items-center gap-1"
              >
                <Award className="w-3 h-3 text-emerald-400" />
                <span>Whiteboard Mock Interview</span>
              </button>
            </div>

            {/* Input Form */}
            <div className="p-4 sm:p-6 bg-slate-950 border-t border-slate-800">
              <form
                onSubmit={e => {
                  e.preventDefault();
                  handleSendMessage();
                }}
                className="flex items-center gap-3"
              >
                <input
                  type="text"
                  value={inputMessage}
                  onChange={e => setInputMessage(e.target.value)}
                  placeholder="Ask any technical doubt, formal logic formula, attack mechanic, or interview question..."
                  disabled={isChatLoading}
                  className="flex-1 px-4 py-3 bg-slate-900 border border-slate-800 rounded-xl text-xs sm:text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors"
                />
                <button
                  type="submit"
                  disabled={isChatLoading || !inputMessage.trim()}
                  className="px-5 py-3 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-xl text-xs sm:text-sm font-bold transition-all flex items-center gap-2 shadow-sm shadow-indigo-600/30 shrink-0"
                >
                  <Send className="w-4 h-4" />
                  <span className="hidden sm:inline">Ask AI</span>
                </button>
              </form>
            </div>
          </div>
        )}

        {/* TAB 2: GENERATE CUSTOM REPORT */}
        {activeTab === 'report' && (
          <div className="flex-1 flex flex-col md:flex-row overflow-hidden bg-slate-950">
            {/* Left Column: Form & Presets */}
            <div className="w-full md:w-96 border-r border-slate-800 flex flex-col overflow-y-auto p-5 space-y-5 shrink-0 bg-slate-950/80">
              <div>
                <h4 className="font-bold text-white text-sm mb-1">
                  Generate Bespoke Security Masterclass Report
                </h4>
                <p className="text-xs text-slate-400">
                  Synthesize an exhaustive, multi-page technical study guide grounded in our 1,110 invariants.
                </p>
              </div>

              {/* Topic Prompt Input */}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-300">
                  Topic / Goal Prompt *
                </label>
                <textarea
                  rows={3}
                  value={reportPrompt}
                  onChange={e => setReportPrompt(e.target.value)}
                  placeholder="e.g. Path Traversal & Arbitrary File Upload: Architectural Invariants & Defense..."
                  className="w-full p-3 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 resize-none"
                />
              </div>

              {/* Live Invariant Grounding Preview */}
              {previewInvariants.length > 0 && (
                <div className="p-3 rounded-xl bg-slate-900/90 border border-indigo-500/30 space-y-2">
                  <div className="text-[11px] font-mono font-bold text-indigo-300 flex items-center gap-1.5">
                    <BookOpen className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Grounded In {previewInvariants.length} Database Invariants:</span>
                  </div>
                  <div className="space-y-1 max-h-24 overflow-y-auto pr-1">
                    {previewInvariants.map(inv => (
                      <div key={inv.id} className="text-[10px] font-mono text-slate-300 truncate">
                        <span className="text-indigo-400 font-bold mr-1">{inv.id}:</span>
                        <span>{inv.title}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Quick Presets */}
              <div className="space-y-1.5">
                <label className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
                  Quick Presets
                </label>
                <div className="space-y-1.5">
                  {reportPresets.map((preset, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => {
                        setReportPrompt(preset.prompt);
                        setSelectedDomains(preset.domains);
                        setReportType(preset.type);
                      }}
                      className="w-full p-2.5 bg-slate-900/60 hover:bg-slate-900 border border-slate-800/80 hover:border-slate-700 rounded-lg text-left transition-colors"
                    >
                      <div className="font-semibold text-xs text-slate-200">
                        {preset.title}
                      </div>
                      <div className="text-[10px] text-slate-400 mt-0.5 truncate">
                        {preset.type}
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Report Category */}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-300">
                  Report Type & Layout
                </label>
                <select
                  value={reportType}
                  onChange={e => setReportType(e.target.value)}
                  className="w-full p-2.5 bg-slate-900 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="Staff Interview Whiteboard Workbook">Staff Interview Whiteboard Workbook (Masterclass)</option>
                  <option value="Architectural Defense & Threat Modeling Audit">Architectural Defense & Threat Modeling Audit</option>
                  <option value="CWE & OWASP Vulnerability Elimination Guide">CWE & OWASP Vulnerability Elimination Guide</option>
                  <option value="CI/CD Automated Test Verification Matrix">CI/CD Automated Test Verification Matrix</option>
                </select>
              </div>

              {/* Preferred Code Language */}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-300">
                  Preferred Code Language
                </label>
                <select
                  value={codeLanguage}
                  onChange={e => setCodeLanguage(e.target.value)}
                  className="w-full p-2.5 bg-slate-900 border border-slate-800 rounded-xl text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                >
                  <option value="TypeScript & Go">TypeScript & Go</option>
                  <option value="Python">Python</option>
                  <option value="Rust">Rust</option>
                  <option value="Java & C++">Java & C++</option>
                  <option value="Solidity (Web3)">Solidity (Web3)</option>
                </select>
              </div>

              {/* Target Audience */}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-300">
                  Target Audience
                </label>
                <input
                  type="text"
                  value={targetAudience}
                  onChange={e => setTargetAudience(e.target.value)}
                  placeholder="e.g. Senior / Staff AppSec Engineers"
                  className="w-full p-2.5 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              {/* Custom Instructions */}
              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-300">
                  Custom Requirements (Optional)
                </label>
                <input
                  type="text"
                  value={customInstructions}
                  onChange={e => setCustomInstructions(e.target.value)}
                  placeholder="e.g. Include executable curl commands and OPA Rego rules"
                  className="w-full p-2.5 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white focus:outline-none focus:border-indigo-500"
                />
              </div>

              {/* Generate Button */}
              <div className="pt-2">
                <button
                  type="button"
                  onClick={handleGenerateReport}
                  disabled={isGeneratingReport || !reportPrompt.trim()}
                  className="w-full py-3 bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition-all flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/30"
                >
                  {isGeneratingReport ? (
                    <>
                      <Brain className="w-4 h-4 animate-spin" />
                      <span>Synthesizing Master Report...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4" />
                      <span>Generate Full Masterclass Report</span>
                    </>
                  )}
                </button>
              </div>

              {reportError && (
                <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl text-xs text-rose-400 flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{reportError}</span>
                </div>
              )}
            </div>

            {/* Right Column: Generated Report Preview & Printing */}
            <div className="flex-1 flex flex-col overflow-hidden bg-slate-900/50">
              {generatedReport ? (
                <div className="flex-1 flex flex-col overflow-hidden">
                  {/* Action Bar */}
                  <div className="px-6 py-3.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between gap-4 shrink-0">
                    <div>
                      <h4 className="font-bold text-white text-sm truncate max-w-lg">
                        {generatedReport.title}
                      </h4>
                      <p className="text-[11px] font-mono text-slate-400">
                        {generatedReport.reportType} · Generated {new Date(generatedReport.generatedAt).toLocaleTimeString()}
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={handlePrintReport}
                        className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
                        title="Print hard copy or save as PDF"
                      >
                        <Printer className="w-3.5 h-3.5" />
                        <span>Print Workbook</span>
                      </button>

                      <button
                        onClick={handleDownloadMarkdown}
                        className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5 border border-slate-700"
                        title="Download Markdown file"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Markdown</span>
                      </button>

                      <button
                        onClick={() => handleCopy(generatedReport.markdownContent, 'report')}
                        className="p-1.5 text-slate-400 hover:text-white bg-slate-800 rounded-lg border border-slate-700 transition-colors"
                        title="Copy Markdown"
                      >
                        {copiedCode === 'report' ? (
                          <Check className="w-4 h-4 text-emerald-400" />
                        ) : (
                          <Copy className="w-4 h-4" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Report Content View */}
                  <div className="flex-1 overflow-y-auto p-6 sm:p-8 bg-slate-950/30">
                    <div className="max-w-4xl mx-auto bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-10 shadow-xl">
                      <div
                        className="prose prose-invert prose-sm max-w-none space-y-4"
                        dangerouslySetInnerHTML={{
                          __html: formatMarkdownToHTML(generatedReport.markdownContent),
                        }}
                      />
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-slate-500">
                  <div className="w-16 h-16 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center mb-4 text-indigo-400">
                    <FileText className="w-8 h-8" />
                  </div>
                  <h4 className="text-base font-bold text-white mb-1">
                    No Report Generated Yet
                  </h4>
                  <p className="text-xs max-w-md text-slate-400 leading-relaxed mb-6">
                    Enter any security topic or select a preset on the left to generate an exhaustive, publication-grade Staff interview workbook or architecture audit.
                  </p>
                  <button
                    onClick={() => {
                      setReportPrompt('Path Traversal & Arbitrary File Upload: Architectural Invariants & Defense');
                      setSelectedDomains(['coding', 'web']);
                    }}
                    className="px-4 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 rounded-xl text-xs font-semibold transition-colors flex items-center gap-2"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Try: Path Traversal & Arbitrary File Upload</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// Markdown and LaTeX Math to HTML formatter for the report & chat display
function formatMarkdownToHTML(markdown: string): string {
  if (!markdown) return '';

  // 1. Temporarily extract code blocks so code contents aren't modified
  const codeBlocks: string[] = [];
  let processed = markdown.replace(/```([a-z0-9_-]*)\n([\s\S]*?)```/g, (_match, _lang, code) => {
    const idx = codeBlocks.length;
    codeBlocks.push(
      `<pre class="p-4 rounded-xl bg-slate-950 border border-slate-800 text-indigo-200 font-mono text-xs overflow-x-auto my-3 leading-relaxed"><code>${escapeHTML(
        code.trim()
      )}</code></pre>`
    );
    return `__CODE_BLOCK_${idx}__`;
  });

  // 2. Format Block Math: $$...$$
  processed = processed.replace(/\$\$([\s\S]*?)\$\$/g, (_match, formula) => {
    return formatBlockMath(formula);
  });

  // 3. Format Inline Math: $...$ (ignoring standalone monetary values like $100)
  processed = processed.replace(/\$([^\$\n]+?)\$/g, (_match, formula) => {
    if (/^\s*\d+([.,]\d+)?\s*$/.test(formula)) {
      return `$${formula}$`;
    }
    return formatInlineMath(formula);
  });

  // 4. Clean any residual raw LaTeX math symbols in text (e.g. \forall, \in, \land, \_, etc.)
  processed = convertLatexToUnicode(processed);

  // 5. Inline code
  processed = processed.replace(/`([^`]+)`/g, '<code class="px-1.5 py-0.5 rounded bg-slate-950 text-indigo-300 font-mono text-xs border border-slate-800">$1</code>');

  // 6. Headers
  processed = processed
    .replace(/^# (.*$)/gim, '<h1 class="text-xl sm:text-2xl font-black text-white pb-2 mb-3 border-b border-indigo-500/30">$1</h1>')
    .replace(/^## (.*$)/gim, '<h2 class="text-lg font-bold text-white mt-6 mb-2 text-indigo-300 border-b border-slate-800 pb-1">$1</h2>')
    .replace(/^### (.*$)/gim, '<h3 class="text-sm font-bold text-slate-200 mt-4 mb-1">$1</h3>')
    .replace(/^#### (.*$)/gim, '<h4 class="text-xs font-bold text-slate-300 mt-3 mb-1 font-mono uppercase tracking-wider">$1</h4>');

  // 7. Bold & italic
  processed = processed
    .replace(/\*\*(.*?)\*\*/g, '<strong class="text-white font-semibold">$1</strong>')
    .replace(/\*(.*?)\*/g, '<em class="text-slate-300">$1</em>');

  // 8. Blockquotes
  processed = processed.replace(/^\> (.*$)/gim, '<blockquote class="border-l-2 border-indigo-500 pl-3 my-2 text-slate-300 italic text-xs leading-relaxed">$1</blockquote>');

  // 9. Unordered & Ordered lists
  processed = processed
    .replace(/^\- (.*$)/gim, '<li class="ml-4 list-disc text-slate-300 mb-1">$1</li>')
    .replace(/^\* (.*$)/gim, '<li class="ml-4 list-disc text-slate-300 mb-1">$1</li>')
    .replace(/^[0-9]+\. (.*$)/gim, '<li class="ml-4 list-decimal text-slate-300 mb-1">$1</li>');

  // 10. Horizontal rules
  processed = processed.replace(/^---$/gim, '<hr class="border-slate-800 my-4" />');

  // 11. Spacing
  processed = processed.replace(/\n\n/g, '<div class="h-2"></div>');

  // 12. Restore protected code blocks
  processed = processed.replace(/__CODE_BLOCK_(\d+)__/g, (_match, idxStr) => {
    const idx = parseInt(idxStr, 10);
    return codeBlocks[idx] || '';
  });

  return processed;
}

function escapeHTML(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

