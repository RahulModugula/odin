import { useState } from 'react';
import type { Finding } from '../types';

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <button
      onClick={copy}
      className="text-[10px] text-gray-500 hover:text-gray-300 px-1.5 py-0.5 rounded transition-colors"
    >
      {copied ? '✓ Copied' : 'Copy'}
    </button>
  );
}

interface FindingCardProps {
  finding: Finding;
}

const SEVERITY_STYLES: Record<Finding['severity'], { border: string; badge: string; badgeText: string }> = {
  critical: { border: 'border-l-red-500', badge: 'bg-red-950/80 text-red-400 ring-1 ring-red-500/20', badgeText: 'CRITICAL' },
  high: { border: 'border-l-orange-500', badge: 'bg-orange-950/80 text-orange-400 ring-1 ring-orange-500/20', badgeText: 'HIGH' },
  medium: { border: 'border-l-amber-500', badge: 'bg-amber-950/80 text-amber-400 ring-1 ring-amber-500/20', badgeText: 'MEDIUM' },
  low: { border: 'border-l-blue-500', badge: 'bg-blue-950/80 text-blue-400 ring-1 ring-blue-500/20', badgeText: 'LOW' },
  info: { border: 'border-l-gray-500', badge: 'bg-gray-800 text-gray-400 ring-1 ring-gray-600/20', badgeText: 'INFO' },
};

export function FindingCard({ finding }: FindingCardProps) {
  const [feedback, setFeedback] = useState<'none' | 'helpful' | 'not_helpful'>('none');
  const style = SEVERITY_STYLES[finding.severity];
  const isRule = finding.source === 'rule';

  const handleFeedback = async (action: 'helpful' | 'not_helpful') => {
    setFeedback(action);
    try {
      await fetch('/api/feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          finding_id: `${finding.category}-${finding.title}`,
          action,
          category: finding.category,
          title: finding.title,
          language: 'unknown',
        }),
      });
    } catch {
      // silent fail
    }
  };

  return (
    <div className={`bg-gray-800/50 rounded-lg border border-gray-700/40 border-l-4 ${style.border} p-4 space-y-2.5`}>
      <div className="flex items-start gap-2 flex-wrap">
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${style.badge} tracking-wider`}>
          {style.badgeText}
        </span>
        <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-gray-800 text-gray-400 tracking-wide">
          {finding.category}
        </span>
        {/* Source badge — driven by the source field, not title heuristics */}
        <span className={`text-[10px] font-medium px-2 py-0.5 rounded tracking-wide ${
          isRule
            ? 'bg-violet-950/60 text-violet-400 ring-1 ring-violet-500/20'
            : 'bg-indigo-950/60 text-indigo-400 ring-1 ring-indigo-500/20'
        }`}>
          {isRule ? '⚡ Rule' : '🤖 AI'}
        </span>
        {finding.line_start != null && (
          <span className="text-[10px] text-gray-500 ml-auto font-mono">
            {finding.line_end != null && finding.line_end !== finding.line_start
              ? `Lines ${finding.line_start}–${finding.line_end}`
              : `Line ${finding.line_start}`}
          </span>
        )}
      </div>

      <h4 className="text-sm font-semibold text-gray-100">{finding.title}</h4>
      <p className="text-sm text-gray-400 leading-relaxed">{finding.description}</p>

      {/* Attack scenario — what an attacker actually does */}
      {finding.attack_scenario && (
        <details className="group">
          <summary className="cursor-pointer text-xs font-medium text-amber-400 hover:text-amber-300 flex items-center gap-1 select-none">
            <span className="group-open:rotate-90 transition-transform inline-block">▶</span>
            ⚠️ Attack scenario
          </summary>
          <div className="mt-2 bg-amber-950/20 border border-amber-500/15 rounded-md px-3 py-2.5">
            <p className="text-xs text-amber-200/80 leading-relaxed">{finding.attack_scenario}</p>
          </div>
        </details>
      )}

      {/* Fix code block — copy-paste fix */}
      {finding.fix_code ? (
        <div className="bg-emerald-950/20 border border-emerald-500/15 rounded-md overflow-hidden">
          <div className="flex items-center justify-between px-3 py-1.5 border-b border-emerald-500/10">
            <p className="text-[10px] font-medium text-emerald-400">✅ Suggested fix</p>
            <CopyButton text={finding.fix_code} />
          </div>
          <pre className="px-3 py-2.5 text-xs text-emerald-100/90 overflow-x-auto font-mono leading-relaxed">
            {finding.fix_code}
          </pre>
        </div>
      ) : finding.suggestion ? (
        <div className="bg-indigo-950/30 border border-indigo-500/15 rounded-md px-3 py-2.5">
          <p className="text-xs font-medium text-indigo-300 mb-1">💡 Suggestion</p>
          <p className="text-sm text-gray-300 leading-relaxed">{finding.suggestion}</p>
        </div>
      ) : null}

      <div className="flex items-center justify-between pt-0.5">
        <div className="text-[10px] text-gray-600 font-medium">
          Confidence: {Math.round(finding.confidence * 100)}%
        </div>

        {/* Feedback buttons */}
        {feedback === 'none' ? (
          <div className="flex items-center gap-1">
            <span className="text-[10px] text-gray-600 mr-1">Helpful?</span>
            <button
              onClick={() => handleFeedback('helpful')}
              className="p-1 rounded hover:bg-gray-700/50 text-gray-600 hover:text-emerald-400 transition-colors"
              title="Mark as helpful"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M14 10h4.764a2 2 0 011.789 2.894l-3.5 7A2 2 0 0115.263 21h-4.017c-.163 0-.326-.02-.485-.06L7 20m7-10V5a2 2 0 00-2-2h-.095c-.5 0-.905.405-.905.905 0 .714-.211 1.412-.608 2.006L7 11v9m7-10h-2M7 20H5a2 2 0 01-2-2v-6a2 2 0 012-2h2.5" />
              </svg>
            </button>
            <button
              onClick={() => handleFeedback('not_helpful')}
              className="p-1 rounded hover:bg-gray-700/50 text-gray-600 hover:text-red-400 transition-colors"
              title="Mark as not helpful / false positive"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M10 14H5.236a2 2 0 01-1.789-2.894l3.5-7A2 2 0 018.736 3h4.018a2 2 0 01.485.06l3.76.94m-7 10v5a2 2 0 002 2h.096c.5 0 .905-.405.905-.904 0-.715.211-1.413.608-2.008L17 13V4m-7 10h2m5-10h2a2 2 0 012 2v6a2 2 0 01-2 2h-2.5" />
              </svg>
            </button>
          </div>
        ) : (
          <span className={`text-[10px] ${feedback === 'helpful' ? 'text-emerald-500' : 'text-gray-500'}`}>
            {feedback === 'helpful' ? '👍 Thanks!' : '👎 Noted'}
          </span>
        )}
      </div>
    </div>
  );
}
