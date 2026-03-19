import type { Finding } from '../types';

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
  const style = SEVERITY_STYLES[finding.severity];

  return (
    <div className={`bg-gray-800/50 rounded-lg border border-gray-700/40 border-l-4 ${style.border} p-4 space-y-2.5`}>
      <div className="flex items-start gap-2 flex-wrap">
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${style.badge} tracking-wider`}>
          {style.badgeText}
        </span>
        <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-gray-800 text-gray-400 tracking-wide">
          {finding.category}
        </span>
        {finding.line_start != null && (
          <span className="text-[10px] text-gray-500 ml-auto font-mono">
            {finding.line_end != null && finding.line_end !== finding.line_start
              ? `Lines ${finding.line_start}-${finding.line_end}`
              : `Line ${finding.line_start}`}
          </span>
        )}
      </div>

      <h4 className="text-sm font-semibold text-gray-100">{finding.title}</h4>
      <p className="text-sm text-gray-400 leading-relaxed">{finding.description}</p>

      {finding.suggestion && (
        <div className="bg-indigo-950/30 border border-indigo-500/15 rounded-md px-3 py-2.5">
          <p className="text-xs font-medium text-indigo-300 mb-1">Suggestion</p>
          <p className="text-sm text-gray-300 leading-relaxed">{finding.suggestion}</p>
        </div>
      )}

      <div className="text-[10px] text-gray-600 font-medium">
        Confidence: {Math.round(finding.confidence * 100)}%
      </div>
    </div>
  );
}
