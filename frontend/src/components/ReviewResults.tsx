import type { Finding, AgentStatuses, CodeMetrics } from '../types';
import { ScoreGauge } from './ScoreGauge';
import { MetricsPanel } from './MetricsPanel';
import { FindingCard } from './FindingCard';
import { AgentProgress } from './AgentProgress';

interface ReviewResultsProps {
  findings: Finding[];
  agentStatuses: AgentStatuses;
  score: number | null;
  summary: string | null;
  isLoading: boolean;
  error: string | null;
  metrics: CodeMetrics | null;
  totalTime: number | null;
  hasStarted: boolean;
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function countFindingsByAgent(findings: Finding[]): { quality: number; security: number; docs: number } {
  const counts = { quality: 0, security: 0, docs: 0 };
  for (const f of findings) {
    const cat = f.category.toLowerCase();
    if (cat.includes('security') || cat.includes('vulnerab') || cat.includes('injection') || cat.includes('auth')) {
      counts.security++;
    } else if (cat.includes('doc') || cat.includes('comment') || cat.includes('readme')) {
      counts.docs++;
    } else {
      counts.quality++;
    }
  }
  return counts;
}

export function ReviewResults({
  findings,
  agentStatuses,
  score,
  summary,
  isLoading,
  error,
  metrics,
  totalTime,
  hasStarted,
}: ReviewResultsProps) {
  if (error) {
    return (
      <div className="flex items-center justify-center h-full p-8">
        <div className="bg-red-950/30 border border-red-500/20 rounded-xl p-6 text-center max-w-md">
          <div className="text-red-400 text-lg font-semibold mb-2">Review Failed</div>
          <p className="text-red-300/80 text-sm">{error}</p>
        </div>
      </div>
    );
  }

  if (!hasStarted) {
    return (
      <div className="flex items-center justify-center h-full p-8">
        <div className="text-center space-y-3">
          <div className="text-gray-600 text-5xl mb-4">&#x2728;</div>
          <p className="text-gray-400 text-lg font-medium">Paste code and click Review</p>
          <p className="text-gray-600 text-sm">Odin will analyze your code for quality, security, and documentation issues.</p>
        </div>
      </div>
    );
  }

  const sortedFindings = [...findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99)
  );
  const findingCounts = countFindingsByAgent(findings);

  return (
    <div className="flex flex-col gap-5 h-full overflow-y-auto pr-1 scrollbar-thin">
      <AgentProgress statuses={agentStatuses} findingCounts={findingCounts} />

      {score !== null && (
        <div className="flex items-start gap-6 bg-gray-800/30 border border-gray-700/30 rounded-xl p-5">
          <ScoreGauge score={score} />
          <div className="flex-1 min-w-0 space-y-3">
            {summary && <p className="text-sm text-gray-300 leading-relaxed">{summary}</p>}
            {totalTime !== null && (
              <p className="text-xs text-gray-600">
                Completed in {(totalTime / 1000).toFixed(1)}s
              </p>
            )}
          </div>
        </div>
      )}

      {metrics && <MetricsPanel metrics={metrics} />}

      {sortedFindings.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
            Findings ({sortedFindings.length})
          </h3>
          {sortedFindings.map((finding, idx) => (
            <FindingCard key={idx} finding={finding} />
          ))}
        </div>
      )}

      {isLoading && findings.length === 0 && (
        <div className="flex items-center justify-center py-12">
          <div className="text-center space-y-3">
            <svg className="animate-spin h-8 w-8 text-indigo-500 mx-auto" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <p className="text-sm text-gray-500">Analyzing your code...</p>
          </div>
        </div>
      )}
    </div>
  );
}
