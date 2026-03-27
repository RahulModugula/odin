import { useState } from 'react';
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

const SEVERITY_CHIP_STYLES: Record<string, string> = {
  critical: 'bg-red-950/70 text-red-400 ring-1 ring-red-500/30 hover:ring-red-400/60',
  high:     'bg-orange-950/70 text-orange-400 ring-1 ring-orange-500/30 hover:ring-orange-400/60',
  medium:   'bg-amber-950/70 text-amber-400 ring-1 ring-amber-500/30 hover:ring-amber-400/60',
  low:      'bg-blue-950/70 text-blue-400 ring-1 ring-blue-500/30 hover:ring-blue-400/60',
  info:     'bg-gray-800 text-gray-400 ring-1 ring-gray-600/30 hover:ring-gray-500/60',
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
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);

  if (error) {
    const hint = (() => {
      if (/failed to fetch|networkerror|load failed/i.test(error)) {
        return 'Could not reach the Odin backend. Make sure it is running: docker compose up';
      }
      if (/server error: 503/i.test(error)) {
        return 'The backend is up but the LLM provider is unreachable. Check your provider settings.';
      }
      if (/server error: 422/i.test(error)) {
        return 'The server rejected the request — make sure the code field is not empty.';
      }
      if (/server error: 401/i.test(error)) {
        return 'Authentication failed. Check your API key in the provider settings.';
      }
      return 'Check the browser console for details, or try refreshing the page.';
    })();

    return (
      <div className="flex items-center justify-center h-full p-8">
        <div className="bg-red-950/30 border border-red-500/20 rounded-xl p-6 max-w-md space-y-3">
          <div className="flex items-center gap-2">
            <svg className="w-5 h-5 text-red-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
            </svg>
            <div className="text-red-400 text-sm font-semibold">Review failed</div>
          </div>
          <p className="text-red-300/70 text-xs font-mono break-all">{error}</p>
          <div className="bg-amber-950/30 border border-amber-500/15 rounded-lg px-3 py-2.5">
            <p className="text-xs text-amber-200/80">💡 {hint}</p>
          </div>
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

  // Counts per severity for filter chip labels
  const severityCounts = sortedFindings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  const visibleSeverities = Object.keys(SEVERITY_ORDER).filter(s => severityCounts[s] > 0);
  const filteredFindings = severityFilter
    ? sortedFindings.filter(f => f.severity === severityFilter)
    : sortedFindings;

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
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Findings ({filteredFindings.length}{severityFilter ? `/${sortedFindings.length}` : ''})
            </h3>
            {visibleSeverities.length > 1 && (
              <div className="flex items-center gap-1 flex-wrap ml-auto">
                {severityFilter && (
                  <button
                    onClick={() => setSeverityFilter(null)}
                    className="text-[10px] px-2 py-0.5 rounded bg-gray-700/60 text-gray-400 hover:text-gray-200 transition-colors"
                  >
                    Clear
                  </button>
                )}
                {visibleSeverities.map(sev => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev === severityFilter ? null : sev)}
                    className={`text-[10px] font-bold px-2 py-0.5 rounded tracking-wider transition-all ${
                      SEVERITY_CHIP_STYLES[sev]
                    } ${severityFilter === sev ? 'ring-2' : ''}`}
                  >
                    {sev.toUpperCase()} {severityCounts[sev]}
                  </button>
                ))}
              </div>
            )}
          </div>
          {filteredFindings.map((finding, idx) => (
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
