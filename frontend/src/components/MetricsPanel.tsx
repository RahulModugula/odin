import type { CodeMetrics } from '../types';

interface MetricsPanelProps {
  metrics: CodeMetrics;
}

interface MetricCardProps {
  label: string;
  value: string | number;
}

function MetricCard({ label, value }: MetricCardProps) {
  return (
    <div className="bg-gray-800/40 border border-gray-700/30 rounded-lg px-3 py-2.5 text-center">
      <div className="text-lg font-bold text-gray-100 tabular-nums">{value}</div>
      <div className="text-[10px] text-gray-500 font-medium tracking-wider uppercase mt-0.5">{label}</div>
    </div>
  );
}

export function MetricsPanel({ metrics }: MetricsPanelProps) {
  return (
    <div className="grid grid-cols-3 gap-2">
      <MetricCard label="LOC" value={metrics.lines_of_code} />
      <MetricCard label="Functions" value={metrics.num_functions} />
      <MetricCard label="Classes" value={metrics.num_classes} />
      <MetricCard label="Complexity" value={metrics.cyclomatic_complexity} />
      <MetricCard label="Max Nesting" value={metrics.max_nesting_depth} />
      <MetricCard label="Comments" value={`${Math.round(metrics.comment_ratio * 100)}%`} />
    </div>
  );
}
