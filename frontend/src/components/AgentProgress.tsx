import type { AgentStatuses, AgentStatus } from '../types';

interface AgentProgressProps {
  statuses: AgentStatuses;
  findingCounts: { quality: number; security: number; docs: number };
}

interface PillProps {
  label: string;
  status: AgentStatus;
  count: number;
}

function Pill({ label, status, count }: PillProps) {
  const base = 'flex items-center gap-2 px-4 py-2 rounded-full text-xs font-semibold tracking-wide transition-all duration-300';

  const styles: Record<AgentStatus, string> = {
    pending: 'bg-gray-800 text-gray-500 border border-gray-700/50',
    running: 'bg-indigo-950/80 text-indigo-300 border border-indigo-500/40 shadow-[0_0_12px_rgba(99,102,241,0.15)]',
    complete: 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30',
  };

  return (
    <div className={`${base} ${styles[status]}`}>
      {status === 'running' && (
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-indigo-400" />
        </span>
      )}
      {status === 'complete' && (
        <svg className="h-3.5 w-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
      )}
      {status === 'pending' && <span className="h-2 w-2 rounded-full bg-gray-600" />}
      <span>{label}</span>
      {status === 'complete' && (
        <span className="bg-emerald-900/50 text-emerald-300 px-1.5 py-0.5 rounded text-[10px] font-bold ml-0.5">
          {count}
        </span>
      )}
    </div>
  );
}

export function AgentProgress({ statuses, findingCounts }: AgentProgressProps) {
  return (
    <div className="flex flex-wrap gap-2">
      <Pill label="Quality" status={statuses.quality} count={findingCounts.quality} />
      <Pill label="Security" status={statuses.security} count={findingCounts.security} />
      <Pill label="Documentation" status={statuses.docs} count={findingCounts.docs} />
    </div>
  );
}
