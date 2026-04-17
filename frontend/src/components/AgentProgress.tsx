import type { AgentStatuses, AgentStatus } from '../types';

interface AgentProgressProps {
  statuses: AgentStatuses;
  findingCounts: { quality: number; security: number; docs: number; dataflow: number; rules: number };
}

interface PillProps {
  label: string;
  status: AgentStatus;
  count: number;
  icon: React.ReactNode;
}

function Pill({ label, status, count, icon }: PillProps) {
  const base = 'flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold tracking-wide transition-all duration-300';

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
        <svg className="h-3 w-3 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
      )}
      {status === 'pending' && <span className="h-2 w-2 rounded-full bg-gray-600" />}
      <span className="text-[11px]">{icon}</span>
      <span>{label}</span>
      {status === 'complete' && count > 0 && (
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
      <Pill label="Quality" status={statuses.quality} count={findingCounts.quality} icon={
        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      } />
      <Pill label="Security" status={statuses.security} count={findingCounts.security} icon={
        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      } />
      <Pill label="Docs" status={statuses.docs} count={findingCounts.docs} icon={
        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      } />
      <Pill label="Dataflow" status={statuses.dataflow} count={findingCounts.dataflow} icon={
        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      } />
      <Pill label="Rules" status={statuses.rules} count={findingCounts.rules} icon={
        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      } />
    </div>
  );
}
