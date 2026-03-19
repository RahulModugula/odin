export interface Finding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  line_start?: number | null;
  line_end?: number | null;
  suggestion?: string | null;
  confidence: number;
}

export interface CodeMetrics {
  lines_of_code: number;
  num_functions: number;
  num_classes: number;
  avg_function_length: number;
  max_function_length: number;
  max_nesting_depth: number;
  cyclomatic_complexity: number;
  comment_ratio: number;
  import_count: number;
}

export interface AgentOutput {
  agent_name: string;
  findings: Finding[];
  execution_time_ms: number;
}

export interface ReviewResult {
  id: string;
  metrics: CodeMetrics;
  findings: Finding[];
  overall_score: number;
  summary: string;
  agent_outputs: AgentOutput[];
  total_time_ms: number;
  language: string;
  cached: boolean;
}

export interface SSEEvent {
  type: 'agent_start' | 'finding' | 'agent_complete' | 'complete';
  agent?: string;
  data?: Finding;
  review_id?: string;
  overall_score?: number;
  summary?: string;
  total_time_ms?: number;
  findings_count?: number;
  metrics?: CodeMetrics;
}

export type AgentStatus = 'pending' | 'running' | 'complete';

export interface AgentStatuses {
  quality: AgentStatus;
  security: AgentStatus;
  docs: AgentStatus;
}

export interface ReviewRequest {
  code: string;
  language: 'python' | 'javascript' | 'typescript' | 'go';
}
