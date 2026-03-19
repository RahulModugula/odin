import { useState, useEffect, useRef, useCallback } from 'react';
import type { Finding, AgentStatuses, CodeMetrics, ReviewRequest, SSEEvent } from '../types';

interface UseReviewStreamReturn {
  findings: Finding[];
  agentStatuses: AgentStatuses;
  score: number | null;
  summary: string | null;
  isLoading: boolean;
  error: string | null;
  metrics: CodeMetrics | null;
  totalTime: number | null;
  startReview: () => void;
  reset: () => void;
}

const AGENT_NAME_MAP: Record<string, keyof AgentStatuses> = {
  quality: 'quality',
  security: 'security',
  docs: 'docs',
  documentation: 'docs',
};

function resolveAgentKey(name: string): keyof AgentStatuses | null {
  const lower = name.toLowerCase();
  for (const [key, value] of Object.entries(AGENT_NAME_MAP)) {
    if (lower.includes(key)) return value;
  }
  return null;
}

export function useReviewStream(request: ReviewRequest): UseReviewStreamReturn {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [agentStatuses, setAgentStatuses] = useState<AgentStatuses>({
    quality: 'pending',
    security: 'pending',
    docs: 'pending',
  });
  const [score, setScore] = useState<number | null>(null);
  const [summary, setSummary] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [metrics, setMetrics] = useState<CodeMetrics | null>(null);
  const [totalTime, setTotalTime] = useState<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const reset = useCallback(() => {
    setFindings([]);
    setAgentStatuses({ quality: 'pending', security: 'pending', docs: 'pending' });
    setScore(null);
    setSummary(null);
    setError(null);
    setMetrics(null);
    setTotalTime(null);
    setIsLoading(false);
  }, []);

  const startReview = useCallback(async () => {
    if (abortRef.current) {
      abortRef.current.abort();
    }

    const controller = new AbortController();
    abortRef.current = controller;

    setFindings([]);
    setAgentStatuses({ quality: 'pending', security: 'pending', docs: 'pending' });
    setScore(null);
    setSummary(null);
    setError(null);
    setMetrics(null);
    setTotalTime(null);
    setIsLoading(true);

    try {
      const response = await fetch('/api/review/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: request.code, language: request.language }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`Server error: ${response.status} - ${text}`);
      }

      const reader = response.body?.getReader();
      if (!reader) throw new Error('No response body');

      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed.startsWith('data: ')) continue;

          const jsonStr = trimmed.slice(6);
          if (!jsonStr || jsonStr === '[DONE]') continue;

          try {
            const event: SSEEvent = JSON.parse(jsonStr);

            switch (event.type) {
              case 'agent_start': {
                const key = event.agent ? resolveAgentKey(event.agent) : null;
                if (key) {
                  setAgentStatuses(prev => ({ ...prev, [key]: 'running' }));
                }
                break;
              }
              case 'finding': {
                if (event.data) {
                  setFindings(prev => [...prev, event.data!]);
                }
                break;
              }
              case 'agent_complete': {
                const key = event.agent ? resolveAgentKey(event.agent) : null;
                if (key) {
                  setAgentStatuses(prev => ({ ...prev, [key]: 'complete' }));
                }
                break;
              }
              case 'complete': {
                if (event.overall_score !== undefined) setScore(event.overall_score);
                if (event.summary) setSummary(event.summary);
                if (event.total_time_ms !== undefined) setTotalTime(event.total_time_ms);
                if (event.metrics) setMetrics(event.metrics);
                setAgentStatuses({ quality: 'complete', security: 'complete', docs: 'complete' });
                break;
              }
            }
          } catch {
            // skip malformed JSON
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') return;
      setError(err instanceof Error ? err.message : 'An unexpected error occurred');
    } finally {
      setIsLoading(false);
    }
  }, [request.code, request.language]);

  useEffect(() => {
    return () => {
      if (abortRef.current) abortRef.current.abort();
    };
  }, []);

  return { findings, agentStatuses, score, summary, isLoading, error, metrics, totalTime, startReview, reset };
}
