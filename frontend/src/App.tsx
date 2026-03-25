import { useState, useCallback, useEffect } from 'react';
import { CodeInput } from './components/CodeInput';
import { ReviewResults } from './components/ReviewResults';
import { SettingsModal } from './components/SettingsModal';
import { useReviewStream } from './hooks/useReviewStream';
import type { ReviewRequest } from './types';

const PROVIDER_LABELS: Record<string, { label: string; color: string; icon: string }> = {
  lmstudio: { label: 'LM Studio', color: 'text-emerald-400', icon: '🖥️' },
  openrouter: { label: 'OpenRouter', color: 'text-blue-400', icon: '🔀' },
  openai: { label: 'OpenAI', color: 'text-purple-400', icon: '🤖' },
  ollama: { label: 'Ollama', color: 'text-orange-400', icon: '🦙' },
  default: { label: 'Default', color: 'text-gray-400', icon: '⚙️' },
};

function App() {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState<ReviewRequest['language']>('python');
  const [hasStarted, setHasStarted] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [activeProvider, setActiveProvider] = useState('default');

  // Fetch current provider from backend on mount
  useEffect(() => {
    fetch('/api/settings')
      .then(r => r.json())
      .then(d => setActiveProvider(d.provider || 'default'))
      .catch(() => {});
  }, []);

  const { findings, agentStatuses, score, summary, isLoading, error, metrics, totalTime, startReview, reset } =
    useReviewStream({ code, language });

  const handleSubmit = useCallback(() => {
    if (!code.trim() || isLoading) return;
    setHasStarted(true);
    startReview();
  }, [code, isLoading, startReview]);

  const handleReset = useCallback(() => {
    setCode('');
    setHasStarted(false);
    reset();
  }, [reset]);

  const providerInfo = PROVIDER_LABELS[activeProvider] || PROVIDER_LABELS.default;

  return (
    <div className="h-screen flex flex-col bg-gray-900 text-gray-100">
      {/* Header */}
      <header className="flex-none border-b border-gray-800 px-6 py-3 flex items-center gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-indigo-600 flex items-center justify-center flex-shrink-0">
            <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
            </svg>
          </div>
          <span className="text-base font-bold tracking-tight">Odin</span>
          <span className="text-[10px] bg-indigo-600/20 text-indigo-400 border border-indigo-500/20 px-2 py-0.5 rounded-full font-medium">v2</span>
        </div>

        <span className="text-sm text-gray-500 hidden sm:block">AI Code Review</span>

        {/* Provider indicator */}
        <button
          onClick={() => setSettingsOpen(true)}
          className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-800/60 border border-gray-700/40 hover:border-gray-600 transition-all group"
        >
          <span className="text-sm">{providerInfo.icon}</span>
          <span className={`text-xs font-medium ${providerInfo.color}`}>{providerInfo.label}</span>
          <svg className="w-3 h-3 text-gray-600 group-hover:text-gray-400 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
        </button>

        {hasStarted && (
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-gray-500 hover:text-gray-300 border border-gray-700/40 hover:border-gray-600 transition-all"
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            New Review
          </button>
        )}
      </header>

      {/* Main */}
      <main className="flex-1 min-h-0 flex flex-col lg:flex-row">
        <section className="lg:w-[55%] w-full flex-shrink-0 border-b lg:border-b-0 lg:border-r border-gray-800 p-4 flex flex-col min-h-[40vh] lg:min-h-0">
          <CodeInput
            code={code}
            language={language}
            isLoading={isLoading}
            onCodeChange={setCode}
            onLanguageChange={setLanguage}
            onSubmit={handleSubmit}
          />
        </section>

        <section className="lg:w-[45%] w-full flex-1 p-4 min-h-0 overflow-hidden flex flex-col">
          <ReviewResults
            findings={findings}
            agentStatuses={agentStatuses}
            score={score}
            summary={summary}
            isLoading={isLoading}
            error={error}
            metrics={metrics}
            totalTime={totalTime}
            hasStarted={hasStarted}
          />
        </section>
      </main>

      <SettingsModal
        isOpen={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        currentProvider={activeProvider}
        onProviderChange={setActiveProvider}
      />
    </div>
  );
}

export default App;
