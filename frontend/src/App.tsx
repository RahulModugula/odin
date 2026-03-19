import { useState, useCallback } from 'react';
import { CodeInput } from './components/CodeInput';
import { ReviewResults } from './components/ReviewResults';
import { useReviewStream } from './hooks/useReviewStream';
import type { ReviewRequest } from './types';

function App() {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState<ReviewRequest['language']>('python');
  const [hasStarted, setHasStarted] = useState(false);

  const { findings, agentStatuses, score, summary, isLoading, error, metrics, totalTime, startReview } =
    useReviewStream({ code, language });

  const handleSubmit = useCallback(() => {
    if (!code.trim() || isLoading) return;
    setHasStarted(true);
    startReview();
  }, [code, isLoading, startReview]);

  return (
    <div className="h-screen flex flex-col bg-gray-900 text-gray-100">
      {/* Header */}
      <header className="flex-none border-b border-gray-800 px-6 py-3.5 flex items-center gap-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center">
            <svg className="w-4.5 h-4.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
            </svg>
          </div>
          <h1 className="text-lg font-bold tracking-tight">Odin</h1>
        </div>
        <span className="text-sm text-gray-500 font-medium">AI-Powered Code Review</span>
      </header>

      {/* Main Content */}
      <main className="flex-1 min-h-0 flex flex-col lg:flex-row">
        {/* Left Panel - Code Input */}
        <section className="lg:w-[55%] w-full flex-shrink-0 border-b lg:border-b-0 lg:border-r border-gray-800 p-5 flex flex-col min-h-[40vh] lg:min-h-0">
          <CodeInput
            code={code}
            language={language}
            isLoading={isLoading}
            onCodeChange={setCode}
            onLanguageChange={setLanguage}
            onSubmit={handleSubmit}
          />
        </section>

        {/* Right Panel - Results */}
        <section className="lg:w-[45%] w-full flex-1 p-5 min-h-0 overflow-hidden flex flex-col">
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
    </div>
  );
}

export default App;
