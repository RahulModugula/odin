import { type ChangeEvent } from 'react';

interface CodeInputProps {
  code: string;
  language: 'python' | 'javascript' | 'typescript' | 'go';
  isLoading: boolean;
  onCodeChange: (code: string) => void;
  onLanguageChange: (lang: 'python' | 'javascript' | 'typescript' | 'go') => void;
  onSubmit: () => void;
}

const LANGUAGES = [
  { value: 'python', label: 'Python' },
  { value: 'javascript', label: 'JavaScript' },
  { value: 'typescript', label: 'TypeScript' },
  { value: 'go', label: 'Go' },
] as const;

export function CodeInput({ code, language, isLoading, onCodeChange, onLanguageChange, onSubmit }: CodeInputProps) {
  const handleLanguageChange = (e: ChangeEvent<HTMLSelectElement>) => {
    onLanguageChange(e.target.value as CodeInputProps['language']);
  };

  return (
    <div className="flex flex-col h-full gap-4">
      <div className="flex items-center gap-3">
        <select
          value={language}
          onChange={handleLanguageChange}
          className="bg-gray-800 text-gray-200 border border-gray-700 rounded-lg px-3 py-2 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent cursor-pointer"
        >
          {LANGUAGES.map(lang => (
            <option key={lang.value} value={lang.value}>
              {lang.label}
            </option>
          ))}
        </select>

        <button
          onClick={onSubmit}
          disabled={isLoading || !code.trim()}
          className="ml-auto bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-700 disabled:text-gray-500 text-white font-semibold px-5 py-2 rounded-lg text-sm transition-colors duration-150 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-gray-900 disabled:cursor-not-allowed flex items-center gap-2"
        >
          {isLoading ? (
            <>
              <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Reviewing...
            </>
          ) : (
            'Review Code'
          )}
        </button>
      </div>

      <div className="relative flex-1 min-h-0">
        <textarea
          value={code}
          onChange={e => onCodeChange(e.target.value)}
          placeholder="Paste your code here..."
          spellCheck={false}
          className="w-full h-full bg-gray-950 text-gray-200 border border-gray-700/50 rounded-xl p-4 font-mono text-sm leading-relaxed resize-none focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 placeholder:text-gray-600 scrollbar-thin"
        />
        <div className="absolute bottom-3 right-4 text-xs text-gray-600 font-mono pointer-events-none">
          {code.length.toLocaleString()} chars
        </div>
      </div>
    </div>
  );
}
