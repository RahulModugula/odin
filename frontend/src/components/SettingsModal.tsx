import { useState, useEffect } from 'react';

interface Provider {
  name: string;
  description: string;
  base_url: string;
  model: string;
  api_key: string;
}

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentProvider: string;
  onProviderChange: (provider: string) => void;
}

const PRESETS: Record<string, Partial<Provider>> = {
  lmstudio: {
    name: 'lmstudio',
    description: 'LM Studio — local models, zero API cost',
    base_url: 'http://localhost:1234/v1',
    model: 'local-model',
    api_key: 'lm-studio',
  },
  openrouter: {
    name: 'openrouter',
    description: 'OpenRouter — BYOK, 100+ models',
    base_url: 'https://openrouter.ai/api/v1',
    model: 'anthropic/claude-sonnet-4-5',
    api_key: '',
  },
  openai: {
    name: 'openai',
    description: 'OpenAI API',
    base_url: 'https://api.openai.com/v1',
    model: 'gpt-4o-mini',
    api_key: '',
  },
  ollama: {
    name: 'ollama',
    description: 'Ollama — local models, zero API cost',
    base_url: 'http://localhost:11434/v1',
    model: 'qwen2.5-coder',
    api_key: 'ollama',
  },
};

const PRESET_ICONS: Record<string, string> = {
  lmstudio: '🖥️',
  openrouter: '🔀',
  openai: '🤖',
  ollama: '🦙',
};

export function SettingsModal({ isOpen, onClose, currentProvider, onProviderChange }: SettingsModalProps) {
  const [selected, setSelected] = useState(currentProvider || 'lmstudio');
  const [apiKey, setApiKey] = useState('');
  const [customModel, setCustomModel] = useState('');
  const [testStatus, setTestStatus] = useState<'idle' | 'testing' | 'ok' | 'error'>('idle');
  const [testError, setTestError] = useState('');

  useEffect(() => {
    setSelected(currentProvider || 'lmstudio');
    setTestStatus('idle');
  }, [currentProvider, isOpen]);

  const preset = PRESETS[selected] || PRESETS.lmstudio;

  const handleTest = async () => {
    setTestStatus('testing');
    setTestError('');
    try {
      const res = await fetch(`/api/settings/providers/${selected}/test`, { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        setTestStatus('ok');
      } else {
        setTestStatus('error');
        setTestError(data.error || 'Connection failed');
      }
    } catch {
      setTestStatus('error');
      setTestError('Could not reach backend');
    }
  };

  const handleSave = () => {
    onProviderChange(selected);
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />

      {/* Modal */}
      <div className="relative bg-gray-900 border border-gray-700/60 rounded-2xl w-full max-w-lg mx-4 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <div>
            <h2 className="text-base font-semibold text-gray-100">LLM Provider Settings</h2>
            <p className="text-xs text-gray-500 mt-0.5">Choose where Odin sends AI requests</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-6 space-y-5">
          {/* Provider grid */}
          <div className="grid grid-cols-2 gap-2">
            {Object.entries(PRESETS).map(([key, p]) => (
              <button
                key={key}
                onClick={() => { setSelected(key); setTestStatus('idle'); }}
                className={`flex flex-col items-start gap-1 p-3 rounded-xl border text-left transition-all ${
                  selected === key
                    ? 'border-indigo-500/60 bg-indigo-950/40 ring-1 ring-indigo-500/20'
                    : 'border-gray-700/50 bg-gray-800/30 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className="text-lg">{PRESET_ICONS[key]}</span>
                  <span className="text-sm font-medium text-gray-200 capitalize">{key}</span>
                  {selected === key && (
                    <span className="ml-auto">
                      <svg className="w-3.5 h-3.5 text-indigo-400" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                      </svg>
                    </span>
                  )}
                </div>
                <p className="text-[10px] text-gray-500 leading-tight">{p.description}</p>
              </button>
            ))}
          </div>

          {/* Config details */}
          <div className="space-y-3 bg-gray-800/30 rounded-xl p-4">
            <div>
              <label className="text-xs text-gray-500 font-medium">Endpoint</label>
              <div className="mt-1 text-sm text-gray-300 font-mono bg-gray-900/50 rounded-lg px-3 py-2 border border-gray-700/40">
                {preset.base_url}
              </div>
            </div>
            <div>
              <label className="text-xs text-gray-500 font-medium">Model</label>
              <input
                type="text"
                value={customModel || preset.model || ''}
                onChange={e => setCustomModel(e.target.value)}
                placeholder={preset.model}
                className="mt-1 w-full text-sm text-gray-200 font-mono bg-gray-900/50 rounded-lg px-3 py-2 border border-gray-700/40 focus:outline-none focus:ring-1 focus:ring-indigo-500/50"
              />
            </div>
            {(selected === 'openrouter' || selected === 'openai') && (
              <div>
                <label className="text-xs text-gray-500 font-medium">API Key</label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={e => setApiKey(e.target.value)}
                  placeholder={selected === 'openrouter' ? 'sk-or-v1-...' : 'sk-...'}
                  className="mt-1 w-full text-sm text-gray-200 font-mono bg-gray-900/50 rounded-lg px-3 py-2 border border-gray-700/40 focus:outline-none focus:ring-1 focus:ring-indigo-500/50"
                />
                <p className="text-[10px] text-gray-600 mt-1">Set via ODIN_LLM_API_KEY env var for persistence</p>
              </div>
            )}

            {/* LM Studio helper */}
            {selected === 'lmstudio' && (
              <div className="bg-indigo-950/30 border border-indigo-500/15 rounded-lg p-3">
                <p className="text-xs text-indigo-300 font-medium">Local Setup</p>
                <p className="text-xs text-gray-400 mt-1">
                  1. Download <span className="text-indigo-300">LM Studio</span> and load a model<br />
                  2. Enable the local server (port 1234)<br />
                  3. Recommended: <span className="font-mono text-indigo-300">Qwen2.5-Coder-32B</span>
                </p>
              </div>
            )}

            {selected === 'ollama' && (
              <div className="bg-indigo-950/30 border border-indigo-500/15 rounded-lg p-3">
                <p className="text-xs text-indigo-300 font-medium">Local Setup</p>
                <p className="text-xs text-gray-400 mt-1 font-mono">
                  ollama pull qwen2.5-coder<br />
                  ollama serve
                </p>
              </div>
            )}
          </div>

          {/* Test connection */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleTest}
              disabled={testStatus === 'testing'}
              className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-600 text-sm text-gray-300 hover:border-gray-500 hover:text-gray-200 transition-all disabled:opacity-50"
            >
              {testStatus === 'testing' ? (
                <svg className="animate-spin h-3.5 w-3.5" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              ) : (
                <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              )}
              Test Connection
            </button>

            {testStatus === 'ok' && (
              <span className="flex items-center gap-1.5 text-xs text-emerald-400">
                <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
                Connected
              </span>
            )}
            {testStatus === 'error' && (
              <span className="flex items-center gap-1.5 text-xs text-red-400">
                <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
                {testError || 'Failed'}
              </span>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-gray-800">
          <p className="text-xs text-gray-600">
            Provider set via <span className="font-mono text-gray-500">ODIN_LLM_PROVIDER</span> env var
          </p>
          <div className="flex gap-2">
            <button onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200 transition-colors">
              Cancel
            </button>
            <button
              onClick={handleSave}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium rounded-lg transition-colors"
            >
              Save
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
