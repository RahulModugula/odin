import { useState, useEffect } from 'react';

interface KeyboardHelpProps {
  isOpen: boolean;
  onClose: () => void;
}

const SHORTCUTS = [
  { keys: '⌘ + ↵', os: 'Mac', action: 'Submit review' },
  { keys: 'Ctrl + ↵', os: 'Windows/Linux', action: 'Submit review' },
  { keys: '?', os: 'All', action: 'Toggle this help' },
  { keys: 'Escape', os: 'All', action: 'Close modals' },
];

export function KeyboardHelp({ isOpen, onClose }: KeyboardHelpProps) {
  useEffect(() => {
    if (!isOpen) return;
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleEscape);
    return () => window.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="fixed inset-0 flex items-center justify-center z-50 p-4">
        <div className="bg-gray-800 border border-gray-700 rounded-xl shadow-2xl max-w-md w-full space-y-4">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-gray-100">Keyboard Shortcuts</h2>
            <button
              onClick={onClose}
              className="text-gray-500 hover:text-gray-400 transition-colors"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Shortcuts table */}
          <div className="px-6 py-4 space-y-3">
            {SHORTCUTS.map((shortcut, idx) => (
              <div key={idx} className="flex items-center gap-4">
                <div className="flex gap-1">
                  {shortcut.keys.split(' + ').map((key, i) => (
                    <div key={i} className="flex items-center gap-1">
                      {i > 0 && <span className="text-gray-500 text-xs">+</span>}
                      <kbd className="bg-gray-700 text-gray-200 px-2 py-1 rounded text-xs font-mono border border-gray-600">
                        {key}
                      </kbd>
                    </div>
                  ))}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-gray-400">{shortcut.action}</p>
                  <p className="text-[10px] text-gray-600">{shortcut.os}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Footer */}
          <div className="px-6 py-3 bg-gray-900/30 rounded-b-xl border-t border-gray-700">
            <p className="text-xs text-gray-500">
              💡 Tip: Press <kbd className="bg-gray-700 px-1 rounded text-[10px]">?</kbd> anytime to show this help
            </p>
          </div>
        </div>
      </div>
    </>
  );
}
