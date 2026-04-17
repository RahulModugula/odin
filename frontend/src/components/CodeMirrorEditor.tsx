import { useRef, useEffect } from 'react';
import { EditorState } from '@codemirror/state';
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, placeholder as cmPlaceholder } from '@codemirror/view';
import { defaultKeymap, indentWithTab, history, historyKeymap } from '@codemirror/commands';
import { syntaxHighlighting, defaultHighlightStyle, bracketMatching, foldGutter, indentOnInput } from '@codemirror/language';
import { python } from '@codemirror/lang-python';
import { javascript } from '@codemirror/lang-javascript';
import { go } from '@codemirror/lang-go';
import { oneDark } from '@codemirror/theme-one-dark';
import type { LanguageSupport } from '@codemirror/language';

interface CodeMirrorEditorProps {
  code: string;
  language: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  placeholder?: string;
}

const LANG_EXTENSIONS: Record<string, () => LanguageSupport> = {
  python: python,
  javascript: javascript,
  typescript: () => javascript({ typescript: true }),
  go: go,
};

function getLanguageExt(lang: string): LanguageSupport | [] {
  const factory = LANG_EXTENSIONS[lang];
  return factory ? factory() : [];
}

const odinTheme = EditorView.theme({
  '&': {
    fontSize: '13px',
    backgroundColor: 'transparent',
    height: '100%',
  },
  '.cm-content': {
    fontFamily: '"JetBrains Mono", "Fira Code", "SF Mono", "Cascadia Code", Menlo, monospace',
    caretColor: '#818cf8',
    lineHeight: '1.6',
    padding: '8px 0',
  },
  '.cm-cursor': {
    borderLeftColor: '#818cf8',
    borderLeftWidth: '2px',
  },
  '.cm-activeLine': {
    backgroundColor: 'rgba(99, 102, 241, 0.06)',
  },
  '.cm-activeLineGutter': {
    backgroundColor: 'rgba(99, 102, 241, 0.08)',
  },
  '.cm-gutters': {
    backgroundColor: 'transparent',
    borderRight: '1px solid rgba(75, 85, 99, 0.2)',
    color: 'rgba(107, 114, 128, 0.6)',
    minWidth: '2.5em',
  },
  '.cm-lineNumbers .cm-gutterElement': {
    fontSize: '11px',
    padding: '0 8px 0 12px',
  },
  '.cm-foldGutter .cm-gutterElement': {
    cursor: 'pointer',
    color: 'rgba(107, 114, 128, 0.4)',
  },
  '&.cm-focused': {
    outline: 'none',
  },
  '.cm-selectionBackground': {
    backgroundColor: 'rgba(99, 102, 241, 0.25) !important',
  },
  '&.cm-focused .cm-selectionBackground': {
    backgroundColor: 'rgba(99, 102, 241, 0.3) !important',
  },
  '.cm-placeholder': {
    color: 'rgba(107, 114, 128, 0.4)',
    fontStyle: 'italic',
  },
}, { dark: true });

export function CodeMirrorEditor({ code, language, onChange, onSubmit, placeholder }: CodeMirrorEditorProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  const onChangeRef = useRef(onChange);
  const onSubmitRef = useRef(onSubmit);

  onChangeRef.current = onChange;
  onSubmitRef.current = onSubmit;

  useEffect(() => {
    if (!containerRef.current) return;

    const submitKeymap = keymap.of([
      {
        key: 'Mod-Enter',
        run: () => {
          onSubmitRef.current();
          return true;
        },
      },
    ]);

    const state = EditorState.create({
      doc: code,
      extensions: [
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightActiveLine(),
        history(),
        foldGutter(),
        indentOnInput(),
        bracketMatching(),
        syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
        getLanguageExt(language),
        odinTheme,
        oneDark,
        submitKeymap,
        keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) {
            onChangeRef.current(update.state.doc.toString());
          }
        }),
        cmPlaceholder(placeholder || 'Paste your code here, drag & drop a file, or choose a sample above...'),
        EditorView.lineWrapping,
      ],
    });

    const view = new EditorView({
      state,
      parent: containerRef.current,
    });

    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [language]);

  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    const currentDoc = view.state.doc.toString();
    if (currentDoc !== code) {
      view.dispatch({
        changes: { from: 0, to: currentDoc.length, insert: code },
      });
    }
  }, [code]);

  return (
    <div
      ref={containerRef}
      className="h-full w-full rounded-xl overflow-hidden border border-gray-700/50 bg-gray-950"
    />
  );
}
