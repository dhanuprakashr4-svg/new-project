import Editor, { type OnMount } from '@monaco-editor/react';

// ===== Monaco editor wrapper configured for Sigma YAML =====
const SIGMA_YAML_LANGUAGE = {
  keywords: ['title', 'id', 'status', 'description', 'author', 'level', 'references',
    'logsource', 'category', 'product', 'service', 'detection', 'condition',
    'falsepositives', 'tags', 'date', 'modified', 'fields'],
  modifiers: ['contains', 'startswith', 'endswith', 're', 'eq', 'ne', 'gt', 'lt', 'gte', 'lte'],
};

export function MonacoYamlEditor({
  value,
  onChange,
  height = '100%',
  markers,
}: {
  value: string;
  onChange: (v: string) => void;
  height?: string;
  markers?: { line: number; message: string; severity: 'error' | 'warning' }[];
}) {
  const handleMount: OnMount = (editor, monaco) => {
    // Register a Sigma-flavored YAML language for better highlighting + validation
    monaco.languages.register({ id: 'sigma-yaml' });

    monaco.languages.setMonarchTokensProvider('sigma-yaml', {
      ignoreCase: true,
      defaultToken: '',
      tokenPostfix: '.yaml',
      keywords: SIGMA_YAML_LANGUAGE.keywords,
      modifiers: SIGMA_YAML_LANGUAGE.modifiers,
      tokenizer: {
        root: [
          [/#.*$/, 'comment'],
          [/^(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*):/, ['white', 'keyword', 'white']],
          [/\|contains|\|startswith|\|endswith|\|re|\|eq|\|ne|\|gt|\|lt/, 'modifier'],
          [/:\s*[A-Za-z_][A-Za-z0-9_]*/, 'string'],
          [/\b\d+\b/, 'number'],
          [/[-]/, 'operator'],
          [/'[^']*'|"[^"]*"/, 'string'],
        ],
      },
    });

    monaco.languages.setLanguageConfiguration('sigma-yaml', {
      comments: { lineComment: '#' },
      brackets: [['{', '}'], ['[', ']']],
      autoClosingPairs: [
        { open: '{', close: '}' },
        { open: '[', close: ']' },
        { open: '"', close: '"' },
        { open: "'", close: "'" },
      ],
    });

    monaco.editor.defineTheme('sentinel-dark', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'keyword', foreground: '40a9ff', fontStyle: 'bold' },
        { token: 'modifier', foreground: 'faad14' },
        { token: 'comment', foreground: '475569', fontStyle: 'italic' },
        { token: 'string', foreground: '52c41a' },
        { token: 'number', foreground: 'ff7875' },
      ],
      colors: {
        'editor.background': '#080d1a',
        'editor.foreground': '#e2e8f0',
        'editorLineNumber.foreground': '#334155',
        'editorLineNumber.activeForeground': '#1890ff',
        'editor.selectionBackground': '#1890ff44',
        'editor.lineHighlightBackground': '#111a30',
        'editorCursor.foreground': '#1890ff',
        'editorIndentGuide.background': '#1e293b',
        'editorIndentGuide.activeBackground': '#334155',
      },
    });

    monaco.editor.setTheme('sentinel-dark');

    // Apply validation markers as editor diagnostics
    if (markers && markers.length > 0) {
      const model = editor.getModel();
      if (model) {
        monaco.editor.setModelMarkers(model, 'sigma-validator', markers.map((m) => ({
          startLineNumber: m.line || 1,
          startColumn: 1,
          endLineNumber: m.line || 1,
          endColumn: model.getLineMaxColumn(m.line || 1),
          message: m.message,
          severity: m.severity === 'error' ? monaco.MarkerSeverity.Error : monaco.MarkerSeverity.Warning,
        })));
      }
    } else {
      const model = editor.getModel();
      if (model) monaco.editor.setModelMarkers(model, 'sigma-validator', []);
    }
  };

  return (
    <Editor
      height={height}
      value={value}
      language="sigma-yaml"
      onMount={handleMount}
      onChange={(v) => onChange(v || '')}
      theme="sentinel-dark"
      options={{
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 13,
        lineHeight: 20,
        minimap: { enabled: false },
        scrollBeyondLastLine: false,
        padding: { top: 12, bottom: 12 },
        smoothScrolling: true,
        cursorBlinking: 'smooth',
        cursorSmoothCaretAnimation: 'on',
        renderLineHighlight: 'all',
        lineNumbers: 'on',
        folding: true,
        wordWrap: 'on',
        tabSize: 2,
        automaticLayout: true,
      }}
    />
  );
}
