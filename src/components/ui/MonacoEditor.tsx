import Editor, { type OnMount } from '@monaco-editor/react';

// ===== Monaco editor wrapper configured for Sigma YAML =====
// Includes custom Sigma YAML language, syntax highlighting, autocompletion,
// snippets, and inline validation markers.

const SIGMA_KEYWORDS = [
  'title', 'id', 'status', 'description', 'author', 'level', 'references',
  'logsource', 'category', 'product', 'service', 'detection', 'condition',
  'falsepositives', 'tags', 'date', 'modified', 'fields', 'related',
];

const SIGMA_MODIFIERS = [
  'contains', 'startswith', 'endswith', 're', 'eq', 'ne', 'gt', 'lt', 'gte', 'lte',
];

const SIGMA_LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];
const SIGMA_STATUSES = ['stable', 'test', 'experimental', 'deprecated', 'unsupported'];

const SIGMA_SNIPPETS: Record<string, { label: string; insertText: string; documentation: string }> = {
  'full-rule': {
    label: 'Sigma Rule (Full Template)',
    insertText: [
      'title: ${1:Rule Title}',
      'id: ${2:uuid}',
      'status: ${3:experimental}',
      'description: ${4:Description}',
      'author: ${5:Author}',
      'level: ${6:high}',
      'logsource:',
      '  category: ${7:process_creation}',
      '  product: ${8:windows}',
      'detection:',
      '  ${9:selection}:',
      '    ${10:Image}|endswith: ${11:\\\\powershell.exe}',
      '  condition: ${12:selection}',
      'falsepositives:',
      '  - ${13:None}',
      'tags:',
      '  - ${14:attack.execution}',
    ].join('\n'),
    documentation: 'Complete Sigma rule template with all standard fields',
  },
  'selection': {
    label: 'Detection Selection',
    insertText: [
      '  ${1:selection_name}:',
      '    ${2:FieldName}|${3|contains,startswith,endswith,re|}: ${4:value}',
    ].join('\n'),
    documentation: 'A named detection selection with a field matcher',
  },
  'filter': {
    label: 'Filter Selection (Exclusion)',
    insertText: [
      '  filter_${1:benign}:',
      '    ${2:CommandLine}|contains:',
      '      - ${3:Get-Process}',
      '      - ${4:Get-Service}',
    ].join('\n'),
    documentation: 'A filter selection to exclude known-benign patterns',
  },
  'logsource-win': {
    label: 'Logsource: Windows Process Creation',
    insertText: [
      'logsource:',
      '  category: process_creation',
      '  product: windows',
    ].join('\n'),
    documentation: 'Windows process creation log source (EID 4688 / Sysmon EID 1)',
  },
  'logsource-sysmon': {
    label: 'Logsource: Sysmon',
    insertText: [
      'logsource:',
      '  category: ${1|process_creation,network_connection,file_change|}',
      '  product: windows',
      '  definition: Sysmon log',
    ].join('\n'),
    documentation: 'Sysmon log source',
  },
  'logsource-web': {
    label: 'Logsource: Web Access',
    insertText: [
      'logsource:',
      '  category: web_access',
      '  product: web',
    ].join('\n'),
    documentation: 'Web server access log source',
  },
  'logsource-auth': {
    label: 'Logsource: Windows Authentication',
    insertText: [
      'logsource:',
      '  category: authentication',
      '  product: windows',
    ].join('\n'),
    documentation: 'Windows authentication log source (EID 4624/4625)',
  },
  'condition-and': {
    label: 'Condition: AND',
    insertText: 'condition: ${1:selection} and ${2:filter}',
    documentation: 'Condition combining selections with AND',
  },
  'condition-or': {
    label: 'Condition: OR',
    insertText: 'condition: ${1:selection1} or ${2:selection2}',
    documentation: 'Condition combining selections with OR',
  },
  'condition-not': {
    label: 'Condition: AND NOT (Filter)',
    insertText: 'condition: ${1:selection} and not ${2:filter}',
    documentation: 'Condition that matches selection but excludes filter',
  },
  'condition-all': {
    label: 'Condition: All of Them',
    insertText: 'condition: all of them',
    documentation: 'Condition matching all selections',
  },
  'condition-1of': {
    label: 'Condition: 1 of Them',
    insertText: 'condition: 1 of them',
    documentation: 'Condition matching at least one selection',
  },
  'tag-attack': {
    label: 'MITRE ATT&CK Tag',
    insertText: '  - attack.${1|execution,persistence,credential_access,lateral_movement,initial_access,defense_evasion,impact|}',
    documentation: 'MITRE ATT&CK tactic tag',
  },
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
    // ===== Register Sigma YAML language =====
    monaco.languages.register({ id: 'sigma-yaml' });

    // Monarch tokenizer for Sigma YAML
    monaco.languages.setMonarchTokensProvider('sigma-yaml', {
      ignoreCase: true,
      defaultToken: '',
      tokenPostfix: '.sigma',
      keywords: SIGMA_KEYWORDS,
      modifiers: SIGMA_MODIFIERS,
      tokenizer: {
        root: [
          [/#.*$/, 'comment'],
          [/^(\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*):/, ['white', 'keyword', 'white']],
          [/\|contains|\|startswith|\|endswith|\|re|\|eq|\|ne|\|gt|\|lt|\|gte|\|lte/, 'modifier'],
          [/:\s*[A-Za-z_][A-Za-z0-9_]*/, 'string'],
          [/\b\d+\b/, 'number'],
          [/[-]/, 'operator'],
          [/'[^']*'|"[^"]*"/, 'string'],
          [/\\+/, 'string.escape'],
        ],
      },
    });

    // Language configuration
    monaco.languages.setLanguageConfiguration('sigma-yaml', {
      comments: { lineComment: '#' },
      brackets: [['{', '}'], ['[', ']']],
      autoClosingPairs: [
        { open: '{', close: '}' },
        { open: '[', close: ']' },
        { open: '"', close: '"' },
        { open: "'", close: "'" },
      ],
      indentationRules: {
        increaseIndentPattern: /^.*:\s*$/,
        decreaseIndentPattern: /^\s+/,
      },
    });

    // ===== Autocompletion provider =====
    monaco.languages.registerCompletionItemProvider('sigma-yaml', {
      triggerCharacters: [':', ' ', '|', '\n'],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provideCompletionItems: (model: any, position: any) => {
        const word = model.getWordUntilPosition(position);
        const lineContent = model.getLineContent(position.lineNumber);
        const textUntilPosition = model.getValueInRange({
          startLineNumber: 1,
          startColumn: 1,
          endLineNumber: position.lineNumber,
          endColumn: position.column,
        });
        const range = {
          startLineNumber: position.lineNumber,
          endLineNumber: position.lineNumber,
          startColumn: word.startColumn,
          endColumn: word.endColumn,
        };

        const suggestions: any[] = [];
        // Top-level keywords (when at root level — no indentation)
        if (lineContent.trim() === '' || (lineContent.match(/^\s*[A-Za-z]/) && !lineContent.includes(':'))) {
          for (const kw of SIGMA_KEYWORDS) {
            if (lineContent.trim() === '' || kw.startsWith(word.word.toLowerCase())) {
              suggestions.push({
                label: kw,
                kind: monaco.languages.CompletionItemKind.Keyword,
                insertText: kw,
                detail: 'Sigma field',
                range,
              });
            }
          }
        }

        // Level values
        if (/level:\s*$/.test(lineContent)) {
          for (const lvl of SIGMA_LEVELS) {
            suggestions.push({
              label: lvl,
              kind: monaco.languages.CompletionItemKind.EnumMember,
              insertText: lvl,
              detail: 'Sigma severity level',
              range,
            });
          }
        }

        // Status values
        if (/status:\s*$/.test(lineContent)) {
          for (const st of SIGMA_STATUSES) {
            suggestions.push({
              label: st,
              kind: monaco.languages.CompletionItemKind.EnumMember,
              insertText: st,
              detail: 'Sigma rule status',
              range,
            });
          }
        }

        // Field modifiers (after | )
        if (/\|/.test(lineContent) && lineContent.lastIndexOf('|') > lineContent.lastIndexOf(':')) {
          for (const mod of SIGMA_MODIFIERS) {
            suggestions.push({
              label: mod,
              kind: monaco.languages.CompletionItemKind.Function,
              insertText: mod,
              detail: 'Sigma field modifier',
              range,
            });
          }
        }

        // Common Sigma field names (after indentation under a selection)
        const commonFields = [
          'Image', 'CommandLine', 'ParentImage', 'EventID', 'User',
          'DestinationIp', 'DestinationPort', 'DestinationHostname', 'Protocol',
          'TargetUsername', 'TargetUserName', 'LogonType', 'AuthenticationPackageName',
          'TaskName', 'TaskAction', 'Creator', 'ServiceName', 'ServiceFile',
          'URL', 'UserAgent', 'Method', 'StatusCode', 'ClientIP', 'Body',
          'SourceIp', 'TargetFilename', 'Hashes',
        ];
        if (/^\s+\S*$/.test(lineContent) && lineContent.trim() !== '' && !lineContent.includes(':')) {
          for (const field of commonFields) {
            if (field.toLowerCase().startsWith(word.word.toLowerCase())) {
              suggestions.push({
                label: field,
                kind: monaco.languages.CompletionItemKind.Variable,
                insertText: field + '|${1|contains,startswith,endswith,re|}: ',
                insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
                detail: 'Common Sigma detection field',
                range,
              });
            }
          }
        }

        // Snippets (triggered by typing or Ctrl+Space)
        const snippetKeys = Object.keys(SIGMA_SNIPPETS);
        for (const key of snippetKeys) {
          const snip = SIGMA_SNIPPETS[key];
          if (word.word === '' || snip.label.toLowerCase().includes(word.word.toLowerCase())) {
            suggestions.push({
              label: snip.label,
              kind: monaco.languages.CompletionItemKind.Snippet,
              insertText: snip.insertText,
              insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
              detail: 'Sigma snippet',
              documentation: snip.documentation,
              range,
            });
          }
        }

        return { suggestions };
      },
    });

    // ===== Hover provider for field documentation =====
    monaco.languages.registerHoverProvider('sigma-yaml', {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      provideHover: (model: any, position: any) => {
        const word = model.getWordAtPosition(position);
        if (!word) return null;
        const docs: Record<string, string> = {
          title: 'Required. A brief, descriptive title for the rule.',
          id: 'Optional. A UUID v4 uniquely identifying the rule.',
          status: 'Rule maturity: stable, test, experimental, deprecated, unsupported.',
          level: 'Severity level: informational, low, medium, high, critical.',
          logsource: 'Defines the log source the rule applies to (category, product, service).',
          detection: 'Core detection logic: named selections + a condition expression.',
          condition: 'Boolean expression combining selections (and, or, not, all of them, 1 of them).',
          falsepositives: 'Known benign conditions that may trigger the rule.',
          tags: 'MITRE ATT&CK tags (attack.tactic, attack.technique).',
          contains: 'Modifier: matches if the field value contains the specified string.',
          startswith: 'Modifier: matches if the field value starts with the specified string.',
          endswith: 'Modifier: matches if the field value ends with the specified string.',
          re: 'Modifier: matches using a regular expression.',
        };
        const doc = docs[word.word.toLowerCase()];
        if (doc) {
          return {
            range: new monaco.Range(position.lineNumber, word.startColumn, position.lineNumber, word.endColumn),
            contents: [{ value: `**${word.word}**: ${doc}` }],
          };
        }
        return null;
      },
    });

    // ===== Theme =====
    monaco.editor.defineTheme('sentinel-dark', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'keyword', foreground: '40a9ff', fontStyle: 'bold' },
        { token: 'modifier', foreground: 'faad14' },
        { token: 'comment', foreground: '475569', fontStyle: 'italic' },
        { token: 'string', foreground: '52c41a' },
        { token: 'number', foreground: 'ff7875' },
        { token: 'string.escape', foreground: 'ff7875' },
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
        'editorSuggestWidget.background': '#0f172a',
        'editorSuggestWidget.border': '#334155',
        'editorSuggestWidget.selectedBackground': '#1890ff22',
        'editorSuggestWidget.foreground': '#e2e8f0',
        'editorWidget.background': '#0f172a',
        'editorWidget.border': '#334155',
      },
    });

    monaco.editor.setTheme('sentinel-dark');

    // ===== Validation markers =====
    const model = editor.getModel();
    if (model) {
      if (markers && markers.length > 0) {
        monaco.editor.setModelMarkers(model, 'sigma-validator', markers.map((m) => ({
          startLineNumber: m.line || 1,
          startColumn: 1,
          endLineNumber: m.line || 1,
          endColumn: model.getLineMaxColumn(m.line || 1),
          message: m.message,
          severity: m.severity === 'error' ? monaco.MarkerSeverity.Error : monaco.MarkerSeverity.Warning,
        })));
      } else {
        monaco.editor.setModelMarkers(model, 'sigma-validator', []);
      }
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
        suggestOnTriggerCharacters: true,
        acceptSuggestionOnEnter: 'on',
        quickSuggestions: { other: true, comments: false, strings: true },
        snippetSuggestions: 'top',
        formatOnPaste: true,
        formatOnType: true,
      }}
    />
  );
}
