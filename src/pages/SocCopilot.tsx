import { useState, useCallback } from 'react';
import { MessageSquare, Send, Bot, User, Sparkles, Zap } from 'lucide-react';
import { Panel } from '@/components/ui/Primitives';
import {
  copilotExplainRule, copilotSummarizeAttack, copilotRecommendResponse,
  suggestSigmaRule, analyzeEvent,
} from '@/lib/aiAssistant';
import { localValidate } from '@/lib/api';
import { DATASETS } from '@/lib/datasets';
import { getMitre } from '@/lib/mitre';
import type { SigmaRule } from '@/lib/types';

interface Message {
  role: 'user' | 'ai';
  content: string;
}

const QUICK_PROMPTS = [
  'Explain a Sigma rule',
  'Summarize an attack',
  'Suggest detection logic',
  'Recommend a response',
];

export function SocCopilot() {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'ai',
      content: 'I am your AI SOC Copilot. I can explain Sigma rules, summarize attacks, suggest detection logic, and recommend incident response. Ask me anything or use a quick prompt.',
    },
  ]);
  const [input, setInput] = useState('');
  const [thinking, setThinking] = useState(false);

  const respond = useCallback((prompt: string): string => {
    const p = prompt.toLowerCase();

    if (p.includes('sigma rule') || p.includes('explain a sigma') || p.includes('detection logic')) {
      const rule = suggestSigmaRule('T1059.001');
      const parsed = localValidate(rule);
      const sampleEvent = DATASETS[4].events.find((e) => e.malicious);
      if (parsed.parsedRule) {
        const explanation = copilotExplainRule(parsed.parsedRule as SigmaRule, sampleEvent);
        return `Here is an AI-suggested Sigma rule for encoded PowerShell (T1059.001):\n\n\`\`\`yaml\n${rule}\n\`\`\`\n\n${explanation}`;
      }
      return 'I can generate and explain Sigma rules. Try: "Suggest a Sigma rule for T1003"';
    }

    if (p.includes('summarize') || p.includes('attack')) {
      const event = DATASETS[4].events.find((e) => e.malicious)!;
      const detection = analyzeEvent(event);
      return copilotSummarizeAttack(detection);
    }

    if (p.includes('response') || p.includes('recommend')) {
      const event = DATASETS[4].events.find((e) => e.malicious)!;
      const detection = analyzeEvent(event);
      const actions = copilotRecommendResponse(detection);
      return `Recommended response for ${detection.attackType} (${detection.mitre}):\n\n${actions.map((a, i) => `${i + 1}. ${a}`).join('\n')}`;
    }

    if (p.includes('why') && p.includes('detect')) {
      return 'This rule detected the attack because the event matched all selection criteria in the detection block. For example, a PowerShell process with an encoded command flag (-EncodedCommand) spawned from an Office application indicates suspicious execution behaviour mapped to MITRE T1059.001. The condition combines selections with AND and excludes known-benign patterns with NOT.';
    }

    if (p.includes('mitre')) {
      const m = getMitre('T1059.001');
      return m ? `${m.id} - ${m.name} falls under the ${m.tactic} tactic with ${m.severity} severity. ${m.description}` : 'MITRE ATT&CK is a knowledge base of adversary tactics and techniques.';
    }

    return 'I can help with: explaining Sigma rules, summarizing attacks, suggesting detection logic, or recommending incident response. Try a quick prompt above.';
  }, []);

  const send = useCallback((text?: string) => {
    const msg = (text || input).trim();
    if (!msg) return;
    setMessages((prev) => [...prev, { role: 'user', content: msg }]);
    setInput('');
    setThinking(true);
    setTimeout(() => {
      const reply = respond(msg);
      setMessages((prev) => [...prev, { role: 'ai', content: reply }]);
      setThinking(false);
    }, 600);
  }, [input, respond]);

  return (
    <div className="h-[calc(100vh-120px)] flex flex-col gap-4 animate-fade-in">
      <Panel title="AI SOC Copilot" icon={MessageSquare} className="flex-none">
        <p className="text-sm text-soc-400">
          Your AI security assistant. Explains incidents, Sigma rules, suggests detection logic, and recommends response actions.
        </p>
        <div className="flex items-center gap-2 mt-3">
          {QUICK_PROMPTS.map((q) => (
            <button key={q} onClick={() => send(q)} className="soc-btn-ghost text-xs">
              <Sparkles className="w-3 h-3 text-cyber-400" /> {q}
            </button>
          ))}
        </div>
      </Panel>

      <div className="flex-1 glass-panel flex flex-col min-h-0">
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {messages.map((m, i) => (
            <div key={i} className={`flex gap-3 ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
              <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                m.role === 'ai' ? 'bg-cyber-500/20 border border-cyber-500/40' : 'bg-soc-700/60'
              }`}>
                {m.role === 'ai' ? <Bot className="w-5 h-5 text-cyber-400" /> : <User className="w-5 h-5 text-soc-300" />}
              </div>
              <div className={`max-w-[75%] p-3.5 rounded-lg ${
                m.role === 'ai' ? 'bg-soc-800/60 border border-soc-700/60' : 'bg-cyber-500/15 border border-cyber-500/40'
              }`}>
                <pre className="text-sm text-soc-200 whitespace-pre-wrap font-sans">{m.content}</pre>
              </div>
            </div>
          ))}
          {thinking && (
            <div className="flex gap-3">
              <div className="w-8 h-8 rounded-lg bg-cyber-500/20 border border-cyber-500/40 flex items-center justify-center">
                <Bot className="w-5 h-5 text-cyber-400" />
              </div>
              <div className="flex items-center gap-1 p-3.5 rounded-lg bg-soc-800/60 border border-soc-700/60">
                <span className="w-2 h-2 bg-cyber-400 rounded-full animate-pulse" />
                <span className="w-2 h-2 bg-cyber-400 rounded-full animate-pulse" style={{ animationDelay: '0.2s' }} />
                <span className="w-2 h-2 bg-cyber-400 rounded-full animate-pulse" style={{ animationDelay: '0.4s' }} />
              </div>
            </div>
          )}
        </div>

        <div className="border-t border-soc-700/60 p-3 flex items-center gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && send()}
            placeholder="Ask the AI SOC Copilot..."
            className="soc-input flex-1"
          />
          <button onClick={() => send()} className="soc-btn-primary">
            <Send className="w-4 h-4" /> Send
          </button>
        </div>
      </div>
    </div>
  );
}
