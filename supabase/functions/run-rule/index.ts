import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import yaml from "npm:js-yaml@4.1.0";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  try {
    const { rule, dataset } = await req.json();
    if (typeof rule !== "string") {
      return new Response(JSON.stringify({ error: "rule (YAML string) required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    if (!Array.isArray(dataset)) {
      return new Response(JSON.stringify({ error: "dataset (event array) required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const parsed = yaml.load(rule) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object" || !parsed.detection) {
      return new Response(JSON.stringify({ error: "Invalid Sigma rule: missing detection" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const result = runSigma(parsed as any, dataset as any[]);
    return new Response(JSON.stringify(result), {
      status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});

interface SecEvent {
  id: string;
  fields: Record<string, string | number | boolean>;
  malicious: boolean;
  mitre?: string;
  timestamp: string;
  source: string;
  category: string;
}

function runSigma(rule: { detection: Record<string, unknown>; title: string }, events: SecEvent[]) {
  const det = rule.detection;
  const condition = (det.condition as string) || "selection";
  const selections: Record<string, (e: SecEvent) => boolean> = {};
  for (const [name, value] of Object.entries(det)) {
    if (name === "condition") continue;
    selections[name] = buildMatcher(value);
  }
  const matcher = buildCondition(condition, selections);
  const matched = events.filter(matcher);

  let tp = 0, fp = 0, fn = 0, tn = 0;
  for (const e of events) {
    const isM = matcher(e);
    if (isM && e.malicious) tp++;
    else if (isM && !e.malicious) fp++;
    else if (!isM && e.malicious) fn++;
    else tn++;
  }

  const matches = matched.length;
  const precision = matches > 0 ? tp / matches : 0;
  const totalMal = events.filter((e) => e.malicious).length;
  const recall = totalMal > 0 ? tp / totalMal : 0;
  const totalBen = events.filter((e) => !e.malicious).length;
  const fpr = totalBen > 0 ? fp / totalBen : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = events.length > 0 ? (tp + tn) / events.length : 0;

  return {
    matches,
    matched_events: matched,
    truePositives: tp, falsePositives: fp, falseNegatives: fn, trueNegatives: tn,
    precision, recall, falsePositiveRate: fpr, f1, accuracy,
    ruleTitle: rule.title, timestamp: new Date().toISOString(),
  };
}

function buildMatcher(value: unknown): (e: SecEvent) => boolean {
  if (value == null) return () => false;
  if (typeof value === "string") return (e) => Object.values(e.fields).some((v) => String(v).toLowerCase() === value.toLowerCase());
  if (typeof value === "number") return (e) => Object.values(e.fields).some((v) => Number(v) === value);
  if (Array.isArray(value)) {
    const ms = value.map(buildMatcher);
    return (e) => ms.some((m) => m(e));
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    return (e) => matchMap(obj, e);
  }
  return () => false;
}

function matchMap(obj: Record<string, unknown>, e: SecEvent): boolean {
  for (const [key, val] of Object.entries(obj)) {
    const parts = key.split("|");
    const modifier = parts.length > 1 ? parts[parts.length - 1] : undefined;
    const field = parts.length > 1 ? parts.slice(0, -1).join("|") : parts[0];
    const actual = getField(e, field);
    if (actual == null || !matchVal(actual, val, modifier)) return false;
  }
  return true;
}

function getField(e: SecEvent, field: string): string | number | boolean | null {
  const lf = field.toLowerCase();
  if (lf === "eventid") return (e.fields.EventID as number) ?? null;
  if (e.fields[field] != null) return e.fields[field];
  const found = Object.entries(e.fields).find(([k]) => k.toLowerCase() === lf);
  return found ? found[1] : null;
}

function matchVal(actual: string | number | boolean, expected: unknown, modifier?: string): boolean {
  const aStr = String(actual).toLowerCase();
  if (Array.isArray(expected)) return expected.some((i) => matchVal(actual, i, modifier));
  const eStr = String(expected).toLowerCase();
  switch (modifier) {
    case "contains": return aStr.includes(eStr);
    case "startswith": return aStr.startsWith(eStr);
    case "endswith": return aStr.endsWith(eStr);
    case "re":
      try { return new RegExp(String(expected)).test(String(actual)); } catch { return false; }
    default:
      if (eStr.includes("*")) {
        const rx = "^" + eStr.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$";
        return new RegExp(rx, "i").test(String(actual));
      }
      return aStr === eStr;
  }
}

function buildCondition(condition: string, selections: Record<string, (e: SecEvent) => boolean>): (e: SecEvent) => boolean {
  const cond = condition.trim().toLowerCase();
  if (/^all\s+of\s+them$/.test(cond)) {
    const all = Object.values(selections);
    return (e) => all.length > 0 && all.every((m) => m(e));
  }
  const nMatch = cond.match(/^(\d+)\s+of\s+them$/);
  if (nMatch) {
    const n = Number(nMatch[1]);
    const all = Object.values(selections);
    return (e) => all.filter((m) => m(e)).length >= n;
  }
  return parseBool(condition, selections);
}

function parseBool(expr: string, selections: Record<string, (e: SecEvent) => boolean>): (e: SecEvent) => boolean {
  const tokens: string[] = [];
  const re = /\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*)\s*/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(expr)) !== null) tokens.push(m[1]);
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];
  function parseOr(): (e: SecEvent) => boolean {
    let l = parseAnd();
    while (peek() === "or") { next(); const r = parseAnd(); const L = l, R = r; l = (e) => L(e) || R(e); }
    return l;
  }
  function parseAnd(): (e: SecEvent) => boolean {
    let l = parseNot();
    while (peek() === "and") { next(); const r = parseNot(); const L = l, R = r; l = (e) => L(e) && R(e); }
    return l;
  }
  function parseNot(): (e: SecEvent) => boolean {
    if (peek() === "not") { next(); const inner = parseNot(); return (e) => !inner(e); }
    return parseAtom();
  }
  function parseAtom(): (e: SecEvent) => boolean {
    const t = peek();
    if (t === "(") { next(); const inner = parseOr(); if (peek() === ")") next(); return inner; }
    if (t && !["and", "or", "not", "(", ")"].includes(t)) {
      next();
      return selections[t] ?? selections[t.toLowerCase()] ?? (() => false);
    }
    next();
    return () => false;
  }
  return parseOr();
}
