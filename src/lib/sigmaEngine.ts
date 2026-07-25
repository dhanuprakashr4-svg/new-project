import { load as yamlLoad } from 'js-yaml';
import type {
  SecEvent,
  ValidationIssue,
  ValidationResult,
  MatchResult,
  SigmaRule,
} from './types';

// ===== Sigma Rule Validation Engine =====
// Validates YAML structure, required Sigma fields, detection object, and condition logic.

const REQUIRED_TOP_LEVEL = ['title', 'logsource', 'detection'];
const VALID_LEVELS = ['informational', 'low', 'medium', 'high', 'critical'];

export function validateRule(yamlText: string): ValidationResult {
  const errors: ValidationIssue[] = [];
  const warnings: ValidationIssue[] = [];

  if (!yamlText.trim()) {
    return { valid: false, errors: [{ field: 'root', message: 'Rule is empty', severity: 'error' }], warnings };
  }

  let parsed: unknown;
  try {
    parsed = yamlLoad(yamlText);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const lineMatch = msg.match(/\((\d+):(\d+)\)/);
    errors.push({
      field: 'yaml',
      message: `YAML syntax error: ${msg}`,
      line: lineMatch ? Number(lineMatch[1]) : undefined,
      severity: 'error',
    });
    return { valid: false, errors, warnings };
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    errors.push({ field: 'root', message: 'Sigma rule must be a YAML mapping (object), not a list or scalar', severity: 'error' });
    return { valid: false, errors, warnings };
  }

  const rule = parsed as Partial<SigmaRule>;

  // Required top-level fields
  for (const field of REQUIRED_TOP_LEVEL) {
    if (!(field in rule) || rule[field as keyof SigmaRule] == null) {
      errors.push({ field, message: `Missing required field: "${field}"`, severity: 'error' });
    }
  }

  if (typeof rule.title === 'string' && rule.title.trim().length < 5) {
    warnings.push({ field: 'title', message: 'Title is very short — use a descriptive name', severity: 'warning' });
  }

  if (rule.level && !VALID_LEVELS.includes(rule.level)) {
    errors.push({ field: 'level', message: `Invalid level "${rule.level}". Valid: ${VALID_LEVELS.join(', ')}`, severity: 'error' });
  }

  // logsource validation
  if (rule.logsource) {
    if (typeof rule.logsource !== 'object' || Array.isArray(rule.logsource)) {
      errors.push({ field: 'logsource', message: 'logsource must be a mapping with category/product/service', severity: 'error' });
    } else {
      const ls = rule.logsource as Record<string, unknown>;
      if (!ls.category && !ls.product && !ls.service) {
        warnings.push({ field: 'logsource', message: 'logsource has no category, product, or service — rule may match too broadly', severity: 'warning' });
      }
    }
  }

  // detection validation
  if (rule.detection) {
    if (typeof rule.detection !== 'object' || Array.isArray(rule.detection)) {
      errors.push({ field: 'detection', message: 'detection must be a mapping of named selections plus a condition', severity: 'error' });
    } else {
      const det = rule.detection as Record<string, unknown>;
      if (!det.condition || typeof det.condition !== 'string') {
        errors.push({ field: 'detection.condition', message: 'detection requires a "condition" string field', severity: 'error' });
      } else {
        validateCondition(det.condition, Object.keys(det).filter((k) => k !== 'condition'), errors, warnings);
      }
      // Validate selection shapes
      for (const [name, value] of Object.entries(det)) {
        if (name === 'condition') continue;
        validateSelection(name, value, errors, warnings);
      }
    }
  }

  if (rule.tags && !Array.isArray(rule.tags)) {
    warnings.push({ field: 'tags', message: 'tags should be a list of strings (e.g. attack.execution, attack.t1059.001)', severity: 'warning' });
  }

  return { valid: errors.length === 0, errors, warnings, parsedRule: errors.length === 0 ? rule as SigmaRule : undefined };
}

function validateCondition(condition: string, selectionNames: string[], errors: ValidationIssue[], warnings: ValidationIssue[]) {
  const cond = condition.trim();
  if (!cond) {
    errors.push({ field: 'detection.condition', message: 'condition is empty', severity: 'error' });
    return;
  }
  const known = new Set(selectionNames);
  const tokens = cond.match(/[A-Za-z_][A-Za-z0-9_]*/g) || [];
  const keywords = new Set(['all', 'of', 'them', 'not', 'and', 'or', '1', 'of']);
  let referenced = 0;
  for (const tok of tokens) {
    if (keywords.has(tok.toLowerCase())) continue;
    if (!known.has(tok)) {
      errors.push({ field: 'detection.condition', message: `condition references unknown selection "${tok}"`, severity: 'error' });
    } else {
      referenced++;
    }
  }
  if (referenced === 0 && !/all\s+of\s+them/i.test(cond)) {
    warnings.push({ field: 'detection.condition', message: 'condition does not reference any selection by name', severity: 'warning' });
  }
}

function validateSelection(name: string, value: unknown, errors: ValidationIssue[], _warnings: ValidationIssue[]) {
  if (value == null) {
    errors.push({ field: `detection.${name}`, message: `selection "${name}" is empty`, severity: 'error' });
    return;
  }
  if (typeof value === 'string' || typeof value === 'number') return; // scalar shorthand
  if (Array.isArray(value)) {
    if (value.length === 0) errors.push({ field: `detection.${name}`, message: `selection "${name}" list is empty`, severity: 'error' });
    return;
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    if (Object.keys(obj).length === 0) {
      errors.push({ field: `detection.${name}`, message: `selection "${name}" has no fields`, severity: 'error' });
    }
  }
}

// ===== Sigma Rule Matching Engine =====
// Evaluates a parsed Sigma rule against a list of security events.
// Supports field modifiers (contains, startswith, endswith, re), lists, and basic condition logic.

export function runRule(rule: SigmaRule, events: SecEvent[]): MatchResult {
  const det = rule.detection as Record<string, unknown>;
  const condition = (det.condition as string) || 'selection';
  const selections: Record<string, (e: SecEvent) => boolean> = {};

  for (const [name, value] of Object.entries(det)) {
    if (name === 'condition') continue;
    selections[name] = buildSelectionMatcher(value);
  }

  const matcher = buildConditionMatcher(condition, selections);
  const matchedEvents = events.filter(matcher);

  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;

  for (const e of events) {
    const isMatch = matcher(e);
    if (isMatch && e.malicious) truePositives++;
    else if (isMatch && !e.malicious) falsePositives++;
    else if (!isMatch && e.malicious) falseNegatives++;
    else trueNegatives++;
  }

  const matches = matchedEvents.length;
  const precision = matches > 0 ? truePositives / matches : 0;
  const totalMalicious = events.filter((e) => e.malicious).length;
  const recall = totalMalicious > 0 ? truePositives / totalMalicious : 0;
  const totalBenign = events.filter((e) => !e.malicious).length;
  const falsePositiveRate = totalBenign > 0 ? falsePositives / totalBenign : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = events.length > 0 ? (truePositives + trueNegatives) / events.length : 0;

  return {
    matches,
    matched_events: matchedEvents,
    truePositives,
    falsePositives,
    falseNegatives,
    trueNegatives,
    precision,
    recall,
    falsePositiveRate,
    f1,
    accuracy,
  };
}

function buildSelectionMatcher(value: unknown): (e: SecEvent) => boolean {
  if (value == null) return () => false;
  if (typeof value === 'string') {
    return (e) => Object.values(e.fields).some((v) => String(v).toLowerCase() === value.toLowerCase());
  }
  if (typeof value === 'number') {
    return (e) => Object.values(e.fields).some((v) => Number(v) === value);
  }
  if (Array.isArray(value)) {
    // list = OR of the items (each item is a field map or scalar)
    const matchers = value.map((item) => buildSelectionMatcher(item));
    return (e) => matchers.some((m) => m(e));
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    return (e) => matchFieldMap(obj, e);
  }
  return () => false;
}

function matchFieldMap(obj: Record<string, unknown>, e: SecEvent): boolean {
  for (const [rawKey, rawVal] of Object.entries(obj)) {
    const { field, modifier } = parseFieldKey(rawKey);
    const fieldValue = getFieldValue(e, field);
    if (fieldValue == null) return false;
    if (!matchValue(fieldValue, rawVal, modifier)) return false;
  }
  return true;
}

function parseFieldKey(key: string): { field: string; modifier?: string } {
  const parts = key.split('|');
  if (parts.length === 1) return { field: parts[0] };
  const modifier = parts[parts.length - 1];
  const field = parts.slice(0, -1).join('|');
  return { field, modifier };
}

function getFieldValue(e: SecEvent, field: string): string | number | boolean | null {
  // Sigma field names map to our event fields; also allow category/source.
  const lowerField = field.toLowerCase();
  if (lowerField === 'eventid') {
    return (e.fields.EventID as number) ?? null;
  }
  if (e.fields[field] != null) return e.fields[field];
  // Case-insensitive fallback
  const found = Object.entries(e.fields).find(([k]) => k.toLowerCase() === lowerField);
  return found ? found[1] : null;
}

function matchValue(actual: string | number | boolean, expected: unknown, modifier?: string): boolean {
  const actualStr = String(actual).toLowerCase();

  if (Array.isArray(expected)) {
    return expected.some((item) => matchValue(actual, item, modifier));
  }

  const expectedStr = String(expected).toLowerCase();

  switch (modifier) {
    case 'contains':
      return actualStr.includes(expectedStr);
    case 'startswith':
      return actualStr.startsWith(expectedStr);
    case 'endswith':
      return actualStr.endsWith(expectedStr);
    case 're':
      try {
        return new RegExp(String(expected)).test(String(actual));
      } catch {
        return false;
      }
    default:
      if (typeof actual === 'number' && typeof expected === 'number') return actual === expected;
      if (typeof expected === 'string') {
        // Wildcard support: * matches anything
        if (expectedStr.includes('*')) {
          const regex = '^' + expectedStr.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
          return new RegExp(regex, 'i').test(String(actual));
        }
        return actualStr === expectedStr;
      }
      return actual === expected;
  }
}

// Condition parser: supports "selection", "selection1 and selection2",
// "selection1 or selection2", "selection and not filter", "all of them", "1 of them"
function buildConditionMatcher(condition: string, selections: Record<string, (e: SecEvent) => boolean>): (e: SecEvent) => boolean {
  const cond = condition.trim().toLowerCase();

  // "all of them"
  if (/^all\s+of\s+them$/.test(cond)) {
    const all = Object.values(selections);
    return (e) => all.length > 0 && all.every((m) => m(e));
  }
  // "N of them" / "1 of them"
  const nOfThem = cond.match(/^(\d+)\s+of\s+them$/);
  if (nOfThem) {
    const n = Number(nOfThem[1]);
    const all = Object.values(selections);
    return (e) => all.filter((m) => m(e)).length >= n;
  }
  // "all of selection*"
  const allOfPattern = cond.match(/^all\s+of\s+([a-z_][a-z0-9_]*)\*$/);
  if (allOfPattern) {
    const prefix = allOfPattern[1];
    const matched = Object.entries(selections).filter(([k]) => k.startsWith(prefix)).map(([, v]) => v);
    return (e) => matched.length > 0 && matched.every((m) => m(e));
  }

  // Tokenize into names, and, or, not, parentheses
  return parseBooleanExpression(condition, selections);
}

function parseBooleanExpression(expr: string, selections: Record<string, (e: SecEvent) => boolean>): (e: SecEvent) => boolean {
  const tokens = tokenize(expr);
  let pos = 0;

  function peek(): string | undefined {
    return tokens[pos];
  }
  function next(): string {
    return tokens[pos++];
  }

  function parseOr(): (e: SecEvent) => boolean {
    let left = parseAnd();
    while (peek() === 'or') {
      next();
      const right = parseAnd();
      const l = left;
      const r = right;
      left = (e) => l(e) || r(e);
    }
    return left;
  }

  function parseAnd(): (e: SecEvent) => boolean {
    let left = parseNot();
    while (peek() === 'and') {
      next();
      const right = parseNot();
      const l = left;
      const r = right;
      left = (e) => l(e) && r(e);
    }
    return left;
  }

  function parseNot(): (e: SecEvent) => boolean {
    if (peek() === 'not') {
      next();
      const inner = parseNot();
      return (e) => !inner(e);
    }
    return parseAtom();
  }

  function parseAtom(): (e: SecEvent) => boolean {
    const tok = peek();
    if (tok === '(') {
      next();
      const inner = parseOr();
      if (peek() === ')') next();
      return inner;
    }
    if (tok && tok !== 'and' && tok !== 'or' && tok !== 'not' && tok !== '(' && tok !== ')') {
      next();
      const matcher = selections[tok] ?? selections[tok.toLowerCase()];
      return matcher ?? (() => false);
    }
    next();
    return () => false;
  }

  return parseOr();
}

function tokenize(expr: string): string[] {
  const tokens: string[] = [];
  const re = /\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*)\s*/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(expr)) !== null) {
    tokens.push(m[1]);
  }
  return tokens;
}
