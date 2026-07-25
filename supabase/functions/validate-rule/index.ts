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
    const { rule } = await req.json();
    if (typeof rule !== "string" || !rule.trim()) {
      return new Response(
        JSON.stringify({ valid: false, errors: [{ field: "root", message: "Rule is empty", severity: "error" }], warnings: [] }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } },
      );
    }

    const result = validateSigma(rule);
    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ valid: false, errors: [{ field: "server", message: String(err), severity: "error" }], warnings: [] }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  }
});

interface Issue {
  line?: number;
  field: string;
  message: string;
  severity: "error" | "warning";
}

interface ValidationResult {
  valid: boolean;
  errors: Issue[];
  warnings: Issue[];
}

function validateSigma(yamlText: string): ValidationResult {
  const errors: Issue[] = [];
  const warnings: Issue[] = [];

  let parsed: unknown;
  try {
    parsed = yaml.load(yamlText);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const lineMatch = msg.match(/\((\d+):(\d+)\)/);
    errors.push({
      field: "yaml",
      message: `YAML syntax error: ${msg}`,
      line: lineMatch ? Number(lineMatch[1]) : undefined,
      severity: "error",
    });
    return { valid: false, errors, warnings };
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    errors.push({ field: "root", message: "Sigma rule must be a YAML mapping", severity: "error" });
    return { valid: false, errors, warnings };
  }

  const rule = parsed as Record<string, unknown>;
  const required = ["title", "logsource", "detection"];
  for (const field of required) {
    if (!(field in rule) || rule[field] == null) {
      errors.push({ field, message: `Missing required field: "${field}"`, severity: "error" });
    }
  }

  if (typeof rule.title === "string" && rule.title.trim().length < 5) {
    warnings.push({ field: "title", message: "Title is very short", severity: "warning" });
  }

  const validLevels = ["informational", "low", "medium", "high", "critical"];
  if (rule.level && !validLevels.includes(String(rule.level))) {
    errors.push({ field: "level", message: `Invalid level "${rule.level}"`, severity: "error" });
  }

  if (rule.logsource && typeof rule.logsource === "object") {
    const ls = rule.logsource as Record<string, unknown>;
    if (!ls.category && !ls.product && !ls.service) {
      warnings.push({ field: "logsource", message: "logsource has no category/product/service", severity: "warning" });
    }
  }

  if (rule.detection && typeof rule.detection === "object") {
    const det = rule.detection as Record<string, unknown>;
    if (!det.condition || typeof det.condition !== "string") {
      errors.push({ field: "detection.condition", message: 'detection requires a "condition" field', severity: "error" });
    } else {
      const names = Object.keys(det).filter((k) => k !== "condition");
      const tokens = String(det.condition).match(/[A-Za-z_][A-Za-z0-9_]*/g) || [];
      const keywords = new Set(["all", "of", "them", "not", "and", "or"]);
      for (const t of tokens) {
        if (keywords.has(t.toLowerCase())) continue;
        if (!names.includes(t)) {
          errors.push({ field: "detection.condition", message: `condition references unknown selection "${t}"`, severity: "error" });
        }
      }
    }
    for (const [name, value] of Object.entries(det)) {
      if (name === "condition") continue;
      if (value == null || (typeof value === "object" && Object.keys(value as object).length === 0)) {
        errors.push({ field: `detection.${name}`, message: `selection "${name}" is empty`, severity: "error" });
      }
    }
  }

  return { valid: errors.length === 0, errors, warnings };
}
