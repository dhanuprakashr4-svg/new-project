import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface ChallengeMeta {
  id: string;
  name: string;
  mitre: string;
  tactic: string;
  difficulty: string;
  briefing: string;
  dataset_id: string;
  target_precision: number;
  target_recall: number;
  target_fpr: number;
  hint: string;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  const challenges: ChallengeMeta[] = [
    {
      id: "ch1",
      name: "Encoded PowerShell Detection",
      mitre: "T1059.001",
      tactic: "Execution",
      difficulty: "Recruit",
      briefing: "Adversaries use encoded PowerShell commands to hide malicious payloads from simple string-based detections. Your mission: write a Sigma rule that catches encoded PowerShell execution while avoiding benign administrative scripts.",
      dataset_id: "sysmon-proc",
      target_precision: 0.6,
      target_recall: 1.0,
      target_fpr: 0.0,
      hint: "Look for -EncodedCommand or -enc in the CommandLine. Add a filter selection for benign Get-Process / Get-Service calls.",
    },
    {
      id: "ch2",
      name: "LSASS Credential Access",
      mitre: "T1003",
      tactic: "Credential Access",
      difficulty: "Analyst",
      briefing: "Credential dumping tools target the LSASS process to extract passwords and hashes from memory. Build a Sigma rule that detects known credential-access tooling and LSASS-targeting command lines.",
      dataset_id: "sysmon-proc",
      target_precision: 0.5,
      target_recall: 1.0,
      target_fpr: 0.0,
      hint: "Match on mimikatz.exe and procdump.exe Image names, plus command lines containing sekurlsa or logonpasswords.",
    },
    {
      id: "ch3",
      name: "Scheduled Task Creation",
      mitre: "T1053",
      tactic: "Execution / Persistence",
      difficulty: "Analyst",
      briefing: "Attackers create scheduled tasks for persistence and recurring execution. Distinguish malicious task creation (running scripts/binaries) from legitimate OS maintenance tasks.",
      dataset_id: "win-4698",
      target_precision: 0.66,
      target_recall: 1.0,
      target_fpr: 0.0,
      hint: "Filter out TaskName containing Microsoft, Defrag, or Update. Flag TaskAction containing powershell, .bat, or .exe.",
    },
    {
      id: "ch4",
      name: "Pass The Hash",
      mitre: "T1550",
      tactic: "Lateral Movement",
      difficulty: "Hunter",
      briefing: "Pass the Hash lets attackers authenticate using NTLM password hashes without knowing the plaintext password. Detect successful NTLM network logons that may indicate PtH lateral movement.",
      dataset_id: "win-4624",
      target_precision: 0.5,
      target_recall: 1.0,
      target_fpr: 0.0,
      hint: "Select EventID 4624 with LogonType 3, AuthenticationPackageName NTLM, and Status Success. Benign Kerberos logons should not match.",
    },
    {
      id: "ch5",
      name: "SQL Injection",
      mitre: "T1190",
      tactic: "Initial Access",
      difficulty: "Specialist",
      briefing: "SQL and command injection remain top initial-access vectors. Detect malicious patterns in HTTP requests - classic SQLi syntax, command chaining, and known scanner user agents.",
      dataset_id: "web-access",
      target_precision: 0.6,
      target_recall: 1.0,
      target_fpr: 0.0,
      hint: "Look for OR 1=1, UNION SELECT, --, sqlmap user agent, and command injection (;wget, ;cat). Combine selections with OR.",
    },
  ];

  return new Response(JSON.stringify({ challenges }), {
    status: 200,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
});
