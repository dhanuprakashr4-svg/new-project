import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Client-Info, Apikey",
};

interface DatasetMeta {
  id: string;
  name: string;
  description: string;
  source: string;
  category: string;
  event_count: number;
  malicious_count: number;
  benign_count: number;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 200, headers: corsHeaders });
  }

  const datasets: DatasetMeta[] = [
    { id: "win-4688", name: "Windows Process Creation (EID 4688)", description: "Process execution events from Windows Security audit logs — includes encoded PowerShell abuse.", source: "Windows Security", category: "process_creation", event_count: 7, malicious_count: 3, benign_count: 4 },
    { id: "win-4624", name: "Windows Authentication (EID 4624/4625)", description: "Logon success and failure events — includes Pass-the-Hash patterns.", source: "Windows Security", category: "authentication", event_count: 6, malicious_count: 3, benign_count: 3 },
    { id: "win-4698", name: "Windows Scheduled Task (EID 4698)", description: "Scheduled task creation events — detects persistence via schtasks.", source: "Windows Security", category: "scheduled_task", event_count: 5, malicious_count: 3, benign_count: 2 },
    { id: "win-7045", name: "Windows Service Install (EID 7045)", description: "Service installation events — detects malicious service-based persistence.", source: "Windows Security", category: "service_install", event_count: 3, malicious_count: 2, benign_count: 1 },
    { id: "sysmon-proc", name: "Sysmon Process Creation (EID 1)", description: "Sysmon EID 1 process creation — encoded PowerShell and LSASS credential access.", source: "Sysmon", category: "process_creation", event_count: 5, malicious_count: 3, benign_count: 2 },
    { id: "sysmon-net", name: "Sysmon Network Connection (EID 3)", description: "Sysmon network connections — C2 beaconing and lateral WMI.", source: "Sysmon", category: "network_connection", event_count: 4, malicious_count: 2, benign_count: 2 },
    { id: "sysmon-file", name: "Sysmon File Creation (EID 11)", description: "Sysmon file creation events — dropped payloads and scripts.", source: "Sysmon", category: "file_change", event_count: 3, malicious_count: 2, benign_count: 1 },
    { id: "web-access", name: "Web Access Logs", description: "HTTP access logs — SQL injection, command injection, suspicious requests.", source: "Web Access", category: "web_access", event_count: 6, malicious_count: 4, benign_count: 2 },
  ];

  return new Response(JSON.stringify({ datasets }), {
    status: 200,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
});
