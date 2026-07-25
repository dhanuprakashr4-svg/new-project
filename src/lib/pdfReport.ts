import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import type { Incident } from './types';
import { getMitre } from './mitre';
import { getNistMapping, NIST_FUNCTIONS } from './nist';
import { DATASETS } from './datasets';
import { ATTACK_CHAINS } from './attackChains';

// ===== PDF Incident Report Generator =====
// Generates a professional forensic incident report PDF with attack details,
// server info, timestamps, IPs, MITRE mapping, NIST CSF mapping, and
// recommended response actions.

export interface PdfReportData {
  incident: Incident;
  serverName: string;
  serverIp: string;
  serverOs: string;
  attackerIp?: string;
  attackerCountry?: string;
  matchedLogLines: string[];
  detectionMetrics?: {
    precision: number;
    recall: number;
    fpr: number;
    accuracy: number;
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
    trueNegatives: number;
  };
}

const COLORS = {
  cyber: [24, 144, 255] as [number, number, number],
  threat: [245, 34, 45] as [number, number, number],
  secure: [82, 196, 26] as [number, number, number],
  alert: [250, 173, 20] as [number, number, number],
  dark: [15, 23, 42] as [number, number, number],
  mid: [51, 65, 85] as [number, number, number],
  light: [226, 232, 240] as [number, number, number],
  white: [255, 255, 255] as [number, number, number],
};

export function generateIncidentPdf(data: PdfReportData): jsPDF {
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  let y = 0;

  const { incident, serverName, serverIp, serverOs, attackerIp, attackerCountry, matchedLogLines, detectionMetrics } = data;
  const mitre = getMitre(incident.mitre);
  const nist = getNistMapping(incident.mitre);

  // ===== Header bar =====
  doc.setFillColor(...COLORS.dark);
  doc.rect(0, 0, pageWidth, 30, 'F');
  doc.setFillColor(...COLORS.cyber);
  doc.rect(0, 30, pageWidth, 1.5, 'F');

  doc.setTextColor(...COLORS.white);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.text('THREATZERO SENTINEL X', margin, 14);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100, 116, 139);
  doc.text('AI-Powered Detection Engineering & SOC Intelligence Platform', margin, 20);
  doc.setFontSize(8);
  doc.text('FORENSIC INCIDENT REPORT', margin, 26);

  doc.setFontSize(8);
  doc.setTextColor(100, 116, 139);
  doc.text(`Report ID: ${incident.id}`, pageWidth - margin, 14, { align: 'right' });
  doc.text(`Generated: ${new Date().toISOString().slice(0, 19).replace('T', ' ')} UTC`, pageWidth - margin, 20, { align: 'right' });
  const severityColor = incident.severity === 'critical' ? COLORS.threat : incident.severity === 'high' ? [250, 140, 22] as [number, number, number] : COLORS.alert;
  doc.setFillColor(...severityColor);
  doc.roundedRect(pageWidth - margin - 25, 23, 25, 5, 1, 1, 'F');
  doc.setTextColor(...COLORS.white);
  doc.setFont('helvetica', 'bold');
  doc.text(incident.severity.toUpperCase(), pageWidth - margin - 12.5, 26.5, { align: 'center' });

  y = 42;

  // ===== Section: Incident Overview =====
  y = addSectionHeader(doc, 'INCIDENT OVERVIEW', y, margin, pageWidth);
  y += 2;

  const overviewData = [
    ['Incident ID', incident.id],
    ['Attack Type', incident.attackType],
    ['MITRE Technique', `${incident.mitre} — ${mitre?.name || 'N/A'}`],
    ['MITRE Tactic', mitre?.tactic || 'N/A'],
    ['Severity', incident.severity.toUpperCase()],
    ['Status', incident.status.toUpperCase()],
    ['Threat Score', `${incident.threatScore}/99`],
    ['Risk Score', `${incident.riskScore}/99`],
    ['Detection Time', incident.timestamp.slice(0, 19).replace('T', ' ') + ' UTC'],
    ['Detection Rule', incident.detectionRule],
  ];

  autoTable(doc, {
    startY: y,
    head: [['Field', 'Value']],
    body: overviewData,
    theme: 'striped',
    headStyles: { fillColor: [24, 144, 255], textColor: [255, 255, 255] },
    bodyStyles: { textColor: [15, 23, 42] },
        margin: { left: margin, right: margin },
    styles: { fontSize: 8, cellPadding: 2 },
    columnStyles: { 0: { fontStyle: 'bold', cellWidth: 45 } },
  });
  y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 8;

  // ===== Section: Infrastructure =====
  y = addSectionHeader(doc, 'AFFECTED INFRASTRUCTURE', y, margin, pageWidth);
  y += 2;

  const infraData = [
    ['Server Name', serverName],
    ['Server IP Address', serverIp],
    ['Operating System', serverOs],
    ['Attacker IP', attackerIp || 'Unknown'],
    ['Attacker Origin', attackerCountry || 'Unknown'],
    ['Network Segment', inferNetworkSegment(serverIp)],
  ];

  autoTable(doc, {
    startY: y,
    head: [['Infrastructure Detail', 'Value']],
    body: infraData,
    theme: 'striped',
    headStyles: { fillColor: [250, 140, 22], textColor: [255, 255, 255] },
    bodyStyles: { textColor: [15, 23, 42] },
    margin: { left: margin, right: margin },
    styles: { fontSize: 8, cellPadding: 2 },
    columnStyles: { 0: { fontStyle: 'bold', cellWidth: 50 } },
  });
  y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 8;

  // ===== Section: MITRE ATT&CK Mapping =====
  if (mitre) {
    if (y > pageHeight - 60) { doc.addPage(); y = 20; }
    y = addSectionHeader(doc, 'MITRE ATT&CK MAPPING', y, margin, pageWidth);
    y += 2;

    autoTable(doc, {
      startY: y,
      head: [['Technique ID', 'Technique Name', 'Tactic', 'Severity', 'Subtechnique']],
      body: [[mitre.id, mitre.name, mitre.tactic, mitre.severity, mitre.subtechnique ? 'Yes' : 'No']],
      theme: 'grid',
      headStyles: { fillColor: [245, 34, 45], textColor: [255, 255, 255] },
      bodyStyles: { textColor: [15, 23, 42] },
      margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 2, lineColor: COLORS.mid, lineWidth: 0.1 },
    });
    y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 3;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...COLORS.dark);
    const descLines = doc.splitTextToSize(`Description: ${mitre.description}`, pageWidth - 2 * margin);
    doc.text(descLines, margin, y);
    y += descLines.length * 4 + 6;
  }

  // ===== Section: NIST CSF Mapping =====
  if (nist) {
    if (y > pageHeight - 50) { doc.addPage(); y = 20; }
    y = addSectionHeader(doc, 'NIST CYBERSECURITY FRAMEWORK MAPPING', y, margin, pageWidth);
    y += 2;

    autoTable(doc, {
      startY: y,
      head: [['CSF Function', 'Categories']],
      body: nist.categories.map((cat, i) => [
        i === 0 ? nist.primaryFunction : '',
        cat,
      ]),
      theme: 'striped',
      headStyles: { fillColor: [114, 46, 209], textColor: [255, 255, 255] },
      bodyStyles: { textColor: [15, 23, 42] },
      margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 2 },
      columnStyles: { 0: { fontStyle: 'bold', cellWidth: 35 } },
    });
    y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 3;

    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(...COLORS.dark);
    doc.text('Recommended Defensive Actions (NIST):', margin, y);
    y += 4;
    doc.setFont('helvetica', 'normal');
    for (const action of nist.defensiveActions) {
      const lines = doc.splitTextToSize(`• ${action}`, pageWidth - 2 * margin - 5);
      doc.text(lines, margin + 3, y);
      y += lines.length * 4 + 1;
    }
    y += 4;
  }

  // ===== Section: Detection Metrics / Confusion Matrix =====
  if (detectionMetrics) {
    if (y > pageHeight - 50) { doc.addPage(); y = 20; }
    y = addSectionHeader(doc, 'DETECTION METRICS & CONFUSION MATRIX', y, margin, pageWidth);
    y += 2;

    autoTable(doc, {
      startY: y,
      head: [['Metric', 'Value', 'Threshold', 'Status']],
      body: [
        ['Precision', `${(detectionMetrics.precision * 100).toFixed(1)}%`, '≥ 60%', detectionMetrics.precision >= 0.6 ? 'PASS' : 'FAIL'],
        ['Recall', `${(detectionMetrics.recall * 100).toFixed(1)}%`, '≥ 100%', detectionMetrics.recall >= 1.0 ? 'PASS' : 'FAIL'],
        ['False Positive Rate', `${(detectionMetrics.fpr * 100).toFixed(1)}%`, '< 70%', detectionMetrics.fpr < 0.7 ? 'PASS' : 'FAIL'],
        ['Accuracy', `${(detectionMetrics.accuracy * 100).toFixed(1)}%`, '-', '-'],
        ['True Positives', String(detectionMetrics.truePositives), '—', '—'],
        ['False Positives', String(detectionMetrics.falsePositives), '—', '—'],
        ['False Negatives', String(detectionMetrics.falseNegatives), '—', '—'],
        ['True Negatives', String(detectionMetrics.trueNegatives), '—', '—'],
      ],
      theme: 'grid',
      headStyles: { fillColor: [24, 144, 255], textColor: [255, 255, 255] },
      bodyStyles: { textColor: [15, 23, 42] },
      margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 2 },
      columnStyles: { 3: { fontStyle: 'bold', halign: 'center' } },
      didParseCell: (data) => {
        if (data.column.index === 3 && data.cell.section === 'body') {
          if (data.cell.text[0] === 'PASS') {
            data.cell.styles.textColor = COLORS.secure;
          } else if (data.cell.text[0] === 'FAIL') {
            data.cell.styles.textColor = COLORS.threat;
          }
        }
      },
    });
    y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 8;
  }

  // ===== Section: AI Analysis Summary =====
  if (incident.aiSummary) {
    if (y > pageHeight - 40) { doc.addPage(); y = 20; }
    y = addSectionHeader(doc, 'AI ANALYSIS SUMMARY', y, margin, pageWidth);
    y += 2;
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(...COLORS.dark);
    const summaryLines = doc.splitTextToSize(incident.aiSummary, pageWidth - 2 * margin);
    doc.text(summaryLines, margin, y);
    y += summaryLines.length * 5 + 6;
  }

  // ===== Section: Matched Logs / Evidence =====
  if (matchedLogLines.length > 0) {
    if (y > pageHeight - 40) { doc.addPage(); y = 20; }
    y = addSectionHeader(doc, 'MATCHED LOG EVIDENCE', y, margin, pageWidth);
    y += 2;

    autoTable(doc, {
      startY: y,
      head: [['#', 'Log Entry']],
      body: matchedLogLines.map((line, i) => [String(i + 1), line]),
      theme: 'striped',
      headStyles: { fillColor: [51, 65, 85], textColor: [255, 255, 255] },
      bodyStyles: { textColor: [15, 23, 42] },
      margin: { left: margin, right: margin },
      styles: { fontSize: 7, cellPadding: 1.5, overflow: 'linebreak' },
      columnStyles: { 0: { cellWidth: 10, halign: 'center' }, 1: { cellWidth: 'auto' } },
    });
    y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 8;
  }

  // ===== Section: Recommended Response Actions =====
  if (incident.recommendedActions.length > 0) {
    if (y > pageHeight - 40) { doc.addPage(); y = 20; }
    y = addSectionHeader(doc, 'RECOMMENDED RESPONSE ACTIONS', y, margin, pageWidth);
    y += 2;

    autoTable(doc, {
      startY: y,
      head: [['#', 'Action']],
      body: incident.recommendedActions.map((action, i) => [String(i + 1), action]),
      theme: 'striped',
      headStyles: { fillColor: [250, 140, 22], textColor: [255, 255, 255] },
      bodyStyles: { textColor: [15, 23, 42] },
      margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 2, overflow: 'linebreak' },
      columnStyles: { 0: { cellWidth: 10, halign: 'center' } },
    });
    y = (doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 10;
  }

  // ===== Footer on every page =====
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFillColor(...COLORS.dark);
    doc.rect(0, pageHeight - 12, pageWidth, 12, 'F');
    doc.setFillColor(...COLORS.cyber);
    doc.rect(0, pageHeight - 12, pageWidth, 0.5, 'F');
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    doc.text('ThreatZero Sentinel X - Confidential Forensic Report', margin, pageHeight - 5);
    doc.text('Page ' + i + ' of ' + pageCount, pageWidth - margin, pageHeight - 5, { align: 'right' });
  }

  return doc;
}

function addSectionHeader(doc: jsPDF, title: string, y: number, margin: number, pageWidth: number): number {
  doc.setFillColor(...COLORS.cyber);
  doc.roundedRect(margin, y, pageWidth - 2 * margin, 6, 1, 1, 'F');
  doc.setTextColor(...COLORS.white);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.text(title, margin + 2, y + 4.2);
  return y + 8;
}

function inferNetworkSegment(ip: string): string {
  if (ip.startsWith('10.')) return 'Internal Corporate Network';
  if (ip.startsWith('192.168.')) return 'Internal LAN';
  if (ip.startsWith('172.')) return 'Internal DMZ';
  return 'External / Unknown';
}

// Build the complete report data from an incident
export function buildReportDataFromIncident(incident: Incident): PdfReportData {
  const mitre = getMitre(incident.mitre);
  const event = DATASETS.flatMap((d) => d.events).find(
    (e) => e.mitre === incident.mitre && e.malicious,
  );

  const serverIp = String(event?.fields?.DestinationIp || event?.fields?.IpAddress || '10.10.20.5');
  const attackerIp = String(event?.fields?.ClientIP || '45.155.205.233');

  const chain = ATTACK_CHAINS.find((c) => c.stages.some((s) => s.mitre === incident.mitre));
  const stage = chain?.stages.find((s) => s.mitre === incident.mitre);

  const matchedLogLines: string[] = [];
  const events = DATASETS.flatMap((d) => d.events).filter((e) => e.mitre === incident.mitre && e.malicious);
  for (const e of events.slice(0, 10)) {
    const fields = Object.entries(e.fields)
      .map(([k, v]) => k + '=' + v)
      .join(' ');
    matchedLogLines.push('[' + e.timestamp.slice(11, 19) + '] ' + e.source + ' EID ' + (e.fields.EventID || '-') + ': ' + fields);
  }

  return {
    incident,
    serverName: chain?.target || 'CORP-SRV-01',
    serverIp,
    serverOs: 'Windows Server 2019 Datacenter',
    attackerIp,
    attackerCountry: 'Unknown',
    matchedLogLines,
    detectionMetrics: undefined,
  };
}
