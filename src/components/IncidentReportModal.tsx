import React, { useState } from 'react';
import { 
  FileText, 
  Download, 
  Copy, 
  Check, 
  X, 
  ShieldCheck, 
  Printer 
} from 'lucide-react';
import { ThreatAlert, Packet, FirewallRule } from '../types';

interface IncidentReportModalProps {
  alerts: ThreatAlert[];
  packets: Packet[];
  rules: FirewallRule[];
  defenseScore: number;
  onClose: () => void;
}

export const IncidentReportModal: React.FC<IncidentReportModalProps> = ({
  alerts,
  packets,
  rules,
  defenseScore,
  onClose
}) => {
  const [copied, setCopied] = useState(false);

  const totalThreats = packets.filter(p => p.isThreat).length;
  const criticalThreats = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highThreats = alerts.filter(a => a.severity === 'HIGH').length;
  const containedAlerts = alerts.filter(a => a.status === 'CONTAINED').length;

  const now = new Date();
  const shiftTimestamp = now.toISOString();

  const reportMarkdown = `# AEGIS-SOC BLUE TEAM SHIFT & INCIDENT REPORT
Generated: ${now.toUTCString()}
Console Version: Blue Team Command Core v4.8
Shift Classification: TACTICAL DEFENSE RECORD // TLP:AMBER

## 1. EXECUTIVE DEFENSE SUMMARY
- Defense Posture Score: ${defenseScore}%
- Total Packets Processed: ${packets.length.toLocaleString()}
- Total Adversarial Threat Pulses Intercepted: ${totalThreats}
- Active Incidents Managed: ${alerts.length} (${containedAlerts} Neutralized / Contained)
- Active Firewall & ACL Rules: ${rules.filter(r => r.active).length}

## 2. SEVERITY BREAKDOWN
- Critical Incidents: ${criticalThreats}
- High Priority Incidents: ${highThreats}
- Medium / Recon Probes: ${alerts.length - criticalThreats - highThreats}

## 3. KEY INCIDENT LOG & MITIGATION ACTIONS
${alerts.map((a, idx) => `### Incident ${idx + 1}: ${a.title}
- Severity: ${a.severity} | MITRE Tactic: ${a.mitreTactic} (${a.mitreId})
- Sockets: ${a.sourceIp}:${a.sourcePort} -> ${a.destIp}:${a.destPort}
- Status: ${a.status} (Confidence: ${a.confidenceScore}%)
- SOAR Actions: ${a.soarActionsTaken.join('; ') || 'Standard sensor capture'}
`).join('\n')}

## 4. FIREWALL & ACL UPDATES INJECTED DURING SHIFT
${rules.slice(0, 5).map(r => `- [${r.action}] ${r.name} | Src: ${r.source} -> Dst: ${r.destination} (${r.protocol}:${r.port}) [Hits: ${r.hitCount}]`).join('\n')}

## 5. HANDOVER RECOMMENDATIONS FOR INCOMING SOC TIER-2
- Maintain host isolation on quarantined subnet endpoints.
- Monitor BGP null-routed adversary C2 IPs for IP rotational shifting.
- Verify Active Directory Kerberos SPN password rotations.
`;

  const copyMarkdown = () => {
    navigator.clipboard.writeText(reportMarkdown);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadJson = () => {
    const reportData = {
      timestamp: shiftTimestamp,
      defenseScore,
      summary: {
        totalPackets: packets.length,
        totalThreats,
        activeAlertsCount: alerts.length,
        containedAlertsCount: containedAlerts
      },
      alerts,
      activeFirewallRules: rules
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `AegisSOC_Shift_Report_${shiftTimestamp.split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-950 border border-slate-700 rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden font-mono text-xs text-slate-100">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-cyan-950 border border-cyan-500 text-cyan-300">
              <FileText className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h2 className="font-bold text-sm text-slate-100">
                AEGIS-SOC BLUE TEAM SHIFT & INCIDENT REPORT
              </h2>
              <span className="text-[11px] text-slate-400">
                Comprehensive security operations log, adversary triage, and handover brief.
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-md transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] text-slate-500 uppercase block font-bold">Defense Posture</span>
              <span className="text-xl font-bold text-emerald-400">{defenseScore}%</span>
            </div>
            <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] text-slate-500 uppercase block font-bold">Packets Inspected</span>
              <span className="text-xl font-bold text-cyan-300">{packets.length.toLocaleString()}</span>
            </div>
            <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] text-slate-500 uppercase block font-bold">Threats Intercepted</span>
              <span className="text-xl font-bold text-red-400">{totalThreats}</span>
            </div>
            <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 text-center">
              <span className="text-[10px] text-slate-500 uppercase block font-bold">Mitigated Incidents</span>
              <span className="text-xl font-bold text-purple-300">{containedAlerts}</span>
            </div>
          </div>

          {/* Markdown Preview */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-4 font-mono text-[11px] text-slate-300 whitespace-pre-wrap max-h-96 overflow-y-auto leading-relaxed selection:bg-cyan-950">
            {reportMarkdown}
          </div>
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex flex-wrap items-center justify-between gap-3">
          <span className="text-[11px] text-slate-400">
            Export ready for SIEM & GRC compliance handoff
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={copyMarkdown}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied Markdown' : 'Copy Markdown'}</span>
            </button>
            <button
              onClick={downloadJson}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-cyan-950 border border-cyan-600 text-cyan-200 hover:bg-cyan-900 font-bold"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download JSON</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
