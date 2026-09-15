import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Flame, 
  Terminal, 
  Zap, 
  CheckCircle2, 
  Sparkles, 
  Ban, 
  Lock, 
  RefreshCw, 
  ChevronRight, 
  AlertTriangle,
  ArrowRight,
  Radio,
  Server
} from 'lucide-react';
import { ThreatAlert } from '../types';
import { soundEffects } from '../utils/audio';

interface ThreatDetectionCenterProps {
  alerts: ThreatAlert[];
  onExecuteSoarAction: (alertId: string, actionType: string) => void;
  onAnalyzeAlertAi: (alert: ThreatAlert) => void;
  onDismissAlert: (alertId: string) => void;
}

export const ThreatDetectionCenter: React.FC<ThreatDetectionCenterProps> = ({
  alerts,
  onExecuteSoarAction,
  onAnalyzeAlertAi,
  onDismissAlert
}) => {
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(
    alerts.length > 0 ? alerts[0].id : null
  );

  const activeAlerts = alerts.filter(a => a.status === 'ACTIVE' || a.status === 'CONTAINING');
  const containedAlerts = alerts.filter(a => a.status === 'CONTAINED');

  const selectedAlert = alerts.find(a => a.id === selectedAlertId) || alerts[0] || null;

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-950/80 border-red-500 text-red-300 animate-pulse';
      case 'HIGH':
        return 'bg-orange-950/80 border-orange-500 text-orange-300';
      case 'MEDIUM':
        return 'bg-amber-950/80 border-amber-500 text-amber-300';
      default:
        return 'bg-blue-950/80 border-blue-500 text-blue-300';
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 text-xs font-mono">
      {/* Left Column: Active Threat Incident Queue (5 cols) */}
      <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 flex flex-col h-[560px]">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-400" />
            <h3 className="font-bold uppercase text-slate-200 tracking-wider">
              Automated Threat Detection Queue
            </h3>
          </div>
          <span className="px-2 py-0.5 rounded-full bg-red-950 border border-red-800 text-red-300 text-[10px] font-bold">
            {activeAlerts.length} ACTIVE
          </span>
        </div>

        {/* Scrollable Alerts List */}
        <div className="flex-1 overflow-y-auto space-y-2 mt-3 pr-1">
          {activeAlerts.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center p-6 text-slate-500 space-y-2">
              <ShieldCheck className="w-10 h-10 text-emerald-500/60" />
              <p className="font-bold text-slate-400">All Threat Vectors Contained</p>
              <p className="text-[11px] text-slate-500">
                Autonomous heuristic engine monitoring traffic. Use "Red Drill Sim" in the HUD to inject adversarial scenarios.
              </p>
            </div>
          ) : (
            activeAlerts.map(alert => {
              const isSelected = selectedAlert?.id === alert.id;
              return (
                <div
                  key={alert.id}
                  onClick={() => {
                    soundEffects.playClick();
                    setSelectedAlertId(alert.id);
                  }}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-slate-950 border-red-500 shadow-md shadow-red-950/60 ring-1 ring-red-500/50'
                      : 'bg-slate-950/60 border-slate-800/80 hover:bg-slate-950 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-1.5">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(alert.severity)}`}>
                      {alert.severity}
                    </span>
                    <span className="text-[10px] text-slate-500">
                      {alert.timestamp.split('T')[1]?.substring(0, 8)}
                    </span>
                  </div>

                  <h4 className="font-bold text-slate-100 text-sm mb-1 leading-snug">
                    {alert.title}
                  </h4>

                  <div className="text-[11px] text-slate-400 flex items-center gap-2 mb-2">
                    <span className="text-red-400 font-semibold">{alert.sourceIp}</span>
                    <ArrowRight className="w-3 h-3 text-slate-600 inline" />
                    <span className="text-slate-300">{alert.destIp}:{alert.destPort}</span>
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 border-t border-slate-800/80 pt-1.5">
                    <span className="bg-slate-800 px-1.5 py-0.5 rounded text-cyan-300">
                      MITRE {alert.mitreId}
                    </span>
                    <span className="text-emerald-400 font-semibold">
                      Confidence: {alert.confidenceScore}%
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Contained Count Footer */}
        {containedAlerts.length > 0 && (
          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-400">
            <span className="flex items-center gap-1 text-emerald-400">
              <CheckCircle2 className="w-3.5 h-3.5" />
              {containedAlerts.length} Incidents Neutralized
            </span>
          </div>
        )}
      </div>

      {/* Right Column: Selected Incident SOAR Execution Panel (7 cols) */}
      <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-lg p-4 flex flex-col h-[560px] overflow-y-auto">
        {selectedAlert ? (
          <div className="space-y-4 flex-1">
            {/* Alert Header & Attribution */}
            <div className="flex flex-wrap items-start justify-between gap-3 pb-3 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(selectedAlert.severity)}`}>
                    {selectedAlert.severity} SEVERITY
                  </span>
                  <span className="px-2 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300 text-[10px] font-semibold">
                    {selectedAlert.mitreTactic} ({selectedAlert.mitreId})
                  </span>
                  <span className="text-slate-500 text-[11px]">{selectedAlert.id}</span>
                </div>
                <h2 className="text-base font-bold text-slate-100">{selectedAlert.title}</h2>
              </div>

              {/* AI Analysis Button */}
              <button
                id="btn-trigger-ai-triage"
                onClick={() => {
                  soundEffects.playClick();
                  onAnalyzeAlertAi(selectedAlert);
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-cyan-950 border border-cyan-500/70 text-cyan-200 hover:bg-cyan-900/80 font-bold transition-all shadow-md shadow-cyan-950"
              >
                <Sparkles className="w-4 h-4 text-cyan-400" />
                <span>AI FORENSICS & RULES</span>
              </button>
            </div>

            {/* Incident Technical Description */}
            <div className="bg-slate-950/80 border border-slate-800 rounded p-3 text-slate-300 text-[11px] leading-relaxed">
              <span className="font-bold text-slate-400 block mb-1">DETECTION HEURISTIC & CONTEXT:</span>
              {selectedAlert.description}
            </div>

            {/* Socket & Flow Telemetry */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
              <div className="bg-slate-950/80 border border-slate-800/80 rounded p-2">
                <span className="text-[10px] text-slate-500 uppercase block">Source Socket</span>
                <span className="text-red-400 font-bold text-xs">{selectedAlert.sourceIp}</span>
                <span className="text-[10px] text-slate-400">:{selectedAlert.sourcePort}</span>
              </div>
              <div className="bg-slate-950/80 border border-slate-800/80 rounded p-2">
                <span className="text-[10px] text-slate-500 uppercase block">Destination Socket</span>
                <span className="text-slate-200 font-bold text-xs">{selectedAlert.destIp}</span>
                <span className="text-[10px] text-slate-400">:{selectedAlert.destPort}</span>
              </div>
              <div className="bg-slate-950/80 border border-slate-800/80 rounded p-2">
                <span className="text-[10px] text-slate-500 uppercase block">Bursted Packets</span>
                <span className="text-cyan-300 font-bold text-xs">{selectedAlert.packetCount}</span>
                <span className="text-[10px] text-slate-400"> pkts</span>
              </div>
              <div className="bg-slate-950/80 border border-slate-800/80 rounded p-2">
                <span className="text-[10px] text-slate-500 uppercase block">Confidence Score</span>
                <span className="text-emerald-400 font-bold text-xs">{selectedAlert.confidenceScore}%</span>
                <span className="text-[10px] text-slate-400"> certainty</span>
              </div>
            </div>

            {/* Automated SOAR Active Playbook Mitigation Buttons */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Zap className="w-4 h-4 text-amber-400" />
                <h3 className="font-bold text-slate-200 uppercase tracking-wider text-xs">
                  Automated SOAR Remediation Playbooks
                </h3>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {/* 1. Host Isolation */}
                <button
                  id="btn-soar-isolate-host"
                  onClick={() => {
                    soundEffects.playQuarantineSuccess();
                    onExecuteSoarAction(selectedAlert.id, 'ISOLATE_HOST');
                  }}
                  className="flex items-center justify-between p-2.5 rounded bg-red-950/60 border border-red-700/80 hover:bg-red-900/80 text-red-200 font-bold transition-colors text-left"
                >
                  <div>
                    <div className="flex items-center gap-1.5 text-red-300">
                      <Lock className="w-3.5 h-3.5" />
                      <span>ISOLATE SOURCE HOST</span>
                    </div>
                    <span className="text-[10px] text-slate-400 font-normal">
                      Quarantine subnet port on switch
                    </span>
                  </div>
                  <ChevronRight className="w-4 h-4 text-red-400" />
                </button>

                {/* 2. Firewall IP Null-Route */}
                <button
                  id="btn-soar-nullroute-ip"
                  onClick={() => {
                    soundEffects.playBlockTick();
                    onExecuteSoarAction(selectedAlert.id, 'NULL_ROUTE_IP');
                  }}
                  className="flex items-center justify-between p-2.5 rounded bg-orange-950/60 border border-orange-700/80 hover:bg-orange-900/80 text-orange-200 font-bold transition-colors text-left"
                >
                  <div>
                    <div className="flex items-center gap-1.5 text-orange-300">
                      <Ban className="w-3.5 h-3.5" />
                      <span>BORDER NULL-ROUTE IP</span>
                    </div>
                    <span className="text-[10px] text-slate-400 font-normal">
                      Inject BGP blackhole / Drop ACL
                    </span>
                  </div>
                  <ChevronRight className="w-4 h-4 text-orange-400" />
                </button>

                {/* 3. Terminate Socket */}
                <button
                  id="btn-soar-kill-socket"
                  onClick={() => {
                    soundEffects.playBlockTick();
                    onExecuteSoarAction(selectedAlert.id, 'KILL_SOCKET');
                  }}
                  className="flex items-center justify-between p-2.5 rounded bg-slate-950 border border-slate-700 hover:bg-slate-800 text-slate-200 font-bold transition-colors text-left"
                >
                  <div>
                    <div className="flex items-center gap-1.5 text-slate-300">
                      <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                      <span>FLUSH TCP STATE TABLE</span>
                    </div>
                    <span className="text-[10px] text-slate-400 font-normal">
                      Send TCP RST to both endpoints
                    </span>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-400" />
                </button>

                {/* 4. Honeytoken Decoy Diversion */}
                <button
                  id="btn-soar-divert-honeynet"
                  onClick={() => {
                    soundEffects.playQuarantineSuccess();
                    onExecuteSoarAction(selectedAlert.id, 'DIVERT_HONEYNET');
                  }}
                  className="flex items-center justify-between p-2.5 rounded bg-purple-950/60 border border-purple-700/80 hover:bg-purple-900/80 text-purple-200 font-bold transition-colors text-left"
                >
                  <div>
                    <div className="flex items-center gap-1.5 text-purple-300">
                      <Radio className="w-3.5 h-3.5" />
                      <span>DIVERT TO DECOY SINKHOLE</span>
                    </div>
                    <span className="text-[10px] text-slate-400 font-normal">
                      Trap adversary in high-interaction honeynet
                    </span>
                  </div>
                  <ChevronRight className="w-4 h-4 text-purple-400" />
                </button>
              </div>
            </div>

            {/* SOAR Action Audit History */}
            {selectedAlert.soarActionsTaken && selectedAlert.soarActionsTaken.length > 0 && (
              <div className="bg-slate-950 border border-emerald-900/60 rounded p-3 space-y-1.5">
                <span className="font-bold text-emerald-400 flex items-center gap-1.5 text-[11px]">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  CONTAINMENT ACTIONS EXECUTED:
                </span>
                <ul className="space-y-1 text-[11px] text-slate-300 list-disc list-inside">
                  {selectedAlert.soarActionsTaken.map((action, idx) => (
                    <li key={idx}>{action}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ) : (
          <div className="h-full flex items-center justify-center text-slate-500">
            Select an alert to view telemetry & SOAR playbooks.
          </div>
        )}
      </div>
    </div>
  );
};
