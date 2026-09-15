import React, { useState } from 'react';
import { 
  Flame, 
  X, 
  Sparkles, 
  Play, 
  CheckCircle2, 
  AlertTriangle, 
  Crosshair,
  Zap,
  RefreshCw
} from 'lucide-react';
import { ThreatCategory } from '../types';
import { soundEffects } from '../utils/audio';

interface AttackSimulationModalProps {
  onClose: () => void;
  onLaunchAttack: (category: ThreatCategory, name: string) => void;
}

const PRESET_DRILLS: {
  category: ThreatCategory;
  name: string;
  adversary: string;
  severity: 'HIGH' | 'CRITICAL' | 'MEDIUM';
  description: string;
  phases: string[];
}[] = [
  {
    category: 'C2_BEACONING',
    name: 'Advanced Persistent Threat (APT-29) Malleable C2 Drill',
    adversary: 'Cozy Bear / Midnight Blizzard',
    severity: 'CRITICAL',
    description: 'Simulates low-jitter TLS/HTTPS heartbeat beaconing with base64 steganographic cookies to test SOC behavioral anomaly detection.',
    phases: ['Initial Ingress via Phish Token', 'C2 Channel Staging', 'Host Enumeration', 'Lateral Escalation']
  },
  {
    category: 'RANSOMWARE_LATERAL',
    name: 'LockBit 3.0 Rapid Lateral SMB PsExec Outbreak',
    adversary: 'Bitwise Spider Syndicate',
    severity: 'CRITICAL',
    description: 'Simulates rapid ADMIN$ share enumeration, Named Pipe IPC$ invocation, and remote service creation across internal subnets.',
    phases: ['Host Compromise WKS-04', 'IPC$ NamedPipe PsExec', 'Pass-the-Hash Cred Spray', 'Database Encryption Stage']
  },
  {
    category: 'SQL_INJECTION',
    name: 'Blind Time-Based SQLi & Schema Exfiltration',
    adversary: 'Anonymous Cyber Extortionist',
    severity: 'HIGH',
    description: 'Simulates heavy stacked UNION SELECT queries against web application endpoints to verify WAF edge blocking.',
    phases: ['Port Reconnaissance', 'Error-based SQL Probing', 'Blind Sleep Timing Injection', 'Information Schema Dump']
  },
  {
    category: 'DNS_TUNNELING',
    name: 'DNS C2 Base64 Encoded Covert Tunneling',
    adversary: 'Lazarus Group (HIDDEN COBRA)',
    severity: 'HIGH',
    description: 'Simulates high-velocity TXT record lookups encoding proprietary source code over port 53.',
    phases: ['DNS Resolver Poisoning', 'Base64 Chunked Encoding', 'Exfil via Subdomain Requests', 'Data Assembly at C2']
  },
  {
    category: 'DDOS_SYN_FLOOD',
    name: 'SYN Flood TCP State Exhaustion Stress Test',
    adversary: 'Mirai IoT Botnet Swarm',
    severity: 'CRITICAL',
    description: 'Simulates 25,000 SYN packets per second targeting public gateway port 443 without ACK completion.',
    phases: ['Volumetric Burst Stage', 'SYN Queue Backlog Saturation', 'BGP Anycast Diversion Test', 'Auto-Mitigation Verification']
  }
];

export const AttackSimulationModal: React.FC<AttackSimulationModalProps> = ({
  onClose,
  onLaunchAttack
}) => {
  const [selectedDrill, setSelectedDrill] = useState(PRESET_DRILLS[0]);
  const [isGeneratingAiScenario, setIsGeneratingAiScenario] = useState(false);
  const [aiCustomScenario, setAiCustomScenario] = useState<any>(null);

  const handleGenerateAiDrill = async () => {
    setIsGeneratingAiScenario(true);
    try {
      const res = await fetch('/api/threats/generate-scenario', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenarioType: 'Zero-Day Supply Chain Compromise',
          difficulty: 'Expert Level'
        })
      });
      const data = await res.json();
      setAiCustomScenario(data);
      soundEffects.playQuarantineSuccess();
    } catch {
      // fallback
    } finally {
      setIsGeneratingAiScenario(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-950 border border-slate-700 rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden font-mono text-xs text-slate-100">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-purple-950 border border-purple-600 text-purple-300">
              <Flame className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <h2 className="font-bold text-sm text-slate-100">
                RED TEAM ATTACK SIMULATION & DRILL LAUNCHER
              </h2>
              <span className="text-[11px] text-slate-400">
                Inject controlled live adversary attacks into the sensor pipeline to test automated SOAR playbooks.
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
          {/* Preset Drill Selection Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {PRESET_DRILLS.map(drill => {
              const isSelected = selectedDrill.category === drill.category;
              return (
                <div
                  key={drill.category}
                  onClick={() => {
                    soundEffects.playClick();
                    setSelectedDrill(drill);
                  }}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-purple-950/70 border-purple-500 shadow-lg shadow-purple-950/60 ring-1 ring-purple-500'
                      : 'bg-slate-900/60 border-slate-800 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      drill.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-700' : 'bg-orange-950 text-orange-300 border border-orange-700'
                    }`}>
                      {drill.severity}
                    </span>
                    <span className="text-[10px] text-purple-400 font-semibold">{drill.adversary}</span>
                  </div>
                  <h4 className="font-bold text-slate-100 text-xs mb-1">{drill.name}</h4>
                  <p className="text-slate-400 text-[10px] line-clamp-2 leading-relaxed">{drill.description}</p>
                </div>
              );
            })}
          </div>

          {/* Selected Drill Phase Plan */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3.5 space-y-2">
            <span className="text-[10px] text-purple-400 uppercase font-bold tracking-wider block">
              ADVERSARY ATTACK PHASES IN THIS DRILL:
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
              {selectedDrill.phases.map((phase, idx) => (
                <div key={idx} className="bg-slate-950 p-2 rounded border border-slate-800 text-[10px]">
                  <span className="text-slate-500 block">PHASE {idx + 1}</span>
                  <span className="text-slate-200 font-semibold">{phase}</span>
                </div>
              ))}
            </div>
          </div>

          {/* AI Dynamic Scenario Generator */}
          <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between">
            <div>
              <span className="font-bold text-slate-200 block text-xs">Generate Custom AI Adversary Scenario</span>
              <span className="text-[11px] text-slate-400">
                Uses Gemini 3.7 Flash to synthesize non-standard multi-stage zero-day attack drills.
              </span>
            </div>
            <button
              onClick={handleGenerateAiDrill}
              disabled={isGeneratingAiScenario}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-purple-950 border border-purple-600 text-purple-200 hover:bg-purple-900 font-bold"
            >
              {isGeneratingAiScenario ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
              <span>AI SYNTHESIZE</span>
            </button>
          </div>

          {aiCustomScenario && (
            <div className="p-3 bg-slate-950 border border-purple-800 rounded-lg text-slate-300 space-y-1">
              <span className="text-purple-400 font-bold">{aiCustomScenario.scenarioName}</span>
              <p className="text-[11px] text-slate-400">{aiCustomScenario.description}</p>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded bg-slate-800 text-slate-300 hover:bg-slate-700"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              soundEffects.playThreatAlarm('CRITICAL');
              onLaunchAttack(selectedDrill.category, selectedDrill.name);
              onClose();
            }}
            className="flex items-center gap-2 px-5 py-2 rounded bg-red-600 text-white font-bold hover:bg-red-500 shadow-lg shadow-red-950"
          >
            <Play className="w-4 h-4" />
            <span>LAUNCH RED DRILL NOW</span>
          </button>
        </div>
      </div>
    </div>
  );
};
