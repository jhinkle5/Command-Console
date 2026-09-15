import React, { useState, useEffect } from 'react';
import { 
  Sparkles, 
  ShieldAlert, 
  Terminal, 
  FileCode, 
  Lock, 
  Check, 
  Copy, 
  X, 
  RefreshCw, 
  AlertTriangle,
  ArrowRight,
  ShieldCheck,
  Send
} from 'lucide-react';
import { ThreatAlert, Packet, AIAnalysisResult } from '../types';
import { soundEffects } from '../utils/audio';

interface AIForensicsLabProps {
  threatData: ThreatAlert | Packet | null;
  onClose: () => void;
  onDeployGeneratedRule: (ruleType: 'SURICATA' | 'IPTABLES', ruleContent: string, name: string) => void;
}

export const AIForensicsLab: React.FC<AIForensicsLabProps> = ({
  threatData,
  onClose,
  onDeployGeneratedRule
}) => {
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AIAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedType, setCopiedType] = useState<string | null>(null);
  const [customPayload, setCustomPayload] = useState('');
  const [deployedSuccess, setDeployedSuccess] = useState<string | null>(null);

  const runAnalysis = async (dataToAnalyze: any) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/threats/ai-analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threatData: dataToAnalyze,
          analysisType: 'DEEP_FORENSIC_TRIAGE'
        })
      });

      if (!res.ok) {
        throw new Error(`HTTP error ${res.status}`);
      }

      const data = await res.json();
      setAnalysisResult(data);
      soundEffects.playQuarantineSuccess();
    } catch (err: any) {
      console.error('AI Analysis failed:', err);
      setError('AI Analysis encountered an error. Check server logs or try again.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (threatData) {
      runAnalysis(threatData);
    }
  }, [threatData]);

  const copyText = (type: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const handleCustomAnalyze = (e: React.FormEvent) => {
    e.preventDefault();
    if (!customPayload.trim()) return;
    const syntheticData = {
      title: 'Custom Raw Forensic Artifact',
      type: 'MANUAL_FORENSIC_INPUT',
      severity: 'HIGH',
      protocol: 'TCP',
      sourceIp: '198.51.100.44',
      destIp: '10.0.1.50',
      payload: customPayload
    };
    runAnalysis(syntheticData);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-950 border border-slate-700 rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden font-mono text-xs text-slate-100">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-900/90 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-cyan-950 border border-cyan-500 text-cyan-300">
              <Sparkles className="w-5 h-5 animate-pulse text-cyan-400" />
            </div>
            <div>
              <h2 className="font-bold text-sm text-slate-100 flex items-center gap-2">
                GEMINI 3.7 FLASH BLUE TEAM FORENSIC LAB
              </h2>
              <span className="text-[11px] text-slate-400">
                Automated Root Cause Triage, ATT&CK Attribution & YARA/Suricata Synthesizer
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

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Custom Artifact Input */}
          <form onSubmit={handleCustomAnalyze} className="bg-slate-900/60 border border-slate-800 rounded-lg p-3 space-y-2">
            <div className="flex items-center justify-between text-[11px]">
              <span className="font-bold text-slate-300">PASTE SUSPICIOUS ARTIFACT / PCAP PAYLOAD:</span>
              <span className="text-slate-500">Live Gemini Inference</span>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={customPayload}
                onChange={e => setCustomPayload(e.target.value)}
                placeholder="e.g. POST /v2/sync?id=7821 HTTP/1.1 Cookie: session=eyJ... or raw payload snippet"
                className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                disabled={loading || !customPayload.trim()}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-cyan-950 border border-cyan-600 text-cyan-200 hover:bg-cyan-900 disabled:opacity-50 font-bold"
              >
                <Send className="w-3.5 h-3.5" />
                <span>INSPECT</span>
              </button>
            </div>
          </form>

          {/* Loading Indicator */}
          {loading && (
            <div className="py-16 flex flex-col items-center justify-center space-y-3">
              <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
              <div className="text-cyan-300 font-bold">DEEP PACKET FORENSICS RUNNING...</div>
              <div className="text-[11px] text-slate-500">
                Correlating Shannon entropy, payload byte offsets, and MITRE matrix telemetry...
              </div>
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="p-4 rounded-lg bg-red-950/60 border border-red-700 text-red-300 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Success Deployed Feedback */}
          {deployedSuccess && (
            <div className="p-3 rounded-lg bg-emerald-950/80 border border-emerald-600 text-emerald-300 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>{deployedSuccess}</span>
            </div>
          )}

          {/* Analysis Results Display */}
          {!loading && analysisResult && (
            <div className="space-y-4">
              {/* Threat Score & Top Attribution Header */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] text-slate-500 uppercase block font-bold">Adversary Threat Score</span>
                    <span className="text-2xl font-bold text-red-400">{analysisResult.threatScore}/100</span>
                  </div>
                  <ShieldAlert className="w-8 h-8 text-red-500/50" />
                </div>

                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block font-bold">ATT&CK Technique & Tactic</span>
                  <span className="text-xs font-bold text-purple-300 block">{analysisResult.mitreTechnique}</span>
                  <span className="text-[10px] text-slate-400">{analysisResult.tactic}</span>
                </div>

                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block font-bold">Adversary Attribution</span>
                  <span className="text-xs font-bold text-cyan-300 block">{analysisResult.threatActorAttribution}</span>
                  <span className="text-[10px] text-slate-400">Heuristic signature match</span>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 space-y-1">
                <span className="text-[10px] text-cyan-400 uppercase font-bold tracking-wider block">
                  EXECUTIVE SOC SUMMARY
                </span>
                <p className="text-slate-200 text-xs leading-relaxed">
                  {analysisResult.executiveSummary}
                </p>
              </div>

              {/* Root Cause Analysis & Forensic Indicators */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 space-y-2">
                  <span className="text-[10px] text-amber-400 uppercase font-bold tracking-wider block">
                    ROOT CAUSE ANALYSIS
                  </span>
                  <p className="text-slate-300 text-[11px] leading-relaxed">
                    {analysisResult.rootCauseAnalysis}
                  </p>
                </div>

                <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 space-y-2">
                  <span className="text-[10px] text-emerald-400 uppercase font-bold tracking-wider block">
                    FORENSIC INDICATORS OF COMPROMISE
                  </span>
                  <ul className="space-y-1 text-[11px] text-slate-300 list-disc list-inside">
                    {analysisResult.forensicIndicators.map((ind, idx) => (
                      <li key={idx}>{ind}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Prioritized Containment Playbook */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-red-400 uppercase font-bold tracking-wider">
                    PRIORITIZED CONTAINMENT STEPS ({analysisResult.soarPlaybookRecommended})
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {analysisResult.containmentSteps.map((step, idx) => (
                    <div key={idx} className="bg-slate-950 p-2 rounded border border-slate-800 flex items-start gap-2">
                      <span className="w-4 h-4 rounded-full bg-red-950 border border-red-700 text-red-300 flex items-center justify-center text-[9px] font-bold flex-shrink-0 mt-0.5">
                        {idx + 1}
                      </span>
                      <span className="text-slate-200 text-[11px]">{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Generated Defense Rules (YARA, Suricata, iptables) */}
              <div className="space-y-3">
                <span className="text-[10px] text-slate-400 uppercase font-bold tracking-wider block">
                  SYNTHESIZED BLUE TEAM RULES
                </span>

                {/* 1. Suricata Rule */}
                <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-cyan-300 text-xs flex items-center gap-1.5">
                      <FileCode className="w-4 h-4 text-cyan-400" />
                      SURICATA IDS/IPS RULE
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => copyText('suricata', analysisResult.generatedRules.suricata)}
                        className="flex items-center gap-1 text-[10px] text-slate-300 hover:text-white px-2 py-1 rounded bg-slate-800"
                      >
                        {copiedType === 'suricata' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>Copy</span>
                      </button>
                      <button
                        onClick={() => {
                          soundEffects.playQuarantineSuccess();
                          onDeployGeneratedRule('SURICATA', analysisResult.generatedRules.suricata, 'AI Generated Suricata Rule');
                          setDeployedSuccess('Suricata rule actively deployed to inline sensor engine!');
                          setTimeout(() => setDeployedSuccess(null), 3000);
                        }}
                        className="px-2.5 py-1 rounded bg-cyan-950 border border-cyan-600 text-cyan-200 hover:bg-cyan-900 text-[10px] font-bold"
                      >
                        Deploy to Inline IDS
                      </button>
                    </div>
                  </div>
                  <pre className="bg-slate-950 p-2.5 rounded border border-slate-800 text-[11px] text-emerald-400 overflow-x-auto whitespace-pre font-mono">
                    {analysisResult.generatedRules.suricata}
                  </pre>
                </div>

                {/* 2. IPTables Command */}
                <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-amber-300 text-xs flex items-center gap-1.5">
                      <Terminal className="w-4 h-4 text-amber-400" />
                      IPTABLES FIREWALL DROP COMMANDS
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => copyText('iptables', analysisResult.generatedRules.iptables)}
                        className="flex items-center gap-1 text-[10px] text-slate-300 hover:text-white px-2 py-1 rounded bg-slate-800"
                      >
                        {copiedType === 'iptables' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>Copy</span>
                      </button>
                      <button
                        onClick={() => {
                          soundEffects.playBlockTick();
                          onDeployGeneratedRule('IPTABLES', analysisResult.generatedRules.iptables, 'AI Generated iptables Rule');
                          setDeployedSuccess('iptables drop rule successfully injected into active firewall table!');
                          setTimeout(() => setDeployedSuccess(null), 3000);
                        }}
                        className="px-2.5 py-1 rounded bg-red-950 border border-red-600 text-red-200 hover:bg-red-900 text-[10px] font-bold"
                      >
                        Execute Firewall Drop
                      </button>
                    </div>
                  </div>
                  <pre className="bg-slate-950 p-2.5 rounded border border-slate-800 text-[11px] text-amber-300 overflow-x-auto whitespace-pre font-mono">
                    {analysisResult.generatedRules.iptables}
                  </pre>
                </div>

                {/* 3. YARA Rule */}
                <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-purple-300 text-xs flex items-center gap-1.5">
                      <Lock className="w-4 h-4 text-purple-400" />
                      YARA MEMORY / PAYLOAD SIGNATURE
                    </span>
                    <button
                      onClick={() => copyText('yara', analysisResult.generatedRules.yara)}
                      className="flex items-center gap-1 text-[10px] text-slate-300 hover:text-white px-2 py-1 rounded bg-slate-800"
                    >
                      {copiedType === 'yara' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>Copy</span>
                    </button>
                  </div>
                  <pre className="bg-slate-950 p-2.5 rounded border border-slate-800 text-[11px] text-purple-300 overflow-x-auto whitespace-pre font-mono">
                    {analysisResult.generatedRules.yara}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
