import React, { useState } from 'react';
import { 
  Crosshair, 
  Users, 
  ShieldAlert, 
  ExternalLink, 
  Globe, 
  Sparkles, 
  Info,
  ChevronRight,
  X
} from 'lucide-react';
import { MITRE_TACTIC_GROUPS, INITIAL_THREAT_ACTORS } from '../utils/packetGenerator';
import { ThreatActor } from '../types';
import { soundEffects } from '../utils/audio';

export const MitreMatrixView: React.FC = () => {
  const [selectedTechnique, setSelectedTechnique] = useState<{
    id: string;
    name: string;
    count: number;
    tactic: string;
    severity: string;
  } | null>(null);

  const [selectedActor, setSelectedActor] = useState<ThreatActor | null>(INITIAL_THREAT_ACTORS[0]);

  return (
    <div className="space-y-4 text-xs font-mono">
      {/* 1. MITRE ATT&CK Enterprise Matrix */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
          <div className="flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-cyan-400" />
            <h3 className="font-bold uppercase text-slate-200 tracking-wider">
              MITRE ATT&CK Active Detection Matrix (v14.1)
            </h3>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            Coverage: <span className="text-cyan-300 font-bold">10 Tactics / 24 Active Techniques</span>
          </span>
        </div>

        {/* Tactical Matrix Columns */}
        <div className="grid grid-cols-2 sm:grid-cols-5 lg:grid-cols-10 gap-2 overflow-x-auto pb-2">
          {MITRE_TACTIC_GROUPS.map(group => (
            <div key={group.tactic} className="bg-slate-950/80 rounded border border-slate-800/80 p-2 flex flex-col">
              <div className="text-[10px] font-bold text-slate-300 uppercase tracking-tight pb-1.5 mb-2 border-b border-slate-800 text-center truncate" title={group.tactic}>
                {group.tactic}
              </div>

              <div className="space-y-1.5 flex-1">
                {group.techniques.map(tech => {
                  const isSelected = selectedTechnique?.id === tech.id;
                  return (
                    <div
                      key={tech.id}
                      onClick={() => {
                        soundEffects.playClick();
                        setSelectedTechnique({
                          ...tech,
                          tactic: group.tactic
                        });
                      }}
                      className={`p-1.5 rounded cursor-pointer border text-[10px] transition-all ${
                        isSelected
                          ? 'bg-cyan-950 border-cyan-400 text-cyan-200'
                          : tech.severity === 'CRITICAL'
                          ? 'bg-red-950/40 border-red-800/60 text-red-300 hover:bg-red-950'
                          : tech.severity === 'HIGH'
                          ? 'bg-orange-950/40 border-orange-800/60 text-orange-300 hover:bg-orange-950'
                          : 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
                      }`}
                    >
                      <div className="font-bold flex justify-between items-center">
                        <span>{tech.id}</span>
                        <span className="px-1 rounded bg-slate-950 text-slate-400 text-[9px]">
                          {tech.count}
                        </span>
                      </div>
                      <div className="truncate text-slate-400 text-[9px] mt-0.5" title={tech.name}>
                        {tech.name}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Selected Technique Inspector Drawer */}
        {selectedTechnique && (
          <div className="mt-3 p-3 bg-slate-950 border border-cyan-800/60 rounded-lg flex items-start justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-cyan-400 font-bold text-sm">
                  {selectedTechnique.id} - {selectedTechnique.name}
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                  Tactic: {selectedTechnique.tactic}
                </span>
                <span className="text-red-400 font-bold text-[10px]">
                  Severity: {selectedTechnique.severity}
                </span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Active blue team sensor correlations: {selectedTechnique.count} occurrences detected during current monitoring shift.
                Automated defensive recommendations: Review process injection API calls, verify Kerberos service ticket renewal jitter, and inspect outbound TLS SNI headers.
              </p>
            </div>
            <button
              onClick={() => setSelectedTechnique(null)}
              className="text-slate-400 hover:text-slate-200 p-1"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>

      {/* 2. Threat Actor Intelligence & Attribution Hub */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Threat Actor Selector (4 cols) */}
        <div className="lg:col-span-4 bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 flex flex-col">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800 mb-2">
            <Users className="w-4 h-4 text-purple-400" />
            <h3 className="font-bold uppercase text-slate-200 tracking-wider">
              Tracked Threat Adversaries
            </h3>
          </div>

          <div className="space-y-2 flex-1 overflow-y-auto">
            {INITIAL_THREAT_ACTORS.map(actor => {
              const isSelected = selectedActor?.id === actor.id;
              return (
                <div
                  key={actor.id}
                  onClick={() => {
                    soundEffects.playClick();
                    setSelectedActor(actor);
                  }}
                  className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-purple-950/70 border-purple-500 shadow-md shadow-purple-950/60'
                      : 'bg-slate-950/60 border-slate-800 hover:bg-slate-950'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-slate-100 text-xs">{actor.name}</span>
                    <span className="px-1.5 py-0.5 rounded text-[9px] bg-red-950 border border-red-800 text-red-300 font-bold">
                      {actor.matchedAlertsCount} MATCHES
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-400 truncate">
                    Origin: {actor.origin}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Adversary Detailed Intelligence Dossier (8 cols) */}
        <div className="lg:col-span-8 bg-slate-900/90 border border-slate-800 rounded-lg p-4">
          {selectedActor ? (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-800">
                <div>
                  <h3 className="text-base font-bold text-slate-100">{selectedActor.name}</h3>
                  <div className="text-[11px] text-slate-400">
                    Known Aliases: <span className="text-purple-300">{selectedActor.aliases.join(', ')}</span>
                  </div>
                </div>
                <div className="px-2.5 py-1 rounded bg-purple-950 border border-purple-700 text-purple-200 text-xs font-bold">
                  Attribution Confidence: {selectedActor.confidence}
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase font-bold">State Origin / Nexus</span>
                  <span className="text-slate-200 font-semibold">{selectedActor.origin}</span>
                </div>
                <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                  <span className="text-slate-500 block text-[10px] uppercase font-bold">Primary Motivation</span>
                  <span className="text-slate-200 font-semibold">{selectedActor.motivation}</span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 block text-[10px] uppercase font-bold mb-1">
                  Signature Tactics, Techniques & Procedures (TTPs)
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {selectedActor.signatureTTPs.map((ttp, idx) => (
                    <span key={idx} className="px-2 py-1 rounded bg-slate-950 border border-cyan-800 text-cyan-300 text-[10px]">
                      {ttp}
                    </span>
                  ))}
                </div>
              </div>

              <div className="bg-slate-950 p-3 rounded border border-slate-800 text-slate-300 leading-relaxed text-[11px]">
                <span className="text-slate-400 block text-[10px] uppercase font-bold mb-1">
                  Recent Observed Campaign Activity
                </span>
                {selectedActor.recentCampaigns}
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center text-slate-500">
              Select a threat actor to view full cyber threat intelligence profile.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
