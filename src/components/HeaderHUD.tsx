import React from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Radio, 
  Volume2, 
  VolumeX, 
  Play, 
  Pause, 
  Zap, 
  Crosshair, 
  FileText, 
  Activity, 
  Lock,
  Flame
} from 'lucide-react';
import { soundEffects } from '../utils/audio';

interface HeaderHUDProps {
  threatLevel: 'NORMAL' | 'ELEVATED' | 'HIGH' | 'SEVERE' | 'CRITICAL';
  isStreaming: boolean;
  onToggleStream: () => void;
  streamRate: number; // packets per sec
  soundEnabled: boolean;
  onToggleSound: () => void;
  defenseScore: number;
  totalPacketsSeen: number;
  totalThreatsBlocked: number;
  activeIncidentsCount: number;
  onOpenSimulation: () => void;
  onOpenReport: () => void;
  onEmergencyLockdown: () => void;
  isLockdownActive: boolean;
  activeView: string;
  onSelectView: (view: string) => void;
}

export const HeaderHUD: React.FC<HeaderHUDProps> = ({
  threatLevel,
  isStreaming,
  onToggleStream,
  soundEnabled,
  onToggleSound,
  defenseScore,
  totalPacketsSeen,
  totalThreatsBlocked,
  activeIncidentsCount,
  onOpenSimulation,
  onOpenReport,
  onEmergencyLockdown,
  isLockdownActive,
  activeView,
  onSelectView
}) => {
  const getThreatBadge = () => {
    switch (threatLevel) {
      case 'CRITICAL':
        return {
          bg: 'bg-red-950/80 border-red-500/80 text-red-300 shadow-red-900/50',
          defcon: 'DEFCON 1',
          label: 'CRITICAL ATTACK ACTIVE',
          pulse: 'animate-pulse bg-red-500'
        };
      case 'SEVERE':
        return {
          bg: 'bg-orange-950/80 border-orange-500/80 text-orange-300 shadow-orange-900/50',
          defcon: 'DEFCON 2',
          label: 'SEVERE THREAT DETECTED',
          pulse: 'animate-pulse bg-orange-500'
        };
      case 'HIGH':
        return {
          bg: 'bg-amber-950/80 border-amber-500/80 text-amber-300 shadow-amber-900/50',
          defcon: 'DEFCON 3',
          label: 'ELEVATED ADVERSARY ACTIVITY',
          pulse: 'bg-amber-500'
        };
      case 'ELEVATED':
        return {
          bg: 'bg-blue-950/80 border-blue-500/80 text-blue-300 shadow-blue-900/50',
          defcon: 'DEFCON 4',
          label: 'ANOMALY SURGE',
          pulse: 'bg-blue-500'
        };
      default:
        return {
          bg: 'bg-emerald-950/80 border-emerald-500/80 text-emerald-300 shadow-emerald-900/50',
          defcon: 'DEFCON 5',
          label: 'SECURE / NORMAL PATROL',
          pulse: 'bg-emerald-500'
        };
    }
  };

  const badge = getThreatBadge();

  return (
    <header className="border-b border-slate-800 bg-slate-950/95 backdrop-blur-md sticky top-0 z-40 text-slate-100">
      {/* Top Ticker & Defcon Strip */}
      <div className="px-4 py-2 flex flex-wrap items-center justify-between gap-3 border-b border-slate-900 text-xs">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="relative flex items-center justify-center">
              <Shield className="w-6 h-6 text-cyan-400" />
              <Activity className="w-3 h-3 text-cyan-200 absolute" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-sm tracking-wider text-slate-100 uppercase">AEGIS-SOC</span>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950 border border-cyan-700/60 text-cyan-300">
                  BLUE TEAM CORE v4.8
                </span>
                <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-400">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping inline-block" />
                  REAL-TIME SENSORS ACTIVE
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* DEFCON & Threat Status */}
        <div className="flex items-center gap-2">
          <div className={`flex items-center gap-2 px-3 py-1 rounded-md border shadow-lg ${badge.bg}`}>
            <span className={`w-2.5 h-2.5 rounded-full ${badge.pulse}`} />
            <span className="font-mono font-bold tracking-wider">{badge.defcon}</span>
            <span className="text-slate-400">|</span>
            <span className="font-mono text-[11px] uppercase font-semibold">{badge.label}</span>
          </div>

          {/* Defense Score */}
          <div className="hidden sm:flex items-center gap-2 px-3 py-1 rounded-md border border-slate-800 bg-slate-900/90">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <div className="text-[11px] font-mono">
              <span className="text-slate-400">DEFENSE POSTURE:</span>{' '}
              <span className={`font-bold ${defenseScore > 80 ? 'text-emerald-400' : defenseScore > 60 ? 'text-amber-400' : 'text-red-400'}`}>
                {defenseScore}%
              </span>
            </div>
          </div>

          {/* Audio HUD Control */}
          <button
            id="btn-toggle-audio"
            onClick={() => {
              soundEffects.playClick();
              onToggleSound();
            }}
            title={soundEnabled ? 'Mute Tactical Audio HUD' : 'Enable Tactical Audio HUD'}
            className={`p-1.5 rounded border transition-colors ${
              soundEnabled
                ? 'border-cyan-700/60 bg-cyan-950/60 text-cyan-300 hover:bg-cyan-900/80'
                : 'border-slate-800 bg-slate-900 text-slate-500 hover:text-slate-300'
            }`}
          >
            {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Main HUD Controls & Stats Bar */}
      <div className="px-4 py-2.5 flex flex-wrap items-center justify-between gap-4">
        {/* Navigation Tabs */}
        <nav className="flex items-center gap-1 bg-slate-900/90 p-1 rounded-lg border border-slate-800">
          {[
            { id: 'traffic', label: 'Live Traffic & DPI', icon: Radio },
            { id: 'threats', label: 'Threat Detection & SOAR', icon: ShieldAlert, badge: activeIncidentsCount },
            { id: 'topology', label: 'Network Mesh & Nodes', icon: Activity },
            { id: 'mitre', label: 'MITRE ATT&CK & Intel', icon: Crosshair },
            { id: 'firewall', label: 'Firewall & ACL Engine', icon: Lock }
          ].map(tab => {
            const Icon = tab.icon;
            const isActive = activeView === tab.id;
            return (
              <button
                key={tab.id}
                id={`tab-nav-${tab.id}`}
                onClick={() => {
                  soundEffects.playClick();
                  onSelectView(tab.id);
                }}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-950 border border-cyan-600/70 text-cyan-200 shadow-sm shadow-cyan-900/40'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{tab.label}</span>
                {tab.badge !== undefined && tab.badge > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-red-600 text-white font-bold animate-pulse">
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Live Metrics Counters */}
        <div className="hidden lg:flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-slate-500">PACKETS INSPECTED:</span>
            <span className="text-cyan-300 font-bold">{totalPacketsSeen.toLocaleString()}</span>
          </div>
          <div className="w-px h-4 bg-slate-800" />
          <div className="flex items-center gap-2">
            <span className="text-slate-500">THREATS INTERCEPTED:</span>
            <span className="text-red-400 font-bold">{totalThreatsBlocked}</span>
          </div>
          <div className="w-px h-4 bg-slate-800" />
          <div className="flex items-center gap-2">
            <span className="text-slate-500">ACTIVE INCIDENTS:</span>
            <span className={`font-bold ${activeIncidentsCount > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
              {activeIncidentsCount}
            </span>
          </div>
        </div>

        {/* Action Triggers */}
        <div className="flex items-center gap-2">
          {/* Pause / Resume Live Sniffer */}
          <button
            id="btn-toggle-stream"
            onClick={() => {
              soundEffects.playClick();
              onToggleStream();
            }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium border transition-colors ${
              isStreaming
                ? 'border-emerald-700/60 bg-emerald-950/50 text-emerald-300 hover:bg-emerald-900/60'
                : 'border-amber-700/60 bg-amber-950/50 text-amber-300 hover:bg-amber-900/60'
            }`}
          >
            {isStreaming ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{isStreaming ? 'STREAMING' : 'PAUSED'}</span>
          </button>

          {/* Red Team Attack Simulation Drill */}
          <button
            id="btn-simulate-drill"
            onClick={() => {
              soundEffects.playClick();
              onOpenSimulation();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-medium border border-purple-700/60 bg-purple-950/50 text-purple-200 hover:bg-purple-900/60 transition-colors shadow-sm"
          >
            <Flame className="w-3.5 h-3.5 text-purple-400" />
            <span>RED DRILL SIM</span>
          </button>

          {/* Emergency Perimeter Lockdown */}
          <button
            id="btn-emergency-lockdown"
            onClick={() => {
              soundEffects.playClick();
              onEmergencyLockdown();
            }}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono font-bold border transition-all ${
              isLockdownActive
                ? 'border-red-500 bg-red-600 text-white animate-pulse shadow-lg shadow-red-900/80'
                : 'border-red-800/80 bg-red-950/60 text-red-300 hover:bg-red-900/70 hover:border-red-600'
            }`}
          >
            <Zap className="w-3.5 h-3.5 text-red-400" />
            <span>{isLockdownActive ? 'LOCKDOWN ACTIVE' : 'PERIMETER LOCKDOWN'}</span>
          </button>

          {/* Incident Shift Report */}
          <button
            id="btn-open-report"
            onClick={() => {
              soundEffects.playClick();
              onOpenReport();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-mono border border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800 transition-colors"
          >
            <FileText className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">SHIFT REPORT</span>
          </button>
        </div>
      </div>
    </header>
  );
};
