import React, { useState } from 'react';
import { 
  Server, 
  Shield, 
  ShieldAlert, 
  Laptop, 
  Database, 
  Lock, 
  Radio, 
  Activity, 
  Zap, 
  AlertTriangle,
  CheckCircle2,
  X,
  Layers
} from 'lucide-react';
import { NetworkNode } from '../types';
import { soundEffects } from '../utils/audio';

interface NetworkTopologyMapProps {
  nodes: NetworkNode[];
  onToggleNodeIsolation: (nodeId: string) => void;
}

export const NetworkTopologyMap: React.FC<NetworkTopologyMapProps> = ({
  nodes,
  onToggleNodeIsolation
}) => {
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'FIREWALL': return Shield;
      case 'WAF': return Lock;
      case 'WEB_SERVER': return Server;
      case 'DATABASE': return Database;
      case 'DOMAIN_CONTROLLER': return Layers;
      case 'WORKSTATION': return Laptop;
      case 'HONEYPOT': return Radio;
      default: return ShieldAlert;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'COMPROMISED':
        return {
          border: 'border-red-500',
          bg: 'bg-red-950/80',
          text: 'text-red-300',
          dot: 'bg-red-500 animate-ping'
        };
      case 'ISOLATED':
        return {
          border: 'border-amber-500',
          bg: 'bg-amber-950/80',
          text: 'text-amber-300',
          dot: 'bg-amber-500'
        };
      case 'WARNING':
        return {
          border: 'border-yellow-500',
          bg: 'bg-yellow-950/80',
          text: 'text-yellow-300',
          dot: 'bg-yellow-500 animate-pulse'
        };
      default:
        return {
          border: 'border-emerald-500/60',
          bg: 'bg-emerald-950/40',
          text: 'text-emerald-300',
          dot: 'bg-emerald-400'
        };
    }
  };

  // Pre-defined network link connections
  const connections = [
    { from: 'ext-c2-01', to: 'fw-perimeter', isAttack: true },
    { from: 'ext-c2-02', to: 'waf-edge', isAttack: true },
    { from: 'fw-perimeter', to: 'web-prod', isAttack: false },
    { from: 'waf-edge', to: 'web-prod', isAttack: false },
    { from: 'web-prod', to: 'db-vault', isAttack: false },
    { from: 'dc-corp', to: 'wks-fin', isAttack: false },
    { from: 'dc-corp', to: 'wks-eng', isAttack: false },
    { from: 'wks-fin', to: 'ext-c2-01', isAttack: true, label: 'C2 BEACON' },
    { from: 'wks-fin', to: 'db-vault', isAttack: true, label: 'LATERAL SMB' },
    { from: 'fw-perimeter', to: 'honeypot-ssh', isAttack: false, isDeception: true }
  ];

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4 h-[560px] flex flex-col text-xs font-mono relative overflow-hidden">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400" />
          <h3 className="font-bold uppercase text-slate-200 tracking-wider">
            Active Network Asset Topology & Compromise Mesh
          </h3>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-3 text-[11px] font-mono">
          <span className="flex items-center gap-1 text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" /> Healthy
          </span>
          <span className="flex items-center gap-1 text-red-400">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-ping inline-block" /> Compromised / C2 Active
          </span>
          <span className="flex items-center gap-1 text-amber-400">
            <span className="w-2 h-2 rounded-full bg-amber-500 inline-block" /> Host Isolated
          </span>
        </div>
      </div>

      {/* Network Visual Map Container */}
      <div className="flex-1 relative mt-3 bg-slate-950/90 rounded-lg border border-slate-800/80 overflow-hidden select-none">
        {/* SVG connection lines */}
        <svg className="w-full h-full absolute inset-0 pointer-events-none z-0">
          <defs>
            <linearGradient id="grad-attack" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#dc2626" stopOpacity="0.2" />
            </linearGradient>
            <linearGradient id="grad-clean" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.5" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.2" />
            </linearGradient>
          </defs>

          {connections.map((conn, idx) => {
            const src = nodes.find(n => n.id === conn.from);
            const dst = nodes.find(n => n.id === conn.to);
            if (!src || !dst) return null;

            return (
              <g key={idx}>
                <line
                  x1={`${(src.x / 900) * 100}%`}
                  y1={`${(src.y / 500) * 100}%`}
                  x2={`${(dst.x / 900) * 100}%`}
                  y2={`${(dst.y / 500) * 100}%`}
                  stroke={conn.isAttack ? 'url(#grad-attack)' : conn.isDeception ? '#a855f7' : 'url(#grad-clean)'}
                  strokeWidth={conn.isAttack ? 2.5 : 1.5}
                  strokeDasharray={conn.isAttack ? '5,5' : undefined}
                  className={conn.isAttack ? 'animate-pulse' : ''}
                />
              </g>
            );
          })}
        </svg>

        {/* Security Zone Labels Background */}
        <div className="absolute top-2 left-4 text-[10px] text-red-500/60 font-bold uppercase tracking-widest pointer-events-none">
          ZONE 0: EXTERNAL ADVERSARY
        </div>
        <div className="absolute top-2 left-[28%] text-[10px] text-cyan-500/60 font-bold uppercase tracking-widest pointer-events-none">
          ZONE 1: PERIMETER DMZ
        </div>
        <div className="absolute top-2 left-[56%] text-[10px] text-blue-500/60 font-bold uppercase tracking-widest pointer-events-none">
          ZONE 2: CORE SERVERS & VAULT
        </div>
        <div className="absolute top-2 left-[82%] text-[10px] text-emerald-500/60 font-bold uppercase tracking-widest pointer-events-none">
          ZONE 3: CORP WORKSTATIONS
        </div>

        {/* Node Cards */}
        {nodes.map(node => {
          const Icon = getNodeIcon(node.type);
          const style = getStatusColor(node.status);
          const isSelected = selectedNode?.id === node.id;

          const leftPercent = (node.x / 900) * 100;
          const topPercent = (node.y / 500) * 100;

          return (
            <div
              key={node.id}
              onClick={() => {
                soundEffects.playClick();
                setSelectedNode(node);
              }}
              style={{
                left: `${leftPercent}%`,
                top: `${topPercent}%`,
                transform: 'translate(-50%, -50%)'
              }}
              className={`absolute z-10 cursor-pointer p-2.5 rounded-lg border transition-all ${style.bg} ${style.border} ${
                isSelected ? 'scale-110 shadow-lg shadow-cyan-900/80 ring-2 ring-cyan-400' : 'hover:scale-105'
              }`}
            >
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Icon className={`w-5 h-5 ${style.text}`} />
                  <span className={`w-2 h-2 rounded-full absolute -top-1 -right-1 ${style.dot}`} />
                </div>
                <div>
                  <div className="font-bold text-[11px] text-slate-100 whitespace-nowrap">{node.name}</div>
                  <div className="text-[10px] text-slate-400 whitespace-nowrap">{node.ip}</div>
                </div>
              </div>
            </div>
          );
        })}

        {/* Selected Node Details Drawer Overlay */}
        {selectedNode && (
          <div className="absolute right-3 top-3 bottom-3 w-80 bg-slate-950/95 border border-slate-700 rounded-lg p-4 z-20 shadow-2xl overflow-y-auto">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800 mb-3">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                <span className="font-bold text-slate-200 text-sm">NODE INSPECTOR</span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-slate-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Host Name</span>
                <span className="text-slate-100 font-bold">{selectedNode.name}</span>
              </div>

              <div>
                <span className="text-[10px] text-slate-500 uppercase block">IP Address</span>
                <span className="text-cyan-300 font-mono font-semibold">{selectedNode.ip}</span>
              </div>

              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Security Zone / Role</span>
                <span className="text-slate-300">{selectedNode.zone} ({selectedNode.type})</span>
              </div>

              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Defense Status</span>
                <span className={`font-bold ${selectedNode.status === 'COMPROMISED' ? 'text-red-400' : selectedNode.status === 'ISOLATED' ? 'text-amber-400' : 'text-emerald-400'}`}>
                  {selectedNode.status}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 bg-slate-900 p-2.5 rounded border border-slate-800 text-center">
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block">Active Sockets</span>
                  <span className="text-slate-200 font-bold">{selectedNode.activeConnections}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 uppercase block">Host Risk Score</span>
                  <span className={`font-bold ${selectedNode.riskScore > 75 ? 'text-red-400' : selectedNode.riskScore > 40 ? 'text-amber-400' : 'text-emerald-400'}`}>
                    {selectedNode.riskScore}/100
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800 space-y-2">
                <button
                  onClick={() => {
                    soundEffects.playQuarantineSuccess();
                    onToggleNodeIsolation(selectedNode.id);
                  }}
                  className={`w-full py-2 px-3 rounded font-bold transition-colors ${
                    selectedNode.status === 'ISOLATED'
                      ? 'bg-emerald-950 border border-emerald-700 text-emerald-300 hover:bg-emerald-900'
                      : 'bg-red-950 border border-red-700 text-red-200 hover:bg-red-900'
                  }`}
                >
                  {selectedNode.status === 'ISOLATED' ? 'RESTORE NETWORK ACCESS' : 'TRIGGER HOST ISOLATION'}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
