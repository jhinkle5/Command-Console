import React from 'react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell,
  BarChart,
  Bar
} from 'recharts';
import { Activity, ShieldAlert, Wifi, HardDrive, Hash } from 'lucide-react';
import { Packet } from '../types';

interface TrafficChartsProps {
  packets: Packet[];
  bandwidthData: { time: string; mbps: number; pps: number; threatPps: number }[];
}

const PROTOCOL_COLORS: { [key: string]: string } = {
  HTTPS: '#06b6d4',
  TLS: '#3b82f6',
  DNS: '#a855f7',
  TCP: '#10b981',
  HTTP: '#f59e0b',
  SMB: '#ef4444',
  SSH: '#ec4899',
  KERBEROS: '#8b5cf6',
  ICMP: '#64748b',
  BGP: '#14b8a6'
};

export const TrafficCharts: React.FC<TrafficChartsProps> = ({ packets, bandwidthData }) => {
  // Protocol aggregation
  const protocolCounts = React.useMemo(() => {
    const map: { [key: string]: number } = {};
    packets.forEach(p => {
      map[p.protocol] = (map[p.protocol] || 0) + 1;
    });
    return Object.keys(map).map(proto => ({
      name: proto,
      value: map[proto],
      color: PROTOCOL_COLORS[proto] || '#64748b'
    })).sort((a, b) => b.value - a.value);
  }, [packets]);

  // Threat vs Clean stats
  const threatStats = React.useMemo(() => {
    let clean = 0;
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;

    packets.forEach(p => {
      if (!p.isThreat) {
        clean++;
      } else {
        if (p.threatSeverity === 'CRITICAL') critical++;
        else if (p.threatSeverity === 'HIGH') high++;
        else if (p.threatSeverity === 'MEDIUM') medium++;
        else low++;
      }
    });

    return [
      { name: 'Clean Traffic', value: clean, color: '#10b981' },
      { name: 'Critical Threats', value: critical, color: '#ef4444' },
      { name: 'High Threats', value: high, color: '#f97316' },
      { name: 'Medium Threats', value: medium, color: '#eab308' },
      { name: 'Low / Recon', value: low, color: '#3b82f6' }
    ].filter(item => item.value > 0);
  }, [packets]);

  // Average payload entropy calculation
  const avgEntropy = React.useMemo(() => {
    if (packets.length === 0) return 0;
    const sum = packets.reduce((acc, p) => acc + p.entropy, 0);
    return (sum / packets.length).toFixed(2);
  }, [packets]);

  const latestMbps = bandwidthData.length > 0 ? bandwidthData[bandwidthData.length - 1].mbps : 0;
  const latestPps = bandwidthData.length > 0 ? bandwidthData[bandwidthData.length - 1].pps : 0;
  const latestThreatPps = bandwidthData.length > 0 ? bandwidthData[bandwidthData.length - 1].threatPps : 0;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
      {/* 1. Real-time Bandwidth & Traffic Rate (Area Chart) */}
      <div className="md:col-span-2 bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-mono font-bold uppercase text-slate-200 tracking-wider">
              Network Bandwidth & Anomaly Ingress
            </h3>
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono">
            <span className="flex items-center gap-1 text-cyan-400">
              <span className="w-2 h-2 rounded-full bg-cyan-400 inline-block" />
              {latestMbps.toFixed(1)} Mbps ({latestPps} Pkt/s)
            </span>
            <span className="flex items-center gap-1 text-red-400">
              <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
              {latestThreatPps} Anomaly Pkt/s
            </span>
          </div>
        </div>

        <div className="h-32 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={bandwidthData} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
              <defs>
                <linearGradient id="colorMbps" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" stroke="#475569" fontSize={9} tickLine={false} />
              <YAxis stroke="#475569" fontSize={9} tickLine={false} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#020617', borderColor: '#334155', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' }}
              />
              <Area type="monotone" dataKey="mbps" stroke="#06b6d4" strokeWidth={1.5} fillOpacity={1} fill="url(#colorMbps)" name="Bandwidth (Mbps)" />
              <Area type="monotone" dataKey="threatPps" stroke="#ef4444" strokeWidth={1.5} fillOpacity={1} fill="url(#colorThreats)" name="Threat Pkt/s" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 2. Protocol Breakdown */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-1">
          <div className="flex items-center gap-2">
            <Wifi className="w-4 h-4 text-purple-400" />
            <h3 className="text-xs font-mono font-bold uppercase text-slate-200 tracking-wider">
              Protocol Distribution
            </h3>
          </div>
          <span className="text-[10px] font-mono text-slate-500">{packets.length} sampled</span>
        </div>

        <div className="flex items-center justify-between gap-2 h-32">
          <div className="w-28 h-28 relative">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protocolCounts}
                  cx="50%"
                  cy="50%"
                  innerRadius={28}
                  outerRadius={44}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {protocolCounts.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#020617', borderColor: '#334155', borderRadius: '6px', fontSize: '10px', fontFamily: 'monospace' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="flex-1 text-[10px] font-mono space-y-1 overflow-y-auto max-h-28 pr-1">
            {protocolCounts.slice(0, 5).map(p => (
              <div key={p.name} className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-slate-300">
                  <span className="w-2 h-2 rounded-sm inline-block" style={{ backgroundColor: p.color }} />
                  {p.name}
                </span>
                <span className="text-slate-400">{p.value} ({Math.round((p.value / packets.length) * 100 || 0)}%)</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 3. Deep Forensic Entropy & Threat Ratio */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3.5 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-1">
          <div className="flex items-center gap-2">
            <Hash className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-mono font-bold uppercase text-slate-200 tracking-wider">
              Entropy & Threat Ratio
            </h3>
          </div>
          <span className="text-[10px] font-mono text-emerald-400">DPI ACTIVE</span>
        </div>

        <div className="grid grid-cols-2 gap-2 my-auto">
          <div className="bg-slate-950/80 border border-slate-800/80 rounded p-2 text-center">
            <div className="text-[10px] font-mono text-slate-500 uppercase">Avg Shannon Entropy</div>
            <div className="text-lg font-mono font-bold text-cyan-300 mt-0.5">{avgEntropy}</div>
            <div className="text-[9px] font-mono text-slate-400">&gt;7.2 = Encrypted C2</div>
          </div>
          <div className="bg-slate-950/80 border border-slate-800/80 rounded p-2 text-center">
            <div className="text-[10px] font-mono text-slate-500 uppercase">Threat Packet Rate</div>
            <div className="text-lg font-mono font-bold text-red-400 mt-0.5">
              {Math.round((packets.filter(p => p.isThreat).length / (packets.length || 1)) * 100)}%
            </div>
            <div className="text-[9px] font-mono text-slate-400">Heuristic correlation</div>
          </div>
        </div>

        <div className="text-[10px] font-mono text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
          <span>Inspection Engine:</span>
          <span className="text-emerald-400 font-semibold">Suricata + eBPF XDP</span>
        </div>
      </div>
    </div>
  );
};
