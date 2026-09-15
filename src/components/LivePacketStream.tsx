import React, { useState, useMemo } from 'react';
import { 
  Search, 
  Filter, 
  ShieldAlert, 
  Eye, 
  Ban, 
  Cpu, 
  Sparkles, 
  ArrowRight, 
  Globe, 
  CheckCircle, 
  Layers, 
  SlidersHorizontal,
  X,
  Copy,
  Check
} from 'lucide-react';
import { Packet, Protocol } from '../types';
import { soundEffects } from '../utils/audio';

interface LivePacketStreamProps {
  packets: Packet[];
  onBlockIp: (ip: string, reason: string) => void;
  onAnalyzeWithAi: (packet: Packet) => void;
  selectedPacket: Packet | null;
  onSelectPacket: (packet: Packet | null) => void;
}

export const LivePacketStream: React.FC<LivePacketStreamProps> = ({
  packets,
  onBlockIp,
  onAnalyzeWithAi,
  selectedPacket,
  onSelectPacket
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [onlyThreats, setOnlyThreats] = useState(false);
  const [copiedHex, setCopiedHex] = useState(false);

  const filteredPackets = useMemo(() => {
    return packets.filter(pkt => {
      if (onlyThreats && !pkt.isThreat) return false;
      if (protocolFilter !== 'ALL' && pkt.protocol !== protocolFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          pkt.sourceIp.toLowerCase().includes(q) ||
          pkt.destIp.toLowerCase().includes(q) ||
          pkt.protocol.toLowerCase().includes(q) ||
          pkt.sourcePort.toString().includes(q) ||
          pkt.destPort.toString().includes(q) ||
          (pkt.threatType && pkt.threatType.toLowerCase().includes(q)) ||
          pkt.payloadPreview.toLowerCase().includes(q) ||
          (pkt.countryName && pkt.countryName.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [packets, searchQuery, protocolFilter, onlyThreats]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHex(true);
    setTimeout(() => setCopiedHex(false), 2000);
  };

  const getProtocolColor = (proto: Protocol) => {
    switch (proto) {
      case 'HTTPS': return 'bg-cyan-950 text-cyan-300 border-cyan-700/60';
      case 'TLS': return 'bg-blue-950 text-blue-300 border-blue-700/60';
      case 'DNS': return 'bg-purple-950 text-purple-300 border-purple-700/60';
      case 'TCP': return 'bg-emerald-950 text-emerald-300 border-emerald-700/60';
      case 'HTTP': return 'bg-amber-950 text-amber-300 border-amber-700/60';
      case 'SMB': return 'bg-red-950 text-red-300 border-red-700/60';
      case 'SSH': return 'bg-pink-950 text-pink-300 border-pink-700/60';
      case 'KERBEROS': return 'bg-violet-950 text-violet-300 border-violet-700/60';
      default: return 'bg-slate-900 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-lg flex flex-col h-[560px] overflow-hidden">
      {/* Header & Filter Controls */}
      <div className="p-3 border-b border-slate-800 bg-slate-950/70 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span className="font-bold uppercase tracking-wider text-slate-200">
            Real-Time Packet Stream & DPI Sniffer
          </span>
          <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 text-[10px]">
            {filteredPackets.length} / {packets.length} Packets Captured
          </span>
        </div>

        {/* Filter Toolbar */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              id="packet-search-input"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Filter IP, Port, Payload, ASN..."
              className="bg-slate-900 border border-slate-700 rounded-md pl-8 pr-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-44 sm:w-60"
            />
            {searchQuery && (
              <button 
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Protocol Dropdown */}
          <select
            id="protocol-filter-select"
            value={protocolFilter}
            onChange={e => setProtocolFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-md px-2 py-1 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Protocols</option>
            <option value="HTTPS">HTTPS (443)</option>
            <option value="TLS">TLS (8443)</option>
            <option value="DNS">DNS (53)</option>
            <option value="TCP">TCP Raw</option>
            <option value="HTTP">HTTP (80)</option>
            <option value="SMB">SMB (445)</option>
            <option value="SSH">SSH (22)</option>
            <option value="KERBEROS">Kerberos (88)</option>
          </select>

          {/* Threat Toggle */}
          <button
            id="toggle-threats-only"
            onClick={() => {
              soundEffects.playClick();
              setOnlyThreats(!onlyThreats);
            }}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-xs transition-colors ${
              onlyThreats
                ? 'bg-red-950 border-red-500 text-red-300'
                : 'bg-slate-900 border-slate-700 text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Threats Only</span>
          </button>
        </div>
      </div>

      {/* Main Content Area (Table + Detail Drawer) */}
      <div className="flex-1 flex overflow-hidden">
        {/* Packet Table */}
        <div className="flex-1 overflow-y-auto overflow-x-auto text-[11px] font-mono select-none">
          <table className="w-full text-left border-collapse">
            <thead className="sticky top-0 bg-slate-950 text-slate-400 border-b border-slate-800 z-10">
              <tr>
                <th className="py-2 px-3">TIMESTAMP</th>
                <th className="py-2 px-2">PROTO</th>
                <th className="py-2 px-3">SOURCE IP:PORT</th>
                <th className="py-2 px-2 text-center"></th>
                <th className="py-2 px-3">DESTINATION IP:PORT</th>
                <th className="py-2 px-2">FLAGS</th>
                <th className="py-2 px-2">LEN</th>
                <th className="py-2 px-2">ENTROPY</th>
                <th className="py-2 px-3">THREAT / STATUS</th>
                <th className="py-2 px-2 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-slate-500">
                    No packets match active sniffer filters.
                  </td>
                </tr>
              ) : (
                filteredPackets.map(pkt => {
                  const isSelected = selectedPacket?.id === pkt.id;
                  return (
                    <tr
                      key={pkt.id}
                      onClick={() => {
                        soundEffects.playClick();
                        onSelectPacket(pkt);
                      }}
                      className={`cursor-pointer transition-colors ${
                        pkt.blocked
                          ? 'bg-slate-950/90 opacity-60 line-through text-slate-600'
                          : pkt.isThreat
                          ? isSelected
                            ? 'bg-red-950/80 border-l-4 border-red-500'
                            : 'bg-red-950/30 hover:bg-red-950/50'
                          : isSelected
                          ? 'bg-cyan-950/50 border-l-4 border-cyan-500'
                          : 'hover:bg-slate-800/40'
                      }`}
                    >
                      <td className="py-1.5 px-3 whitespace-nowrap text-slate-400">
                        {pkt.timestamp.split('T')[1]?.substring(0, 8) || pkt.timestamp}
                      </td>
                      <td className="py-1.5 px-2 whitespace-nowrap">
                        <span className={`px-1.5 py-0.5 rounded border text-[10px] font-bold ${getProtocolColor(pkt.protocol)}`}>
                          {pkt.protocol}
                        </span>
                      </td>
                      <td className="py-1.5 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span className={pkt.isThreat ? 'text-red-300 font-semibold' : 'text-slate-200'}>
                            {pkt.sourceIp}
                          </span>
                          <span className="text-slate-500">:{pkt.sourcePort}</span>
                        </div>
                      </td>
                      <td className="py-1.5 px-2 text-slate-500 text-center">
                        <ArrowRight className="w-3 h-3 inline" />
                      </td>
                      <td className="py-1.5 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span className="text-slate-200">{pkt.destIp}</span>
                          <span className="text-slate-500">:{pkt.destPort}</span>
                        </div>
                      </td>
                      <td className="py-1.5 px-2 whitespace-nowrap text-[10px] text-slate-400">
                        {pkt.flags.syn && <span className="text-emerald-400 mr-1">[S]</span>}
                        {pkt.flags.ack && <span className="text-blue-400 mr-1">[A]</span>}
                        {pkt.flags.psh && <span className="text-purple-400 mr-1">[P]</span>}
                        {pkt.flags.fin && <span className="text-amber-400 mr-1">[F]</span>}
                        {pkt.flags.rst && <span className="text-red-400 mr-1">[R]</span>}
                      </td>
                      <td className="py-1.5 px-2 whitespace-nowrap text-slate-400">
                        {pkt.length} B
                      </td>
                      <td className="py-1.5 px-2 whitespace-nowrap">
                        <span className={`font-semibold ${pkt.entropy > 7.0 ? 'text-red-400' : pkt.entropy > 5.5 ? 'text-amber-400' : 'text-emerald-400'}`}>
                          {pkt.entropy}
                        </span>
                      </td>
                      <td className="py-1.5 px-3 whitespace-nowrap">
                        {pkt.blocked ? (
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 text-[10px]">
                            DROPPED / SINKHOLED
                          </span>
                        ) : pkt.isThreat ? (
                          <span className="flex items-center gap-1 text-red-400 font-bold text-[10px]">
                            <ShieldAlert className="w-3 h-3 text-red-500" />
                            {pkt.threatType} ({pkt.threatConfidence}%)
                          </span>
                        ) : (
                          <span className="text-emerald-500/80 text-[10px]">CLEAN / PASSED</span>
                        )}
                      </td>
                      <td className="py-1.5 px-2 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            soundEffects.playClick();
                            onSelectPacket(pkt);
                          }}
                          className="p-1 text-slate-400 hover:text-cyan-300 hover:bg-slate-800 rounded"
                          title="Deep Packet Inspection"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Selected Packet Deep Inspection Drawer */}
        {selectedPacket && (
          <div className="w-96 border-l border-slate-800 bg-slate-950 flex flex-col text-xs font-mono overflow-y-auto">
            <div className="p-3 border-b border-slate-800 bg-slate-900/80 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" />
                <span className="font-bold text-slate-200">DEEP PACKET INSPECTOR</span>
              </div>
              <button
                onClick={() => onSelectPacket(null)}
                className="text-slate-400 hover:text-slate-200 p-1 rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-3.5 space-y-4 flex-1">
              {/* Threat Alert Banner if threat */}
              {selectedPacket.isThreat && (
                <div className="p-3 rounded-md bg-red-950/70 border border-red-500/80 text-red-200 space-y-1">
                  <div className="flex items-center gap-1.5 font-bold text-red-300">
                    <ShieldAlert className="w-4 h-4 text-red-400" />
                    <span>ADVERSARIAL SIGNATURE DETECTED</span>
                  </div>
                  <div className="text-[11px] text-slate-300">
                    Type: <span className="font-semibold text-red-300">{selectedPacket.threatType}</span>
                  </div>
                  <div className="text-[11px] text-slate-300">
                    Severity: <span className="font-semibold text-red-400">{selectedPacket.threatSeverity}</span> | Confidence: {selectedPacket.threatConfidence}%
                  </div>
                </div>
              )}

              {/* Protocol Header Dissection */}
              <div>
                <h4 className="text-[10px] text-slate-400 uppercase tracking-wider font-bold mb-2">
                  Layer 3 / Layer 4 Header Telemetry
                </h4>
                <div className="bg-slate-900/90 rounded border border-slate-800 p-2.5 space-y-1.5 text-[11px]">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Packet ID:</span>
                    <span className="text-cyan-300 font-semibold">{selectedPacket.id}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Source:</span>
                    <span className="text-slate-200">{selectedPacket.sourceIp}:{selectedPacket.sourcePort}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Destination:</span>
                    <span className="text-slate-200">{selectedPacket.destIp}:{selectedPacket.destPort}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Protocol / TTL:</span>
                    <span className="text-slate-200">{selectedPacket.protocol} (TTL: {selectedPacket.ttl})</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Payload Size:</span>
                    <span className="text-slate-200">{selectedPacket.length} bytes</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Shannon Entropy:</span>
                    <span className={`font-bold ${selectedPacket.entropy > 7 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {selectedPacket.entropy} bits/byte
                    </span>
                  </div>
                  {selectedPacket.countryName && (
                    <div className="flex justify-between pt-1 border-t border-slate-800">
                      <span className="text-slate-400">GeoIP & ASN:</span>
                      <span className="text-slate-300 text-right">
                        {selectedPacket.countryName} ({selectedPacket.countryCode})<br />
                        <span className="text-[10px] text-slate-500">{selectedPacket.asn}</span>
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Raw Hex & ASCII Dump */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <h4 className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">
                    Payload Hex & ASCII Dissection
                  </h4>
                  <button
                    onClick={() => copyToClipboard(selectedPacket.rawHex)}
                    className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300"
                  >
                    {copiedHex ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedHex ? 'Copied' : 'Copy Hex'}</span>
                  </button>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded p-2 text-[10px] font-mono text-emerald-400 max-h-36 overflow-y-auto whitespace-pre leading-relaxed selection:bg-emerald-900">
                  {selectedPacket.rawHex}
                </div>
              </div>

              {/* ASCII Payload String */}
              <div>
                <h4 className="text-[10px] text-slate-400 uppercase tracking-wider font-bold mb-1">
                  Decoded ASCII Stream
                </h4>
                <div className="bg-slate-900 border border-slate-800 rounded p-2 text-[11px] text-slate-300 max-h-24 overflow-y-auto break-all font-mono">
                  {selectedPacket.payloadPreview}
                </div>
              </div>

              {/* Tactical Quick Actions */}
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <button
                  id="btn-ai-analyze-packet"
                  onClick={() => {
                    soundEffects.playClick();
                    onAnalyzeWithAi(selectedPacket);
                  }}
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded bg-cyan-950 border border-cyan-600/70 text-cyan-200 hover:bg-cyan-900/80 font-bold transition-all shadow-md shadow-cyan-950/50"
                >
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  <span>AI DEEP FORENSIC LAB</span>
                </button>

                <button
                  id="btn-nullroute-ip"
                  onClick={() => {
                    soundEffects.playBlockTick();
                    onBlockIp(selectedPacket.sourceIp, `Automated drop from DPI on ${selectedPacket.sourceIp}`);
                  }}
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded bg-red-950 border border-red-700 text-red-200 hover:bg-red-900 font-bold transition-colors"
                >
                  <Ban className="w-4 h-4 text-red-400" />
                  <span>NULL-ROUTE SOURCE IP ({selectedPacket.sourceIp})</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
