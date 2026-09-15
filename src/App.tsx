import React, { useState, useEffect, useRef, useCallback } from 'react';
import { 
  Packet, 
  ThreatAlert, 
  NetworkNode, 
  FirewallRule, 
  ThreatCategory 
} from './types';
import { 
  generateRandomPacket, 
  INITIAL_NETWORK_NODES, 
  INITIAL_FIREWALL_RULES 
} from './utils/packetGenerator';
import { soundEffects } from './utils/audio';
import { HeaderHUD } from './components/HeaderHUD';
import { TrafficCharts } from './components/TrafficCharts';
import { LivePacketStream } from './components/LivePacketStream';
import { ThreatDetectionCenter } from './components/ThreatDetectionCenter';
import { NetworkTopologyMap } from './components/NetworkTopologyMap';
import { MitreMatrixView } from './components/MitreMatrixView';
import { FirewallRuleManager } from './components/FirewallRuleManager';
import { AIForensicsLab } from './components/AIForensicsLab';
import { AttackSimulationModal } from './components/AttackSimulationModal';
import { IncidentReportModal } from './components/IncidentReportModal';

export default function App() {
  // Navigation View: 'traffic' | 'threats' | 'topology' | 'mitre' | 'firewall'
  const [activeView, setActiveView] = useState<string>('traffic');

  // Telemetry state
  const [packets, setPackets] = useState<Packet[]>([]);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [bandwidthHistory, setBandwidthHistory] = useState<{ time: string; mbps: number; pps: number; threatPps: number }[]>([]);
  const [nodes, setNodes] = useState<NetworkNode[]>(INITIAL_NETWORK_NODES);
  const [firewallRules, setFirewallRules] = useState<FirewallRule[]>(INITIAL_FIREWALL_RULES);

  // Streaming controls
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);
  const [isLockdownActive, setIsLockdownActive] = useState<boolean>(false);
  const [totalPacketsCount, setTotalPacketsCount] = useState<number>(1420);
  const [totalThreatsBlocked, setTotalThreatsBlocked] = useState<number>(87);

  // Modals & Selected items
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [aiLabTarget, setAiLabTarget] = useState<ThreatAlert | Packet | null>(null);
  const [showSimulationModal, setShowSimulationModal] = useState<boolean>(false);
  const [showReportModal, setShowReportModal] = useState<boolean>(false);

  // Check if an IP is currently blocked by active firewall rules or lockdown
  const isIpBlocked = useCallback((ip: string): boolean => {
    if (isLockdownActive) {
      // In lockdown, block all external non-DMZ traffic
      if (ip.startsWith('185.') || ip.startsWith('45.') || ip.startsWith('194.') || ip.startsWith('103.')) {
        return true;
      }
    }
    return firewallRules.some(r => r.active && (r.action === 'DROP' || r.action === 'SINKHOLE' || r.action === 'REJECT') && (r.source === ip || r.source === '0.0.0.0/0'));
  }, [firewallRules, isLockdownActive]);

  // Initial seed of packets & sample alerts on first render
  useEffect(() => {
    const seedPackets: Packet[] = [];
    const seedAlerts: ThreatAlert[] = [];

    for (let i = 0; i < 40; i++) {
      const { packet, alert } = generateRandomPacket(undefined, isIpBlocked);
      seedPackets.unshift(packet);
      if (alert) {
        seedAlerts.unshift(alert);
      }
    }

    setPackets(seedPackets);
    setAlerts(seedAlerts.slice(0, 5));

    // Seed initial bandwidth graph points
    const now = new Date();
    const initialBw = [];
    for (let j = 10; j >= 0; j--) {
      const d = new Date(now.getTime() - j * 2000);
      initialBw.push({
        time: d.toTimeString().substring(0, 8),
        mbps: Number((Math.random() * 8 + 12).toFixed(1)),
        pps: Math.floor(Math.random() * 200 + 400),
        threatPps: Math.floor(Math.random() * 8 + 2)
      });
    }
    setBandwidthHistory(initialBw);
  }, []);

  // Main real-time telemetry ingestion ticker
  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      const { packet, alert } = generateRandomPacket(undefined, isIpBlocked);

      setTotalPacketsCount(prev => prev + 1);

      setPackets(prev => {
        const next = [packet, ...prev];
        return next.slice(0, 80); // keep last 80 in memory
      });

      if (alert) {
        if (alert.severity === 'CRITICAL' || alert.severity === 'HIGH') {
          soundEffects.playThreatAlarm(alert.severity);
        }
        setAlerts(prev => [alert, ...prev].slice(0, 20));
      }

      // Update node states dynamically based on packet source/dest
      if (packet.isThreat && !packet.blocked) {
        setNodes(prev => prev.map(node => {
          if (node.ip === packet.sourceIp || node.ip === packet.destIp) {
            return {
              ...node,
              activeConnections: node.activeConnections + 1,
              riskScore: Math.min(100, node.riskScore + 3),
              status: node.status === 'ISOLATED' ? 'ISOLATED' : 'COMPROMISED'
            };
          }
          return node;
        }));
      }

      // Update bandwidth graph once every 2 seconds
      const nowStr = new Date().toTimeString().substring(0, 8);
      setBandwidthHistory(prev => {
        const currentMbps = Number((Math.random() * 12 + 14 + (packet.isThreat ? 8 : 0)).toFixed(1));
        const currentPps = Math.floor(Math.random() * 150 + 500);
        const currentThreatPps = packet.isThreat ? Math.floor(Math.random() * 12 + 5) : Math.floor(Math.random() * 3);

        const next = [...prev, {
          time: nowStr,
          mbps: currentMbps,
          pps: currentPps,
          threatPps: currentThreatPps
        }];
        return next.slice(-15);
      });
    }, 900); // approx ~1.1 packets/sec

    return () => clearInterval(interval);
  }, [isStreaming, isIpBlocked]);

  // Execute SOAR Automated Mitigation
  const handleExecuteSoarAction = (alertId: string, actionType: string) => {
    setAlerts(prev => prev.map(alt => {
      if (alt.id === alertId) {
        const actionLabel = 
          actionType === 'ISOLATE_HOST' ? `Isolated host ${alt.sourceIp}` :
          actionType === 'NULL_ROUTE_IP' ? `Injected border null-route for ${alt.sourceIp}` :
          actionType === 'KILL_SOCKET' ? `Flushed TCP state for socket ${alt.sourceIp}:${alt.sourcePort}` :
          `Diverted ${alt.sourceIp} to honeynet decoy sinkhole`;

        return {
          ...alt,
          status: 'CONTAINED',
          soarActionsTaken: [...(alt.soarActionsTaken || []), actionLabel]
        };
      }
      return alt;
    }));

    const targetAlert = alerts.find(a => a.id === alertId);
    if (!targetAlert) return;

    if (actionType === 'NULL_ROUTE_IP') {
      // Add a firewall drop rule automatically
      const newRule: FirewallRule = {
        id: 'auto-drop-' + Math.random().toString(36).substring(2, 7),
        name: `AUTO-SOAR: Drop ${targetAlert.sourceIp}`,
        action: 'DROP',
        source: targetAlert.sourceIp,
        destination: '0.0.0.0/0',
        protocol: targetAlert.protocol,
        port: 'ANY',
        createdTime: new Date().toLocaleTimeString(),
        active: true,
        hitCount: 1,
        generatedBy: 'AUTO_SOAR'
      };
      setFirewallRules(prev => [newRule, ...prev]);
      setTotalThreatsBlocked(prev => prev + 1);
    } else if (actionType === 'ISOLATE_HOST') {
      // Isolate corresponding network node
      setNodes(prev => prev.map(node => {
        if (node.ip === targetAlert.sourceIp) {
          return { ...node, status: 'ISOLATED', riskScore: 15 };
        }
        return node;
      }));
      setTotalThreatsBlocked(prev => prev + 1);
    } else if (actionType === 'DIVERT_HONEYNET') {
      const sinkholeRule: FirewallRule = {
        id: 'auto-sinkhole-' + Math.random().toString(36).substring(2, 7),
        name: `AUTO-SOAR: Honeynet Diversion for ${targetAlert.sourceIp}`,
        action: 'SINKHOLE',
        source: targetAlert.sourceIp,
        destination: '10.0.3.5',
        protocol: 'ANY',
        port: 'ANY',
        createdTime: new Date().toLocaleTimeString(),
        active: true,
        hitCount: 4,
        generatedBy: 'AUTO_SOAR'
      };
      setFirewallRules(prev => [sinkholeRule, ...prev]);
      setTotalThreatsBlocked(prev => prev + 1);
    }
  };

  // Block an IP from DPI
  const handleBlockIp = (ip: string, reason: string) => {
    const newRule: FirewallRule = {
      id: 'dpi-drop-' + Math.random().toString(36).substring(2, 7),
      name: `DPI-BLOCK: ${ip}`,
      action: 'DROP',
      source: ip,
      destination: '0.0.0.0/0',
      protocol: 'ANY',
      port: 'ANY',
      createdTime: new Date().toLocaleTimeString(),
      active: true,
      hitCount: 1,
      generatedBy: 'MANUAL'
    };
    setFirewallRules(prev => [newRule, ...prev]);
    setTotalThreatsBlocked(prev => prev + 1);
  };

  // Toggle Emergency Perimeter Lockdown
  const handleEmergencyLockdown = () => {
    setIsLockdownActive(prev => {
      const next = !prev;
      if (next) {
        soundEffects.playThreatAlarm('CRITICAL');
      } else {
        soundEffects.playQuarantineSuccess();
      }
      return next;
    });
  };

  // Launch Red Team Simulation Drill
  const handleLaunchAttack = (category: ThreatCategory, name: string) => {
    // Generate immediate burst of 5-8 attack packets
    for (let i = 0; i < 6; i++) {
      setTimeout(() => {
        const { packet, alert } = generateRandomPacket(category, isIpBlocked);
        setPackets(prev => [packet, ...prev].slice(0, 80));
        if (alert) {
          setAlerts(prev => [alert, ...prev].slice(0, 20));
        }
      }, i * 250);
    }
  };

  // Deploy AI synthesized rules
  const handleDeployGeneratedRule = (ruleType: 'SURICATA' | 'IPTABLES', ruleContent: string, name: string) => {
    const newRule: FirewallRule = {
      id: 'ai-rule-' + Math.random().toString(36).substring(2, 7),
      name: `AI-DEPLOYED: ${name}`,
      action: 'DROP',
      source: '185.220.101.0/24',
      destination: '0.0.0.0/0',
      protocol: 'TCP',
      port: '443, 8080',
      createdTime: new Date().toLocaleTimeString(),
      active: true,
      hitCount: 0,
      generatedBy: 'AI_ANALYST'
    };
    setFirewallRules(prev => [newRule, ...prev]);
  };

  // Calculate dynamic Threat Level & Defense Posture
  const activeCriticals = alerts.filter(a => a.status === 'ACTIVE' && a.severity === 'CRITICAL').length;
  const activeHighs = alerts.filter(a => a.status === 'ACTIVE' && a.severity === 'HIGH').length;
  const activeTotal = alerts.filter(a => a.status === 'ACTIVE').length;

  const threatLevel: 'NORMAL' | 'ELEVATED' | 'HIGH' | 'SEVERE' | 'CRITICAL' =
    isLockdownActive || activeCriticals >= 2
      ? 'CRITICAL'
      : activeCriticals === 1 || activeHighs >= 2
      ? 'SEVERE'
      : activeHighs === 1 || activeTotal >= 3
      ? 'HIGH'
      : activeTotal > 0
      ? 'ELEVATED'
      : 'NORMAL';

  const defenseScore = Math.max(
    30,
    Math.min(99, 95 - activeCriticals * 15 - activeHighs * 8 + (isLockdownActive ? 10 : 0))
  );

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-mono flex flex-col selection:bg-cyan-900 selection:text-cyan-100">
      {/* Top Tactical Command HUD Header */}
      <HeaderHUD
        threatLevel={threatLevel}
        isStreaming={isStreaming}
        onToggleStream={() => setIsStreaming(!isStreaming)}
        streamRate={1.1}
        soundEnabled={soundEnabled}
        onToggleSound={() => {
          const next = !soundEnabled;
          soundEffects.enabled = next;
          setSoundEnabled(next);
        }}
        defenseScore={defenseScore}
        totalPacketsSeen={totalPacketsCount}
        totalThreatsBlocked={totalThreatsBlocked}
        activeIncidentsCount={activeTotal}
        onOpenSimulation={() => setShowSimulationModal(true)}
        onOpenReport={() => setShowReportModal(true)}
        onEmergencyLockdown={handleEmergencyLockdown}
        isLockdownActive={isLockdownActive}
        activeView={activeView}
        onSelectView={setActiveView}
      />

      {/* Main Console Canvas */}
      <main className="flex-1 p-3 sm:p-4 max-w-[1600px] w-full mx-auto space-y-3">
        {/* Real-time Telemetry Metrics Bar & Bandwidth Recharts */}
        <TrafficCharts packets={packets} bandwidthData={bandwidthHistory} />

        {/* View Routing */}
        {activeView === 'traffic' && (
          <LivePacketStream
            packets={packets}
            onBlockIp={handleBlockIp}
            onAnalyzeWithAi={pkt => setAiLabTarget(pkt)}
            selectedPacket={selectedPacket}
            onSelectPacket={setSelectedPacket}
          />
        )}

        {activeView === 'threats' && (
          <ThreatDetectionCenter
            alerts={alerts}
            onExecuteSoarAction={handleExecuteSoarAction}
            onAnalyzeAlertAi={alt => setAiLabTarget(alt)}
            onDismissAlert={id => {
              setAlerts(prev => prev.filter(a => a.id !== id));
            }}
          />
        )}

        {activeView === 'topology' && (
          <NetworkTopologyMap
            nodes={nodes}
            onToggleNodeIsolation={nodeId => {
              setNodes(prev => prev.map(n => {
                if (n.id === nodeId) {
                  return { ...n, status: n.status === 'ISOLATED' ? 'HEALTHY' : 'ISOLATED' };
                }
                return n;
              }));
            }}
          />
        )}

        {activeView === 'mitre' && (
          <MitreMatrixView />
        )}

        {activeView === 'firewall' && (
          <FirewallRuleManager
            rules={firewallRules}
            onAddRule={rule => {
              const newR: FirewallRule = {
                ...rule,
                id: 'custom-' + Math.random().toString(36).substring(2, 7),
                createdTime: new Date().toLocaleTimeString(),
                hitCount: 0
              };
              setFirewallRules(prev => [newR, ...prev]);
            }}
            onToggleRule={id => {
              setFirewallRules(prev => prev.map(r => r.id === id ? { ...r, active: !r.active } : r));
            }}
            onDeleteRule={id => {
              setFirewallRules(prev => prev.filter(r => r.id !== id));
            }}
          />
        )}
      </main>

      {/* AI Deep Forensics Lab Modal */}
      {aiLabTarget && (
        <AIForensicsLab
          threatData={aiLabTarget}
          onClose={() => setAiLabTarget(null)}
          onDeployGeneratedRule={handleDeployGeneratedRule}
        />
      )}

      {/* Red Team Attack Drill Launcher Modal */}
      {showSimulationModal && (
        <AttackSimulationModal
          onClose={() => setShowSimulationModal(false)}
          onLaunchAttack={handleLaunchAttack}
        />
      )}

      {/* Incident Shift Handover Report Modal */}
      {showReportModal && (
        <IncidentReportModal
          alerts={alerts}
          packets={packets}
          rules={firewallRules}
          defenseScore={defenseScore}
          onClose={() => setShowReportModal(false)}
        />
      )}
    </div>
  );
}
