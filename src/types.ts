export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'TLS' | 'HTTP' | 'HTTPS' | 'SSH' | 'SMB' | 'KERBEROS' | 'BGP';

export type ThreatCategory = 
  | 'C2_BEACONING'
  | 'SQL_INJECTION'
  | 'PORT_SCAN'
  | 'RANSOMWARE_LATERAL'
  | 'DNS_TUNNELING'
  | 'SSH_BRUTE_FORCE'
  | 'KERBEROASTING'
  | 'DATA_EXFILTRATION'
  | 'DDOS_SYN_FLOOD'
  | 'PRIVILEGE_ESCALATION';

export interface Packet {
  id: string;
  timestamp: string;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  protocol: Protocol;
  length: number; // in bytes
  ttl: number;
  flags: {
    syn?: boolean;
    ack?: boolean;
    fin?: boolean;
    rst?: boolean;
    psh?: boolean;
    urg?: boolean;
  };
  payloadPreview: string;
  rawHex: string;
  entropy: number;
  isThreat: boolean;
  threatType?: ThreatCategory;
  threatSeverity?: Severity;
  threatConfidence?: number; // 0-100%
  countryCode?: string;
  countryName?: string;
  asn?: string;
  blocked?: boolean;
}

export interface ThreatAlert {
  id: string;
  timestamp: string;
  title: string;
  type: ThreatCategory;
  severity: Severity;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  protocol: Protocol;
  packetCount: number;
  bandwidthBytes: number;
  mitreId: string;
  mitreTactic: string;
  status: 'ACTIVE' | 'CONTAINING' | 'CONTAINED' | 'DISMISSED';
  autoBlocked: boolean;
  confidenceScore: number;
  description: string;
  payload: string;
  rawHex?: string;
  suggestedAction: string;
  soarActionsTaken: string[];
  aiAnalysis?: AIAnalysisResult;
}

export interface AIAnalysisResult {
  threatScore: number;
  mitreTechnique: string;
  tactic: string;
  threatActorAttribution: string;
  executiveSummary: string;
  rootCauseAnalysis: string;
  forensicIndicators: string[];
  containmentSteps: string[];
  generatedRules: {
    yara: string;
    suricata: string;
    iptables: string;
  };
  soarPlaybookRecommended: string;
}

export interface NetworkNode {
  id: string;
  name: string;
  ip: string;
  type: 'FIREWALL' | 'WAF' | 'GATEWAY' | 'WEB_SERVER' | 'DATABASE' | 'DOMAIN_CONTROLLER' | 'WORKSTATION' | 'EXTERNAL_THREAT' | 'HONEYPOT';
  zone: 'EXTERNAL' | 'DMZ' | 'INTERNAL_SERVERS' | 'CORP_LAN' | 'DECEPTION_ZONE';
  status: 'HEALTHY' | 'WARNING' | 'COMPROMISED' | 'ISOLATED';
  activeConnections: number;
  cpuLoad: number;
  riskScore: number;
  x: number;
  y: number;
}

export interface FirewallRule {
  id: string;
  name: string;
  action: 'DROP' | 'REJECT' | 'ALLOW' | 'SINKHOLE';
  source: string;
  destination: string;
  protocol: string;
  port: string;
  createdTime: string;
  active: boolean;
  hitCount: number;
  generatedBy: 'AUTO_SOAR' | 'AI_ANALYST' | 'MANUAL' | 'DEFAULT_ACL';
}

export interface MitreTacticItem {
  id: string;
  name: string;
  tactic: string;
  description: string;
  detectionsCount: number;
  adversaries: string[];
  status: 'ACTIVE' | 'MONITORED' | 'BLOCKED';
}

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  origin: string;
  motivation: string;
  signatureTTPs: string[];
  recentCampaigns: string;
  confidence: 'HIGH' | 'CONFIRMED' | 'SUSPECTED';
  matchedAlertsCount: number;
}

export interface AttackScenario {
  id: string;
  name: string;
  description: string;
  adversary: string;
  category: ThreatCategory;
  packetRate: number; // pkts/sec
  stages: {
    phase: string;
    description: string;
    severity: Severity;
    durationSec: number;
  }[];
}
