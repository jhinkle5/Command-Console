import { Packet, ThreatCategory, ThreatAlert, NetworkNode, Severity, Protocol } from '../types';

// Helper for Shannon Entropy
export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const map: { [key: string]: number } = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    map[char] = (map[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in map) {
    const p = map[char] / str.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

// Convert string to realistic hex dump
export function toHexDump(str: string): string {
  let hex = '';
  for (let i = 0; i < Math.min(str.length, 64); i++) {
    const byte = str.charCodeAt(i).toString(16).padStart(2, '0').toUpperCase();
    hex += byte + (i % 2 === 1 ? ' ' : '');
    if ((i + 1) % 16 === 0) hex += '\n';
  }
  return hex.trim();
}

const COMMON_COUNTRIES = [
  { code: 'US', name: 'United States', asn: 'AS15169 Google LLC' },
  { code: 'DE', name: 'Germany', asn: 'AS24940 Hetzner Online' },
  { code: 'RU', name: 'Russian Federation', asn: 'AS12389 Rostelecom' },
  { code: 'CN', name: 'China', asn: 'AS4134 CHINANET' },
  { code: 'NL', name: 'Netherlands', asn: 'AS1103 SURF B.V.' },
  { code: 'UA', name: 'Ukraine', asn: 'AS15895 Kyivstar' },
  { code: 'BR', name: 'Brazil', asn: 'AS28573 Claro S.A.' },
  { code: 'IR', name: 'Iran', asn: 'AS58224 TIC' },
  { code: 'KP', name: 'North Korea', asn: 'AS131279 Star JV' },
  { code: 'GB', name: 'United Kingdom', asn: 'AS2856 British Telecommunications' }
];

const INTERNAL_IPS = [
  { ip: '10.0.1.10', name: 'DC-PRIMARY-01 (Domain Controller)' },
  { ip: '10.0.1.25', name: 'APP-PROD-CLUSTER-01' },
  { ip: '10.0.1.50', name: 'DB-SQL-CORE (Vault Data)' },
  { ip: '10.0.2.14', name: 'WKS-FINANCE-04' },
  { ip: '10.0.2.88', name: 'WKS-ENG-LEAD' },
  { ip: '10.0.2.102', name: 'WKS-EXEC-CFO' },
  { ip: '10.0.3.5', name: 'HONEYPOT-DECOY-SSH' },
  { ip: '172.16.4.1', name: 'DMZ-INGRESS-GATEWAY' },
  { ip: '172.16.4.20', name: 'DMZ-K8S-INGRESS' }
];

const EXTERNAL_BENIGN_IPS = [
  '142.250.190.46',
  '104.16.249.249',
  '151.101.65.140',
  '13.107.42.16',
  '185.199.108.153',
  '1.1.1.1',
  '8.8.8.8'
];

const ADVERSARY_C2_IPS = [
  '185.220.101.4',
  '45.142.214.88',
  '194.26.29.112',
  '103.151.125.10',
  '91.240.118.17',
  '178.62.204.91'
];

const BENIGN_PAYLOAD_TEMPLATES = [
  'GET /api/v2/telemetry/heartbeat HTTP/1.1\\r\\nHost: api.cloud.internal\\r\\nAuthorization: Bearer token_9821\\r\\n',
  'POST /graphql HTTP/2\\r\\ncontent-type: application/json\\r\\n{"query":"query GetMetrics { systemLoad memory }"}\\r\\n',
  'TLSv1.3 Client Hello (SNI: auth.enterprise.internal, Cipher: TLS_AES_256_GCM_SHA384)',
  'DNS Standard query 0x3f4a A secure-vault.corp.internal',
  'SMB2 Tree Connect Request Tree: \\\\DC-PRIMARY-01\\SYSVOL User: CORP\\svc_backup',
  'SSH-2.0-OpenSSH_9.3p1 Debian-1ubuntu3.2 Client: Key exchange init'
];

export const ATTACK_TEMPLATES: {
  type: ThreatCategory;
  title: string;
  severity: Severity;
  mitreId: string;
  mitreTactic: string;
  destPort: number;
  protocol: Protocol;
  description: string;
  suggestedAction: string;
  payloadGenerator: (src: string, dst: string) => string;
}[] = [
  {
    type: 'C2_BEACONING',
    title: 'Cobalt Strike Malleable C2 Beacon Heartbeat',
    severity: 'CRITICAL',
    mitreId: 'T1071.001',
    mitreTactic: 'Command and Control',
    destPort: 443,
    protocol: 'HTTPS',
    description: 'Periodic low-jitter HTTP POST beacon with high-entropy base64 cookie payload matching known Cobalt Strike malleable C2 profile.',
    suggestedAction: 'Isolate compromised source endpoint & inject firewall null-route on C2 IP.',
    payloadGenerator: (src, dst) => `POST /updates/v1/sync?id=8491 HTTP/1.1\r\nHost: ${dst}\r\nCookie: session=eyJhbGciOiJSU0EyNTYiLCJleHBsaWNpdCI6Ijc1YWJlNDkifQ.payload_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko`
  },
  {
    type: 'SQL_INJECTION',
    title: 'Blind Time-Based SQL Injection & Schema Dumping',
    severity: 'HIGH',
    mitreId: 'T1190',
    mitreTactic: 'Initial Access',
    destPort: 80,
    protocol: 'HTTP',
    description: 'Malicious SQL stacking payloads targeted at user login endpoint attempting database schema enumeration via pg_sleep / UNION SELECT.',
    suggestedAction: 'Block offending IP on WAF layer & sanitize database query parameters.',
    payloadGenerator: (src, dst) => `GET /api/v1/users?search=' UNION SELECT null,table_name,column_name FROM information_schema.columns WHERE table_schema='public'-- AND 1=(SELECT 1 FROM pg_sleep(5)) HTTP/1.1\r\nHost: api.enterprise.internal`
  },
  {
    type: 'KERBEROASTING',
    title: 'Active Directory Kerberoasting Service Ticket Request Sweep',
    severity: 'HIGH',
    mitreId: 'T1558.003',
    mitreTactic: 'Credential Access',
    destPort: 88,
    protocol: 'KERBEROS',
    description: 'Anomalous burst of Kerberos TGS-REQ packets with RC4-HMAC cipher for high-privilege SPN service accounts (MSSQL, HTTP, Backups).',
    suggestedAction: 'Rotate Service Account passwords to 25+ character AES-256 keys & investigate origin host.',
    payloadGenerator: (src, dst) => `KRB5 TGS-REQ (etype: rc4-hmac, spn: MSSQLSvc/db-sql-core.corp.internal:1433, realm: CORP.INTERNAL, cname: WKS-FINANCE-04$)`
  },
  {
    type: 'RANSOMWARE_LATERAL',
    title: 'Lateral SMB PsExec / Named Pipe Infiltration',
    severity: 'CRITICAL',
    mitreId: 'T1021.002',
    mitreTactic: 'Lateral Movement',
    destPort: 445,
    protocol: 'SMB',
    description: 'Rapid SMB Tree Connect to IPC$ followed by remote service binary injection (psexesvc.exe) and ADMIN$ share enumeration.',
    suggestedAction: 'Trigger Host Isolation protocol on infected subnet and disable SMBv1/v2 remote access.',
    payloadGenerator: (src, dst) => `SMB2 Create Request File: ADMIN$\\System32\\svc_payload_64.exe IPC$ NamedPipe: \\PIPE\\PSEXECSVC CreateOptions: 0x00000040`
  },
  {
    type: 'DNS_TUNNELING',
    title: 'DNS C2 Tunneling & Staged Data Exfiltration',
    severity: 'HIGH',
    mitreId: 'T1048.003',
    mitreTactic: 'Exfiltration',
    destPort: 53,
    protocol: 'DNS',
    description: 'High frequency of encoded TXT / A record subdomains with excessive query length and non-standard DNS resolvers.',
    suggestedAction: 'Blacklist authoritative nameserver at perimeter DNS forwarders and sinkhole domain.',
    payloadGenerator: (src, dst) => `DNS Standard query 0x8a92 TXT 4d5a90000300000004000000ffff0000b80000000000000040000000.exfil.darkops-c2.cc`
  },
  {
    type: 'SSH_BRUTE_FORCE',
    title: 'SSH Distributed Dictionary Brute Force Attack',
    severity: 'MEDIUM',
    mitreId: 'T1110.001',
    mitreTactic: 'Credential Access',
    destPort: 22,
    protocol: 'SSH',
    description: 'Rapid failed password authentication attempts against SSH bastion server from rotating external IP pool.',
    suggestedAction: 'Enforce Fail2ban rate limiting & restrict SSH ingress to WireGuard VPN only.',
    payloadGenerator: (src, dst) => `SSH-2.0-OpenSSH_8.9 UserAuth Request: user="root" method="password" (Attempt 48/50 in 3 sec window)`
  },
  {
    type: 'DDOS_SYN_FLOOD',
    title: 'SYN Flood TCP Resource Exhaustion Attack',
    severity: 'CRITICAL',
    mitreId: 'T1498.001',
    mitreTactic: 'Impact',
    destPort: 443,
    protocol: 'TCP',
    description: 'Massive volume of spoofed TCP SYN packets without completing the 3-way handshake, exhausting kernel SYN backlog queues.',
    suggestedAction: 'Enable TCP SYN Cookies on perimeter edge & engage BGP Anycast DDoS scrubbing.',
    payloadGenerator: (src, dst) => `TCP SYN Flags: [S], Seq: 289104812, Win: 1024, Len: 0, Options: [mss 1460, nop, nop, sackOK]`
  },
  {
    type: 'PORT_SCAN',
    title: 'Stealth SYN/ACK Reconnaissance Port Sweep (Nmap/Masscan)',
    severity: 'LOW',
    mitreId: 'T1046',
    mitreTactic: 'Discovery',
    destPort: 8080,
    protocol: 'TCP',
    description: 'Sequential scanning of top 1000 ports across public DMZ gateway to detect unpatched exposed microservices.',
    suggestedAction: 'Drop scanning IP at border router and feed to Threat Intelligence blacklist.',
    payloadGenerator: (src, dst) => `TCP [S] Seq=0 Win=1024 Len=0 (Target Port Sweep: 80, 443, 8080, 8443, 9000, 27017, 6379)`
  }
];

export function generateRandomPacket(forceThreat?: ThreatCategory, isBlockedCheck?: (ip: string) => boolean): { packet: Packet; alert?: ThreatAlert } {
  const isAttack = forceThreat !== undefined || Math.random() < 0.22;
  const attackDef = isAttack 
    ? (forceThreat ? ATTACK_TEMPLATES.find(a => a.type === forceThreat) || ATTACK_TEMPLATES[0] : ATTACK_TEMPLATES[Math.floor(Math.random() * ATTACK_TEMPLATES.length)])
    : null;

  const now = new Date().toISOString();
  const id = 'pkt_' + Math.random().toString(36).substring(2, 9);

  let sourceIp = '';
  let destIp = '';
  let sourcePort = Math.floor(Math.random() * 50000) + 1024;
  let destPort = 443;
  let protocol: Protocol = 'HTTPS';
  let payloadStr = '';
  let country = COMMON_COUNTRIES[Math.floor(Math.random() * COMMON_COUNTRIES.length)];

  if (attackDef) {
    protocol = attackDef.protocol;
    destPort = attackDef.destPort;

    if (attackDef.type === 'C2_BEACONING' || attackDef.type === 'DNS_TUNNELING' || attackDef.type === 'DATA_EXFILTRATION') {
      // Internal compromised workstation calling out to adversary C2
      const internalSrc = INTERNAL_IPS[Math.floor(Math.random() * INTERNAL_IPS.length)];
      sourceIp = internalSrc.ip;
      destIp = ADVERSARY_C2_IPS[Math.floor(Math.random() * ADVERSARY_C2_IPS.length)];
      country = COMMON_COUNTRIES.find(c => c.code === 'RU' || c.code === 'CN' || c.code === 'KP') || COMMON_COUNTRIES[2];
    } else if (attackDef.type === 'RANSOMWARE_LATERAL' || attackDef.type === 'KERBEROASTING') {
      // Internal to Internal
      sourceIp = '10.0.2.14'; // WKS-FINANCE-04 (compromised)
      destIp = attackDef.type === 'KERBEROASTING' ? '10.0.1.10' : '10.0.1.50';
      country = { code: 'US', name: 'Internal HQ Subnet', asn: 'AS-CORP-LAN' };
    } else {
      // External attacker attacking DMZ / Gateway
      sourceIp = ADVERSARY_C2_IPS[Math.floor(Math.random() * ADVERSARY_C2_IPS.length)];
      destIp = '172.16.4.1'; // DMZ Ingress
      country = COMMON_COUNTRIES[Math.floor(Math.random() * COMMON_COUNTRIES.length)];
    }

    payloadStr = attackDef.payloadGenerator(sourceIp, destIp);
  } else {
    // Benign traffic
    const isOutbound = Math.random() > 0.5;
    if (isOutbound) {
      sourceIp = INTERNAL_IPS[Math.floor(Math.random() * INTERNAL_IPS.length)].ip;
      destIp = EXTERNAL_BENIGN_IPS[Math.floor(Math.random() * EXTERNAL_BENIGN_IPS.length)];
    } else {
      sourceIp = EXTERNAL_BENIGN_IPS[Math.floor(Math.random() * EXTERNAL_BENIGN_IPS.length)];
      destIp = '172.16.4.20';
    }

    const protocols: Protocol[] = ['HTTPS', 'TLS', 'DNS', 'TCP', 'HTTP', 'SMB', 'SSH'];
    protocol = protocols[Math.floor(Math.random() * protocols.length)];
    destPort = protocol === 'HTTPS' ? 443 : protocol === 'HTTP' ? 80 : protocol === 'DNS' ? 53 : protocol === 'SSH' ? 22 : protocol === 'SMB' ? 445 : 8443;
    payloadStr = BENIGN_PAYLOAD_TEMPLATES[Math.floor(Math.random() * BENIGN_PAYLOAD_TEMPLATES.length)];
  }

  const entropy = calculateEntropy(payloadStr);
  const rawHex = toHexDump(payloadStr);
  const length = Math.floor(Math.random() * 1200) + 64;

  const isBlocked = isBlockedCheck ? isBlockedCheck(sourceIp) || isBlockedCheck(destIp) : false;

  const packet: Packet = {
    id,
    timestamp: now,
    sourceIp,
    sourcePort,
    destIp,
    destPort,
    protocol,
    length,
    ttl: Math.floor(Math.random() * 64) + 64,
    flags: {
      syn: attackDef?.type === 'DDOS_SYN_FLOOD' || attackDef?.type === 'PORT_SCAN' || Math.random() < 0.2,
      ack: Math.random() > 0.3,
      fin: Math.random() < 0.1,
      rst: Math.random() < 0.05,
      psh: Math.random() < 0.4,
    },
    payloadPreview: payloadStr.length > 80 ? payloadStr.substring(0, 80) + '...' : payloadStr,
    rawHex,
    entropy,
    isThreat: !!attackDef,
    threatType: attackDef?.type,
    threatSeverity: attackDef?.severity,
    threatConfidence: attackDef ? Math.floor(Math.random() * 15) + 85 : undefined,
    countryCode: country.code,
    countryName: country.name,
    asn: country.asn,
    blocked: isBlocked
  };

  let alert: ThreatAlert | undefined = undefined;
  if (attackDef && !isBlocked) {
    alert = {
      id: 'alt_' + Math.random().toString(36).substring(2, 9),
      timestamp: now,
      title: attackDef.title,
      type: attackDef.type,
      severity: attackDef.severity,
      sourceIp,
      sourcePort,
      destIp,
      destPort,
      protocol,
      packetCount: Math.floor(Math.random() * 45) + 12,
      bandwidthBytes: length * 15,
      mitreId: attackDef.mitreId,
      mitreTactic: attackDef.mitreTactic,
      status: 'ACTIVE',
      autoBlocked: false,
      confidenceScore: Math.floor(Math.random() * 12) + 88,
      description: attackDef.description,
      payload: payloadStr,
      rawHex,
      suggestedAction: attackDef.suggestedAction,
      soarActionsTaken: []
    };
  }

  return { packet, alert };
}

export const INITIAL_NETWORK_NODES: NetworkNode[] = [
  { id: 'ext-c2-01', name: 'DarkOps C2 Server', ip: '185.220.101.4', type: 'EXTERNAL_THREAT', zone: 'EXTERNAL', status: 'COMPROMISED', activeConnections: 14, cpuLoad: 88, riskScore: 98, x: 80, y: 80 },
  { id: 'ext-c2-02', name: 'Bulletproof Relaying Node', ip: '45.142.214.88', type: 'EXTERNAL_THREAT', zone: 'EXTERNAL', status: 'COMPROMISED', activeConnections: 6, cpuLoad: 65, riskScore: 91, x: 80, y: 320 },
  { id: 'fw-perimeter', name: 'Border Firewall ASA-X', ip: '172.16.4.1', type: 'FIREWALL', zone: 'DMZ', status: 'HEALTHY', activeConnections: 842, cpuLoad: 42, riskScore: 12, x: 300, y: 200 },
  { id: 'waf-edge', name: 'Cloud WAF / Rate Limiter', ip: '172.16.4.20', type: 'WAF', zone: 'DMZ', status: 'HEALTHY', activeConnections: 512, cpuLoad: 38, riskScore: 18, x: 300, y: 340 },
  { id: 'web-prod', name: 'K8s Ingress API Portal', ip: '10.0.1.25', type: 'WEB_SERVER', zone: 'INTERNAL_SERVERS', status: 'WARNING', activeConnections: 184, cpuLoad: 68, riskScore: 45, x: 550, y: 120 },
  { id: 'dc-corp', name: 'DC-PRIMARY-01 (Active Dir)', ip: '10.0.1.10', type: 'DOMAIN_CONTROLLER', zone: 'INTERNAL_SERVERS', status: 'HEALTHY', activeConnections: 95, cpuLoad: 31, riskScore: 22, x: 550, y: 280 },
  { id: 'db-vault', name: 'DB-SQL-CORE (PCI / Vault)', ip: '10.0.1.50', type: 'DATABASE', zone: 'INTERNAL_SERVERS', status: 'HEALTHY', activeConnections: 42, cpuLoad: 24, riskScore: 15, x: 550, y: 440 },
  { id: 'wks-fin', name: 'WKS-FINANCE-04', ip: '10.0.2.14', type: 'WORKSTATION', zone: 'CORP_LAN', status: 'COMPROMISED', activeConnections: 19, cpuLoad: 79, riskScore: 88, x: 800, y: 150 },
  { id: 'wks-eng', name: 'WKS-ENG-LEAD', ip: '10.0.2.88', type: 'WORKSTATION', zone: 'CORP_LAN', status: 'HEALTHY', activeConnections: 12, cpuLoad: 18, riskScore: 10, x: 800, y: 300 },
  { id: 'honeypot-ssh', name: 'Decoy SSH Honeytoken', ip: '10.0.3.5', type: 'HONEYPOT', zone: 'DECEPTION_ZONE', status: 'HEALTHY', activeConnections: 3, cpuLoad: 5, riskScore: 5, x: 800, y: 450 }
];

export const INITIAL_FIREWALL_RULES = [
  { id: 'rule-01', name: 'Default Outbound Egress Policy', action: 'ALLOW' as const, source: '10.0.0.0/16', destination: '0.0.0.0/0', protocol: 'TCP/UDP', port: '443, 53', createdTime: '2026-08-16 00:00', active: true, hitCount: 14209, generatedBy: 'DEFAULT_ACL' as const },
  { id: 'rule-02', name: 'Drop Telnet & Insecure Protocols', action: 'DROP' as const, source: '0.0.0.0/0', destination: '10.0.0.0/16', protocol: 'TCP', port: '23, 69, 514', createdTime: '2026-08-16 00:00', active: true, hitCount: 432, generatedBy: 'DEFAULT_ACL' as const },
  { id: 'rule-03', name: 'Block Known Tor Exit Relay Pool', action: 'DROP' as const, source: '185.220.101.0/24', destination: '172.16.4.0/24', protocol: 'ANY', port: 'ANY', createdTime: '2026-08-16 04:12', active: true, hitCount: 189, generatedBy: 'AUTO_SOAR' as const }
];

export const INITIAL_THREAT_ACTORS = [
  {
    id: 'apt-29',
    name: 'APT29 (Cozy Bear / Midnight Blizzard)',
    aliases: ['NOBELIUM', 'UNC2452', 'YTTRIUM'],
    origin: 'Russian Federation (SVR)',
    motivation: 'State Espionage, Cloud Token Theft, Supply Chain',
    signatureTTPs: ['T1078.004 Cloud Accounts', 'T1071.001 Web Protocols Malleable C2', 'T1558.003 Kerberoasting', 'T1195.002 Supply Chain Compromise'],
    recentCampaigns: 'Targeted Microsoft 365 OAuth app hijacking & diplomat spearphishing campaigns.',
    confidence: 'HIGH' as const,
    matchedAlertsCount: 8
  },
  {
    id: 'lazarus-group',
    name: 'Lazarus Group (HIDDEN COBRA)',
    aliases: ['APT38', 'Diamond Sleet', 'Zinc'],
    origin: 'DPRK (RGB)',
    motivation: 'Financial Theft, Crypto Heists, Defense R&D Infiltration',
    signatureTTPs: ['T1048.003 DNS Tunneling', 'T1204.002 Malicious Link', 'T1059.001 PowerShell Memory Ingress', 'T1486 Data Encrypted for Impact'],
    recentCampaigns: 'Weaponized open-source npm/PyPI packages & defense contractor spear-recon.',
    confidence: 'CONFIRMED' as const,
    matchedAlertsCount: 14
  },
  {
    id: 'volt-typhoon',
    name: 'Volt Typhoon (Vanguard Panda)',
    aliases: ['BRONZE SILHOUETTE', 'Dev-0391'],
    origin: 'China (MSS)',
    motivation: 'Critical Infrastructure Pre-positioning, Living-off-the-Land (LotL)',
    signatureTTPs: ['T1021.002 SMB/Windows Admin Shares', 'T1110.001 Brute Force', 'T1562.001 Impair Defenses', 'T1090.002 Proxy Chaining'],
    recentCampaigns: 'SOHO router proxy mesh exploitation & SCADA utility perimeter probing.',
    confidence: 'CONFIRMED' as const,
    matchedAlertsCount: 6
  },
  {
    id: 'lockbit-supp',
    name: 'LockBit 3.0 (Black Syndicate)',
    aliases: ['Bitwise Spider', 'LockBit Green'],
    origin: 'Transnational Cybercrime',
    motivation: 'Extortion, Double Ransomware, Data Auction',
    signatureTTPs: ['T1486 Ransomware Encryption', 'T1021.002 PsExec Infiltration', 'T1569.002 System Services', 'T1070.004 File Deletion'],
    recentCampaigns: 'Rapid automated Active Directory group policy privilege abuse.',
    confidence: 'SUSPECTED' as const,
    matchedAlertsCount: 11
  }
];

export const MITRE_TACTIC_GROUPS = [
  {
    tactic: 'Reconnaissance',
    techniques: [
      { id: 'T1595', name: 'Active Scanning', count: 34, severity: 'LOW' },
      { id: 'T1592', name: 'Gather Victim Host Info', count: 12, severity: 'LOW' }
    ]
  },
  {
    tactic: 'Initial Access',
    techniques: [
      { id: 'T1190', name: 'Exploit Public-Facing Application', count: 19, severity: 'HIGH' },
      { id: 'T1566', name: 'Phishing: Spearphishing Link', count: 8, severity: 'HIGH' },
      { id: 'T1078', name: 'Valid Accounts', count: 15, severity: 'MEDIUM' }
    ]
  },
  {
    tactic: 'Execution',
    techniques: [
      { id: 'T1059.001', name: 'Command & Scripting: PowerShell', count: 27, severity: 'HIGH' },
      { id: 'T1204', name: 'User Execution: Malicious File', count: 6, severity: 'HIGH' }
    ]
  },
  {
    tactic: 'Persistence',
    techniques: [
      { id: 'T1547', name: 'Boot or Logon Autostart', count: 14, severity: 'MEDIUM' },
      { id: 'T1098', name: 'Account Manipulation', count: 9, severity: 'HIGH' }
    ]
  },
  {
    tactic: 'Privilege Escalation',
    techniques: [
      { id: 'T1068', name: 'Exploitation for Privilege Escalation', count: 11, severity: 'CRITICAL' },
      { id: 'T1548', name: 'Abuse Elevation Control', count: 5, severity: 'HIGH' }
    ]
  },
  {
    tactic: 'Credential Access',
    techniques: [
      { id: 'T1558.003', name: 'Kerberoasting', count: 23, severity: 'HIGH' },
      { id: 'T1110.001', name: 'Password Guessing / Brute Force', count: 42, severity: 'MEDIUM' },
      { id: 'T1003', name: 'OS Credential Dumping: LSASS', count: 7, severity: 'CRITICAL' }
    ]
  },
  {
    tactic: 'Lateral Movement',
    techniques: [
      { id: 'T1021.002', name: 'SMB/Windows Admin Shares', count: 18, severity: 'CRITICAL' },
      { id: 'T1570', name: 'Lateral Tool Transfer', count: 12, severity: 'HIGH' }
    ]
  },
  {
    tactic: 'Command and Control',
    techniques: [
      { id: 'T1071.001', name: 'Web Protocols (Malleable C2)', count: 51, severity: 'CRITICAL' },
      { id: 'T1071.004', name: 'DNS Tunneling Communication', count: 16, severity: 'HIGH' },
      { id: 'T1573', name: 'Encrypted Channel (TLS/Custom)', count: 39, severity: 'HIGH' }
    ]
  },
  {
    tactic: 'Exfiltration',
    techniques: [
      { id: 'T1048.003', name: 'Exfil Over Alternative Protocol', count: 14, severity: 'HIGH' },
      { id: 'T1567', name: 'Exfiltration Over Web Service', count: 8, severity: 'HIGH' }
    ]
  },
  {
    tactic: 'Impact',
    techniques: [
      { id: 'T1498.001', name: 'Direct Network Flood (SYN DDoS)', count: 68, severity: 'CRITICAL' },
      { id: 'T1486', name: 'Data Encrypted for Ransom', count: 3, severity: 'CRITICAL' }
    ]
  }
];
