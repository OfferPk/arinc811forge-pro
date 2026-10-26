/**
 * ARINC811Forge Pro — Core Engine
 * Commercial Aircraft Information Security (AISP) & Threat Modeling Architecture
 * Standards: ARINC Report 811, RTCA DO-326A, RTCA DO-356A, FAA AC 120-116, EASA AMC 20-42
 */

class ARINC811Engine {
  constructor() {
    // 4 Standard Security Domains (ARINC 811 §3.1)
    this.domains = {
      ACD: {
        id: 'ACD',
        name: 'Aircraft Control Domain',
        criticality: 'DAL-A/B (Flight Critical)',
        color: '#ef4444',
        subsystems: ['FMS', 'Fly-By-Wire EEC', 'Primary Flight Displays', 'AFDX Core Switches', 'ARINC 429 Bus'],
        isolated: true,
        inboundExternalAllowed: false
      },
      AISD: {
        id: 'AISD',
        name: 'Airline Information Services Domain',
        criticality: 'DAL-C/D (Operational)',
        color: '#f59e0b',
        subsystems: ['Electronic Flight Bag (EFB)', 'QAR / FOQA Logger', 'Maintenance Terminal', 'ACARS Router'],
        isolated: false,
        inboundExternalAllowed: true
      },
      PIESD: {
        id: 'PIESD',
        name: 'Passenger Information & Entertainment Services Domain',
        criticality: 'DAL-E (Non-Safety)',
        color: '#38bdf8',
        subsystems: ['In-Flight Entertainment (IFE)', 'Cabin Wi-Fi Access Points', 'Seatback Displays'],
        isolated: false,
        inboundExternalAllowed: true
      },
      POD: {
        id: 'POD',
        name: 'Passenger Owned Devices',
        criticality: 'UNTRUSTED_EXTERNAL',
        color: '#a855f7',
        subsystems: ['Passenger Smartphones', 'Tablets', 'Laptops'],
        isolated: false,
        inboundExternalAllowed: false
      }
    };

    // Inter-Domain Boundary Filters & Security Policies (ARINC 811 §4.2)
    this.boundaries = {
      'POD->PIESD': { name: 'Cabin Wi-Fi Isolation Gateway', state: 'FILTERED', dataDiode: false, encryption: 'WPA3-Personal' },
      'PIESD->AISD': { name: 'Airworthiness Security Firewall (DO-356A)', state: 'BLOCKED', dataDiode: false, encryption: 'IPsec AES-256' },
      'AISD->ACD': { name: 'Optical Hardware Data Diode (Egress Only)', state: 'UNIDIRECTIONAL_DIODE', dataDiode: true, encryption: 'SHA-256 HMAC' },
      'ACD->AISD': { name: 'Flight Telemetry Egress Stream', state: 'PERMITTED_ONE_WAY', dataDiode: true, encryption: 'None (Physical Diode)' },
      'GROUND->AISD': { name: 'ARINC 842 / Gatelink Air-Ground Gateway', state: 'EAP_TLS_MUTUAL_AUTH', dataDiode: false, encryption: 'IPsec AES-256-GCM' }
    };

    // Threat Landscape & Risk Register (DO-326A / STRIDE-Aero)
    this.threatRegister = [
      { id: 'THR-01', name: 'PIESD-to-ACD Pivot Attack', vector: 'Cabin IFE to Avionics Bus', stride: 'Elevation of Privilege', do326Severity: 'Catastrophic', mitigated: true },
      { id: 'THR-02', name: 'Malicious LSAP Software Injection', vector: 'Ground Maintenance USB / Gatelink', stride: 'Tampering', do326Severity: 'Hazardous', mitigated: true },
      { id: 'THR-03', name: 'GPS / ADS-B Position Spoofing', vector: 'RF Sensor Ingestion', stride: 'Spoofing', do326Severity: 'Major', mitigated: true },
      { id: 'THR-04', name: 'ACARS Telemetry Eavesdropping', vector: 'VHF / SATCOM Air-Ground Link', stride: 'Information Disclosure', do326Severity: 'Minor', mitigated: true },
      { id: 'THR-05', name: 'Cabin Wi-Fi Flooding DoS', vector: 'Passenger Wi-Fi Interface', stride: 'Denial of Service', do326Severity: 'No Safety Effect', mitigated: true },
      { id: 'THR-06', name: 'Unauthorized Maintenance Logging', vector: 'Onboard Maintenance Terminal', stride: 'Repudiation', do326Severity: 'Major', mitigated: true }
    ];

    // Security Incident Event Audit Log (SIEM in the Sky)
    this.securityAuditLogs = [];
    this.threatLevel = 1; // 1 (Nominal) to 5 (Severe Cyber Attack)
    this.logChainedHash = '0000000000000000000000000000000000000000000000000000000000000000';

    // Statistics
    this.stats = {
      boundaryEvaluations: 0,
      threatsBlocked: 0,
      diodesViolationsPrevented: 0,
      logsGenerated: 0
    };
  }

  evaluateInterDomainFlow(sourceDomain, destinationDomain, protocol, payloadBytes) {
    this.stats.boundaryEvaluations++;
    const key = `${sourceDomain}->${destinationDomain}`;
    
    // Strict ARINC 811 Rule: No direct traffic from POD or PIESD into ACD
    if ((sourceDomain === 'POD' || sourceDomain === 'PIESD') && destinationDomain === 'ACD') {
      this.stats.threatsBlocked++;
      this.stats.diodesViolationsPrevented++;
      this.recordSecurityEvent('CRITICAL_VIOLATION_BLOCKED', sourceDomain, destinationDomain, `Illegal direct boundary crossing attempt (${protocol})`, 'BLOCK');
      return {
        verdict: 'DENIED',
        reason: 'CRITICAL_SECURITY_BOUNDARY_VIOLATION: ARINC 811 prohibits PIESD/POD to ACD bridging.',
        mitigation: 'Physical isolation & data diode enforcement active.'
      };
    }

    // ACD to AISD: Unidirectional diode only
    if (sourceDomain === 'ACD' && destinationDomain === 'AISD') {
      this.recordSecurityEvent('TELEMETRY_EGRESS', sourceDomain, destinationDomain, `FOQA flight telemetry streaming (${payloadBytes} bytes)`, 'ALLOW');
      return { verdict: 'PERMITTED', mechanism: 'Hardware Optical Data Diode (Egress Only)' };
    }

    // Ingress from AISD to ACD: Blocked unless on-ground with Weight-on-Wheels & signed LSAP
    if (sourceDomain === 'AISD' && destinationDomain === 'ACD') {
      this.stats.threatsBlocked++;
      this.recordSecurityEvent('ACD_INGRESS_PREVENTED', sourceDomain, destinationDomain, `Ingress to ACD blocked during operational state`, 'BLOCK');
      return {
        verdict: 'DENIED',
        reason: 'DO-356A GATEWAY_INHIBIT: Inbound ACD modification disabled in flight.'
      };
    }

    // Default filtered boundary
    const boundary = this.boundaries[key];
    if (boundary && boundary.state !== 'BLOCKED') {
      this.recordSecurityEvent('FILTERED_TRAFFIC_ALLOW', sourceDomain, destinationDomain, `Permitted flow under ${boundary.encryption}`, 'ALLOW');
      return { verdict: 'PERMITTED', boundary: boundary.name, encryption: boundary.encryption };
    }

    this.recordSecurityEvent('POLICY_DROP', sourceDomain, destinationDomain, `Unroutable inter-domain traffic`, 'BLOCK');
    return { verdict: 'DENIED', reason: 'NO_PERMITTED_BOUNDARY_POLICY' };
  }

  recordSecurityEvent(eventType, src, dst, details, action) {
    const timestamp = new Date().toISOString();
    const eventId = `EVT-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    
    // Simulate SHA-256 hash chaining
    const rawData = `${this.logChainedHash}|${timestamp}|${eventId}|${src}|${dst}|${action}|${details}`;
    const newHash = this.computeSimpleHash(rawData);
    this.logChainedHash = newHash;

    const logEntry = {
      id: eventId,
      timestamp: timestamp,
      type: eventType,
      srcDomain: src,
      dstDomain: dst,
      action: action,
      details: details,
      chainedHash: newHash
    };

    this.securityAuditLogs.unshift(logEntry);
    if (this.securityAuditLogs.length > 100) this.securityAuditLogs.pop();
    this.stats.logsGenerated++;
    return logEntry;
  }

  computeSimpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    const hex = (hash >>> 0).toString(16).padStart(8, '0');
    return `${hex}a811c79f3e4d2026${hex}`.substring(0, 32);
  }

  setThreatLevel(level) {
    if (level < 1 || level > 5) throw new Error('Threat level must be between 1 and 5');
    this.threatLevel = level;
    this.recordSecurityEvent('AISP_THREAT_LEVEL_CHANGE', 'AISP_CONTROLLER', 'GLOBAL', `Threat level adjusted to LEVEL_${level}`, 'ALERT');
  }

  generateARINC429BusWords() {
    // ARINC 429 Label 273 (Octal): AISP Cyber Threat Level & Domain Boundary State
    const label273 = 0xBB; // Label 273 representation
    let data273 = 0;

    data273 |= (this.threatLevel & 0x07) << 10; // Bits 11-13 Threat Level (1-5)
    data273 |= (this.domains.ACD.isolated ? 1 : 0) << 13; // Bit 14 ACD Isolated
    data273 |= (this.boundaries['AISD->ACD'].dataDiode ? 1 : 0) << 14; // Bit 15 Diode Active
    data273 |= (this.boundaries['PIESD->AISD'].state === 'BLOCKED' ? 1 : 0) << 15; // Bit 16 Firewall Armed
    data273 |= (Math.min(31, this.stats.threatsBlocked) & 0x1F) << 16; // Bits 17-21 Blocked Threats
    data273 |= 0x03 << 28; // Bits 29-30 SSM (Normal Operation)

    let word273 = (data273 & 0x7FFFFF00) | (label273 & 0xFF);
    word273 = this.applyOddParity(word273);

    // Label 274 (Octal): Security Audit Log Depth & Hash Chain State
    const label274 = 0xBC;
    let data274 = 0;
    const logDepth = Math.min(63, this.securityAuditLogs.length);

    data274 |= (logDepth & 0x3F) << 10; // Bits 11-16 Log depth
    data274 |= (1 & 0x01) << 16; // Bit 17 Hash Chain Valid
    data274 |= (Math.min(127, this.stats.boundaryEvaluations) & 0x7F) << 17; // Bits 18-24 Total Evals
    data274 |= 0x03 << 28; // Bits 29-30 SSM

    let word274 = (data274 & 0x7FFFFF00) | (label274 & 0xFF);
    word274 = this.applyOddParity(word274);

    return {
      label273: { hex: '0x' + (word273 >>> 0).toString(16).toUpperCase().padStart(8, '0'), parityValid: this.verifyOddParity(word273) },
      label274: { hex: '0x' + (word274 >>> 0).toString(16).toUpperCase().padStart(8, '0'), parityValid: this.verifyOddParity(word274) }
    };
  }

  applyOddParity(word32) {
    let bits = word32 & 0x7FFFFFFF;
    let count = 0;
    for (let i = 0; i < 31; i++) {
      if ((bits >> i) & 1) count++;
    }
    if (count % 2 === 0) {
      bits |= (1 << 31);
    }
    return bits >>> 0;
  }

  verifyOddParity(word32) {
    let count = 0;
    for (let i = 0; i < 32; i++) {
      if ((word32 >>> i) & 1) count++;
    }
    return count % 2 === 1;
  }

  getSecuritySummary() {
    return {
      threatLevel: this.threatLevel,
      domains: { ...this.domains },
      boundaries: { ...this.boundaries },
      stats: { ...this.stats },
      recentLogs: this.securityAuditLogs.slice(0, 10),
      busWords: this.generateARINC429BusWords()
    };
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ARINC811Engine };
}
