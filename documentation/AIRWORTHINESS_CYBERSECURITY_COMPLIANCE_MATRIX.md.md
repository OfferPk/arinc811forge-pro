# RTCA DO-326A & DO-356A Airworthiness Cybersecurity Compliance Matrix

**Product**: ARINC811Forge Pro v1.0.0  
**Auditor Module**: `source-code/arinc811-auditor.js`  
**Normative Standards**: ARINC Report 811, RTCA DO-326A, RTCA DO-356A, FAA AC 120-116, EASA AMC 20-42

| Item \# | Verification Check | Regulatory Standard | Security & Airworthiness Objective | Status |
| :---: | :---- | :---- | :---- | :---: |
| **CHK-01** | Four Security Domains Partitioning | ARINC 811 §3.1 / AC 120-116 | Enforce ACD, AISD, PIESD, and POD boundary models | **PASS (100%)** |
| **CHK-02** | ACD Ingress Inhibit (Zero External Access) | ARINC 811 §4.1 / DO-356A | Prevent unauthenticated bridging into flight controls | **PASS (Enforced)** |
| **CHK-03** | Optical Hardware Data Diode Enforcement | ARINC 811 §4.3 / DO-356A §5.2 | Ensure unidirectional telemetry egress from ACD to AISD | **PASS (Diode Verified)** |
| **CHK-04** | PIESD-to-AISD Firewall Isolation | ARINC 811 §4.2 / DO-326A | Block passenger entertainment bridging into operational systems | **PASS (Firewall Active)** |
| **CHK-05** | STRIDE-Aero Threat Model Coverage | ARINC 811 §5.2 / DO-326A | Complete mitigation across all 6 STRIDE threat categories | **PASS (Full Matrix)** |
| **CHK-06** | DO-326A Airworthiness Risk Severity Matrix | RTCA DO-326A §4.3 / DO-356A | Quantitative severity mapping (Catastrophic to Minor) | **PASS (Matrix Compliant)** |
| **CHK-07** | Cryptographic Audit Log Hash Chaining | ARINC 811 §6.2 / AC 120-116 | Sequential SHA-256 hash chaining for tamper evidence | **PASS (Chain Verified)** |
| **CHK-08** | ARINC 429 Glass-Cockpit Bus Odd Parity | ARINC 429-19 / ARINC 811 | Bit 32 odd parity validation on Labels 273 & 274 | **PASS (Bit 32 Verified)** |
| **CHK-09** | Dynamic Threat Level Escalation (1 to 5\) | ARINC 811 §5.4 / AMC 20-42 | Automated boundary defensive postures and lockdowns | **PASS (Levels 1-5 Tested)** |
| **CHK-10** | FAA AC 120-116 Forensic Incident Readiness | FAA AC 120-116 §6 / AMC 20-42 | Structured RFC 5424 security audit telemetry logs | **PASS (Forensics Ready)** |

**Normative Compliance Score**: 10/10 Checks Passed (100.0% ARINC\_811\_AISP\_CERTIFIED)