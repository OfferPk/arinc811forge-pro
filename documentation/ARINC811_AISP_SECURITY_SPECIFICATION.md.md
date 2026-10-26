# ARINC Report 811 Commercial Aircraft Information Security Program (AISP) Specification

**Document ID**: ARINC811-SPEC-2026-v1.0  
**Normative Standards**: ARINC Report 811, RTCA DO-326A, RTCA DO-356A, FAA AC 120-116, EASA AMC 20-42, FAR 25.1309  
**Classification**: Commercial Aircraft Avionics & Ground Systems Cybersecurity Technical Standard

---

## 1\. Executive Summary & Operational Scope

The **ARINC Report 811 (Commercial Aircraft Information Security Concepts of Operation and Process Framework)** establishes the industry-standard architecture, operational framework, and threat management processes for securing e-Enabled commercial aircraft.

Modern connected aircraft interface with airport wireless gateways (ARINC 842), satellite constellations (ARINC 781), cellular networks, and passenger Wi-Fi systems. ARINC 811 specifies physical and logical domain isolation to ensure that non-safety critical systems cannot compromise flight safety.

---

## 2\. Four Standard Security Domains

ARINC 811 partitions commercial aircraft electronic systems into four distinct security domains:

1. **Aircraft Control Domain (ACD)**:  
   - Contains flight-critical and safety-critical functions: Fly-By-Wire, Engine Electronic Controllers (EEC), Flight Management Systems (FMS), AFDX/ARINC 664 switches, and ARINC 429 discrete buses.  
   - Assigned Development Assurance Level **DAL-A/B**.  
   - Enforces **Zero External Ingress**: No direct network connectivity from passenger or external domains is permitted.  
2. **Airline Information Services Domain (AISD)**:  
   - Contains airline administrative and operational support systems: Electronic Flight Bag (EFB), Quick Access Recorder (QAR), maintenance laptops, and ACARS routers.  
   - Assigned **DAL-C/D**.  
   - Interfaces with the ground via certified air-ground security gateways.  
3. **Passenger Information and Entertainment Services Domain (PIESD)**:  
   - Contains passenger in-flight entertainment (IFE), seatback displays, and cabin Wi-Fi access points.  
   - Assigned **DAL-E**.  
   - Logically and physically firewalled from the AISD and ACD.  
4. **Passenger Owned Devices (POD)**:  
   - Encompasses personal passenger electronics (smartphones, laptops, tablets) connecting via cabin Wi-Fi.  
   - Classified as an **Untrusted External Domain**.

---

## 3\. Boundary Controls & Hardware Data Diodes

ARINC 811 mandates strict security mechanisms across domain boundaries:

- **Optical Hardware Data Diodes**: Installed between the ACD and AISD to allow unidirectional flight parameter streaming (FOQA/QAR) while physically making inbound packet propagation impossible.  
- **Airworthiness Boundary Firewalls**: Dual-homed, stateful deep packet inspection firewalls compliant with RTCA DO-356A, isolating PIESD from AISD.  
- **Mutual PKI Authentication**: IEEE 802.1X EAP-TLS and IPsec AES-256-GCM tunneling for all ground-to-aircraft software uploads (ARINC 665 LSAP).

---

## 4\. STRIDE-Aero Threat Model & DO-326A Risk Severity

Threats to aircraft airworthiness are systematically modeled across 6 STRIDE-Aero vectors:

- **Spoofing**: GNSS/ADS-B sensor spoofing.  
- **Tampering**: Malicious LSAP software loading or configuration tampering.  
- **Repudiation**: Unlogged maintenance activities.  
- **Information Disclosure**: Interception of operational flight telemetry.  
- **Denial of Service**: IFE saturation or SATCOM link flooding.  
- **Elevation of Privilege**: Pivoting from PIESD cabin Wi-Fi into flight control avionics.

Quantitative risk severity is classified according to RTCA DO-326A: Catastrophic, Hazardous, Major, Minor, or No Safety Effect.

---

## 5\. ARINC 429 Glass-Cockpit Discrete Bus Output

The AISP LRU outputs cyber health status onto the aircraft low-speed ARINC 429 bus:

- **Label 273 (Octal)**: AISP Cyber Threat Level & Boundary States  
  - Bits 11-13: Threat Level (Level 1 Nominal to Level 5 Severe)  
  - Bit 14: ACD Isolated Status (1: Active)  
  - Bit 15: Optical Data Diode Active (1: Verified)  
  - Bit 16: PIESD-to-AISD Firewall Armed (1: Armed)  
  - Bits 17-21: Blocked Threat Count  
  - Bits 29-30: SSM (Normal Operation: 11b)  
  - Bit 32: Odd Parity  
- **Label 274 (Octal)**: Security Event Audit Depth & Cryptographic Hash Chain State  
  - Bits 11-16: Security Audit Log Queue Depth  
  - Bit 17: SHA-256 Hash Chain Valid  
  - Bits 18-24: Total Boundary Flow Evaluations  
  - Bits 29-30: SSM  
  - Bit 32: Odd Parity