#!/usr/bin/env python3
"""
ARINC811Forge Pro — Standalone Python 3 CLI Runner & Security Assessment Suite
Commercial Aircraft Information Security Program (AISP) & Threat Modeling Studio
Standards: ARINC Report 811, RTCA DO-326A, RTCA DO-356A, FAA AC 120-116
"""

import sys
import json
import time

class ARINC811Simulator:
    def __init__(self):
        self.domains = {
            "ACD": {"name": "Aircraft Control Domain", "dal": "DAL-A/B", "isolated": True},
            "AISD": {"name": "Airline Information Services Domain", "dal": "DAL-C/D", "isolated": False},
            "PIESD": {"name": "Passenger Information & Entertainment Domain", "dal": "DAL-E", "isolated": False},
            "POD": {"name": "Passenger Owned Devices", "dal": "UNTRUSTED", "isolated": False}
        }

        self.threat_level = 1  # 1 to 5
        self.logs = []
        self.chained_hash = "00000000000000000000000000000000"
        self.threats_blocked = 0
        self.flow_evaluations = 0

    def evaluate_flow(self, src, dst, protocol, size_bytes):
        self.flow_evaluations += 1
        
        # Rule 1: No POD or PIESD into ACD
        if (src in ["POD", "PIESD"]) and dst == "ACD":
            self.threats_blocked += 1
            log = self.record_log("SECURITY_VIOLATION", src, dst, f"Illegal bridging attempt via {protocol}", "BLOCK")
            return {"verdict": "DENIED", "rule": "ARINC 811 §4.1 ACD Isolation", "action": "BLOCKED"}

        # Rule 2: ACD to AISD telemetry egress via data diode
        if src == "ACD" and dst == "AISD":
            log = self.record_log("DATA_DIODE_EGRESS", src, dst, f"FOQA Telemetry Stream ({size_bytes}B)", "ALLOW")
            return {"verdict": "PERMITTED", "mechanism": "Optical Hardware Data Diode"}

        # Rule 3: AISD into ACD inbound modification blocked
        if src == "AISD" and dst == "ACD":
            self.threats_blocked += 1
            log = self.record_log("ACD_INBOUND_INHIBIT", src, dst, "Inbound ACD modification prohibited", "BLOCK")
            return {"verdict": "DENIED", "rule": "DO-356A Boundary Inhibit", "action": "BLOCKED"}

        # Permitted filtered flows
        log = self.record_log("FILTERED_ALLOW", src, dst, f"Traffic permitted ({protocol})", "ALLOW")
        return {"verdict": "PERMITTED", "rule": "Domain Boundary Policy"}

    def record_log(self, evt_type, src, dst, details, action):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        raw = f"{self.chained_hash}|{ts}|{evt_type}|{src}|{dst}|{action}|{details}"
        # Compute 32-char hex hash
        h = format(hash(raw) & 0xFFFFFFFFFFFFFFFF, '016x')
        self.chained_hash = f"{h}{h}"[:32]

        entry = {
            "timestamp": ts,
            "type": evt_type,
            "src": src,
            "dst": dst,
            "action": action,
            "details": details,
            "chained_hash": self.chained_hash
        }
        self.logs.append(entry)
        return entry

    def generate_arinc429_words(self):
        # Label 273 (Octal): Threat Level & Boundary Firewall State
        label273 = 0xBB
        data273 = ((self.threat_level & 0x07) << 10) | (1 << 13) | (1 << 14) | (1 << 15) | ((min(31, self.threats_blocked) & 0x1F) << 16) | (0x03 << 28)
        word273 = (data273 & 0x7FFFFF00) | label273
        word273 = self.apply_odd_parity(word273)

        # Label 274 (Octal): Security Audit Depth & Hash Chain State
        label274 = 0xBC
        log_depth = min(63, len(self.logs))
        data274 = ((log_depth & 0x3F) << 10) | (1 << 16) | ((min(127, self.flow_evaluations) & 0x7F) << 17) | (0x03 << 28)
        word274 = (data274 & 0x7FFFFF00) | label274
        word274 = self.apply_odd_parity(word274)

        return {
            "label273": hex(word273),
            "label274": hex(word274),
            "odd_parity_valid": self.verify_odd_parity(word273) and self.verify_odd_parity(word274)
        }

    def apply_odd_parity(self, word):
        bits = word & 0x7FFFFFFF
        count = bin(bits).count('1')
        if count % 2 == 0:
            bits |= (1 << 31)
        return bits

    def verify_odd_parity(self, word):
        return bin(word).count('1') % 2 == 1

def run_cli():
    sim = ARINC811Simulator()
    print("=" * 70)
    print("ARINC811Forge Pro — Aircraft Information Security Program (AISP) CLI")
    print("Standard Compliance: ARINC Report 811, RTCA DO-326A, RTCA DO-356A")
    print("=" * 70)

    # Simulate Boundary Test Scenarios
    scenarios = [
        ("PIESD", "ACD", "TCP/443 (Exploit Ingress)", 1024),
        ("POD", "ACD", "UDP/161 (SNMP Flood)", 512),
        ("ACD", "AISD", "ARINC664 Telemetry Stream", 4096),
        ("AISD", "ACD", "LSAP Load Request", 2048),
        ("POD", "PIESD", "HTTP Stream", 1500)
    ]

    for src, dst, proto, size in scenarios:
        res = sim.evaluate_flow(src, dst, proto, size)
        print(f"\n[EVALUATING FLOW: {src} -> {dst}]")
        print(f"  Protocol/Payload : {proto} ({size} bytes)")
        print(f"  Boundary Verdict : {res['verdict']}")
        print(f"  Enforced Policy  : {res.get('rule', res.get('mechanism', 'N/A'))}")

    bus_words = sim.generate_arinc429_words()
    print("\n" + "-" * 70)
    print("ARINC 429 Glass-Cockpit Discrete Bus Output:")
    print(f"  Label 273 (Threat Level & State) : {bus_words['label273']}")
    print(f"  Label 274 (Audit Depth & Hash Q) : {bus_words['label274']}")
    print(f"  Bit 32 Odd Parity Status         : {'VALID (PASS)' if bus_words['odd_parity_valid'] else 'INVALID (FAIL)'}")
    print(f"  Threats Intercepted & Blocked    : {sim.threats_blocked}")
    print(f"  Chained Audit Hash               : {sim.chained_hash}")
    print("=" * 70)

if __name__ == "__main__":
    run_cli()
