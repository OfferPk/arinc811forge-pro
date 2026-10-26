#!/usr/bin/env python3
"""
ARINC811Forge Pro — Automated Unit & Regression Test Suite
10 Comprehensive Verification Tests for ARINC 811 AISP & Security Boundary Engine
"""

import unittest
from arinc811_cli import ARINC811Simulator

class TestARINC811ForgePro(unittest.TestCase):
    def setUp(self):
        self.sim = ARINC811Simulator()

    def test_01_domain_partitioning(self):
        """Test 01: Four Standard Security Domains Partitioning (ARINC 811 §3.1)"""
        expected = {"ACD", "AISD", "PIESD", "POD"}
        self.assertEqual(set(self.sim.domains.keys()), expected)
        self.assertTrue(self.sim.domains["ACD"]["isolated"])
        self.assertEqual(self.sim.domains["ACD"]["dal"], "DAL-A/B")

    def test_02_piesd_to_acd_inhibit(self):
        """Test 02: Inhibit Passenger Entertainment to Flight Control Bridge"""
        res = self.sim.evaluate_flow("PIESD", "ACD", "TCP/443", 1024)
        self.assertEqual(res["verdict"], "DENIED")
        self.assertEqual(res["action"], "BLOCKED")
        self.assertGreater(self.sim.threats_blocked, 0)

    def test_03_pod_to_acd_inhibit(self):
        """Test 03: Inhibit Passenger Owned Device Ingress into ACD"""
        res = self.sim.evaluate_flow("POD", "ACD", "UDP/161", 512)
        self.assertEqual(res["verdict"], "DENIED")
        self.assertEqual(res["action"], "BLOCKED")

    def test_04_acd_to_aisd_diode_egress(self):
        """Test 04: Hardware Data Diode Unidirectional Egress Streaming"""
        res = self.sim.evaluate_flow("ACD", "AISD", "ARINC664_STREAM", 4096)
        self.assertEqual(res["verdict"], "PERMITTED")
        self.assertIn("Data Diode", res["mechanism"])

    def test_05_aisd_to_acd_ingress_block(self):
        """Test 05: Operational Domain Inbound Modification Prevention"""
        res = self.sim.evaluate_flow("AISD", "ACD", "LSAP_LOAD", 2048)
        self.assertEqual(res["verdict"], "DENIED")
        self.assertEqual(res["action"], "BLOCKED")

    def test_06_audit_log_hash_chaining(self):
        """Test 06: Sequential Cryptographic Hash Chaining Integrity"""
        initial_hash = self.sim.chained_hash
        self.sim.record_log("TEST_EVENT", "AISD", "GROUND", "Handshake test", "ALLOW")
        self.assertNotEqual(self.sim.chained_hash, initial_hash)
        self.assertEqual(len(self.sim.chained_hash), 32)

    def test_07_threat_level_scaling(self):
        """Test 07: AISP Dynamic Threat Level Escalation (1 to 5)"""
        self.sim.threat_level = 4
        words = self.sim.generate_arinc429_words()
        word273_int = int(words["label273"], 16)
        # Check bits 11-13 (threat level = 4)
        extracted_level = (word273_int >> 10) & 0x07
        self.assertEqual(extracted_level, 4)

    def test_08_arinc429_label273_parity(self):
        """Test 08: ARINC 429 Label 273 Bit 32 Odd Parity Verification"""
        words = self.sim.generate_arinc429_words()
        word273_int = int(words["label273"], 16)
        bit_count = bin(word273_int).count('1')
        self.assertEqual(bit_count % 2, 1, f"Label 273 parity must be odd (bits: {bit_count})")

    def test_09_arinc429_label274_parity(self):
        """Test 09: ARINC 429 Label 274 Bit 32 Odd Parity Verification"""
        words = self.sim.generate_arinc429_words()
        word274_int = int(words["label274"], 16)
        bit_count = bin(word274_int).count('1')
        self.assertEqual(bit_count % 2, 1, f"Label 274 parity must be odd (bits: {bit_count})")

    def test_10_boundary_statistics_tracking(self):
        """Test 10: Boundary Security Counters & Log Depth Tracking"""
        self.sim.evaluate_flow("POD", "ACD", "TCP", 100)
        self.sim.evaluate_flow("ACD", "AISD", "UDP", 200)
        self.assertEqual(self.sim.flow_evaluations, 2)
        self.assertEqual(self.sim.threats_blocked, 1)
        self.assertEqual(len(self.sim.logs), 2)

if __name__ == "__main__":
    unittest.main()
