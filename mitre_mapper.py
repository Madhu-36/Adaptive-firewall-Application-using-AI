"""
mitre_mapper.py
===============
MITRE ATT&CK Enterprise Framework Correlation Engine.

Maps network anomalies, flow heuristics, and threat classifications to official
MITRE ATT&CK Tactics, Techniques, and Sub-technique IDs.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger("firewall.mitre")

# MITRE ATT&CK Matrix Repository for Network Threats
MITRE_TACTIC_MAP = {
    "SYN_FLOOD": {
        "technique_id": "T1498.001",
        "technique_name": "Network Denial of Service: Direct Network Flooding",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "severity": "CRITICAL",
        "kill_chain_phase": "Action on Objectives",
        "mitigation": "M1037 - Filter Network Traffic (Kernel SYN-Drop / Rate Limit)",
        "description": "Adversary floods the network connection with high-rate TCP SYN packets, exhausting server socket state tables.",
    },
    "PORT_SCAN": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "severity": "HIGH",
        "kill_chain_phase": "Reconnaissance",
        "mitigation": "M1037 - Dynamic Kernel Blacklisting & Port Sweep Suppression",
        "description": "Adversary attempts to enumerate listening services across multiple TCP/UDP ports to locate exploitable attack vectors.",
    },
    "UDP_BURST": {
        "technique_id": "T1498.002",
        "technique_name": "Network Denial of Service: Reflection & Amplification Flood",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "severity": "CRITICAL",
        "kill_chain_phase": "Action on Objectives",
        "mitigation": "M1037 - Volumetric Thresholding & Per-Flow Bandwidth Quotas",
        "description": "Adversary transmits high-bandwidth UDP datagram bursts targeting open application endpoints to saturate downlink capacity.",
    },
    "ZERO_DAY_ANOMALY": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Traffic Polymorphism",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "severity": "HIGH",
        "kill_chain_phase": "Command & Control / Exfiltration",
        "mitigation": "M1031 - Network Intrusion Prevention (LSTM-Autoencoder Baseline Quarantine)",
        "description": "Adversary generates atypical packet sizing and inter-arrival patterns deviating from established normal operational baselines.",
    },
    "OSINT_FLAGGED_IP": {
        "technique_id": "T1595.002",
        "technique_name": "Active Scanning: Vulnerability Scanning",
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "severity": "HIGH",
        "kill_chain_phase": "Pre-Attack",
        "mitigation": "M1037 - Automated OSINT Threat Feed Quarantine",
        "description": "Traffic originating from known malicious infrastructure indexed by CISA, AlienVault OTX, or Spamhaus threat feeds.",
    },
    "BRUTE_FORCE_SSH": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "severity": "CRITICAL",
        "kill_chain_phase": "Exploitation",
        "mitigation": "M1036 - Account Use Policies & Connection Rate Limiting",
        "description": "Repeated unauthorized authentication handshakes targeting administrative management ports.",
    },
    "NORMAL": {
        "technique_id": "NONE",
        "technique_name": "Benign Network Traffic",
        "tactic": "Standard Operations",
        "tactic_id": "TA0000",
        "severity": "INFO",
        "kill_chain_phase": "Normal Operation",
        "mitigation": "None required",
        "description": "Traffic conforms to established baseline statistical distributions.",
    },
}


class MitreAttackMapper:
    """
    Correlates firewall threat detections with MITRE ATT&CK Matrix specifications.
    """

    @staticmethod
    def map_threat(threat_label: str) -> Dict[str, Any]:
        """
        Return the MITRE ATT&CK taxonomy dictionary for a given threat label.
        """
        clean_label = str(threat_label).strip().upper()
        if clean_label in MITRE_TACTIC_MAP:
            return MITRE_TACTIC_MAP[clean_label]
        
        # Fallback for composite or unknown threat labels
        if "SYN" in clean_label:
            return MITRE_TACTIC_MAP["SYN_FLOOD"]
        if "SCAN" in clean_label:
            return MITRE_TACTIC_MAP["PORT_SCAN"]
        if "UDP" in clean_label:
            return MITRE_TACTIC_MAP["UDP_BURST"]
        if "ZERO" in clean_label:
            return MITRE_TACTIC_MAP["ZERO_DAY_ANOMALY"]
        if "OSINT" in clean_label:
            return MITRE_TACTIC_MAP["OSINT_FLAGGED_IP"]
        if "SSH" in clean_label or "BRUTE" in clean_label:
            return MITRE_TACTIC_MAP["BRUTE_FORCE_SSH"]

        return MITRE_TACTIC_MAP["NORMAL"]

    @staticmethod
    def get_all_matrix_tactics() -> List[Dict[str, Any]]:
        """
        Return full active matrix of monitored enterprise techniques.
        """
        return [
            {"label": k, **v}
            for k, v in MITRE_TACTIC_MAP.items()
            if k != "NORMAL"
        ]
