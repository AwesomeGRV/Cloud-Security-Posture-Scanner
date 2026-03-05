"""MITRE ATT&CK framework mapping for security findings."""

from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict, Counter

from .models import SecurityFinding, SeverityLevel, ResourceType


class MITRETactic(str, Enum):
    """MITRE ATT&CK tactics."""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class MITRETechnique(str, Enum):
    """MITRE ATT&CK techniques."""
    # Reconnaissance
    ACTIVE_SCANNING = "T1595"
    PASSIVE_SCANNING = "T1592"
    GATHER_VICTIM_INFO = "T1593"
    
    # Initial Access
    VALID_ACCOUNTS = "T1078"
    EXPLOIT_PUBLIC_FACING_APP = "T1190"
    PHISHING = "T1566"
    SUPPLY_CHAIN_COMPROMISE = "T1195"
    
    # Execution
    COMMAND_LINE_SCRIPTING = "T1059"
    USER_EXECUTION = "T1204"
    EXPLOITATION_FOR_EXECUTION = "T1203"
    
    # Persistence
    VALID_ACCOUNTS_PERSIST = "T1078"
    CREATE_ACCOUNT = "T1136"
    MODIFY_ACCOUNT = "T1098"
    HIDDEN_FILES = "T1158"
    
    # Privilege Escalation
    VALID_ACCOUNTS_ESCALATE = "T1078"
    ABUSE_ELEVATION_CONTROL = "T1548"
    MODIFY_PROCESS = "T1484"
    
    # Defense Evasion
    DISABLE_OR_TOOLS = "T1562"
    IMPAIR_DEFENSES = "T1562"
    HIDE_ARTIFACTS = "T1564"
    OBFUSCATED_FILES = "T1027"
    
    # Credential Access
    CREDENTIAL_DUMPING = "T1003"
    STEAL_OR_FORGE = "T1558"
    UNSECURED_CREDENTIALS = "T1552"
    
    # Discovery
    SYSTEM_INFO_DISCOVERY = "T1082"
    NETWORK_DISCOVERY = "T1018"
    PROCESS_DISCOVERY = "T1057"
    ACCOUNT_DISCOVERY = "T1087"
    
    # Lateral Movement
    REMOTE_SERVICES = "T1021"
    REMOTE_COPY = "T1021"
    LATERAL_TOOL_TRANSFER = "T1570"
    
    # Collection
    DATA_FROM_LOCAL_SYSTEM = "T1005"
    DATA_FROM_NETWORK_SHARED_DRIVE = "T1039"
    DATA_FROM_REPOSITORY = "T1213"
    
    # Exfiltration
    EXFILTRATION_OVER_NETWORK = "T1041"
    EXFILTRATION_OVER_WEB_SERVICE = "T1567"
    EXFILTRATION_OVER_OTHER_MEDIUM = "T1567"
    
    # Impact
    DATA_DESTRUCTION = "T1485"
    SERVICE_STOP = "T1489"
    RESOURCE_HIJACKING = "T1496"
    INHIBIT_SYSTEM_RECOVERY = "T1490"


@dataclass
class MITREAttackPattern:
    """MITRE ATT&CK attack pattern."""
    technique_id: MITRETechnique
    technique_name: str
    tactic: MITRETactic
    tactic_name: str
    description: str
    detection_methods: List[str]
    mitigation_strategies: List[str]
    references: List[str]
    platforms: List[str]


@dataclass
class AttackPatternMatch:
    """Attack pattern match for a finding."""
    finding_id: str
    technique_id: MITRETechnique
    technique_name: str
    tactic: MITRETactic
    tactic_name: str
    confidence_score: float
    matching_keywords: List[str]
    detection_recommendations: List[str]


class MITREAttackMapper:
    """Maps security findings to MITRE ATT&CK framework."""
    
    def __init__(self):
        self.attack_patterns = self._load_attack_patterns()
        self.technique_mappings = self._create_technique_mappings()
        self.tactic_hierarchy = self._load_tactic_hierarchy()
    
    def _load_attack_patterns(self) -> Dict[MITRETechnique, MITREAttackPattern]:
        """Load MITRE ATT&CK attack patterns."""
        return {
            # Reconnaissance
            MITRETechnique.ACTIVE_SCANNING: MITREAttackPattern(
                technique_id=MITRETechnique.ACTIVE_SCANNING,
                technique_name="Active Scanning",
                tactic=MITRETactic.RECONNAISSANCE,
                tactic_name="Reconnaissance",
                description="Adversaries may attempt to gain information about the target network through active scanning.",
                detection_methods=[
                    "Network traffic analysis",
                    "Port scan detection",
                    "Firewall log analysis",
                    "IDS/IPS alerts"
                ],
                mitigation_strategies=[
                    "Network segmentation",
                    "Port filtering",
                    "Network access control",
                    "Deception techniques"
                ],
                references=["https://attack.mitre.org/techniques/T1595/"],
                platforms=["Azure", "Network", "Cloud"]
            ),
            
            # Initial Access
            MITRETechnique.VALID_ACCOUNTS: MITREAttackPattern(
                technique_id=MITRETechnique.VALID_ACCOUNTS,
                technique_name="Valid Accounts",
                tactic=MITRETactic.INITIAL_ACCESS,
                tactic_name="Initial Access",
                description="Adversaries may obtain and abuse credentials of existing accounts.",
                detection_methods=[
                    "Account usage monitoring",
                    "Failed login tracking",
                    "Anomalous access patterns",
                    "Privileged account monitoring"
                ],
                mitigation_strategies=[
                    "Multi-factor authentication",
                    "Account lockout policies",
                    "Privileged access management",
                    "Regular credential rotation"
                ],
                references=["https://attack.mitre.org/techniques/T1078/"],
                platforms=["Azure AD", "IAM", "All"]
            ),
            
            MITRETechnique.EXPLOIT_PUBLIC_FACING_APP: MITREAttackPattern(
                technique_id=MITRETechnique.EXPLOIT_PUBLIC_FACING_APP,
                technique_name="Exploit Public-Facing Application",
                tactic=MITRETactic.INITIAL_ACCESS,
                tactic_name="Initial Access",
                description="Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.",
                detection_methods=[
                    "Web application firewalls",
                    "Application logs",
                    "Vulnerability scanning",
                    "Network traffic analysis"
                ],
                mitigation_strategies=[
                    "Regular patching",
                    "Web application firewalls",
                    "Input validation",
                    "Secure coding practices"
                ],
                references=["https://attack.mitre.org/techniques/T1190/"],
                platforms=["Web Apps", "Storage", "Network"]
            ),
            
            # Persistence
            MITRETechnique.CREATE_ACCOUNT: MITREAttackPattern(
                technique_id=MITRETechnique.CREATE_ACCOUNT,
                technique_name="Create Account",
                tactic=MITRETactic.PERSISTENCE,
                tactic_name="Persistence",
                description="Adversaries may create accounts to maintain access to victim systems.",
                detection_methods=[
                    "Account creation monitoring",
                    "Audit log analysis",
                    "New account alerts",
                    "Privilege escalation monitoring"
                ],
                mitigation_strategies=[
                    "Account creation policies",
                    "Approval workflows",
                    "Regular account reviews",
                    "Least privilege principle"
                ],
                references=["https://attack.mitre.org/techniques/T1136/"],
                platforms=["Azure AD", "IAM", "All"]
            ),
            
            # Privilege Escalation
            MITRETechnique.ABUSE_ELEVATION_CONTROL: MITREAttackPattern(
                technique_id=MITRETechnique.ABUSE_ELEVATION_CONTROL,
                technique_name="Abuse Elevation Control Mechanism",
                tactic=MITRETactic.PRIVILEGE_ESCALATION,
                tactic_name="Privilege Escalation",
                description="Adversaries may bypass or disable mechanisms to gain elevated permissions.",
                detection_methods=[
                    "Privilege usage monitoring",
                    "System integrity checks",
                    "Process monitoring",
                    "Permission changes tracking"
                ],
                mitigation_strategies=[
                    "Principle of least privilege",
                    "Application control",
                    "User account control",
                    "Regular privilege reviews"
                ],
                references=["https://attack.mitre.org/techniques/T1548/"],
                platforms=["Windows", "Linux", "All"]
            ),
            
            # Defense Evasion
            MITRETechnique.DISABLE_OR_TOOLS: MITREAttackPattern(
                technique_id=MITRETechnique.DISABLE_OR_TOOLS,
                technique_name="Disable or Modify Tools",
                tactic=MITRETactic.DEFENSE_EVASION,
                tactic_name="Defense Evasion",
                description="Adversaries may modify or disable security tools to avoid detection.",
                detection_methods=[
                    "Security tool monitoring",
                "Configuration change tracking",
                "Service status monitoring",
                "Integrity monitoring"
                ],
                mitigation_strategies=[
                    "Tamper protection",
                    "Immutable logging",
                    "Security tool hardening",
                    "Monitoring for changes"
                ],
                references=["https://attack.mitre.org/techniques/T1562/"],
                platforms=["All", "Security Tools"]
            ),
            
            # Credential Access
            MITRETechnique.UNSECURED_CREDENTIALS: MITREAttackPattern(
                technique_id=MITRETechnique.UNSECURED_CREDENTIALS,
                technique_name="Unsecured Credentials",
                tactic=MITRETactic.CREDENTIAL_ACCESS,
                tactic_name="Credential Access",
                description="Adversaries may search for unsecured credentials in various locations.",
                detection_methods=[
                    "File access monitoring",
                    "Credential storage monitoring",
                    "Data loss prevention",
                    "Anomalous file access"
                ],
                mitigation_strategies=[
                    "Secure credential storage",
                    "Encryption at rest",
                    "Access controls",
                    "Regular credential audits"
                ],
                references=["https://attack.mitre.org/techniques/T1552/"],
                platforms=["All", "Storage", "Key Management"]
            ),
            
            # Discovery
            MITRETechnique.NETWORK_DISCOVERY: MITREAttackPattern(
                technique_id=MITRETechnique.NETWORK_DISCOVERY,
                technique_name="Network Share Discovery",
                tactic=MITRETactic.DISCOVERY,
                tactic_name="Discovery",
                description="Adversaries may attempt to get a listing of network shares.",
                detection_methods=[
                    "Network traffic monitoring",
                    "SMB monitoring",
                    "File share access logs",
                    "Anomalous network behavior"
                ],
                mitigation_strategies=[
                    "Network segmentation",
                    "Access controls",
                    "Network monitoring",
                    "Share permission reviews"
                ],
                references=["https://attack.mitre.org/techniques/T1018/"],
                platforms=["Network", "Storage", "All"]
            ),
            
            MITRETechnique.ACCOUNT_DISCOVERY: MITREAttackPattern(
                technique_id=MITRETechnique.ACCOUNT_DISCOVERY,
                technique_name="Account Discovery",
                tactic=MITRETactic.DISCOVERY,
                tactic_name="Discovery",
                description="Adversaries may attempt to get a listing of accounts on the system.",
                detection_methods=[
                    "Account enumeration monitoring",
                    "Authentication logs",
                    "User behavior analytics",
                    "Account access patterns"
                ],
                mitigation_strategies=[
                    "Account access controls",
                    "Monitoring for enumeration",
                    "Account hiding techniques",
                    "Regular access reviews"
                ],
                references=["https://attack.mitre.org/techniques/T1087/"],
                platforms=["All", "IAM", "Azure AD"]
            ),
            
            # Lateral Movement
            MITRETechnique.REMOTE_SERVICES: MITREAttackPattern(
                technique_id=MITRETechnique.REMOTE_SERVICES,
                technique_name="Remote Services",
                tactic=MITRETactic.LATERAL_MOVEMENT,
                tactic_name="Lateral Movement",
                description="Adversaries may use remote services to move laterally across networks.",
                detection_methods=[
                    "Remote access monitoring",
                    "Network traffic analysis",
                    "Authentication logs",
                    "Connection tracking"
                ],
                mitigation_strategies=[
                    "Network segmentation",
                    "Access controls",
                    "Multi-factor authentication",
                    "Remote access policies"
                ],
                references=["https://attack.mitre.org/techniques/T1021/"],
                platforms=["Network", "Remote Access", "All"]
            ),
            
            # Collection
            MITRETechnique.DATA_FROM_LOCAL_SYSTEM: MITREAttackPattern(
                technique_id=MITRETechnique.DATA_FROM_LOCAL_SYSTEM,
                technique_name="Data from Local System",
                tactic=MITRETactic.COLLECTION,
                tactic_name="Collection",
                description="Adversaries may collect data from the local system.",
                detection_methods=[
                    "File access monitoring",
                    "Data access patterns",
                    "Process monitoring",
                    "Data loss prevention"
                ],
                mitigation_strategies=[
                    "Data classification",
                    "Access controls",
                    "Encryption",
                    "Data loss prevention"
                ],
                references=["https://attack.mitre.org/techniques/T1005/"],
                platforms=["All", "Storage", "File Systems"]
            ),
            
            # Exfiltration
            MITRETechnique.EXFILTRATION_OVER_NETWORK: MITREAttackPattern(
                technique_id=MITRETechnique.EXFILTRATION_OVER_NETWORK,
                technique_name="Exfiltration Over Network",
                tactic=MITRETactic.EXFILTRATION,
                tactic_name="Exfiltration",
                description="Adversaries may steal data by exfiltrating it over network.",
                detection_methods=[
                    "Network traffic monitoring",
                    "Data transfer analysis",
                    "Anomalous connections",
                    "Data loss prevention"
                ],
                mitigation_strategies=[
                    "Network segmentation",
                    "Data loss prevention",
                    "Traffic inspection",
                    "Egress filtering"
                ],
                references=["https://attack.mitre.org/techniques/T1041/"],
                platforms=["Network", "All", "Data Transfer"]
            ),
            
            # Impact
            MITRETechnique.DATA_DESTRUCTION: MITREAttackPattern(
                technique_id=MITRETechnique.DATA_DESTRUCTION,
                technique_name="Data Destruction",
                tactic=MITRETactic.IMPACT,
                tactic_name="Impact",
                description="Adversaries may destroy data to disrupt operations or harm the organization.",
                detection_methods=[
                    "File deletion monitoring",
                    "Data integrity checks",
                    "Backup monitoring",
                    "System logs"
                ],
                mitigation_strategies=[
                    "Regular backups",
                    "Data immutability",
                    "Access controls",
                    "Recovery planning"
                ],
                references=["https://attack.mitre.org/techniques/T1485/"],
                platforms=["All", "Storage", "Data"]
            ),
            
            MITRETechnique.RESOURCE_HIJACKING: MITREAttackPattern(
                technique_id=MITRETechnique.RESOURCE_HIJACKING,
                technique_name="Resource Hijacking",
                tactic=MITRETactic.IMPACT,
                tactic_name="Impact",
                description="Adversaries may hijack legitimate computing resources for their own purposes.",
                detection_methods=[
                    "Resource utilization monitoring",
                    "Process monitoring",
                    "Network traffic analysis",
                    "Performance monitoring"
                ],
                mitigation_strategies=[
                    "Resource monitoring",
                    "Access controls",
                    "Usage limits",
                    "Anomaly detection"
                ],
                references=["https://attack.mitre.org/techniques/T1496/"],
                platforms=["Compute", "All", "Cloud"]
            )
        }
    
    def _create_technique_mappings(self) -> Dict[str, List[MITRETechnique]]:
        """Create keyword-based mappings to MITRE techniques."""
        return {
            # Storage-related findings
            "public_blob_access": [MITRETechnique.EXPLOIT_PUBLIC_FACING_APP, MITRETechnique.DATA_FROM_LOCAL_SYSTEM],
            "insecure_transfer": [MITRETechnique.EXFILTRATION_OVER_NETWORK],
            "storage_encryption": [MITRETechnique.UNSECURED_CREDENTIALS],
            "default_network_access": [MITRETechnique.EXPLOIT_PUBLIC_FACING_APP],
            
            # Network-related findings
            "overly_permissive_inbound": [MITRETechnique.EXPLOIT_PUBLIC_FACING_APP, MITRETechnique.REMOTE_SERVICES],
            "rdp_from_internet": [MITRETechnique.REMOTE_SERVICES, MITRETechnique.VALID_ACCOUNTS],
            "ssh_from_internet": [MITRETechnique.REMOTE_SERVICES, MITRETechnique.VALID_ACCOUNTS],
            "network_security": [MITRETechnique.NETWORK_DISCOVERY, MITRETechnique.REMOTE_SERVICES],
            
            # Key Vault findings
            "public_network_access": [MITRETechnique.EXPLOIT_PUBLIC_FACING_APP, MITRETechnique.UNSECURED_CREDENTIALS],
            "soft_delete_not_enabled": [MITRETechnique.DATA_DESTRUCTION],
            "purge_protection_not_enabled": [MITRETechnique.DATA_DESTRUCTION],
            "rbac_authorization": [MITRETechnique.ABUSE_ELEVATION_CONTROL, MITRETechnique.VALID_ACCOUNTS],
            
            # General findings
            "access_control": [MITRETechnique.VALID_ACCOUNTS, MITRETechnique.ABUSE_ELEVATION_CONTROL],
            "authentication": [MITRETechnique.VALID_ACCOUNTS],
            "privilege": [MITRETechnique.ABUSE_ELEVATION_CONTROL],
            "encryption": [MITRETechnique.UNSECURED_CREDENTIALS],
            "monitoring": [MITRETechnique.DISABLE_OR_TOOLS],
            "audit": [MITRETechnique.DISABLE_OR_TOOLS],
            "logging": [MITRETechnique.DISABLE_OR_TOOLS],
            "backup": [MITRETechnique.DATA_DESTRUCTION],
            "recovery": [MITRETechnique.DATA_DESTRUCTION],
            "resource": [MITRETechnique.RESOURCE_HIJACKING],
            "compute": [MITRETechnique.RESOURCE_HIJACKING],
            "data": [MITRETechnique.DATA_FROM_LOCAL_SYSTEM, MITRETechnique.EXFILTRATION_OVER_NETWORK],
            "network": [MITRETechnique.NETWORK_DISCOVERY, MITRETechnique.REMOTE_SERVICES],
            "account": [MITRETechnique.VALID_ACCOUNTS, MITRETechnique.CREATE_ACCOUNT, MITRETechnique.ACCOUNT_DISCOVERY],
            "credential": [MITRETechnique.UNSECURED_CREDENTIALS],
            "scan": [MITRETechnique.ACTIVE_SCANNING],
            "discovery": [MITRETechnique.NETWORK_DISCOVERY, MITRETechnique.ACCOUNT_DISCOVERY],
            "lateral": [MITRETechnique.REMOTE_SERVICES],
            "movement": [MITRETechnique.REMOTE_SERVICES],
            "exfiltration": [MITRETechnique.EXFILTRATION_OVER_NETWORK],
            "destruction": [MITRETechnique.DATA_DESTRUCTION],
            "impact": [MITRETechnique.DATA_DESTRUCTION, MITRETechnique.RESOURCE_HIJACKING]
        }
    
    def _load_tactic_hierarchy(self) -> Dict[MITRETactic, List[str]]:
        """Load MITRE ATT&CK tactic hierarchy."""
        return {
            MITRETactic.RECONNAISSANCE: ["Pre-attack", "Information Gathering"],
            MITRETactic.RESOURCE_DEVELOPMENT: ["Pre-attack", "Preparation"],
            MITRETactic.INITIAL_ACCESS: ["Initial Access", "Compromise"],
            MITRETactic.EXECUTION: ["Execution", "Command and Control"],
            MITRETactic.PERSISTENCE: ["Persistence", "Maintain Access"],
            MITRETactic.PRIVILEGE_ESCALATION: ["Privilege Escalation", "Expand Access"],
            MITRETactic.DEFENSE_EVASION: ["Defense Evasion", "Stealth"],
            MITRETactic.CREDENTIAL_ACCESS: ["Credential Access", "Collection"],
            MITRETactic.DISCOVERY: ["Discovery", "Collection"],
            MITRETactic.LATERAL_MOVEMENT: ["Lateral Movement", "Expand Access"],
            MITRETactic.COLLECTION: ["Collection", "Data Gathering"],
            MITRETactic.COMMAND_AND_CONTROL: ["Command and Control", "C2"],
            MITRETactic.EXFILTRATION: ["Exfiltration", "Data Theft"],
            MITRETactic.IMPACT: ["Impact", "Destruction"]
        }
    
    def map_finding_to_mitre_attack(self, finding: SecurityFinding) -> List[AttackPatternMatch]:
        """Map a security finding to MITRE ATT&CK techniques."""
        matches = []
        
        # Extract keywords from finding
        finding_text = f"{finding.title} {finding.description}".lower()
        keywords = self._extract_keywords(finding_text)
        
        # Find matching techniques
        matched_techniques = set()
        
        for keyword in keywords:
            if keyword in self.technique_mappings:
                matched_techniques.update(self.technique_mappings[keyword])
        
        # Create attack pattern matches
        for technique in matched_techniques:
            if technique in self.attack_patterns:
                pattern = self.attack_patterns[technique]
                
                # Calculate confidence score
                confidence = self._calculate_confidence_score(keywords, technique, finding)
                
                if confidence > 0.3:  # Minimum confidence threshold
                    match = AttackPatternMatch(
                        finding_id=finding.id,
                        technique_id=technique,
                        technique_name=pattern.technique_name,
                        tactic=pattern.tactic,
                        tactic_name=pattern.tactic_name,
                        confidence_score=confidence,
                        matching_keywords=self._get_matching_keywords(keywords, technique),
                        detection_recommendations=pattern.detection_methods
                    )
                    matches.append(match)
        
        # Sort by confidence score
        matches.sort(key=lambda x: x.confidence_score, reverse=True)
        
        return matches[:3]  # Return top 3 matches
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract relevant keywords from text."""
        # Simple keyword extraction - in practice, you might use NLP techniques
        keywords = []
        
        # Define important security keywords
        security_keywords = [
            "public", "access", "network", "security", "encryption", "storage", "data",
            "account", "credential", "authentication", "privilege", "escalation", "scan",
            "discovery", "lateral", "movement", "exfiltration", "destruction", "impact",
            "resource", "compute", "monitoring", "audit", "logging", "backup", "recovery",
            "rbac", "authorization", "firewall", "network", "internet", "ssh", "rdp",
            "blob", "file", "transfer", "secure", "insecure", "delete", "purge", "soft"
        ]
        
        text_lower = text.lower()
        
        for keyword in security_keywords:
            if keyword in text_lower:
                keywords.append(keyword)
        
        return keywords
    
    def _calculate_confidence_score(self, keywords: List[str], technique: MITRETechnique, 
                                  finding: SecurityFinding) -> float:
        """Calculate confidence score for technique match."""
        base_confidence = 0.0
        
        # Check keyword matches
        matching_keywords = self._get_matching_keywords(keywords, technique)
        keyword_match_ratio = len(matching_keywords) / len(keywords) if keywords else 0
        base_confidence += keyword_match_ratio * 0.6
        
        # Consider severity
        severity_weights = {
            SeverityLevel.CRITICAL: 0.2,
            SeverityLevel.HIGH: 0.15,
            SeverityLevel.MEDIUM: 0.1,
            SeverityLevel.LOW: 0.05,
            SeverityLevel.INFO: 0.02
        }
        base_confidence += severity_weights.get(finding.severity, 0)
        
        # Consider resource type relevance
        if technique in self.attack_patterns:
            pattern = self.attack_patterns[technique]
            if "All" in pattern.platforms or finding.resource_type.value in pattern.platforms:
                base_confidence += 0.1
        
        return min(1.0, base_confidence)
    
    def _get_matching_keywords(self, keywords: List[str], technique: MITRETechnique) -> List[str]:
        """Get keywords that match a technique."""
        matching_keywords = []
        
        if technique in self.technique_mappings:
            # This is a simplified approach - in practice, you'd have more sophisticated matching
            for keyword in keywords:
                if keyword in self.technique_mappings and technique in self.technique_mappings[keyword]:
                    matching_keywords.append(keyword)
        
        return matching_keywords
    
    def analyze_attack_patterns(self, findings: List[SecurityFinding]) -> Dict:
        """Analyze attack patterns across all findings."""
        attack_pattern_analysis = {
            "technique_distribution": {},
            "tactic_distribution": {},
            "high_confidence_matches": [],
            "attack_chain_analysis": {},
            "detection_gaps": [],
            "mitigation_priorities": []
        }
        
        # Map all findings to attack patterns
        all_matches = []
        for finding in findings:
            matches = self.map_finding_to_mitre_attack(finding)
            all_matches.extend(matches)
        
        # Analyze technique distribution
        technique_counts = Counter(match.technique_id.value for match in all_matches)
        attack_pattern_analysis["technique_distribution"] = dict(technique_counts.most_common(10))
        
        # Analyze tactic distribution
        tactic_counts = Counter(match.tactic.value for match in all_matches)
        attack_pattern_analysis["tactic_distribution"] = dict(tactic_counts.most_common())
        
        # High confidence matches
        attack_pattern_analysis["high_confidence_matches"] = [
            {
                "finding_id": match.finding_id,
                "technique_id": match.technique_id.value,
                "technique_name": match.technique_name,
                "tactic": match.tactic.value,
                "tactic_name": match.tactic_name,
                "confidence_score": match.confidence_score,
                "matching_keywords": match.matching_keywords
            }
            for match in all_matches
            if match.confidence_score > 0.7
        ]
        
        # Attack chain analysis
        attack_pattern_analysis["attack_chain_analysis"] = self._analyze_attack_chains(all_matches)
        
        # Detection gaps
        attack_pattern_analysis["detection_gaps"] = self._identify_detection_gaps(all_matches)
        
        # Mitigation priorities
        attack_pattern_analysis["mitigation_priorities"] = self._prioritize_mitigations(all_matches)
        
        return attack_pattern_analysis
    
    def _analyze_attack_chains(self, matches: List[AttackPatternMatch]) -> Dict:
        """Analyze potential attack chains."""
        # Group tactics by finding to identify potential chains
        finding_tactics = defaultdict(list)
        for match in matches:
            finding_tactics[match.finding_id].append(match.tactic)
        
        # Identify common attack chains
        attack_chains = {
            "reconnaissance_to_initial_access": 0,
            "initial_access_to_execution": 0,
            "execution_to_persistence": 0,
            "persistence_to_privilege_escalation": 0,
            "privilege_escalation_to_lateral_movement": 0,
            "lateral_movement_to_exfiltration": 0,
            "exfiltration_to_impact": 0
        }
        
        # Simple chain detection based on tactic combinations
        for finding_id, tactics in finding_tactics.items():
            tactic_set = set(tactics)
            
            if MITRETactic.RECONNAISSANCE in tactic_set and MITRETactic.INITIAL_ACCESS in tactic_set:
                attack_chains["reconnaissance_to_initial_access"] += 1
            
            if MITRETactic.INITIAL_ACCESS in tactic_set and MITRETactic.EXECUTION in tactic_set:
                attack_chains["initial_access_to_execution"] += 1
            
            if MITRETactic.EXECUTION in tactic_set and MITRETactic.PERSISTENCE in tactic_set:
                attack_chains["execution_to_persistence"] += 1
            
            if MITRETactic.PERSISTENCE in tactic_set and MITRETactic.PRIVILEGE_ESCALATION in tactic_set:
                attack_chains["persistence_to_privilege_escalation"] += 1
            
            if MITRETactic.PRIVILEGE_ESCALATION in tactic_set and MITRETactic.LATERAL_MOVEMENT in tactic_set:
                attack_chains["privilege_escalation_to_lateral_movement"] += 1
            
            if MITRETactic.LATERAL_MOVEMENT in tactic_set and MITRETactic.EXFILTRATION in tactic_set:
                attack_chains["lateral_movement_to_exfiltration"] += 1
            
            if MITRETactic.EXFILTRATION in tactic_set and MITRETactic.IMPACT in tactic_set:
                attack_chains["exfiltration_to_impact"] += 1
        
        return attack_chains
    
    def _identify_detection_gaps(self, matches: List[AttackPatternMatch]) -> List[Dict]:
        """Identify detection gaps based on attack patterns."""
        detection_gaps = []
        
        # Group by technique
        technique_matches = defaultdict(list)
        for match in matches:
            technique_matches[match.technique_id].append(match)
        
        # Identify techniques with high confidence but no detection recommendations
        for technique, technique_matches_list in technique_matches.items():
            if technique in self.attack_patterns:
                pattern = self.attack_patterns[technique]
                avg_confidence = sum(m.confidence_score for m in technique_matches_list) / len(technique_matches_list)
                
                if avg_confidence > 0.6:
                    detection_gaps.append({
                        "technique_id": technique.value,
                        "technique_name": pattern.technique_name,
                        "tactic": pattern.tactic.value,
                        "tactic_name": pattern.tactic_name,
                        "average_confidence": round(avg_confidence, 2),
                        "finding_count": len(technique_matches_list),
                        "detection_methods": pattern.detection_methods,
                        "priority": "high" if avg_confidence > 0.8 else "medium"
                    })
        
        # Sort by confidence
        detection_gaps.sort(key=lambda x: x["average_confidence"], reverse=True)
        
        return detection_gaps[:10]  # Top 10 detection gaps
    
    def _prioritize_mitigations(self, matches: List[AttackPatternMatch]) -> List[Dict]:
        """Prioritize mitigation strategies based on attack patterns."""
        mitigation_priorities = []
        
        # Group by technique
        technique_matches = defaultdict(list)
        for match in matches:
            technique_matches[match.technique_id].append(match)
        
        # Calculate risk scores for techniques
        technique_risks = {}
        for technique, technique_matches_list in technique_matches.items():
            if technique in self.attack_patterns:
                pattern = self.attack_patterns[technique]
                
                # Calculate risk based on confidence and frequency
                avg_confidence = sum(m.confidence_score for m in technique_matches_list) / len(technique_matches_list)
                frequency = len(technique_matches_list)
                risk_score = avg_confidence * frequency * 10  # Scale to 0-100
                
                technique_risks[technique] = {
                    "risk_score": risk_score,
                    "pattern": pattern,
                    "frequency": frequency,
                    "avg_confidence": avg_confidence
                }
        
        # Sort by risk score
        sorted_techniques = sorted(technique_risks.items(), key=lambda x: x[1]["risk_score"], reverse=True)
        
        # Create mitigation priorities
        for technique, risk_data in sorted_techniques[:10]:
            pattern = risk_data["pattern"]
            
            mitigation_priorities.append({
                "technique_id": technique.value,
                "technique_name": pattern.technique_name,
                "tactic": pattern.tactic.value,
                "tactic_name": pattern.tactic_name,
                "risk_score": round(risk_data["risk_score"], 2),
                "frequency": risk_data["frequency"],
                "average_confidence": round(risk_data["avg_confidence"], 2),
                "mitigation_strategies": pattern.mitigation_strategies,
                "detection_methods": pattern.detection_methods,
                "references": pattern.references
            })
        
        return mitigation_priorities
    
    def generate_mitre_attack_report(self, findings: List[SecurityFinding]) -> Dict:
        """Generate comprehensive MITRE ATT&CK analysis report."""
        attack_pattern_analysis = self.analyze_attack_patterns(findings)
        
        # Generate executive summary
        executive_summary = {
            "total_techniques_identified": len(attack_pattern_analysis["technique_distribution"]),
            "total_tactics_identified": len(attack_pattern_analysis["tactic_distribution"]),
            "high_confidence_matches": len(attack_pattern_analysis["high_confidence_matches"]),
            "top_techniques": list(attack_pattern_analysis["technique_distribution"].keys())[:5],
            "primary_attack_vectors": self._identify_primary_attack_vectors(attack_pattern_analysis),
            "critical_detection_gaps": len([
                gap for gap in attack_pattern_analysis["detection_gaps"]
                if gap["priority"] == "high"
            ])
        }
        
        return {
            "executive_summary": executive_summary,
            "attack_pattern_analysis": attack_pattern_analysis,
            "tactical_analysis": self._generate_tactical_analysis(attack_pattern_analysis),
            "recommendations": self._generate_mitre_recommendations(attack_pattern_analysis),
            "detection_roadmap": self._generate_detection_roadmap(attack_pattern_analysis)
        }
    
    def _identify_primary_attack_vectors(self, analysis: Dict) -> List[str]:
        """Identify primary attack vectors from analysis."""
        primary_vectors = []
        
        # Get top tactics
        top_tactics = sorted(
            analysis["tactic_distribution"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:3]
        
        for tactic_id, count in top_tactics:
            if tactic_id in self.tactic_hierarchy:
                tactic_name = self.tactic_hierarchy[tactic_id][0]
                primary_vectors.append(f"{tactic_name} ({count} findings)")
        
        return primary_vectors
    
    def _generate_tactical_analysis(self, analysis: Dict) -> Dict:
        """Generate tactical analysis."""
        tactical_analysis = {
            "attack_lifecycle": {},
            "tactic_severity": {},
            "coverage_gaps": []
        }
        
        # Analyze attack lifecycle coverage
        lifecycle_phases = [
            "Pre-attack", "Initial Access", "Execution", "Persistence",
            "Privilege Escalation", "Defense Evasion", "Credential Access",
            "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"
        ]
        
        for phase in lifecycle_phases:
            phase_count = 0
            for tactic_id, tactic_data in self.tactic_hierarchy.items():
                if phase in tactic_data and tactic_id.value in analysis["tactic_distribution"]:
                    phase_count += analysis["tactic_distribution"][tactic_id.value]
            
            tactical_analysis["attack_lifecycle"][phase] = phase_count
        
        return tactical_analysis
    
    def _generate_mitre_recommendations(self, analysis: Dict) -> List[str]:
        """Generate MITRE ATT&CK based recommendations."""
        recommendations = []
        
        # High confidence technique recommendations
        high_confidence_count = len(analysis["high_confidence_matches"])
        if high_confidence_count > 0:
            recommendations.append(
                f"URGENT: {high_confidence_count} high-confidence MITRE ATT&CK technique matches detected. "
                f"Implement corresponding detection and mitigation strategies."
            )
        
        # Detection gap recommendations
        critical_gaps = len([
            gap for gap in analysis["detection_gaps"]
            if gap["priority"] == "high"
        ])
        
        if critical_gaps > 0:
            recommendations.append(
                f"CRITICAL: {critical_gaps} critical detection gaps identified. "
                f"Prioritize implementing detection methods for these techniques."
            )
        
        # Attack chain recommendations
        attack_chains = analysis["attack_chain_analysis"]
        high_risk_chains = [
            chain for chain, count in attack_chains.items()
            if count > 2
        ]
        
        if high_risk_chains:
            recommendations.append(
                f"Multiple potential attack chains detected: {', '.join(high_risk_chains)}. "
                f"Implement controls to break these attack chains."
            )
        
        # Tactic-specific recommendations
        top_tactics = sorted(
            analysis["tactic_distribution"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:3]
        
        for tactic_id, count in top_tactics:
            if tactic_id in self.tactic_hierarchy:
                tactic_name = self.tactic_hierarchy[tactic_id][0]
                recommendations.append(
                    f"Strengthen defenses against {tactic_name} tactics ({count} findings). "
                    f"Review and enhance corresponding security controls."
                )
        
        if not recommendations:
            recommendations.append(
                "MITRE ATT&CK analysis shows good coverage. Continue monitoring for new attack patterns."
            )
        
        return recommendations
    
    def _generate_detection_roadmap(self, analysis: Dict) -> Dict:
        """Generate detection roadmap based on analysis."""
        roadmap = {
            "immediate": [],
            "short_term": [],
            "long_term": []
        }
        
        # Prioritize detection gaps
        for gap in analysis["detection_gaps"]:
            priority = gap["priority"]
            detection_methods = gap["detection_methods"]
            
            roadmap_item = {
                "technique": gap["technique_name"],
                "tactic": gap["tactic_name"],
                "detection_methods": detection_methods,
                "confidence": gap["average_confidence"]
            }
            
            if priority == "high":
                roadmap["immediate"].append(roadmap_item)
            elif priority == "medium":
                roadmap["short_term"].append(roadmap_item)
            else:
                roadmap["long_term"].append(roadmap_item)
        
        return roadmap


# Global MITRE ATT&CK mapper instance
mitre_attack_mapper = MITREAttackMapper()
