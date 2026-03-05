"""Threat modeling and attack surface analysis."""

from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
from dataclasses import dataclass
from collections import defaultdict, Counter

from .models import SecurityFinding, SeverityLevel, ResourceType


class ThreatActor(str, Enum):
    """Types of threat actors."""
    INSIDER_THREAT = "insider_threat"
    EXTERNAL_ATTACKER = "external_attacker"
    COMPETITOR = "competitor"
    CYBERCRIMINAL = "cybercriminal"
    ADVANCED_PERSISTENT_THREAT = "advanced_persistent_threat"
    HACKTIVIST = "hacktivist"


class AttackVector(str, Enum):
    """Attack vectors."""
    NETWORK = "network"
    LOCAL = "local"
    PHYSICAL = "physical"
    SOCIAL_ENGINEERING = "social_engineering"
    SUPPLY_CHAIN = "supply_chain"
    MISCONFIGURATION = "misconfiguration"


class ThreatCategory(str, Enum):
    """Threat categories."""
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_HIJACKING = "resource_hijacking"


@dataclass
class Threat:
    """Threat definition."""
    threat_id: str
    name: str
    description: str
    category: ThreatCategory
    attack_vectors: List[AttackVector]
    threat_actors: List[ThreatActor]
    likelihood: str  # low, medium, high
    impact: str  # low, medium, high
    mitigations: List[str]
    detection_methods: List[str]


@dataclass
class AttackSurface:
    """Attack surface component."""
    component_id: str
    name: str
    resource_type: ResourceType
    exposure_level: str  # internal, external, internet_facing
    attack_vectors: List[AttackVector]
    vulnerabilities: List[str]
    risk_score: int


class ThreatModelingEngine:
    """Engine for threat modeling and attack surface analysis."""
    
    def __init__(self):
        self.threats = self._load_threat_library()
        self.attack_patterns = self._load_attack_patterns()
        self.resource_exposure = self._load_resource_exposure_data()
    
    def _load_threat_library(self) -> Dict[str, Threat]:
        """Load threat library."""
        return {
            "data_breach": Threat(
                threat_id="data_breach",
                name="Data Breach",
                description="Unauthorized access and exfiltration of sensitive data",
                category=ThreatCategory.DATA_EXFILTRATION,
                attack_vectors=[AttackVector.NETWORK, AttackVector.LOCAL, AttackVector.MISCONFIGURATION],
                threat_actors=[ThreatActor.EXTERNAL_ATTACKER, ThreatActor.INSIDER_THREAT, ThreatActor.CYBERCRIMINAL],
                likelihood="medium",
                impact="high",
                mitigations=[
                    "Implement strong access controls",
                    "Encrypt sensitive data",
                    "Monitor for unusual data access patterns",
                    "Implement data loss prevention"
                ],
                detection_methods=[
                    "Data access monitoring",
                    "Network traffic analysis",
                    "User behavior analytics",
                    "File integrity monitoring"
                ]
            ),
            "privilege_escalation": Threat(
                threat_id="privilege_escalation",
                name="Privilege Escalation",
                description="Gaining higher-level privileges than authorized",
                category=ThreatCategory.PRIVILEGE_ESCALATION,
                attack_vectors=[AttackVector.LOCAL, AttackVector.MISCONFIGURATION, AttackVector.SOCIAL_ENGINEERING],
                threat_actors=[ThreatActor.EXTERNAL_ATTACKER, ThreatActor.INSIDER_THREAT],
                likelihood="medium",
                impact="high",
                mitigations=[
                    "Implement principle of least privilege",
                    "Regular privilege reviews",
                    "Strong authentication mechanisms",
                    "Monitor privilege changes"
                ],
                detection_methods=[
                    "Privilege usage monitoring",
                    "Account change monitoring",
                    "System log analysis",
                    "Behavior analytics"
                ]
            ),
            "lateral_movement": Threat(
                threat_id="lateral_movement",
                name="Lateral Movement",
                description="Moving between systems and resources within the network",
                category=ThreatCategory.LATERAL_MOVEMENT,
                attack_vectors=[AttackVector.NETWORK, AttackVector.LOCAL],
                threat_actors=[ThreatActor.EXTERNAL_ATTACKER, ThreatActor.ADVANCED_PERSISTENT_THREAT],
                likelihood="medium",
                impact="high",
                mitigations=[
                    "Network segmentation",
                    "Zero trust architecture",
                    "Strong authentication between services",
                    "Monitor network traffic"
                ],
                detection_methods=[
                    "Network flow monitoring",
                    "Authentication log analysis",
                    "Process monitoring",
                    "Network anomaly detection"
                ]
            ),
            "resource_hijacking": Threat(
                threat_id="resource_hijacking",
                name="Resource Hijacking",
                description="Unauthorized use of computing resources",
                category=ThreatCategory.RESOURCE_HIJACKING,
                attack_vectors=[AttackVector.NETWORK, AttackVector.MISCONFIGURATION],
                threat_actors=[ThreatActor.CYBERCRIMINAL],
                likelihood="medium",
                impact="medium",
                mitigations=[
                    "Resource usage monitoring",
                    "Strong access controls",
                    "Regular security updates",
                    "Network security groups"
                ],
                detection_methods=[
                    "Resource utilization monitoring",
                    "Network traffic analysis",
                    "Process monitoring",
                    "Unusual connection detection"
                ]
            ),
            "denial_of_service": Threat(
                threat_id="denial_of_service",
                name="Denial of Service",
                description="Making resources unavailable to legitimate users",
                category=ThreatCategory.DENIAL_OF_SERVICE,
                attack_vectors=[AttackVector.NETWORK, AttackVector.PHYSICAL],
                threat_actors=[ThreatActor.CYBERCRIMINAL, ThreatActor.HACKTIVIST],
                likelihood="medium",
                impact="medium",
                mitigations=[
                    "DDoS protection services",
                    "Rate limiting",
                    "Traffic filtering",
                    "Redundant infrastructure"
                ],
                detection_methods=[
                    "Traffic volume monitoring",
                    "Service availability monitoring",
                    "Network anomaly detection",
                    "Performance monitoring"
                ]
            ),
            "reconnaissance": Threat(
                threat_id="reconnaissance",
                name="Reconnaissance",
                description="Information gathering about target systems",
                category=ThreatCategory.RECONNAISSANCE,
                attack_vectors=[AttackVector.NETWORK, AttackVector.SOCIAL_ENGINEERING],
                threat_actors=[ThreatActor.EXTERNAL_ATTACKER, ThreatActor.COMPETITOR],
                likelihood="high",
                impact="low",
                mitigations=[
                    "Information disclosure prevention",
                    "Network security monitoring",
                    "Public exposure minimization",
                    "Security through obscurity"
                ],
                detection_methods=[
                    "Port scanning detection",
                    "DNS query monitoring",
                    "Web application firewalls",
                    "Log analysis"
                ]
            ),
            "persistence": Threat(
                threat_id="persistence",
                name="Persistence",
                description="Maintaining access to compromised systems",
                category=ThreatCategory.PERSISTENCE,
                attack_vectors=[AttackVector.LOCAL, AttackVector.NETWORK, AttackVector.MISCONFIGURATION],
                threat_actors=[ThreatActor.ADVANCED_PERSISTENT_THREAT, ThreatActor.EXTERNAL_ATTACKER],
                likelihood="medium",
                impact="high",
                mitigations=[
                    "Regular system updates",
                    "Malware detection",
                    "System integrity monitoring",
                    "Secure configuration management"
                ],
                detection_methods=[
                    "File integrity monitoring",
                    "Process monitoring",
                    "Registry monitoring",
                    "Scheduled task monitoring"
                ]
            ),
            "unauthorized_access": Threat(
                threat_id="unauthorized_access",
                name="Unauthorized Access",
                description="Accessing resources without proper authorization",
                category=ThreatCategory.UNAUTHORIZED_ACCESS,
                attack_vectors=[AttackVector.NETWORK, AttackVector.LOCAL, AttackVector.SOCIAL_ENGINEERING],
                threat_actors=[ThreatActor.EXTERNAL_ATTACKER, ThreatActor.INSIDER_THREAT],
                likelihood="high",
                impact="medium",
                mitigations=[
                    "Strong authentication",
                    "Authorization controls",
                    "Regular access reviews",
                    "Multi-factor authentication"
                ],
                detection_methods=[
                    "Access log monitoring",
                    "Failed login monitoring",
                    "User behavior analytics",
                    "Session monitoring"
                ]
            )
        }
    
    def _load_attack_patterns(self) -> Dict[str, List[str]]:
        """Load attack patterns for different resource types."""
        return {
            "Microsoft.Storage/storageAccounts": [
                "public_blob_access",
                "insecure_transfer",
                "data_exfiltration",
                "malicious_upload",
                "sas_token_abuse"
            ],
            "Microsoft.Network/networkSecurityGroups": [
                "port_scanning",
                "lateral_movement",
                "network_injection",
                "ddos_amplification",
                "unauthorized_access"
            ],
            "Microsoft.KeyVault/vaults": [
                "credential_theft",
                "key_extraction",
                "privilege_escalation",
                "data_decryption",
                "unauthorized_access"
            ],
            "Microsoft.Compute/virtualMachines": [
                "brute_force",
                "malware_injection",
                "resource_hijacking",
                "privilege_escalation",
                "lateral_movement"
            ],
            "Microsoft.Compute/disks": [
                "data_exfiltration",
                "unauthorized_access",
                "disk_encryption_bypass",
                "snapshot_exposure"
            ],
            "Microsoft.Databricks/workspaces": [
                "data_exfiltration",
                "code_injection",
                "unauthorized_access",
                "resource_hijacking"
            ]
        }
    
    def _load_resource_exposure_data(self) -> Dict[ResourceType, str]:
        """Load default exposure levels for resource types."""
        return {
            ResourceType.STORAGE_ACCOUNT: "internet_facing",
            ResourceType.NETWORK_SECURITY_GROUP: "external",
            ResourceType.KEY_VAULT: "internal",
            ResourceType.VIRTUAL_MACHINE: "internal",
            ResourceType.DISK: "internal",
            ResourceType.DATABRICKS_WORKSPACE: "internal"
        }
    
    def analyze_attack_surface(self, findings: List[SecurityFinding]) -> List[AttackSurface]:
        """Analyze attack surface based on security findings."""
        attack_surfaces = []
        
        # Group findings by resource
        resource_findings = defaultdict(list)
        for finding in findings:
            resource_key = f"{finding.resource_type}:{finding.resource_id}"
            resource_findings[resource_key].append(finding)
        
        for resource_key, resource_finding_list in resource_findings.items():
            resource_type, resource_id = resource_key.split(":", 1)
            resource_type_enum = ResourceType(resource_type)
            
            # Determine exposure level based on findings
            exposure_level = self._determine_exposure_level(resource_finding_list)
            
            # Identify attack vectors
            attack_vectors = self._identify_attack_vectors(resource_finding_list)
            
            # Extract vulnerabilities
            vulnerabilities = [f.title for f in resource_finding_list]
            
            # Calculate risk score
            risk_score = sum(f.risk_score for f in resource_finding_list)
            
            attack_surface = AttackSurface(
                component_id=resource_id,
                name=resource_finding_list[0].resource_name,
                resource_type=resource_type_enum,
                exposure_level=exposure_level,
                attack_vectors=attack_vectors,
                vulnerabilities=vulnerabilities,
                risk_score=risk_score
            )
            
            attack_surfaces.append(attack_surface)
        
        return attack_surfaces
    
    def _determine_exposure_level(self, findings: List[SecurityFinding]) -> str:
        """Determine exposure level based on findings."""
        for finding in findings:
            if "public" in finding.title.lower() or "internet" in finding.title.lower():
                return "internet_facing"
            elif "network" in finding.title.lower():
                return "external"
        
        return "internal"
    
    def _identify_attack_vectors(self, findings: List[SecurityFinding]) -> List[AttackVector]:
        """Identify attack vectors based on findings."""
        vectors = set()
        
        for finding in findings:
            title_lower = finding.title.lower()
            desc_lower = finding.description.lower()
            
            if "public" in title_lower or "internet" in title_lower:
                vectors.add(AttackVector.NETWORK)
            if "misconfiguration" in title_lower or "not enabled" in title_lower:
                vectors.add(AttackVector.MISCONFIGURATION)
            if "access" in title_lower or "authentication" in title_lower:
                vectors.add(AttackVector.NETWORK)
            if "storage" in title_lower or "data" in title_lower:
                vectors.add(AttackVector.NETWORK)
        
        return list(vectors)
    
    def assess_threats(self, findings: List[SecurityFinding]) -> Dict[str, Dict]:
        """Assess threats based on security findings."""
        threat_assessment = {}
        
        # Map findings to threats
        finding_threats = self._map_findings_to_threats(findings)
        
        for threat_id, threat in self.threats.items():
            assessment = {
                "threat": threat,
                "likelihood": self._calculate_threat_likelihood(threat, findings),
                "impact": self._calculate_threat_impact(threat, findings),
                "risk_score": 0,
                "relevant_findings": [],
                "attack_vectors": [],
                "mitigations": threat.mitigations,
                "detection_methods": threat.detection_methods
            }
            
            # Find relevant findings
            relevant_findings = finding_threats.get(threat_id, [])
            assessment["relevant_findings"] = [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "risk_score": f.risk_score,
                    "resource_type": f.resource_type.value
                }
                for f in relevant_findings
            ]
            
            # Calculate overall risk score
            if relevant_findings:
                assessment["risk_score"] = sum(f.risk_score for f in relevant_findings)
            
            # Identify attack vectors from findings
            assessment["attack_vectors"] = list(set(
                vector for finding in relevant_findings 
                for vector in self._identify_attack_vectors([finding])
            ))
            
            threat_assessment[threat_id] = assessment
        
        return threat_assessment
    
    def _map_findings_to_threats(self, findings: List[SecurityFinding]) -> Dict[str, List[SecurityFinding]]:
        """Map security findings to relevant threats."""
        finding_threats = defaultdict(list)
        
        for finding in findings:
            title_lower = finding.title.lower()
            desc_lower = finding.description.lower()
            
            # Map based on keywords
            if any(keyword in title_lower or keyword in desc_lower for keyword in 
                   ["public", "access", "unauthorized", "authentication"]):
                finding_threats["unauthorized_access"].append(finding)
            
            if any(keyword in title_lower or keyword in desc_lower for keyword in 
                   ["privilege", "escalation", "admin", "elevated"]):
                finding_threats["privilege_escalation"].append(finding)
            
            if any(keyword in title_lower or keyword in desc_lower for keyword in 
                   ["data", "exfiltration", "storage", "blob", "file"]):
                finding_threats["data_breach"].append(finding)
            
            if any(keyword in title_lower or keyword in desc_lower for keyword in 
                   ["network", "lateral", "movement", "nsg", "firewall"]):
                finding_threats["lateral_movement"].append(finding)
            
            if any(keyword in title_lower or keyword in desc_lower for keyword in 
                   ["resource", "hijacking", "crypto", "mining"]):
                finding_threats["resource_hijacking"].append(finding)
            
            if any(keyword in title_lower or keyword in desc_lower for keyword in 
                   ["dos", "denial", "service", "availability"]):
                finding_threats["denial_of_service"].append(finding)
            
            if any(keyword in title_lower or keyword in desc_lower for keyword in 
                   ["reconnaissance", "scanning", "enumeration", "discovery"]):
                finding_threats["reconnaissance"].append(finding)
            
            if any(keyword in title_lower or keyword in desc_lower for keyword in 
                   ["persistence", "backdoor", "malware", "implant"]):
                finding_threats["persistence"].append(finding)
        
        return finding_threats
    
    def _calculate_threat_likelihood(self, threat: Threat, findings: List[SecurityFinding]) -> str:
        """Calculate threat likelihood based on findings."""
        relevant_findings = self._map_findings_to_threats(findings).get(threat.threat_id, [])
        
        if not relevant_findings:
            return "low"
        
        # Count high and critical findings
        high_severity_count = sum(1 for f in relevant_findings 
                                if f.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL])
        
        if high_severity_count >= 3:
            return "high"
        elif high_severity_count >= 1:
            return "medium"
        else:
            return "low"
    
    def _calculate_threat_impact(self, threat: Threat, findings: List[SecurityFinding]) -> str:
        """Calculate threat impact based on findings."""
        relevant_findings = self._map_findings_to_threats(findings).get(threat.threat_id, [])
        
        if not relevant_findings:
            return "low"
        
        # Check for critical findings
        has_critical = any(f.severity == SeverityLevel.CRITICAL for f in relevant_findings)
        
        if has_critical:
            return "high"
        elif len(relevant_findings) >= 5:
            return "medium"
        else:
            return "low"
    
    def generate_threat_model_report(self, findings: List[SecurityFinding]) -> Dict:
        """Generate comprehensive threat model report."""
        attack_surfaces = self.analyze_attack_surface(findings)
        threat_assessment = self.assess_threats(findings)
        
        # Calculate overall metrics
        total_attack_surface = sum(as_.risk_score for as_ in attack_surfaces)
        total_threat_risk = sum(assessment["risk_score"] for assessment in threat_assessment.values())
        
        # Identify top threats
        top_threats = sorted(
            threat_assessment.items(),
            key=lambda x: x[1]["risk_score"],
            reverse=True
        )[:5]
        
        # Identify top attack surfaces
        top_attack_surfaces = sorted(
            attack_surfaces,
            key=lambda x: x.risk_score,
            reverse=True
        )[:5]
        
        # Generate recommendations
        recommendations = self._generate_threat_recommendations(threat_assessment, attack_surfaces)
        
        return {
            "summary": {
                "total_attack_surface_score": total_attack_surface,
                "total_threat_risk_score": total_threat_risk,
                "attack_surface_components": len(attack_surfaces),
                "active_threats": len([t for t in threat_assessment.values() if t["risk_score"] > 0]),
                "high_risk_threats": len([t for t in threat_assessment.values() if t["risk_score"] > 80]),
                "exposure_breakdown": self._calculate_exposure_breakdown(attack_surfaces)
            },
            "attack_surfaces": [
                {
                    "component_id": as_.component_id,
                    "name": as_.name,
                    "resource_type": as_.resource_type.value,
                    "exposure_level": as_.exposure_level,
                    "risk_score": as_.risk_score,
                    "attack_vectors": [v.value for v in as_.attack_vectors],
                    "vulnerabilities": as_.vulnerabilities
                }
                for as_ in attack_surfaces
            ],
            "threat_assessment": threat_assessment,
            "top_threats": [
                {
                    "threat_id": threat_id,
                    "threat_name": assessment["threat"].name,
                    "risk_score": assessment["risk_score"],
                    "likelihood": assessment["likelihood"],
                    "impact": assessment["impact"],
                    "relevant_findings_count": len(assessment["relevant_findings"])
                }
                for threat_id, assessment in top_threats
            ],
            "top_attack_surfaces": [
                {
                    "component_id": as_.component_id,
                    "name": as_.name,
                    "risk_score": as_.risk_score,
                    "exposure_level": as_.exposure_level,
                    "vulnerability_count": len(as_.vulnerabilities)
                }
                for as_ in top_attack_surfaces
            ],
            "recommendations": recommendations
        }
    
    def _calculate_exposure_breakdown(self, attack_surfaces: List[AttackSurface]) -> Dict[str, int]:
        """Calculate breakdown of exposure levels."""
        breakdown = defaultdict(int)
        for as_ in attack_surfaces:
            breakdown[as_.exposure_level] += 1
        return dict(breakdown)
    
    def _generate_threat_recommendations(self, threat_assessment: Dict, 
                                       attack_surfaces: List[AttackSurface]) -> List[str]:
        """Generate threat mitigation recommendations."""
        recommendations = []
        
        # High-risk threats
        high_risk_threats = [
            threat_id for threat_id, assessment in threat_assessment.items()
            if assessment["risk_score"] > 80
        ]
        
        if high_risk_threats:
            recommendations.append(
                f"URGENT: Address {len(high_risk_threats)} high-risk threats immediately. "
                f"Focus on {', '.join(high_risk_threats[:3])}"
            )
        
        # Internet-facing components
        internet_facing = [as_ for as_ in attack_surfaces if as_.exposure_level == "internet_facing"]
        if internet_facing:
            recommendations.append(
                f"Review {len(internet_facing)} internet-facing components. "
                "Consider implementing additional security controls."
            )
        
        # Common attack vectors
        vector_counts = Counter()
        for as_ in attack_surfaces:
            for vector in as_.attack_vectors:
                vector_counts[vector.value] += 1
        
        common_vectors = vector_counts.most_common(3)
        if common_vectors:
            recommendations.append(
                f"Strengthen defenses against common attack vectors: "
                f"{', '.join(v[0] for v in common_vectors)}"
            )
        
        # Resource-specific recommendations
        resource_risks = defaultdict(int)
        for as_ in attack_surfaces:
            resource_risks[as_.resource_type.value] += as_.risk_score
        
        high_risk_resources = [
            resource for resource, score in resource_risks.items() if score > 100
        ]
        
        if high_risk_resources:
            recommendations.append(
                f"Focus security efforts on high-risk resource types: "
                f"{', '.join(high_risk_resources)}"
            )
        
        if not recommendations:
            recommendations.append("Continue monitoring threat landscape and maintain security posture.")
        
        return recommendations


# Global threat modeling engine instance
threat_engine = ThreatModelingEngine()
