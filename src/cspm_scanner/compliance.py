"""Compliance framework mappings and assessment."""

from typing import Dict, List, Optional, Set
from enum import Enum
from dataclasses import dataclass

from .models import SecurityFinding, SeverityLevel, ResourceType


class ComplianceFramework(str, Enum):
    """Compliance frameworks."""
    CIS_AZURE_1_4 = "cis_azure_1.4"
    CIS_AZURE_1_5 = "cis_azure_1.5"
    NIST_800_53 = "nist_800_53"
    NIST_800_171 = "nist_800_171"
    ISO_27001 = "iso_27001"
    ISO_27018 = "iso_27018"
    SOC_2 = "soc_2"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    CCPA = "ccpa"


class ComplianceCategory(str, Enum):
    """Compliance categories."""
    ACCESS_CONTROL = "access_control"
    AUDIT_LOGGING = "audit_logging"
    DATA_PROTECTION = "data_protection"
    NETWORK_SECURITY = "network_security"
    ENCRYPTION = "encryption"
    IDENTITY_MANAGEMENT = "identity_management"
    INCIDENT_RESPONSE = "incident_response"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    BUSINESS_CONTINUITY = "business_continuity"
    PRIVACY = "privacy"


@dataclass
class ComplianceControl:
    """Compliance control definition."""
    control_id: str
    framework: ComplianceFramework
    category: ComplianceCategory
    title: str
    description: str
    requirement_level: str  # mandatory, recommended, optional
    testing_procedure: str
    remediation_guidance: str


class ComplianceMapper:
    """Maps security findings to compliance frameworks."""
    
    def __init__(self):
        self.controls = self._load_compliance_controls()
        self.finding_mappings = self._create_finding_mappings()
    
    def _load_compliance_controls(self) -> Dict[str, ComplianceControl]:
        """Load compliance control definitions."""
        controls = {}
        
        # CIS Azure 1.4 Controls
        controls.update(self._load_cis_azure_14_controls())
        
        # NIST 800-53 Controls
        controls.update(self._load_nist_800_53_controls())
        
        # ISO 27001 Controls
        controls.update(self._load_iso_27001_controls())
        
        # PCI DSS Controls
        controls.update(self._load_pci_dss_controls())
        
        # HIPAA Controls
        controls.update(self._load_hipaa_controls())
        
        return controls
    
    def _load_cis_azure_14_controls(self) -> Dict[str, ComplianceControl]:
        """Load CIS Azure 1.4 controls."""
        return {
            "cis_1.1": ComplianceControl(
                control_id="1.1",
                framework=ComplianceFramework.CIS_AZURE_1_4,
                category=ComplianceCategory.IDENTITY_MANAGEMENT,
                title="Ensure that multi-factor authentication is enabled for all users",
                description="Multi-factor authentication (MFA) helps protect against unauthorized access even if credentials are compromised.",
                requirement_level="mandatory",
                testing_procedure="Check Azure AD MFA settings for all user accounts",
                remediation_guidance="Enable MFA for all users through Azure AD security defaults or Conditional Access policies"
            ),
            "cis_2.1": ComplianceControl(
                control_id="2.1",
                framework=ComplianceFramework.CIS_AZURE_1_4,
                category=ComplianceCategory.STORAGE_SECURITY,
                title="Ensure that 'Secure transfer required' is enabled for all storage accounts",
                description="Secure transfer required ensures that data is transferred securely using HTTPS.",
                requirement_level="mandatory",
                testing_procedure="Check storage account configuration for secure transfer setting",
                remediation_guidance="Enable 'Secure transfer required' in storage account configuration"
            ),
            "cis_3.1": ComplianceControl(
                control_id="3.1",
                framework=ComplianceFramework.CIS_AZURE_1_4,
                category=ComplianceCategory.NETWORK_SECURITY,
                title="Ensure that network security groups are associated with subnets",
                description="Network security groups provide network-level security for Azure resources.",
                requirement_level="mandatory",
                testing_procedure="Verify that all subnets have associated NSGs",
                remediation_guidance="Associate appropriate NSGs with all subnets"
            ),
            "cis_4.1": ComplianceControl(
                control_id="4.1",
                framework=ComplianceFramework.CIS_AZURE_1_4,
                category=ComplianceCategory.DATA_PROTECTION,
                title="Ensure that Key Vault is enabled with purge protection",
                description="Purge protection helps protect against accidental or malicious deletion of Key Vault items.",
                requirement_level="recommended",
                testing_procedure="Check Key Vault configuration for purge protection setting",
                remediation_guidance="Enable purge protection in Key Vault settings"
            ),
            "cis_5.1": ComplianceControl(
                control_id="5.1",
                framework=ComplianceFramework.CIS_AZURE_1_4,
                category=ComplianceCategory.AUDIT_LOGGING,
                title="Ensure that Activity Log retention is set to 365 days or greater",
                description="Activity logs provide visibility into subscription-level events.",
                requirement_level="mandatory",
                testing_procedure="Check Activity Log retention settings",
                remediation_guidance="Set Activity Log retention to 365 days or more"
            )
        }
    
    def _load_nist_800_53_controls(self) -> Dict[str, ComplianceControl]:
        """Load NIST 800-53 controls."""
        return {
            "nist_ac_1": ComplianceControl(
                control_id="AC-1",
                framework=ComplianceFramework.NIST_800_53,
                category=ComplianceCategory.ACCESS_CONTROL,
                title="Access Control Policy and Procedures",
                description="Develop, document, and disseminate access control policy and procedures.",
                requirement_level="mandatory",
                testing_procedure="Review access control policies and procedures",
                remediation_guidance="Develop and implement comprehensive access control policies"
            ),
            "nist_ac_2": ComplianceControl(
                control_id="AC-2",
                framework=ComplianceFramework.NIST_800_53,
                category=ComplianceCategory.ACCESS_CONTROL,
                title="Account Management",
                description="Manage user accounts and permissions to enforce least privilege.",
                requirement_level="mandatory",
                testing_procedure="Review account management processes and permissions",
                remediation_guidance="Implement proper account lifecycle management and least privilege access"
            ),
            "nist_ac_3": ComplianceControl(
                control_id="AC-3",
                framework=ComplianceFramework.NIST_800_53,
                category=ComplianceCategory.ACCESS_CONTROL,
                title="Access Enforcement",
                description="Enforce approved authorizations for logical access to information and system resources.",
                requirement_level="mandatory",
                testing_procedure="Verify access control mechanisms are properly configured",
                remediation_guidance="Implement proper access control enforcement mechanisms"
            ),
            "nist_au_2": ComplianceControl(
                control_id="AU-2",
                framework=ComplianceFramework.NIST_800_53,
                category=ComplianceCategory.AUDIT_LOGGING,
                title="Audit Events",
                description="Audit events include comprehensive information about system activities.",
                requirement_level="mandatory",
                testing_procedure="Review audit logging configuration and coverage",
                remediation_guidance="Enable comprehensive audit logging for all systems"
            ),
            "nist_sc_7": ComplianceControl(
                control_id="SC-7",
                framework=ComplianceFramework.NIST_800_53,
                category=ComplianceCategory.NETWORK_SECURITY,
                title="Boundary Protection",
                description="Monitor and control communications at external boundaries and key internal boundaries.",
                requirement_level="mandatory",
                testing_procedure="Review network boundary controls and monitoring",
                remediation_guidance="Implement proper network boundary protection and monitoring"
            ),
            "nist_sc_12": ComplianceControl(
                control_id="SC-12",
                framework=ComplianceFramework.NIST_800_53,
                category=ComplianceCategory.ENCRYPTION,
                title="Cryptographic Key Establishment and Management",
                description="Manage cryptographic keys using approved algorithms and key lengths.",
                requirement_level="mandatory",
                testing_procedure="Review cryptographic key management processes",
                remediation_guidance="Implement proper cryptographic key management"
            )
        }
    
    def _load_iso_27001_controls(self) -> Dict[str, ComplianceControl]:
        """Load ISO 27001 controls."""
        return {
            "iso_a9": ComplianceControl(
                control_id="A.9",
                framework=ComplianceFramework.ISO_27001,
                category=ComplianceCategory.ACCESS_CONTROL,
                title="Access Control",
                description="Control access to information based on business and security requirements.",
                requirement_level="mandatory",
                testing_procedure="Review access control policies and implementation",
                remediation_guidance="Implement comprehensive access control measures"
            ),
            "iso_a10": ComplianceControl(
                control_id="A.10",
                framework=ComplianceFramework.ISO_27001,
                category=ComplianceCategory.CRYPTOGRAPHY,
                title="Cryptography",
                description="Implement proper cryptographic controls for data protection.",
                requirement_level="mandatory",
                testing_procedure="Review cryptographic implementation and key management",
                remediation_guidance="Implement appropriate cryptographic controls"
            ),
            "iso_a12": ComplianceControl(
                control_id="A.12",
                framework=ComplianceFramework.ISO_27001,
                category=ComplianceCategory.OPERATIONS_SECURITY,
                title="Operations Security",
                description="Ensure correct and secure operations of information processing facilities.",
                requirement_level="mandatory",
                testing_procedure="Review operational security procedures",
                remediation_guidance="Implement proper operational security controls"
            ),
            "iso_a13": ComplianceControl(
                control_id="A.13",
                framework=ComplianceFramework.ISO_27001,
                category=ComplianceCategory.COMMUNICATIONS_SECURITY,
                title="Communications Security",
                description="Ensure security of information in networks and related information processing facilities.",
                requirement_level="mandatory",
                testing_procedure="Review network security controls",
                remediation_guidance="Implement proper network security measures"
            ),
            "iso_a14": ComplianceControl(
                control_id="A.14",
                framework=ComplianceFramework.ISO_27001,
                category=ComplianceCategory.SYSTEM_ACQUISITION,
                title="System Acquisition, Development and Maintenance",
                description="Ensure security is integrated throughout the system lifecycle.",
                requirement_level="mandatory",
                testing_procedure="Review system development and maintenance processes",
                remediation_guidance="Integrate security into system lifecycle"
            ),
            "iso_a16": ComplianceControl(
                control_id="A.16",
                framework=ComplianceFramework.ISO_27001,
                category=ComplianceCategory.INCIDENT_RESPONSE,
                title="Incident Management",
                description="Establish effective incident management processes.",
                requirement_level="mandatory",
                testing_procedure="Review incident response procedures",
                remediation_guidance="Implement comprehensive incident management"
            )
        }
    
    def _load_pci_dss_controls(self) -> Dict[str, ComplianceControl]:
        """Load PCI DSS controls."""
        return {
            "pci_1": ComplianceControl(
                control_id="Requirement 1",
                framework=ComplianceFramework.PCI_DSS,
                category=ComplianceCategory.NETWORK_SECURITY,
                title="Install and maintain a firewall configuration",
                description="Firewall configurations must protect cardholder data.",
                requirement_level="mandatory",
                testing_procedure="Review firewall configurations and rules",
                remediation_guidance="Implement and maintain proper firewall configurations"
            ),
            "pci_2": ComplianceControl(
                control_id="Requirement 2",
                framework=ComplianceFramework.PCI_DSS,
                category=ComplianceCategory.SYSTEM_CONFIGURATION,
                title="Do not use vendor-supplied defaults",
                description="Change vendor-supplied defaults and remove unnecessary accounts.",
                requirement_level="mandatory",
                testing_procedure="Review system configurations for default settings",
                remediation_guidance="Remove default configurations and harden systems"
            ),
            "pci_3": ComplianceControl(
                control_id="Requirement 3",
                framework=ComplianceFramework.PCI_DSS,
                category=ComplianceCategory.DATA_PROTECTION,
                title="Protect stored cardholder data",
                description="Implement strong cryptography for cardholder data protection.",
                requirement_level="mandatory",
                testing_procedure="Review data protection and encryption measures",
                remediation_guidance="Implement proper data protection and encryption"
            ),
            "pci_4": ComplianceControl(
                control_id="Requirement 4",
                framework=ComplianceFramework.PCI_DSS,
                category=ComplianceCategory.NETWORK_SECURITY,
                title="Encrypt transmission of cardholder data",
                description="Encrypt cardholder data across open, public networks.",
                requirement_level="mandatory",
                testing_procedure="Review transmission encryption implementation",
                remediation_guidance="Implement proper transmission encryption"
            ),
            "pci_7": ComplianceControl(
                control_id="Requirement 7",
                framework=ComplianceFramework.PCI_DSS,
                category=ComplianceCategory.ACCESS_CONTROL,
                title="Restrict access to cardholder data",
                description="Implement access control measures based on need-to-know.",
                requirement_level="mandatory",
                testing_procedure="Review access control implementation",
                remediation_guidance="Implement proper access control measures"
            )
        }
    
    def _load_hipaa_controls(self) -> Dict[str, ComplianceControl]:
        """Load HIPAA controls."""
        return {
            "hipaa_164_308": ComplianceControl(
                control_id="164.308",
                framework=ComplianceFramework.HIPAA,
                category=ComplianceCategory.ADMINISTRATIVE,
                title="Administrative Safeguards",
                description="Implement policies and procedures to prevent, detect, and contain security violations.",
                requirement_level="mandatory",
                testing_procedure="Review administrative safeguards implementation",
                remediation_guidance="Implement comprehensive administrative safeguards"
            ),
            "hipaa_164_312": ComplianceControl(
                control_id="164.312",
                framework=ComplianceFramework.HIPAA,
                category=ComplianceCategory.TECHNICAL,
                title="Technical Safeguards",
                description="Implement technical policies and procedures for electronic protected health information.",
                requirement_level="mandatory",
                testing_procedure="Review technical safeguards implementation",
                remediation_guidance="Implement proper technical safeguards"
            ),
            "hipaa_164_314": ComplianceControl(
                control_id="164.314",
                framework=ComplianceFramework.HIPAA,
                category=ComplianceCategory.PHYSICAL,
                title="Physical Safeguards",
                description="Implement policies and procedures to protect physical equipment.",
                requirement_level="mandatory",
                testing_procedure="Review physical safeguards implementation",
                remediation_guidance="Implement proper physical safeguards"
            )
        }
    
    def _create_finding_mappings(self) -> Dict[str, Set[str]]:
        """Create mappings from finding patterns to compliance controls."""
        return {
            # Storage findings
            "public_blob_access": {
                "cis_2.1", "nist_ac_3", "iso_a10", "pci_3", "pci_4", "hipaa_164_312"
            },
            "insecure_transfer": {
                "cis_2.1", "nist_sc_12", "iso_a10", "pci_4", "hipaa_164_312"
            },
            "storage_encryption": {
                "cis_2.1", "nist_sc_12", "iso_a10", "pci_3", "hipaa_164_312"
            },
            "default_network_access": {
                "cis_3.1", "nist_sc_7", "iso_a13", "pci_1"
            },
            
            # Network findings
            "overly_permissive_inbound": {
                "cis_3.1", "nist_sc_7", "iso_a13", "pci_1"
            },
            "rdp_from_internet": {
                "cis_3.1", "nist_sc_7", "iso_a13", "pci_1"
            },
            "ssh_from_internet": {
                "cis_3.1", "nist_sc_7", "iso_a13", "pci_1"
            },
            
            # Key Vault findings
            "public_network_access": {
                "cis_4.1", "nist_sc_7", "iso_a13", "pci_1"
            },
            "soft_delete_not_enabled": {
                "cis_4.1", "nist_ac_2", "iso_a9"
            },
            "purge_protection_not_enabled": {
                "cis_4.1", "nist_ac_2", "iso_a9"
            },
            
            # General findings
            "audit_logging": {
                "cis_5.1", "nist_au_2", "iso_a12", "pci_10", "hipaa_164_308"
            },
            "access_control": {
                "cis_1.1", "nist_ac_1", "nist_ac_2", "nist_ac_3", "iso_a9", "pci_7", "hipaa_164_312"
            }
        }
    
    def map_finding_to_compliance(self, finding: SecurityFinding) -> Dict[str, List[str]]:
        """Map a security finding to relevant compliance controls."""
        mapped_controls = {}
        
        # Find matching patterns in finding title and description
        finding_text = f"{finding.title} {finding.description}".lower()
        
        for pattern, control_ids in self.finding_mappings.items():
            if pattern in finding_text:
                for control_id in control_ids:
                    if control_id in self.controls:
                        control = self.controls[control_id]
                        framework = control.framework.value
                        
                        if framework not in mapped_controls:
                            mapped_controls[framework] = []
                        
                        mapped_controls[framework].append({
                            "control_id": control.control_id,
                            "title": control.title,
                            "category": control.category.value,
                            "requirement_level": control.requirement_level,
                            "remediation_guidance": control.remediation_guidance
                        })
        
        return mapped_controls
    
    def assess_compliance_posture(self, findings: List[SecurityFinding], 
                                 frameworks: Optional[List[ComplianceFramework]] = None) -> Dict:
        """Assess overall compliance posture against specified frameworks."""
        if frameworks is None:
            frameworks = list(ComplianceFramework)
        
        compliance_assessment = {}
        
        for framework in frameworks:
            framework_controls = {k: v for k, v in self.controls.items() 
                                if v.framework == framework}
            
            assessment = {
                "framework": framework.value,
                "total_controls": len(framework_controls),
                "compliant_controls": 0,
                "non_compliant_controls": 0,
                "partial_compliance": 0,
                "compliance_score": 0.0,
                "violations": [],
                "categories": {}
            }
            
            # Track which controls are violated
            violated_controls = set()
            
            for finding in findings:
                mapped_controls = self.map_finding_to_compliance(finding)
                
                if framework.value in mapped_controls:
                    for control_info in mapped_controls[framework.value]:
                        control_id = control_info["control_id"]
                        violated_controls.add(control_id)
                        
                        assessment["violations"].append({
                            "control_id": control_id,
                            "control_title": control_info["title"],
                            "category": control_info["category"],
                            "requirement_level": control_info["requirement_level"],
                            "finding_id": finding.id,
                            "finding_title": finding.title,
                            "severity": finding.severity.value,
                            "remediation_guidance": control_info["remediation_guidance"]
                        })
            
            # Calculate compliance metrics
            assessment["non_compliant_controls"] = len(violated_controls)
            assessment["compliant_controls"] = len(framework_controls) - len(violated_controls)
            
            if assessment["total_controls"] > 0:
                assessment["compliance_score"] = round(
                    (assessment["compliant_controls"] / assessment["total_controls"]) * 100, 2
                )
            
            # Categorize violations
            category_counts = {}
            for violation in assessment["violations"]:
                category = violation["category"]
                if category not in category_counts:
                    category_counts[category] = 0
                category_counts[category] += 1
            
            assessment["categories"] = category_counts
            
            compliance_assessment[framework.value] = assessment
        
        return compliance_assessment
    
    def generate_compliance_report(self, findings: List[SecurityFinding], 
                                 frameworks: Optional[List[ComplianceFramework]] = None) -> Dict:
        """Generate comprehensive compliance report."""
        compliance_assessment = self.assess_compliance_posture(findings, frameworks)
        
        # Generate summary statistics
        total_frameworks = len(compliance_assessment)
        avg_compliance = sum(
            assessment["compliance_score"] 
            for assessment in compliance_assessment.values()
        ) / total_frameworks if total_frameworks > 0 else 0
        
        # Identify high-risk areas
        high_risk_categories = {}
        for framework, assessment in compliance_assessment.items():
            for category, count in assessment["categories"].items():
                if category not in high_risk_categories:
                    high_risk_categories[category] = 0
                high_risk_categories[category] += count
        
        # Sort categories by violation count
        sorted_categories = sorted(
            high_risk_categories.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        return {
            "summary": {
                "total_frameworks_assessed": total_frameworks,
                "average_compliance_score": round(avg_compliance, 2),
                "total_violations": sum(
                    len(assessment["violations"]) 
                    for assessment in compliance_assessment.values()
                ),
                "high_risk_categories": sorted_categories[:5]
            },
            "framework_assessments": compliance_assessment,
            "recommendations": self._generate_compliance_recommendations(compliance_assessment)
        }
    
    def _generate_compliance_recommendations(self, compliance_assessment: Dict) -> List[str]:
        """Generate compliance improvement recommendations."""
        recommendations = []
        
        for framework, assessment in compliance_assessment.items():
            score = assessment["compliance_score"]
            
            if score < 50:
                recommendations.append(
                    f"Critical: {framework} compliance score is {score}%. "
                    f"Immediate action required for {assessment['non_compliant_controls']} controls."
                )
            elif score < 80:
                recommendations.append(
                    f"Warning: {framework} compliance score is {score}%. "
                    f"Address {assessment['non_compliant_controls']} non-compliant controls."
                )
            
            # Category-specific recommendations
            for category, count in assessment["categories"].items():
                if count > 3:
                    recommendations.append(
                        f"Multiple violations in {category} category. "
                        f"Review and strengthen {category} controls."
                    )
        
        if not recommendations:
            recommendations.append("Good compliance posture across all frameworks. Continue monitoring.")
        
        return recommendations


# Global compliance mapper instance
compliance_mapper = ComplianceMapper()
