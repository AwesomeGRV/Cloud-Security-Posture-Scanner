"""Risk tolerance and acceptance policies for security findings."""

from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import json

from .models import SecurityFinding, SeverityLevel, ResourceType


class RiskToleranceLevel(str, Enum):
    """Risk tolerance levels."""
    ZERO_TOLERANCE = "zero_tolerance"
    LOW_TOLERANCE = "low_tolerance"
    MEDIUM_TOLERANCE = "medium_tolerance"
    HIGH_TOLERANCE = "high_tolerance"
    ACCEPT_ALL = "accept_all"


class AcceptanceStatus(str, Enum):
    """Finding acceptance status."""
    PENDING_REVIEW = "pending_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"
    RESCINDED = "rescinded"


class PolicyScope(str, Enum):
    """Policy scope levels."""
    ORGANIZATION = "organization"
    SUBSCRIPTION = "subscription"
    RESOURCE_GROUP = "resource_group"
    RESOURCE_TYPE = "resource_type"
    INDIVIDUAL_RESOURCE = "individual_resource"


@dataclass
class RiskTolerancePolicy:
    """Risk tolerance policy definition."""
    policy_id: str
    name: str
    description: str
    scope: PolicyScope
    scope_value: str
    tolerance_level: RiskToleranceLevel
    max_risk_score: int
    allowed_severities: List[SeverityLevel]
    expiration_days: Optional[int]
    approval_required: bool
    auto_approval_conditions: List[str]
    monitoring_requirements: List[str]
    created_at: datetime
    created_by: str
    is_active: bool


@dataclass
class RiskAcceptance:
    """Risk acceptance record."""
    acceptance_id: str
    finding_id: str
    policy_id: str
    acceptance_status: AcceptanceStatus
    accepted_by: str
    accepted_at: datetime
    expires_at: Optional[datetime]
    justification: str
    business_rationale: str
    mitigation_plan: str
    monitoring_plan: str
    review_schedule: str
    conditions: List[str]


@dataclass
class RiskToleranceAssessment:
    """Risk tolerance assessment result."""
    finding_id: str
    is_acceptable: bool
    tolerance_level: RiskToleranceLevel
    applicable_policies: List[str]
    auto_acceptable: bool
    requires_approval: bool
    recommended_actions: List[str]
    risk_score: int
    tolerance_threshold: int


class RiskToleranceEngine:
    """Engine for managing risk tolerance and acceptance policies."""
    
    def __init__(self):
        self.policies: Dict[str, RiskTolerancePolicy] = {}
        self.acceptances: Dict[str, RiskAcceptance] = {}
        self.default_policies = self._create_default_policies()
        self.tolerance_thresholds = self._load_tolerance_thresholds()
        self.compliance_requirements = self._load_compliance_requirements()
    
    def _create_default_policies(self) -> Dict[str, RiskTolerancePolicy]:
        """Create default risk tolerance policies."""
        policies = {}
        
        # Zero tolerance for critical findings
        policies["critical_zero_tolerance"] = RiskTolerancePolicy(
            policy_id="critical_zero_tolerance",
            name="Critical Findings Zero Tolerance",
            description="No tolerance for critical security findings",
            scope=PolicyScope.ORGANIZATION,
            scope_value="organization",
            tolerance_level=RiskToleranceLevel.ZERO_TOLERANCE,
            max_risk_score=0,
            allowed_severities=[],
            expiration_days=None,
            approval_required=False,
            auto_approval_conditions=[],
            monitoring_requirements=["Immediate remediation required"],
            created_at=datetime.utcnow(),
            created_by="system",
            is_active=True
        )
        
        # Low tolerance for high severity findings
        policies["high_low_tolerance"] = RiskTolerancePolicy(
            policy_id="high_low_tolerance",
            name="High Severity Low Tolerance",
            description="Low tolerance for high severity findings with exceptions",
            scope=PolicyScope.ORGANIZATION,
            scope_value="organization",
            tolerance_level=RiskToleranceLevel.LOW_TOLERANCE,
            max_risk_score=40,
            allowed_severities=[SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO],
            expiration_days=30,
            approval_required=True,
            auto_approval_conditions=[
                "Finding is in development environment",
                "Business justification provided",
                "Temporary workaround in place"
            ],
            monitoring_requirements=[
                "Weekly risk review",
                "Mitigation progress tracking",
                "Business impact assessment"
            ],
            created_at=datetime.utcnow(),
            created_by="system",
            is_active=True
        )
        
        # Medium tolerance for medium severity findings
        policies["medium_tolerance"] = RiskTolerancePolicy(
            policy_id="medium_tolerance",
            name="Medium Severity Tolerance",
            description="Medium tolerance for medium severity findings",
            scope=PolicyScope.ORGANIZATION,
            scope_value="organization",
            tolerance_level=RiskToleranceLevel.MEDIUM_TOLERANCE,
            max_risk_score=60,
            allowed_severities=[SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO],
            expiration_days=90,
            approval_required=True,
            auto_approval_conditions=[
                "Finding is in non-production environment",
                "Compensating controls in place",
                "Risk acceptance documented"
            ],
            monitoring_requirements=[
                "Monthly risk review",
                "Quarterly reassessment",
                "Compliance verification"
            ],
            created_at=datetime.utcnow(),
            created_by="system",
            is_active=True
        )
        
        # High tolerance for low severity findings
        policies["low_high_tolerance"] = RiskTolerancePolicy(
            policy_id="low_high_tolerance",
            name="Low Severity High Tolerance",
            description="High tolerance for low severity findings",
            scope=PolicyScope.ORGANIZATION,
            scope_value="organization",
            tolerance_level=RiskToleranceLevel.HIGH_TOLERANCE,
            max_risk_score=80,
            allowed_severities=[SeverityLevel.LOW, SeverityLevel.INFO],
            expiration_days=180,
            approval_required=False,
            auto_approval_conditions=[
                "Finding is informational",
                "No business impact",
                "Best practice recommendation"
            ],
            monitoring_requirements=[
                "Quarterly review",
                "Trend monitoring",
                "Continuous assessment"
            ],
            created_at=datetime.utcnow(),
            created_by="system",
            is_active=True
        )
        
        # Resource type specific policies
        policies["storage_security"] = RiskTolerancePolicy(
            policy_id="storage_security",
            name="Storage Security Policy",
            description="Specific tolerance for storage-related findings",
            scope=PolicyScope.RESOURCE_TYPE,
            scope_value="Microsoft.Storage/storageAccounts",
            tolerance_level=RiskToleranceLevel.LOW_TOLERANCE,
            max_risk_score=50,
            allowed_severities=[SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO],
            expiration_days=60,
            approval_required=True,
            auto_approval_conditions=[
                "Data is non-sensitive",
                "Access is restricted",
                "Encryption enabled"
            ],
            monitoring_requirements=[
                "Data access monitoring",
                "Configuration review",
                "Compliance check"
            ],
            created_at=datetime.utcnow(),
            created_by="system",
            is_active=True
        )
        
        policies["network_security"] = RiskTolerancePolicy(
            policy_id="network_security",
            name="Network Security Policy",
            description="Specific tolerance for network-related findings",
            scope=PolicyScope.RESOURCE_TYPE,
            scope_value="Microsoft.Network/networkSecurityGroups",
            tolerance_level=RiskToleranceLevel.MEDIUM_TOLERANCE,
            max_risk_score=70,
            allowed_severities=[SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO],
            expiration_days=90,
            approval_required=True,
            auto_approval_conditions=[
                "Network is isolated",
                "No sensitive data",
                "Monitoring in place"
            ],
            monitoring_requirements=[
                "Network traffic monitoring",
                "Access log review",
                "Security assessment"
            ],
            created_at=datetime.utcnow(),
            created_by="system",
            is_active=True
        )
        
        return policies
    
    def _load_tolerance_thresholds(self) -> Dict[str, Dict]:
        """Load tolerance thresholds by context."""
        return {
            "production": {
                "critical": 0,
                "high": 30,
                "medium": 50,
                "low": 70,
                "info": 90
            },
            "staging": {
                "critical": 20,
                "high": 50,
                "medium": 70,
                "low": 85,
                "info": 95
            },
            "development": {
                "critical": 40,
                "high": 60,
                "medium": 80,
                "low": 90,
                "info": 100
            }
        }
    
    def _load_compliance_requirements(self) -> Dict[str, List[str]]:
        """Load compliance requirements that affect risk tolerance."""
        return {
            "pci_dss": ["no_critical_findings", "no_high_findings", "document_acceptance"],
            "hipaa": ["no_critical_findings", " PHI_protection", "access_control"],
            "gdpr": ["data_protection", "privacy_controls", "documentation"],
            "sox": ["financial_controls", "audit_trail", "segregation_of_duties"],
            "iso_27001": ["risk_assessment", "continuous_monitoring", "improvement"]
        }
    
    def add_policy(self, policy: RiskTolerancePolicy) -> str:
        """Add a new risk tolerance policy."""
        self.policies[policy.policy_id] = policy
        return policy.policy_id
    
    def update_policy(self, policy_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing risk tolerance policy."""
        if policy_id not in self.policies:
            return False
        
        policy = self.policies[policy_id]
        for key, value in updates.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        
        return True
    
    def delete_policy(self, policy_id: str) -> bool:
        """Delete a risk tolerance policy."""
        if policy_id in self.policies:
            del self.policies[policy_id]
            return True
        return False
    
    def assess_risk_tolerance(self, finding: SecurityFinding, 
                            context: Optional[Dict[str, Any]] = None) -> RiskToleranceAssessment:
        """Assess if a finding meets risk tolerance criteria."""
        context = context or {}
        
        # Get applicable policies
        applicable_policies = self._get_applicable_policies(finding, context)
        
        # Determine tolerance level
        tolerance_level = self._determine_tolerance_level(finding, applicable_policies, context)
        
        # Calculate tolerance threshold
        tolerance_threshold = self._calculate_tolerance_threshold(finding, tolerance_level, context)
        
        # Assess acceptability
        is_acceptable = self._is_acceptable(finding, tolerance_threshold, applicable_policies)
        
        # Check auto-acceptability
        auto_acceptable = self._is_auto_acceptable(finding, applicable_policies, context)
        
        # Check approval requirements
        requires_approval = self._requires_approval(finding, applicable_policies)
        
        # Generate recommendations
        recommended_actions = self._generate_tolerance_recommendations(
            finding, is_acceptable, requires_approval, applicable_policies
        )
        
        return RiskToleranceAssessment(
            finding_id=finding.id,
            is_acceptable=is_acceptable,
            tolerance_level=tolerance_level,
            applicable_policies=[p.policy_id for p in applicable_policies],
            auto_acceptable=auto_acceptable,
            requires_approval=requires_approval,
            recommended_actions=recommended_actions,
            risk_score=finding.risk_score,
            tolerance_threshold=tolerance_threshold
        )
    
    def _get_applicable_policies(self, finding: SecurityFinding, 
                                context: Dict[str, Any]) -> List[RiskTolerancePolicy]:
        """Get policies applicable to a finding."""
        applicable = []
        
        # Check organization-wide policies
        for policy in self.policies.values():
            if (policy.scope == PolicyScope.ORGANIZATION and 
                policy.is_active and 
                self._policy_applies_to_finding(policy, finding, context)):
                applicable.append(policy)
        
        # Check subscription-specific policies
        subscription_id = finding.subscription_id
        for policy in self.policies.values():
            if (policy.scope == PolicyScope.SUBSCRIPTION and 
                policy.scope_value == subscription_id and 
                policy.is_active and 
                self._policy_applies_to_finding(policy, finding, context)):
                applicable.append(policy)
        
        # Check resource group-specific policies
        resource_group = finding.resource_group
        for policy in self.policies.values():
            if (policy.scope == PolicyScope.RESOURCE_GROUP and 
                policy.scope_value == resource_group and 
                policy.is_active and 
                self._policy_applies_to_finding(policy, finding, context)):
                applicable.append(policy)
        
        # Check resource type-specific policies
        resource_type = finding.resource_type.value
        for policy in self.policies.values():
            if (policy.scope == PolicyScope.RESOURCE_TYPE and 
                policy.scope_value == resource_type and 
                policy.is_active and 
                self._policy_applies_to_finding(policy, finding, context)):
                applicable.append(policy)
        
        # Sort by specificity (more specific policies first)
        applicable.sort(key=lambda p: self._get_policy_specificity(p.scope))
        
        return applicable
    
    def _policy_applies_to_finding(self, policy: RiskTolerancePolicy, 
                                  finding: SecurityFinding, context: Dict[str, Any]) -> bool:
        """Check if a policy applies to a specific finding."""
        # Check severity restrictions
        if policy.allowed_severities and finding.severity not in policy.allowed_severities:
            return False
        
        # Check risk score limits
        if finding.risk_score > policy.max_risk_score:
            return False
        
        # Check compliance requirements
        compliance_frameworks = context.get("compliance_frameworks", [])
        for framework in compliance_frameworks:
            if framework in self.compliance_requirements:
                requirements = self.compliance_requirements[framework]
                if "no_critical_findings" in requirements and finding.severity == SeverityLevel.CRITICAL:
                    return False
                if "no_high_findings" in requirements and finding.severity == SeverityLevel.HIGH:
                    return False
        
        return True
    
    def _get_policy_specificity(self, scope: PolicyScope) -> int:
        """Get policy specificity level for sorting."""
        specificity_map = {
            PolicyScope.ORGANIZATION: 1,
            PolicyScope.SUBSCRIPTION: 2,
            PolicyScope.RESOURCE_GROUP: 3,
            PolicyScope.RESOURCE_TYPE: 4,
            PolicyScope.INDIVIDUAL_RESOURCE: 5
        }
        return specificity_map.get(scope, 0)
    
    def _determine_tolerance_level(self, finding: SecurityFinding, 
                                 applicable_policies: List[RiskTolerancePolicy],
                                 context: Dict[str, Any]) -> RiskToleranceLevel:
        """Determine the tolerance level for a finding."""
        if not applicable_policies:
            # Use default tolerance based on environment
            environment = context.get("environment", "production")
            if environment == "production":
                return RiskToleranceLevel.LOW_TOLERANCE
            elif environment == "staging":
                return RiskToleranceLevel.MEDIUM_TOLERANCE
            else:
                return RiskToleranceLevel.HIGH_TOLERANCE
        
        # Use the most specific applicable policy
        most_specific_policy = applicable_policies[0]
        return most_specific_policy.tolerance_level
    
    def _calculate_tolerance_threshold(self, finding: SecurityFinding, 
                                     tolerance_level: RiskToleranceLevel,
                                     context: Dict[str, Any]) -> int:
        """Calculate tolerance threshold for a finding."""
        environment = context.get("environment", "production")
        severity = finding.severity.value
        
        # Get base threshold from tolerance thresholds
        base_threshold = self.tolerance_thresholds.get(environment, {}).get(severity, 50)
        
        # Adjust based on tolerance level
        tolerance_adjustments = {
            RiskToleranceLevel.ZERO_TOLERANCE: 0,
            RiskToleranceLevel.LOW_TOLERANCE: 0.7,
            RiskToleranceLevel.MEDIUM_TOLERANCE: 1.0,
            RiskToleranceLevel.HIGH_TOLERANCE: 1.3,
            RiskToleranceLevel.ACCEPT_ALL: 2.0
        }
        
        adjustment = tolerance_adjustments.get(tolerance_level, 1.0)
        adjusted_threshold = int(base_threshold * adjustment)
        
        return min(100, adjusted_threshold)
    
    def _is_acceptable(self, finding: SecurityFinding, 
                      tolerance_threshold: int,
                      applicable_policies: List[RiskTolerancePolicy]) -> bool:
        """Determine if a finding is acceptable under tolerance policies."""
        # Check if risk score is within threshold
        if finding.risk_score > tolerance_threshold:
            return False
        
        # Check if any policy explicitly disallows the finding
        for policy in applicable_policies:
            if finding.severity not in policy.allowed_severities:
                return False
            if finding.risk_score > policy.max_risk_score:
                return False
        
        return True
    
    def _is_auto_acceptable(self, finding: SecurityFinding, 
                           applicable_policies: List[RiskTolerancePolicy],
                           context: Dict[str, Any]) -> bool:
        """Check if a finding can be automatically accepted."""
        for policy in applicable_policies:
            if not policy.auto_approval_conditions:
                continue
            
            # Check auto-approval conditions
            conditions_met = []
            for condition in policy.auto_approval_conditions:
                if self._evaluate_condition(condition, finding, context):
                    conditions_met.append(condition)
            
            # If all conditions are met, auto-accept
            if len(conditions_met) == len(policy.auto_approval_conditions):
                return True
        
        return False
    
    def _evaluate_condition(self, condition: str, finding: SecurityFinding, 
                          context: Dict[str, Any]) -> bool:
        """Evaluate an auto-approval condition."""
        environment = context.get("environment", "")
        resource_tags = context.get("resource_tags", {})
        business_context = context.get("business_context", {})
        
        # Evaluate common conditions
        if condition == "Finding is in development environment":
            return environment.lower() == "development"
        elif condition == "Finding is in non-production environment":
            return environment.lower() != "production"
        elif condition == "Finding is informational":
            return finding.severity == SeverityLevel.INFO
        elif condition == "No business impact":
            return business_context.get("business_impact", "medium") == "low"
        elif condition == "Business justification provided":
            return context.get("business_justification", "") != ""
        elif condition == "Temporary workaround in place":
            return context.get("workaround", False)
        elif condition == "Compensating controls in place":
            return context.get("compensating_controls", False)
        elif condition == "Risk acceptance documented":
            return context.get("documentation", False)
        elif condition == "Data is non-sensitive":
            return business_context.get("data_sensitivity", "confidential") == "public"
        elif condition == "Access is restricted":
            return context.get("access_restriction", False)
        elif condition == "Encryption enabled":
            return context.get("encryption_enabled", False)
        elif condition == "Network is isolated":
            return context.get("network_isolation", False)
        elif condition == "No sensitive data":
            return business_context.get("contains_sensitive_data", False)
        elif condition == "Monitoring in place":
            return context.get("monitoring", False)
        elif condition == "Best practice recommendation":
            return finding.severity in [SeverityLevel.LOW, SeverityLevel.INFO]
        
        return False
    
    def _requires_approval(self, finding: SecurityFinding, 
                          applicable_policies: List[RiskTolerancePolicy]) -> bool:
        """Check if a finding requires approval for acceptance."""
        for policy in applicable_policies:
            if policy.approval_required:
                return True
        
        # High and critical findings always require approval
        if finding.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
            return True
        
        return False
    
    def _generate_tolerance_recommendations(self, finding: SecurityFinding, 
                                          is_acceptable: bool,
                                          requires_approval: bool,
                                          applicable_policies: List[RiskTolerancePolicy]) -> List[str]:
        """Generate recommendations based on tolerance assessment."""
        recommendations = []
        
        if not is_acceptable:
            recommendations.append(
                f"Finding exceeds tolerance threshold. Immediate remediation required."
            )
        elif requires_approval:
            recommendations.append(
                f"Finding requires approval for risk acceptance. Submit formal request."
            )
        elif is_acceptable:
            recommendations.append(
                f"Finding is within tolerance limits. Consider acceptance with monitoring."
            )
        
        # Add policy-specific recommendations
        for policy in applicable_policies:
            if policy.monitoring_requirements:
                recommendations.extend([
                    f"Policy '{policy.name}' requires: {req}"
                    for req in policy.monitoring_requirements
                ])
        
        # Add severity-specific recommendations
        if finding.severity == SeverityLevel.CRITICAL:
            recommendations.append("Critical finding - immediate action required regardless of tolerance.")
        elif finding.severity == SeverityLevel.HIGH:
            recommendations.append("High severity finding - prioritize remediation or formal acceptance.")
        elif finding.severity == SeverityLevel.MEDIUM:
            recommendations.append("Medium severity finding - monitor and plan remediation.")
        
        return recommendations
    
    def request_risk_acceptance(self, finding: SecurityFinding, 
                              policy_id: str,
                              requester: str,
                              justification: str,
                              business_rationale: str,
                              mitigation_plan: str,
                              monitoring_plan: str,
                              review_schedule: str,
                              conditions: List[str]) -> str:
        """Request risk acceptance for a finding."""
        # Get the policy
        policy = self.policies.get(policy_id)
        if not policy:
            raise ValueError(f"Policy {policy_id} not found")
        
        # Create acceptance record
        acceptance_id = f"acceptance_{finding.id}_{datetime.utcnow().timestamp()}"
        
        # Calculate expiration
        expires_at = None
        if policy.expiration_days:
            expires_at = datetime.utcnow() + timedelta(days=policy.expiration_days)
        
        acceptance = RiskAcceptance(
            acceptance_id=acceptance_id,
            finding_id=finding.id,
            policy_id=policy_id,
            acceptance_status=AcceptanceStatus.PENDING_REVIEW,
            accepted_by=requester,
            accepted_at=datetime.utcnow(),
            expires_at=expires_at,
            justification=justification,
            business_rationale=business_rationale,
            mitigation_plan=mitigation_plan,
            monitoring_plan=monitoring_plan,
            review_schedule=review_schedule,
            conditions=conditions
        )
        
        self.acceptances[acceptance_id] = acceptance
        return acceptance_id
    
    def approve_risk_acceptance(self, acceptance_id: str, approver: str) -> bool:
        """Approve a risk acceptance request."""
        if acceptance_id not in self.acceptances:
            return False
        
        acceptance = self.acceptances[acceptance_id]
        acceptance.acceptance_status = AcceptanceStatus.ACCEPTED
        acceptance.accepted_by = approver
        acceptance.accepted_at = datetime.utcnow()
        
        return True
    
    def reject_risk_acceptance(self, acceptance_id: str, approver: str, reason: str) -> bool:
        """Reject a risk acceptance request."""
        if acceptance_id not in self.acceptances:
            return False
        
        acceptance = self.acceptances[acceptance_id]
        acceptance.acceptance_status = AcceptanceStatus.REJECTED
        acceptance.accepted_by = approver
        acceptance.accepted_at = datetime.utcnow()
        acceptance.justification += f" [REJECTED: {reason}]"
        
        return True
    
    def expire_risk_acceptances(self) -> List[str]:
        """Expire risk acceptances that have passed their expiration date."""
        expired = []
        now = datetime.utcnow()
        
        for acceptance_id, acceptance in self.acceptances.items():
            if (acceptance.expires_at and 
                acceptance.expires_at < now and 
                acceptance.acceptance_status == AcceptanceStatus.ACCEPTED):
                acceptance.acceptance_status = AcceptanceStatus.EXPIRED
                expired.append(acceptance_id)
        
        return expired
    
    def get_active_acceptances(self) -> List[RiskAcceptance]:
        """Get all active risk acceptances."""
        return [
            acceptance for acceptance in self.acceptances.values()
            if acceptance.acceptance_status == AcceptanceStatus.ACCEPTED
        ]
    
    def generate_tolerance_report(self, findings: List[SecurityFinding], 
                                 context: Optional[Dict[str, Any]] = None) -> Dict:
        """Generate comprehensive risk tolerance report."""
        context = context or {}
        
        # Assess all findings
        assessments = []
        for finding in findings:
            assessment = self.assess_risk_tolerance(finding, context)
            assessments.append(assessment)
        
        # Generate summary statistics
        total_findings = len(findings)
        acceptable_findings = len([a for a in assessments if a.is_acceptable])
        auto_acceptable_findings = len([a for a in assessments if a.auto_acceptable])
        approval_required_findings = len([a for a in assessments if a.requires_approval])
        
        # Breakdown by tolerance level
        tolerance_breakdown = defaultdict(int)
        for assessment in assessments:
            tolerance_breakdown[assessment.tolerance_level.value] += 1
        
        # Breakdown by severity
        severity_breakdown = defaultdict(int)
        for finding in findings:
            severity_breakdown[finding.severity.value] += 1
        
        # Active acceptances
        active_acceptances = self.get_active_acceptances()
        
        # Policy utilization
        policy_utilization = defaultdict(int)
        for assessment in assessments:
            for policy_id in assessment.applicable_policies:
                policy_utilization[policy_id] += 1
        
        # Generate recommendations
        recommendations = self._generate_tolerance_report_recommendations(
            assessments, active_acceptances, policy_utilization
        )
        
        return {
            "summary": {
                "total_findings": total_findings,
                "acceptable_findings": acceptable_findings,
                "auto_acceptable_findings": auto_acceptable_findings,
                "approval_required_findings": approval_required_findings,
                "active_acceptances": len(active_acceptances),
                "acceptance_rate": round((acceptable_findings / total_findings) * 100, 2) if total_findings > 0 else 0
            },
            "tolerance_breakdown": dict(tolerance_breakdown),
            "severity_breakdown": dict(severity_breakdown),
            "policy_utilization": dict(policy_utilization),
            "assessments": [
                {
                    "finding_id": a.finding_id,
                    "is_acceptable": a.is_acceptable,
                    "tolerance_level": a.tolerance_level.value,
                    "applicable_policies": a.applicable_policies,
                    "auto_acceptable": a.auto_acceptable,
                    "requires_approval": a.requires_approval,
                    "risk_score": a.risk_score,
                    "tolerance_threshold": a.tolerance_threshold,
                    "recommended_actions": a.recommended_actions
                }
                for a in assessments
            ],
            "active_acceptances": [
                {
                    "acceptance_id": a.acceptance_id,
                    "finding_id": a.finding_id,
                    "policy_id": a.policy_id,
                    "status": a.acceptance_status.value,
                    "accepted_by": a.accepted_by,
                    "accepted_at": a.accepted_at.isoformat(),
                    "expires_at": a.expires_at.isoformat() if a.expires_at else None,
                    "conditions": a.conditions
                }
                for a in active_acceptances
            ],
            "recommendations": recommendations
        }
    
    def _generate_tolerance_report_recommendations(self, assessments: List[RiskToleranceAssessment],
                                                  active_acceptances: List[RiskAcceptance],
                                                  policy_utilization: Dict[str, int]) -> List[str]:
        """Generate recommendations for tolerance report."""
        recommendations = []
        
        # High acceptance rate
        if len(assessments) > 0:
            acceptance_rate = len([a for a in assessments if a.is_acceptable]) / len(assessments)
            if acceptance_rate > 0.8:
                recommendations.append(
                    "High risk acceptance rate detected. Review tolerance policies for appropriateness."
                )
            elif acceptance_rate < 0.3:
                recommendations.append(
                    "Low risk acceptance rate. Consider if tolerance policies are too restrictive."
                )
        
        # Expired acceptances
        expired_acceptances = [
            a for a in active_acceptances
            if a.expires_at and a.expires_at < datetime.utcnow()
        ]
        if expired_acceptances:
            recommendations.append(
                f"{len(expired_acceptances)} risk acceptances have expired. Review and renew if needed."
            )
        
        # Policy utilization
        unused_policies = [
            policy_id for policy_id in self.policies.keys()
            if policy_id not in policy_utilization
        ]
        if unused_policies:
            recommendations.append(
                f"{len(unused_policies)} policies are unused. Review if they are still needed."
            )
        
        # High-risk acceptances
        high_risk_acceptances = [
            a for a in active_acceptances
            if a.acceptance_id in assessments and 
            any(ass.finding_id == a.finding_id and ass.risk_score > 70 for ass in assessments)
        ]
        if high_risk_acceptances:
            recommendations.append(
                f"{len(high_risk_acceptances)} high-risk acceptances require regular monitoring."
            )
        
        # Approval requirements
        approval_required = len([a for a in assessments if a.requires_approval])
        if approval_required > 10:
            recommendations.append(
                f"{approval_required} findings require approval. Streamline approval process if needed."
            )
        
        if not recommendations:
            recommendations.append("Risk tolerance policies are functioning effectively.")
        
        return recommendations


# Global risk tolerance engine instance
risk_tolerance_engine = RiskToleranceEngine()
