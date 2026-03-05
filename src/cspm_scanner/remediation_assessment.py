"""Automated remediation risk assessment and planning."""

from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import statistics

from .models import SecurityFinding, SeverityLevel, ResourceType


class RemediationComplexity(str, Enum):
    """Remediation complexity levels."""
    TRIVIAL = "trivial"
    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    CRITICAL = "critical"


class RemediationRisk(str, Enum):
    """Remediation risk levels."""
    NO_RISK = "no_risk"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    CRITICAL_RISK = "critical_risk"


class AutomationLevel(str, Enum):
    """Automation levels."""
    FULLY_AUTOMATED = "fully_automated"
    SEMI_AUTOMATED = "semi_automated"
    MANUAL_REVIEW = "manual_review"
    MANUAL_ONLY = "manual_only"


class RemediationPriority(str, Enum):
    """Remediation priority levels."""
    IMMEDIATE = "immediate"
    URGENT = "urgent"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MONITOR = "monitor"


@dataclass
class RemediationAction:
    """Individual remediation action."""
    action_id: str
    name: str
    description: str
    resource_type: ResourceType
    complexity: RemediationComplexity
    risk: RemediationRisk
    automation_level: AutomationLevel
    estimated_duration: int  # minutes
    prerequisites: List[str]
    potential_side_effects: List[str]
    rollback_plan: str
    verification_steps: List[str]
    success_criteria: List[str]


@dataclass
class RemediationPlan:
    """Complete remediation plan for a finding."""
    plan_id: str
    finding_id: str
    priority: RemediationPriority
    actions: List[RemediationAction]
    total_complexity: RemediationComplexity
    total_risk: RemediationRisk
    estimated_duration: int  # minutes
    dependencies: List[str]
    business_impact: str
    approval_required: bool
    approval_level: str
    scheduled_time: Optional[datetime]
    estimated_cost: float


@dataclass
class RemediationAssessment:
    """Assessment of remediation options for a finding."""
    finding_id: str
    auto_remediatable: bool
    recommended_approach: str
    complexity_score: int
    risk_score: int
    automation_potential: float
    business_risk: str
    remediation_options: List[RemediationPlan]
    blocking_factors: List[str]
    prerequisites: List[str]


class RemediationAssessmentEngine:
    """Engine for assessing automated remediation options and risks."""
    
    def __init__(self):
        self.remediation_actions = self._load_remediation_actions()
        self.complexity_weights = {
            RemediationComplexity.TRIVIAL: 1,
            RemediationComplexity.SIMPLE: 2,
            RemediationComplexity.MODERATE: 3,
            RemediationComplexity.COMPLEX: 4,
            RemediationComplexity.CRITICAL: 5
        }
        self.risk_weights = {
            RemediationRisk.NO_RISK: 0,
            RemediationRisk.LOW_RISK: 1,
            RemediationRisk.MEDIUM_RISK: 2,
            RemediationRisk.HIGH_RISK: 3,
            RemediationRisk.CRITICAL_RISK: 4
        }
        self.automation_weights = {
            AutomationLevel.FULLY_AUTOMATED: 1.0,
            AutomationLevel.SEMI_AUTOMATED: 0.7,
            AutomationLevel.MANUAL_REVIEW: 0.3,
            AutomationLevel.MANUAL_ONLY: 0.0
        }
    
    def _load_remediation_actions(self) -> Dict[str, List[RemediationAction]]:
        """Load remediation actions for different finding types."""
        return {
            "public_blob_access": [
                RemediationAction(
                    action_id="disable_public_blob_access",
                    name="Disable Public Blob Access",
                    description="Disable public access to blob containers",
                    resource_type=ResourceType.STORAGE_ACCOUNT,
                    complexity=RemediationComplexity.SIMPLE,
                    risk=RemediationRisk.LOW_RISK,
                    automation_level=AutomationLevel.FULLY_AUTOMATED,
                    estimated_duration=5,
                    prerequisites=["Storage account access", "Backup current settings"],
                    potential_side_effects=["Applications using public access may fail"],
                    rollback_plan="Re-enable public access if applications fail",
                    verification_steps=["Test blob access", "Verify application functionality"],
                    success_criteria=["Public access disabled", "Applications functioning"]
                ),
                RemediationAction(
                    action_id="implement_private_endpoints",
                    name="Implement Private Endpoints",
                    description="Configure private endpoints for secure access",
                    resource_type=ResourceType.STORAGE_ACCOUNT,
                    complexity=RemediationComplexity.MODERATE,
                    risk=RemediationRisk.MEDIUM_RISK,
                    automation_level=AutomationLevel.SEMI_AUTOMATED,
                    estimated_duration=30,
                    prerequisites=["VNet configuration", "DNS setup"],
                    potential_side_effects=["Network connectivity changes", "DNS resolution issues"],
                    rollback_plan="Remove private endpoints and restore public access",
                    verification_steps=["Test private endpoint connectivity", "Verify DNS resolution"],
                    success_criteria=["Private endpoints configured", "Connectivity verified"]
                )
            ],
            "insecure_transfer": [
                RemediationAction(
                    action_id="enable_secure_transfer",
                    name="Enable Secure Transfer",
                    description="Enable HTTPS-only access to storage account",
                    resource_type=ResourceType.STORAGE_ACCOUNT,
                    complexity=RemediationComplexity.TRIVIAL,
                    risk=RemediationRisk.NO_RISK,
                    automation_level=AutomationLevel.FULLY_AUTOMATED,
                    estimated_duration=2,
                    prerequisites=["Storage account access"],
                    potential_side_effects=["HTTP-only applications may fail"],
                    rollback_plan="Disable secure transfer if needed",
                    verification_steps=["Test HTTPS access", "Verify application compatibility"],
                    success_criteria=["HTTPS-only enabled", "Applications working"]
                )
            ],
            "storage_encryption": [
                RemediationAction(
                    action_id="enable_storage_encryption",
                    name="Enable Storage Encryption",
                    description="Enable encryption for all storage services",
                    resource_type=ResourceType.STORAGE_ACCOUNT,
                    complexity=RemediationComplexity.SIMPLE,
                    risk=RemediationRisk.LOW_RISK,
                    automation_level=AutomationLevel.FULLY_AUTOMATED,
                    estimated_duration=10,
                    prerequisites=["Storage account access"],
                    potential_side_effects=["Performance impact on encryption operations"],
                    rollback_plan="Disable encryption if performance issues occur",
                    verification_steps=["Verify encryption status", "Test performance"],
                    success_criteria=["Encryption enabled", "Performance acceptable"]
                )
            ],
            "default_network_access": [
                RemediationAction(
                    action_id="restrict_network_access",
                    name="Restrict Network Access",
                    description="Configure network rules to restrict access",
                    resource_type=ResourceType.STORAGE_ACCOUNT,
                    complexity=RemediationComplexity.MODERATE,
                    risk=RemediationRisk.MEDIUM_RISK,
                    automation_level=AutomationLevel.SEMI_AUTOMATED,
                    estimated_duration=20,
                    prerequisites=["Network configuration", "IP ranges"],
                    potential_side_effects=["Legitimate access may be blocked"],
                    rollback_plan="Restore previous network rules",
                    verification_steps=["Test network access", "Verify connectivity"],
                    success_criteria=["Network access restricted", "Required access working"]
                )
            ],
            "overly_permissive_inbound": [
                RemediationAction(
                    action_id="restrict_inbound_rules",
                    name="Restrict Inbound Rules",
                    description="Modify NSG rules to restrict inbound access",
                    resource_type=ResourceType.NETWORK_SECURITY_GROUP,
                    complexity=RemediationComplexity.MODERATE,
                    risk=RemediationRisk.HIGH_RISK,
                    automation_level=AutomationLevel.SEMI_AUTOMATED,
                    estimated_duration=15,
                    prerequisites=["NSG access", "Allowed IP ranges"],
                    potential_side_effects=["Network connectivity disruption", "Service outages"],
                    rollback_plan="Restore original NSG rules",
                    verification_steps=["Test network connectivity", "Verify service access"],
                    success_criteria=["Inbound rules restricted", "Services accessible"]
                )
            ],
            "rdp_from_internet": [
                RemediationAction(
                    action_id="block_rdp_internet",
                    name="Block RDP from Internet",
                    description="Remove RDP access from internet",
                    resource_type=ResourceType.NETWORK_SECURITY_GROUP,
                    complexity=RemediationComplexity.SIMPLE,
                    risk=RemediationRisk.MEDIUM_RISK,
                    automation_level=AutomationLevel.FULLY_AUTOMATED,
                    estimated_duration=5,
                    prerequisites=["NSG access"],
                    potential_side_effects=["Remote desktop access blocked"],
                    rollback_plan="Restore RDP rule if needed",
                    verification_steps=["Test RDP access", "Verify alternative access"],
                    success_criteria=["RDP blocked from internet", "Alternative access working"]
                )
            ],
            "ssh_from_internet": [
                RemediationAction(
                    action_id="block_ssh_internet",
                    name="Block SSH from Internet",
                    description="Remove SSH access from internet",
                    resource_type=ResourceType.NETWORK_SECURITY_GROUP,
                    complexity=RemediationComplexity.SIMPLE,
                    risk=RemediationRisk.MEDIUM_RISK,
                    automation_level=AutomationLevel.FULLY_AUTOMATED,
                    estimated_duration=5,
                    prerequisites=["NSG access"],
                    potential_side_effects=["SSH access blocked"],
                    rollback_plan="Restore SSH rule if needed",
                    verification_steps=["Test SSH access", "Verify alternative access"],
                    success_criteria=["SSH blocked from internet", "Alternative access working"]
                )
            ],
            "public_network_access": [
                RemediationAction(
                    action_id="disable_public_network_access",
                    name="Disable Public Network Access",
                    description="Disable public network access to Key Vault",
                    resource_type=ResourceType.KEY_VAULT,
                    complexity=RemediationComplexity.SIMPLE,
                    risk=RemediationRisk.MEDIUM_RISK,
                    automation_level=AutomationLevel.SEMI_AUTOMATED,
                    estimated_duration=10,
                    prerequisites=["Key Vault access", "Private endpoints"],
                    potential_side_effects=["Applications using public access may fail"],
                    rollback_plan="Re-enable public access if needed",
                    verification_steps=["Test Key Vault access", "Verify application functionality"],
                    success_criteria=["Public access disabled", "Applications working"]
                )
            ],
            "soft_delete_not_enabled": [
                RemediationAction(
                    action_id="enable_soft_delete",
                    name="Enable Soft Delete",
                    description="Enable soft delete protection for Key Vault",
                    resource_type=ResourceType.KEY_VAULT,
                    complexity=RemediationComplexity.TRIVIAL,
                    risk=RemediationRisk.NO_RISK,
                    automation_level=AutomationLevel.FULLY_AUTOMATED,
                    estimated_duration=3,
                    prerequisites=["Key Vault access"],
                    potential_side_effects=["None"],
                    rollback_plan="Disable soft delete if needed",
                    verification_steps=["Verify soft delete status", "Test deletion/recovery"],
                    success_criteria=["Soft delete enabled", "Recovery working"]
                )
            ],
            "purge_protection_not_enabled": [
                RemediationAction(
                    action_id="enable_purge_protection",
                    name="Enable Purge Protection",
                    description="Enable purge protection for Key Vault",
                    resource_type=ResourceType.KEY_VAULT,
                    complexity=RemediationComplexity.TRIVIAL,
                    risk=RemediationRisk.NO_RISK,
                    automation_level=AutomationLevel.FULLY_AUTOMATED,
                    estimated_duration=3,
                    prerequisites=["Key Vault access", "Soft delete enabled"],
                    potential_side_effects=["Cannot permanently delete items"],
                    rollback_plan="Disable purge protection if needed",
                    verification_steps=["Verify purge protection status", "Test deletion"],
                    success_criteria=["Purge protection enabled", "Deletion controlled"]
                )
            ]
        }
    
    def assess_remediation_options(self, finding: SecurityFinding, 
                                  context: Optional[Dict[str, Any]] = None) -> RemediationAssessment:
        """Assess remediation options for a security finding."""
        context = context or {}
        
        # Find applicable remediation actions
        applicable_actions = self._find_applicable_actions(finding)
        
        if not applicable_actions:
            return self._create_no_remediation_assessment(finding)
        
        # Create remediation plans
        remediation_plans = self._create_remediation_plans(finding, applicable_actions, context)
        
        # Assess auto-remediation potential
        auto_remediatable = self._assess_auto_remediation_potential(applicable_actions)
        
        # Calculate complexity and risk scores
        complexity_score = self._calculate_complexity_score(applicable_actions)
        risk_score = self._calculate_risk_score(applicable_actions)
        
        # Calculate automation potential
        automation_potential = self._calculate_automation_potential(applicable_actions)
        
        # Assess business risk
        business_risk = self._assess_business_risk(finding, context)
        
        # Identify blocking factors
        blocking_factors = self._identify_blocking_factors(finding, applicable_actions, context)
        
        # Identify prerequisites
        prerequisites = self._identify_prerequisites(applicable_actions)
        
        # Determine recommended approach
        recommended_approach = self._determine_recommended_approach(
            auto_remediatable, complexity_score, risk_score, business_risk
        )
        
        return RemediationAssessment(
            finding_id=finding.id,
            auto_remediatable=auto_remediatable,
            recommended_approach=recommended_approach,
            complexity_score=complexity_score,
            risk_score=risk_score,
            automation_potential=automation_potential,
            business_risk=business_risk,
            remediation_options=remediation_plans,
            blocking_factors=blocking_factors,
            prerequisites=prerequisites
        )
    
    def _find_applicable_actions(self, finding: SecurityFinding) -> List[RemediationAction]:
        """Find remediation actions applicable to a finding."""
        applicable_actions = []
        
        # Extract keywords from finding title and description
        finding_text = f"{finding.title} {finding.description}".lower()
        
        # Find matching action categories
        for category, actions in self.remediation_actions.items():
            if category in finding_text:
                applicable_actions.extend(actions)
        
        return applicable_actions
    
    def _create_no_remediation_assessment(self, finding: SecurityFinding) -> RemediationAssessment:
        """Create assessment when no remediation actions are available."""
        return RemediationAssessment(
            finding_id=finding.id,
            auto_remediatable=False,
            recommended_approach="Manual investigation required",
            complexity_score=0,
            risk_score=0,
            automation_potential=0.0,
            business_risk="Unknown - no remediation path identified",
            remediation_options=[],
            blocking_factors=["No automated remediation actions available"],
            prerequisites=["Manual investigation", "Custom remediation development"]
        )
    
    def _create_remediation_plans(self, finding: SecurityFinding, 
                                actions: List[RemediationAction],
                                context: Dict[str, Any]) -> List[RemediationPlan]:
        """Create remediation plans from available actions."""
        plans = []
        
        # Create individual action plans
        for action in actions:
            plan = self._create_single_action_plan(finding, action, context)
            plans.append(plan)
        
        # Create combined action plans if applicable
        if len(actions) > 1:
            combined_plan = self._create_combined_action_plan(finding, actions, context)
            plans.append(combined_plan)
        
        # Sort by priority
        plans.sort(key=lambda p: self._priority_to_score(p.priority))
        
        return plans
    
    def _create_single_action_plan(self, finding: SecurityFinding, 
                                  action: RemediationAction,
                                  context: Dict[str, Any]) -> RemediationPlan:
        """Create a remediation plan for a single action."""
        # Determine priority
        priority = self._determine_priority(finding, action, context)
        
        # Calculate total complexity and risk
        total_complexity = action.complexity
        total_risk = action.risk
        
        # Estimate duration
        estimated_duration = action.estimated_duration
        
        # Determine dependencies
        dependencies = action.prerequisites.copy()
        
        # Assess business impact
        business_impact = self._assess_business_impact(finding, action, context)
        
        # Determine approval requirements
        approval_required, approval_level = self._determine_approval_requirements(
            finding, action, context
        )
        
        # Estimate cost
        estimated_cost = self._estimate_remediation_cost(action, context)
        
        return RemediationPlan(
            plan_id=f"plan_{finding.id}_{action.action_id}",
            finding_id=finding.id,
            priority=priority,
            actions=[action],
            total_complexity=total_complexity,
            total_risk=total_risk,
            estimated_duration=estimated_duration,
            dependencies=dependencies,
            business_impact=business_impact,
            approval_required=approval_required,
            approval_level=approval_level,
            scheduled_time=None,
            estimated_cost=estimated_cost
        )
    
    def _create_combined_action_plan(self, finding: SecurityFinding, 
                                   actions: List[RemediationAction],
                                   context: Dict[str, Any]) -> RemediationPlan:
        """Create a combined remediation plan with multiple actions."""
        # Determine priority based on highest priority action
        priorities = [self._determine_priority(finding, action, context) for action in actions]
        priority = min(priorities)  # Highest priority (lowest enum value)
        
        # Calculate total complexity and risk
        complexity_scores = [self.complexity_weights[action.complexity] for action in actions]
        risk_scores = [self.risk_weights[action.risk] for action in actions]
        
        total_complexity = self._score_to_complexity(sum(complexity_scores) / len(complexity_scores))
        total_risk = self._score_to_risk(sum(risk_scores) / len(risk_scores))
        
        # Estimate total duration
        estimated_duration = sum(action.estimated_duration for action in actions)
        
        # Combine dependencies
        dependencies = []
        for action in actions:
            dependencies.extend(action.prerequisites)
        dependencies = list(set(dependencies))  # Remove duplicates
        
        # Assess business impact
        business_impact = self._assess_combined_business_impact(finding, actions, context)
        
        # Determine approval requirements
        approval_required = any(
            self._determine_approval_requirements(finding, action, context)[0]
            for action in actions
        )
        approval_level = max(
            self._determine_approval_requirements(finding, action, context)[1]
            for action in actions
        ) if approval_required else "None"
        
        # Estimate total cost
        estimated_cost = sum(self._estimate_remediation_cost(action, context) for action in actions)
        
        return RemediationPlan(
            plan_id=f"plan_{finding.id}_combined",
            finding_id=finding.id,
            priority=priority,
            actions=actions,
            total_complexity=total_complexity,
            total_risk=total_risk,
            estimated_duration=estimated_duration,
            dependencies=dependencies,
            business_impact=business_impact,
            approval_required=approval_required,
            approval_level=approval_level,
            scheduled_time=None,
            estimated_cost=estimated_cost
        )
    
    def _determine_priority(self, finding: SecurityFinding, 
                           action: RemediationAction,
                           context: Dict[str, Any]) -> RemediationPriority:
        """Determine remediation priority."""
        # Base priority from severity
        severity_priority = {
            SeverityLevel.CRITICAL: RemediationPriority.IMMEDIATE,
            SeverityLevel.HIGH: RemediationPriority.URGENT,
            SeverityLevel.MEDIUM: RemediationPriority.HIGH,
            SeverityLevel.LOW: RemediationPriority.MEDIUM,
            SeverityLevel.INFO: RemediationPriority.LOW
        }
        
        base_priority = severity_priority.get(finding.severity, RemediationPriority.MEDIUM)
        
        # Adjust based on risk
        if action.risk in [RemediationRisk.HIGH_RISK, RemediationRisk.CRITICAL_RISK]:
            # Lower priority for high-risk remediation
            priority_order = [
                RemediationPriority.IMMEDIATE,
                RemediationPriority.URGENT,
                RemediationPriority.HIGH,
                RemediationPriority.MEDIUM,
                RemediationPriority.LOW,
                RemediationPriority.MONITOR
            ]
            current_index = priority_order.index(base_priority)
            if current_index < len(priority_order) - 1:
                base_priority = priority_order[current_index + 1]
        
        # Adjust based on environment
        environment = context.get("environment", "production")
        if environment == "production":
            # More cautious in production
            if base_priority in [RemediationPriority.IMMEDIATE, RemediationPriority.URGENT]:
                if action.risk != RemediationRisk.NO_RISK:
                    base_priority = RemediationPriority.HIGH
        elif environment == "development":
            # More aggressive in development
            if base_priority == RemediationPriority.MEDIUM:
                base_priority = RemediationPriority.HIGH
            elif base_priority == RemediationPriority.LOW:
                base_priority = RemediationPriority.MEDIUM
        
        return base_priority
    
    def _score_to_complexity(self, score: float) -> RemediationComplexity:
        """Convert complexity score to complexity level."""
        if score <= 1.5:
            return RemediationComplexity.TRIVIAL
        elif score <= 2.5:
            return RemediationComplexity.SIMPLE
        elif score <= 3.5:
            return RemediationComplexity.MODERATE
        elif score <= 4.5:
            return RemediationComplexity.COMPLEX
        else:
            return RemediationComplexity.CRITICAL
    
    def _score_to_risk(self, score: float) -> RemediationRisk:
        """Convert risk score to risk level."""
        if score <= 0.5:
            return RemediationRisk.NO_RISK
        elif score <= 1.5:
            return RemediationRisk.LOW_RISK
        elif score <= 2.5:
            return RemediationRisk.MEDIUM_RISK
        elif score <= 3.5:
            return RemediationRisk.HIGH_RISK
        else:
            return RemediationRisk.CRITICAL_RISK
    
    def _assess_business_impact(self, finding: SecurityFinding, 
                               action: RemediationAction,
                               context: Dict[str, Any]) -> str:
        """Assess business impact of remediation."""
        impacts = []
        
        # Check for potential side effects
        if action.potential_side_effects:
            impacts.append("Potential service disruption")
        
        # Check environment
        environment = context.get("environment", "production")
        if environment == "production":
            impacts.append("Production environment impact")
        
        # Check business criticality
        business_criticality = context.get("business_criticality", "standard")
        if business_criticality == "critical":
            impacts.append("Critical business service")
        
        # Check user impact
        user_impact = context.get("user_impact", "internal")
        if user_impact == "external":
            impacts.append("External user impact")
        
        if not impacts:
            return "Minimal business impact expected"
        elif len(impacts) == 1:
            return f"Potential {impacts[0].lower()}"
        else:
            return f"Multiple impacts: {', '.join(impacts)}"
    
    def _assess_combined_business_impact(self, finding: SecurityFinding, 
                                        actions: List[RemediationAction],
                                        context: Dict[str, Any]) -> str:
        """Assess combined business impact of multiple actions."""
        all_side_effects = []
        for action in actions:
            all_side_effects.extend(action.potential_side_effects)
        
        unique_side_effects = list(set(all_side_effects))
        
        if not unique_side_effects:
            return "Minimal combined business impact expected"
        elif len(unique_side_effects) <= 2:
            return f"Potential impacts: {', '.join(unique_side_effects)}"
        else:
            return f"Multiple potential impacts including {', '.join(unique_side_effects[:3])}"
    
    def _determine_approval_requirements(self, finding: SecurityFinding, 
                                       action: RemediationAction,
                                       context: Dict[str, Any]) -> Tuple[bool, str]:
        """Determine if approval is required and at what level."""
        # High-risk actions always require approval
        if action.risk in [RemediationRisk.HIGH_RISK, RemediationRisk.CRITICAL_RISK]:
            return True, "Security Team"
        
        # Production environment requires approval
        if context.get("environment") == "production":
            if action.complexity in [RemediationComplexity.COMPLEX, RemediationComplexity.CRITICAL]:
                return True, "Operations Team"
            elif action.risk == RemediationRisk.MEDIUM_RISK:
                return True, "Team Lead"
        
        # Critical findings require approval
        if finding.severity == SeverityLevel.CRITICAL:
            return True, "Security Team"
        
        # High severity findings may require approval
        if finding.severity == SeverityLevel.HIGH and action.complexity != RemediationComplexity.TRIVIAL:
            return True, "Team Lead"
        
        return False, "None"
    
    def _estimate_remediation_cost(self, action: RemediationAction, 
                                 context: Dict[str, Any]) -> float:
        """Estimate remediation cost."""
        # Base cost per minute (simplified model)
        cost_per_minute = 2.0  # $2 per minute
        
        # Adjust based on complexity
        complexity_multiplier = {
            RemediationComplexity.TRIVIAL: 1.0,
            RemediationComplexity.SIMPLE: 1.2,
            RemediationComplexity.MODERATE: 1.5,
            RemediationComplexity.COMPLEX: 2.0,
            RemediationComplexity.CRITICAL: 3.0
        }
        
        # Adjust based on automation level
        automation_multiplier = {
            AutomationLevel.FULLY_AUTOMATED: 0.1,
            AutomationLevel.SEMI_AUTOMATED: 0.5,
            AutomationLevel.MANUAL_REVIEW: 1.0,
            AutomationLevel.MANUAL_ONLY: 1.5
        }
        
        base_cost = action.estimated_duration * cost_per_minute
        adjusted_cost = (base_cost * 
                         complexity_multiplier.get(action.complexity, 1.0) * 
                         automation_multiplier.get(action.automation_level, 1.0))
        
        return round(adjusted_cost, 2)
    
    def _priority_to_score(self, priority: RemediationPriority) -> int:
        """Convert priority to numeric score for sorting."""
        priority_scores = {
            RemediationPriority.IMMEDIATE: 1,
            RemediationPriority.URGENT: 2,
            RemediationPriority.HIGH: 3,
            RemediationPriority.MEDIUM: 4,
            RemediationPriority.LOW: 5,
            RemediationPriority.MONITOR: 6
        }
        return priority_scores.get(priority, 4)
    
    def _assess_auto_remediation_potential(self, actions: List[RemediationAction]) -> bool:
        """Assess if finding can be auto-remediated."""
        if not actions:
            return False
        
        # Check if any action is fully automated
        fully_automated_actions = [
            action for action in actions
            if action.automation_level == AutomationLevel.FULLY_AUTOMATED
        ]
        
        return len(fully_automated_actions) > 0
    
    def _calculate_complexity_score(self, actions: List[RemediationAction]) -> int:
        """Calculate overall complexity score."""
        if not actions:
            return 0
        
        complexity_scores = [self.complexity_weights[action.complexity] for action in actions]
        return int(statistics.mean(complexity_scores))
    
    def _calculate_risk_score(self, actions: List[RemediationAction]) -> int:
        """Calculate overall risk score."""
        if not actions:
            return 0
        
        risk_scores = [self.risk_weights[action.risk] for action in actions]
        return int(statistics.mean(risk_scores))
    
    def _calculate_automation_potential(self, actions: List[RemediationAction]) -> float:
        """Calculate automation potential."""
        if not actions:
            return 0.0
        
        automation_scores = [
            self.automation_weights[action.automation_level] for action in actions
        ]
        return statistics.mean(automation_scores)
    
    def _assess_business_risk(self, finding: SecurityFinding, 
                             context: Dict[str, Any]) -> str:
        """Assess business risk of the finding itself."""
        risk_factors = []
        
        # Severity-based risk
        if finding.severity == SeverityLevel.CRITICAL:
            risk_factors.append("Critical security vulnerability")
        elif finding.severity == SeverityLevel.HIGH:
            risk_factors.append("High security risk")
        
        # Environment-based risk
        environment = context.get("environment", "production")
        if environment == "production":
            risk_factors.append("Production environment exposure")
        
        # Business criticality
        business_criticality = context.get("business_criticality", "standard")
        if business_criticality == "critical":
            risk_factors.append("Critical business service")
        
        # Data sensitivity
        data_sensitivity = context.get("data_sensitivity", "internal")
        if data_sensitivity in ["restricted", "confidential"]:
            risk_factors.append("Sensitive data exposure")
        
        if not risk_factors:
            return "Low business risk"
        elif len(risk_factors) == 1:
            return risk_factors[0]
        else:
            return f"Multiple risk factors: {', '.join(risk_factors)}"
    
    def _identify_blocking_factors(self, finding: SecurityFinding, 
                                  actions: List[RemediationAction],
                                  context: Dict[str, Any]) -> List[str]:
        """Identify factors blocking remediation."""
        blocking_factors = []
        
        # Check for high-risk actions
        high_risk_actions = [
            action for action in actions
            if action.risk in [RemediationRisk.HIGH_RISK, RemediationRisk.CRITICAL_RISK]
        ]
        if high_risk_actions:
            blocking_factors.append("High remediation risk requires careful planning")
        
        # Check for complex actions
        complex_actions = [
            action for action in actions
            if action.complexity in [RemediationComplexity.COMPLEX, RemediationComplexity.CRITICAL]
        ]
        if complex_actions:
            blocking_factors.append("Complex remediation requires specialized expertise")
        
        # Check environment constraints
        environment = context.get("environment", "production")
        if environment == "production":
            blocking_factors.append("Production environment requires change management")
        
        # Check for missing prerequisites
        missing_prereqs = []
        for action in actions:
            for prereq in action.prerequisites:
                if not context.get(prereq.lower().replace(" ", "_"), False):
                    missing_prereqs.append(prereq)
        
        if missing_prereqs:
            blocking_factors.append(f"Missing prerequisites: {', '.join(missing_prereqs)}")
        
        # Check for approval requirements
        approval_required = any(
            self._determine_approval_requirements(finding, action, context)[0]
            for action in actions
        )
        if approval_required:
            blocking_factors.append("Approval process required before remediation")
        
        return blocking_factors
    
    def _identify_prerequisites(self, actions: List[RemediationAction]) -> List[str]:
        """Identify all prerequisites for remediation."""
        all_prerequisites = []
        for action in actions:
            all_prerequisites.extend(action.prerequisites)
        
        return list(set(all_prerequisites))  # Remove duplicates
    
    def _determine_recommended_approach(self, auto_remediatable: bool,
                                       complexity_score: int,
                                       risk_score: int,
                                       business_risk: str) -> str:
        """Determine recommended remediation approach."""
        if auto_remediatable and complexity_score <= 2 and risk_score <= 1:
            return "Fully automated remediation recommended"
        elif auto_remediatable and complexity_score <= 3 and risk_score <= 2:
            return "Semi-automated remediation with manual verification"
        elif complexity_score <= 3 and risk_score <= 2:
            return "Manual remediation with standard procedures"
        elif complexity_score <= 4 and risk_score <= 3:
            return "Manual remediation with detailed planning and testing"
        else:
            return "Expert consultation required before remediation"
    
    def generate_remediation_report(self, findings: List[SecurityFinding], 
                                  context: Optional[Dict[str, Any]] = None) -> Dict:
        """Generate comprehensive remediation assessment report."""
        context = context or {}
        
        # Assess all findings
        assessments = []
        for finding in findings:
            assessment = self.assess_remediation_options(finding, context)
            assessments.append(assessment)
        
        # Generate summary statistics
        total_findings = len(findings)
        auto_remediatable_count = len([a for a in assessments if a.auto_remediatable])
        manual_only_count = total_findings - auto_remediatable_count
        
        # Complexity breakdown
        complexity_breakdown = defaultdict(int)
        for assessment in assessments:
            if assessment.complexity_score > 0:
                complexity_breakdown[f"complexity_{assessment.complexity_score}"] += 1
        
        # Risk breakdown
        risk_breakdown = defaultdict(int)
        for assessment in assessments:
            if assessment.risk_score > 0:
                risk_breakdown[f"risk_{assessment.risk_score}"] += 1
        
        # Automation potential
        automation_scores = [a.automation_potential for a in assessments if a.automation_potential > 0]
        avg_automation_potential = statistics.mean(automation_scores) if automation_scores else 0.0
        
        # Cost estimation
        total_estimated_cost = 0.0
        for assessment in assessments:
            for plan in assessment.remediation_options:
                total_estimated_cost += plan.estimated_cost
        
        # Priority distribution
        priority_distribution = defaultdict(int)
        for assessment in assessments:
            for plan in assessment.remediation_options:
                priority_distribution[plan.priority.value] += 1
        
        # Blocking factors analysis
        all_blocking_factors = []
        for assessment in assessments:
            all_blocking_factors.extend(assessment.blocking_factors)
        
        blocking_factor_counts = Counter(all_blocking_factors)
        
        # Generate recommendations
        recommendations = self._generate_remediation_recommendations(
            assessments, context
        )
        
        return {
            "summary": {
                "total_findings": total_findings,
                "auto_remediatable": auto_remediatable_count,
                "manual_only": manual_only_count,
                "automation_rate": round((auto_remediatable_count / total_findings) * 100, 2) if total_findings > 0 else 0,
                "avg_automation_potential": round(avg_automation_potential, 2),
                "total_estimated_cost": round(total_estimated_cost, 2),
                "high_complexity_findings": len([a for a in assessments if a.complexity_score >= 4]),
                "high_risk_remediations": len([a for a in assessments if a.risk_score >= 3])
            },
            "complexity_breakdown": dict(complexity_breakdown),
            "risk_breakdown": dict(risk_breakdown),
            "priority_distribution": dict(priority_distribution),
            "blocking_factors": dict(blocking_factor_counts.most_common(10)),
            "assessments": [
                {
                    "finding_id": a.finding_id,
                    "auto_remediatable": a.auto_remediatable,
                    "recommended_approach": a.recommended_approach,
                    "complexity_score": a.complexity_score,
                    "risk_score": a.risk_score,
                    "automation_potential": a.automation_potential,
                    "business_risk": a.business_risk,
                    "remediation_options_count": len(a.remediation_options),
                    "blocking_factors": a.blocking_factors,
                    "prerequisites": a.prerequisites
                }
                for a in assessments
            ],
            "recommendations": recommendations
        }
    
    def _generate_remediation_recommendations(self, assessments: List[RemediationAssessment],
                                             context: Dict[str, Any]) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []
        
        # Auto-remediation potential
        auto_remediatable = len([a for a in assessments if a.auto_remediatable])
        if auto_remediatable > 0:
            recommendations.append(
                f"{auto_remediatable} findings can be automatically remediated. "
                f"Implement automated remediation workflows to reduce manual effort."
            )
        
        # High complexity findings
        high_complexity = len([a for a in assessments if a.complexity_score >= 4])
        if high_complexity > 0:
            recommendations.append(
                f"{high_complexity} findings require complex remediation. "
                f"Allocate specialized resources and plan carefully."
            )
        
        # High risk remediations
        high_risk = len([a for a in assessments if a.risk_score >= 3])
        if high_risk > 0:
            recommendations.append(
                f"{high_risk} remediations have high risk. "
                f"Implement additional safeguards and testing procedures."
            )
        
        # Common blocking factors
        all_blocking_factors = []
        for assessment in assessments:
            all_blocking_factors.extend(assessment.blocking_factors)
        
        blocking_factor_counts = Counter(all_blocking_factors)
        common_blocking_factors = blocking_factor_counts.most_common(3)
        
        if common_blocking_factors:
            recommendations.append(
                f"Address common blocking factors: "
                f"{', '.join([f'{factor} ({count})' for factor, count in common_blocking_factors])}"
            )
        
        # Environment-specific recommendations
        environment = context.get("environment", "production")
        if environment == "production":
            recommendations.append(
                "Production environment detected. Implement change management and "
                "approval processes for all remediation activities."
            )
        
        # Cost optimization
        total_cost = sum(
            sum(plan.estimated_cost for plan in assessment.remediation_options)
            for assessment in assessments
        )
        
        if total_cost > 1000:
            recommendations.append(
                f"Total estimated remediation cost is ${total_cost:.2f}. "
                f"Consider prioritizing high-impact, low-cost remediations first."
            )
        
        # Automation improvement
        automation_scores = [a.automation_potential for a in assessments if a.automation_potential > 0]
        if automation_scores:
            avg_automation = statistics.mean(automation_scores)
            if avg_automation < 0.5:
                recommendations.append(
                    f"Low automation potential ({avg_automation:.1%}). "
                    f"Consider developing additional automated remediation capabilities."
                )
        
        if not recommendations:
            recommendations.append(
                "Remediation assessment complete. Current remediation capabilities are adequate."
            )
        
        return recommendations


# Global remediation assessment engine instance
remediation_assessment_engine = RemediationAssessmentEngine()
