"""Business impact assessment for security findings."""

from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass
from datetime import datetime, timedelta
import statistics

from .models import SecurityFinding, SeverityLevel, ResourceType


class BusinessImpactCategory(str, Enum):
    """Business impact categories."""
    FINANCIAL = "financial"
    REPUTATIONAL = "reputational"
    OPERATIONAL = "operational"
    LEGAL_REGULATORY = "legal_regulatory"
    CUSTOMER_TRUST = "customer_trust"
    COMPETITIVE_ADVANTAGE = "competitive_advantage"


class ImpactLevel(str, Enum):
    """Impact levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


@dataclass
class BusinessImpact:
    """Business impact definition."""
    category: BusinessImpactCategory
    level: ImpactLevel
    description: str
    financial_impact: Optional[float] = None
    time_to_recovery: Optional[int] = None  # hours
    affected_users: Optional[int] = None
    confidence_score: float = 0.8


@dataclass
class ResourceBusinessContext:
    """Business context for a resource."""
    resource_id: str
    resource_name: str
    resource_type: ResourceType
    business_criticality: str  # critical, important, standard, low
    data_classification: str  # restricted, confidential, internal, public
    revenue_dependency: float  # 0.0 to 1.0
    user_impact: str  # all_users, department, external, internal
    compliance_requirements: List[str]
    recovery_time_objective: int  # hours
    recovery_point_objective: int  # minutes


class BusinessImpactAssessment:
    """Engine for assessing business impact of security findings."""
    
    def __init__(self):
        self.impact_weights = {
            BusinessImpactCategory.FINANCIAL: 0.35,
            BusinessImpactCategory.OPERATIONAL: 0.25,
            BusinessImpactCategory.REPUTATIONAL: 0.20,
            BusinessImpactCategory.LEGAL_REGULATORY: 0.15,
            BusinessImpactCategory.CUSTOMER_TRUST: 0.03,
            BusinessImpactCategory.COMPETITIVE_ADVANTAGE: 0.02
        }
        
        self.severity_impact_mapping = {
            SeverityLevel.CRITICAL: ImpactLevel.CRITICAL,
            SeverityLevel.HIGH: ImpactLevel.HIGH,
            SeverityLevel.MEDIUM: ImpactLevel.MEDIUM,
            SeverityLevel.LOW: ImpactLevel.LOW,
            SeverityLevel.INFO: ImpactLevel.NEGLIGIBLE
        }
        
        self.resource_criticality_multipliers = {
            "critical": 1.5,
            "important": 1.2,
            "standard": 1.0,
            "low": 0.8
        }
        
        self.data_classification_multipliers = {
            "restricted": 1.5,
            "confidential": 1.3,
            "internal": 1.0,
            "public": 0.7
        }
    
    def assess_business_impact(self, findings: List[SecurityFinding], 
                              business_context: Optional[Dict[str, ResourceBusinessContext]] = None) -> Dict:
        """Assess business impact of security findings."""
        business_context = business_context or {}
        
        impact_assessment = {
            "overall_impact_score": 0,
            "impact_by_category": {},
            "impact_by_severity": {},
            "high_impact_findings": [],
            "business_risk_trend": {},
            "recommendations": [],
            "financial_exposure": 0,
            "operational_risk": 0
        }
        
        # Calculate impacts for each finding
        finding_impacts = []
        for finding in findings:
            impact = self._calculate_finding_impact(finding, business_context)
            finding_impacts.append(impact)
        
        # Aggregate impacts by category
        category_impacts = self._aggregate_impacts_by_category(finding_impacts)
        impact_assessment["impact_by_category"] = category_impacts
        
        # Aggregate impacts by severity
        severity_impacts = self._aggregate_impacts_by_severity(finding_impacts)
        impact_assessment["impact_by_severity"] = severity_impacts
        
        # Calculate overall impact score
        overall_score = self._calculate_overall_impact_score(category_impacts)
        impact_assessment["overall_impact_score"] = overall_score
        
        # Identify high impact findings
        impact_assessment["high_impact_findings"] = [
            {
                "finding_id": impact["finding_id"],
                "finding_title": impact["finding_title"],
                "resource_name": impact["resource_name"],
                "impact_score": impact["impact_score"],
                "primary_impact_category": impact["primary_impact_category"],
                "business_criticality": impact["business_criticality"]
            }
            for impact in finding_impacts
            if impact["impact_score"] > 70
        ]
        
        # Calculate financial exposure
        impact_assessment["financial_exposure"] = self._calculate_financial_exposure(finding_impacts)
        
        # Calculate operational risk
        impact_assessment["operational_risk"] = self._calculate_operational_risk(finding_impacts)
        
        # Generate recommendations
        impact_assessment["recommendations"] = self._generate_business_recommendations(
            finding_impacts, category_impacts
        )
        
        return impact_assessment
    
    def _calculate_finding_impact(self, finding: SecurityFinding, 
                                 business_context: Dict[str, ResourceBusinessContext]) -> Dict:
        """Calculate business impact for a single finding."""
        # Get business context for the resource
        resource_context = business_context.get(finding.resource_id)
        
        # Base impact from severity
        base_impact_level = self.severity_impact_mapping[finding.severity]
        
        # Calculate category impacts
        category_impacts = {}
        
        for category in BusinessImpactCategory:
            impact_level = self._calculate_category_impact(
                category, finding, resource_context, base_impact_level
            )
            category_impacts[category.value] = {
                "level": impact_level,
                "score": self._impact_level_to_score(impact_level),
                "description": self._get_impact_description(category, impact_level)
            }
        
        # Calculate overall impact score for this finding
        impact_score = self._calculate_finding_impact_score(category_impacts)
        
        # Apply business context multipliers
        if resource_context:
            criticality_multiplier = self.resource_criticality_multipliers.get(
                resource_context.business_criticality, 1.0
            )
            data_multiplier = self.data_classification_multipliers.get(
                resource_context.data_classification, 1.0
            )
            
            impact_score *= criticality_multiplier * data_multiplier
            impact_score = min(100, impact_score)
        
        # Determine primary impact category
        primary_category = max(
            category_impacts.items(),
            key=lambda x: x[1]["score"]
        )[0]
        
        return {
            "finding_id": finding.id,
            "finding_title": finding.title,
            "resource_name": finding.resource_name,
            "resource_type": finding.resource_type.value,
            "severity": finding.severity.value,
            "business_criticality": resource_context.business_criticality if resource_context else "unknown",
            "data_classification": resource_context.data_classification if resource_context else "unknown",
            "category_impacts": category_impacts,
            "impact_score": int(impact_score),
            "primary_impact_category": primary_category,
            "confidence_score": 0.8
        }
    
    def _calculate_category_impact(self, category: BusinessImpactCategory, 
                                 finding: SecurityFinding, 
                                 resource_context: Optional[ResourceBusinessContext],
                                 base_impact_level: ImpactLevel) -> ImpactLevel:
        """Calculate impact level for a specific category."""
        # Start with base impact level
        impact_level = base_impact_level
        
        # Adjust based on finding characteristics
        finding_text = f"{finding.title} {finding.description}".lower()
        
        if category == BusinessImpactCategory.FINANCIAL:
            if any(keyword in finding_text for keyword in ["data", "storage", "encryption"]):
                impact_level = self._increase_impact_level(impact_level)
            if resource_context and resource_context.revenue_dependency > 0.7:
                impact_level = self._increase_impact_level(impact_level)
        
        elif category == BusinessImpactCategory.OPERATIONAL:
            if any(keyword in finding_text for keyword in ["network", "access", "availability"]):
                impact_level = self._increase_impact_level(impact_level)
            if resource_context and resource_context.recovery_time_objective < 4:
                impact_level = self._increase_impact_level(impact_level)
        
        elif category == BusinessImpactCategory.REPUTATIONAL:
            if any(keyword in finding_text for keyword in ["public", "internet", "data"]):
                impact_level = self._increase_impact_level(impact_level)
            if resource_context and resource_context.user_impact in ["all_users", "external"]:
                impact_level = self._increase_impact_level(impact_level)
        
        elif category == BusinessImpactCategory.LEGAL_REGULATORY:
            if resource_context and resource_context.compliance_requirements:
                impact_level = self._increase_impact_level(impact_level)
            if any(keyword in finding_text for keyword in ["data", "privacy", "audit"]):
                impact_level = self._increase_impact_level(impact_level)
        
        elif category == BusinessImpactCategory.CUSTOMER_TRUST:
            if any(keyword in finding_text for keyword in ["public", "data", "security"]):
                impact_level = self._increase_impact_level(impact_level)
            if resource_context and resource_context.user_impact == "external":
                impact_level = self._increase_impact_level(impact_level)
        
        elif category == BusinessImpactCategory.COMPETITIVE_ADVANTAGE:
            if resource_context and resource_context.data_classification in ["restricted", "confidential"]:
                impact_level = self._increase_impact_level(impact_level)
            if any(keyword in finding_text for keyword in ["data", "intellectual", "proprietary"]):
                impact_level = self._increase_impact_level(impact_level)
        
        return impact_level
    
    def _increase_impact_level(self, current_level: ImpactLevel) -> ImpactLevel:
        """Increase impact level by one step."""
        level_order = [ImpactLevel.NEGLIGIBLE, ImpactLevel.LOW, ImpactLevel.MEDIUM, 
                      ImpactLevel.HIGH, ImpactLevel.CRITICAL]
        
        current_index = level_order.index(current_level)
        if current_index < len(level_order) - 1:
            return level_order[current_index + 1]
        return current_level
    
    def _impact_level_to_score(self, level: ImpactLevel) -> float:
        """Convert impact level to numeric score."""
        level_scores = {
            ImpactLevel.NEGLIGIBLE: 10,
            ImpactLevel.LOW: 30,
            ImpactLevel.MEDIUM: 50,
            ImpactLevel.HIGH: 75,
            ImpactLevel.CRITICAL: 100
        }
        return level_scores[level]
    
    def _get_impact_description(self, category: BusinessImpactCategory, level: ImpactLevel) -> str:
        """Get impact description for category and level."""
        descriptions = {
            BusinessImpactCategory.FINANCIAL: {
                ImpactLevel.CRITICAL: "Severe financial losses, potential bankruptcy",
                ImpactLevel.HIGH: "Significant financial losses, revenue impact",
                ImpactLevel.MEDIUM: "Moderate financial losses, cost increases",
                ImpactLevel.LOW: "Minor financial impact, minimal costs",
                ImpactLevel.NEGLIGIBLE: "Minimal to no financial impact"
            },
            BusinessImpactCategory.OPERATIONAL: {
                ImpactLevel.CRITICAL: "Complete operational shutdown",
                ImpactLevel.HIGH: "Major operational disruptions",
                ImpactLevel.MEDIUM: "Moderate operational impact",
                ImpactLevel.LOW: "Minor operational issues",
                ImpactLevel.NEGLIGIBLE: "No operational impact"
            },
            BusinessImpactCategory.REPUTATIONAL: {
                ImpactLevel.CRITICAL: "Severe reputational damage, loss of trust",
                ImpactLevel.HIGH: "Significant reputational impact",
                ImpactLevel.MEDIUM: "Moderate reputational concerns",
                ImpactLevel.LOW: "Minor reputational impact",
                ImpactLevel.NEGLIGIBLE: "No reputational impact"
            },
            BusinessImpactCategory.LEGAL_REGULATORY: {
                ImpactLevel.CRITICAL: "Major legal violations, heavy penalties",
                ImpactLevel.HIGH: "Significant regulatory issues",
                ImpactLevel.MEDIUM: "Moderate compliance concerns",
                ImpactLevel.LOW: "Minor compliance issues",
                ImpactLevel.NEGLIGIBLE: "No legal impact"
            },
            BusinessImpactCategory.CUSTOMER_TRUST: {
                ImpactLevel.CRITICAL: "Complete loss of customer trust",
                ImpactLevel.HIGH: "Significant customer trust erosion",
                ImpactLevel.MEDIUM: "Moderate customer trust impact",
                ImpactLevel.LOW: "Minor customer trust concerns",
                ImpactLevel.NEGLIGIBLE: "No customer trust impact"
            },
            BusinessImpactCategory.COMPETITIVE_ADVANTAGE: {
                ImpactLevel.CRITICAL: "Loss of competitive advantage",
                ImpactLevel.HIGH: "Significant competitive disadvantage",
                ImpactLevel.MEDIUM: "Moderate competitive impact",
                ImpactLevel.LOW: "Minor competitive concerns",
                ImpactLevel.NEGLIGIBLE: "No competitive impact"
            }
        }
        
        return descriptions.get(category, {}).get(level, "Unknown impact")
    
    def _calculate_finding_impact_score(self, category_impacts: Dict[str, Dict]) -> float:
        """Calculate overall impact score for a finding."""
        weighted_score = 0.0
        total_weight = 0.0
        
        for category, impact_data in category_impacts.items():
            weight = self.impact_weights.get(BusinessImpactCategory(category), 0)
            score = impact_data["score"]
            
            weighted_score += weight * score
            total_weight += weight
        
        return weighted_score / total_weight if total_weight > 0 else 0
    
    def _aggregate_impacts_by_category(self, finding_impacts: List[Dict]) -> Dict[str, Dict]:
        """Aggregate impacts by business category."""
        category_aggregates = {}
        
        for category in BusinessImpactCategory:
            category_scores = [
                impact["category_impacts"][category.value]["score"]
                for impact in finding_impacts
                if category.value in impact["category_impacts"]
            ]
            
            if category_scores:
                category_aggregates[category.value] = {
                    "average_score": statistics.mean(category_scores),
                    "max_score": max(category_scores),
                    "total_score": sum(category_scores),
                    "finding_count": len(category_scores),
                    "high_impact_count": len([s for s in category_scores if s > 70])
                }
            else:
                category_aggregates[category.value] = {
                    "average_score": 0,
                    "max_score": 0,
                    "total_score": 0,
                    "finding_count": 0,
                    "high_impact_count": 0
                }
        
        return category_aggregates
    
    def _aggregate_impacts_by_severity(self, finding_impacts: List[Dict]) -> Dict[str, Dict]:
        """Aggregate impacts by severity level."""
        severity_aggregates = {}
        
        for severity in SeverityLevel:
            severity_impacts = [
                impact["impact_score"]
                for impact in finding_impacts
                if impact["severity"] == severity.value
            ]
            
            if severity_impacts:
                severity_aggregates[severity.value] = {
                    "average_impact_score": statistics.mean(severity_impacts),
                    "max_impact_score": max(severity_impacts),
                    "total_impact_score": sum(severity_impacts),
                    "finding_count": len(severity_impacts)
                }
            else:
                severity_aggregates[severity.value] = {
                    "average_impact_score": 0,
                    "max_impact_score": 0,
                    "total_impact_score": 0,
                    "finding_count": 0
                }
        
        return severity_aggregates
    
    def _calculate_overall_impact_score(self, category_impacts: Dict[str, Dict]) -> float:
        """Calculate overall business impact score."""
        weighted_score = 0.0
        total_weight = 0.0
        
        for category, impact_data in category_impacts.items():
            weight = self.impact_weights.get(BusinessImpactCategory(category), 0)
            avg_score = impact_data["average_score"]
            
            weighted_score += weight * avg_score
            total_weight += weight
        
        return weighted_score / total_weight if total_weight > 0 else 0
    
    def _calculate_financial_exposure(self, finding_impacts: List[Dict]) -> Dict[str, float]:
        """Calculate financial exposure metrics."""
        financial_impacts = [
            impact["category_impacts"].get(BusinessImpactCategory.FINANCIAL.value, {}).get("score", 0)
            for impact in finding_impacts
        ]
        
        if not financial_impacts:
            return {"total_exposure": 0, "average_exposure": 0, "max_exposure": 0}
        
        # Estimate financial impact based on scores
        # This is a simplified model - in practice, you'd use actual financial data
        score_to_dollar_multiplier = 10000  # $10,000 per impact point
        
        return {
            "total_exposure": sum(financial_impacts) * score_to_dollar_multiplier,
            "average_exposure": statistics.mean(financial_impacts) * score_to_dollar_multiplier,
            "max_exposure": max(financial_impacts) * score_to_dollar_multiplier
        }
    
    def _calculate_operational_risk(self, finding_impacts: List[Dict]) -> Dict[str, float]:
        """Calculate operational risk metrics."""
        operational_impacts = [
            impact["category_impacts"].get(BusinessImpactCategory.OPERATIONAL.value, {}).get("score", 0)
            for impact in finding_impacts
        ]
        
        if not operational_impacts:
            return {"total_risk": 0, "average_risk": 0, "max_risk": 0}
        
        return {
            "total_risk": sum(operational_impacts),
            "average_risk": statistics.mean(operational_impacts),
            "max_risk": max(operational_impacts)
        }
    
    def _generate_business_recommendations(self, finding_impacts: List[Dict], 
                                         category_impacts: Dict[str, Dict]) -> List[str]:
        """Generate business-focused recommendations."""
        recommendations = []
        
        # High-impact findings
        high_impact_count = len([f for f in finding_impacts if f["impact_score"] > 70])
        if high_impact_count > 0:
            recommendations.append(
                f"URGENT: Address {high_impact_count} high business impact findings immediately "
                f"to prevent significant business disruption."
            )
        
        # Category-specific recommendations
        for category, impact_data in category_impacts.items():
            if impact_data["high_impact_count"] > 2:
                recommendations.append(
                    f"Critical: Multiple high-impact issues in {category.replace('_', ' ').title()} "
                    f"category. Implement targeted controls and monitoring."
                )
        
        # Financial exposure
        total_financial_impact = category_impacts.get(
            BusinessImpactCategory.FINANCIAL.value, {}
        ).get("total_score", 0)
        
        if total_financial_impact > 200:
            recommendations.append(
                "High financial exposure detected. Consider investing in additional security controls "
                "to reduce potential financial losses."
            )
        
        # Operational risk
        total_operational_impact = category_impacts.get(
            BusinessImpactCategory.OPERATIONAL.value, {}
        ).get("total_score", 0)
        
        if total_operational_impact > 200:
            recommendations.append(
                "High operational risk identified. Review business continuity plans and "
                "implement redundancy measures."
            )
        
        # Business criticality
        critical_resources = len([
            f for f in finding_impacts 
            if f.get("business_criticality") == "critical"
        ])
        
        if critical_resources > 0:
            recommendations.append(
                f"Security issues affecting {critical_resources} business-critical resources. "
                "Prioritize remediation to protect core business operations."
            )
        
        if not recommendations:
            recommendations.append(
                "Business impact is within acceptable levels. Continue monitoring and "
                "maintain security posture."
            )
        
        return recommendations
    
    def generate_business_impact_report(self, findings: List[SecurityFinding],
                                       business_context: Optional[Dict[str, ResourceBusinessContext]] = None) -> Dict:
        """Generate comprehensive business impact report."""
        impact_assessment = self.assess_business_impact(findings, business_context)
        
        # Add executive summary
        executive_summary = {
            "overall_business_risk": self._get_business_risk_level(impact_assessment["overall_impact_score"]),
            "critical_findings_count": len([
                f for f in findings if f.severity == SeverityLevel.CRITICAL
            ]),
            "high_impact_findings_count": len(impact_assessment["high_impact_findings"]),
            "estimated_financial_exposure": impact_assessment["financial_exposure"]["total_exposure"],
            "key_risk_areas": self._identify_key_risk_areas(impact_assessment["impact_by_category"]),
            "immediate_actions_required": len([
                r for r in impact_assessment["recommendations"] if "URGENT" in r or "Critical" in r
            ])
        }
        
        return {
            "executive_summary": executive_summary,
            "detailed_assessment": impact_assessment,
            "trending_analysis": self._generate_trending_analysis(findings),
            "resource_prioritization": self._prioritize_resources_by_impact(findings, business_context),
            "action_plan": self._generate_action_plan(impact_assessment)
        }
    
    def _get_business_risk_level(self, score: float) -> str:
        """Get business risk level based on score."""
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    def _identify_key_risk_areas(self, category_impacts: Dict[str, Dict]) -> List[str]:
        """Identify key risk areas based on category impacts."""
        risk_areas = []
        
        for category, impact_data in category_impacts.items():
            if impact_data["average_score"] > 60:
                risk_areas.append(category.replace("_", " ").title())
        
        return risk_areas
    
    def _generate_trending_analysis(self, findings: List[SecurityFinding]) -> Dict:
        """Generate trending analysis (placeholder for historical data)."""
        # In a real implementation, this would analyze historical data
        return {
            "trend_direction": "stable",
            "trend_percentage": 0.0,
            "trend_period": "30 days",
            "insights": [
                "Insufficient historical data for trend analysis",
                "Establish baseline metrics for future trend analysis"
            ]
        }
    
    def _prioritize_resources_by_impact(self, findings: List[SecurityFinding],
                                       business_context: Optional[Dict[str, ResourceBusinessContext]]) -> List[Dict]:
        """Prioritize resources by business impact."""
        resource_priorities = defaultdict(list)
        
        for finding in findings:
            resource_priorities[finding.resource_id].append(finding)
        
        prioritized_resources = []
        for resource_id, resource_findings in resource_priorities.items():
            # Calculate resource impact score
            total_impact = sum(f.risk_score for f in resource_findings)
            
            # Get business context
            context = business_context.get(resource_id) if business_context else None
            
            prioritized_resources.append({
                "resource_id": resource_id,
                "resource_name": resource_findings[0].resource_name,
                "resource_type": resource_findings[0].resource_type.value,
                "business_criticality": context.business_criticality if context else "unknown",
                "total_impact_score": total_impact,
                "finding_count": len(resource_findings),
                "critical_findings": len([f for f in resource_findings if f.severity == SeverityLevel.CRITICAL])
            })
        
        # Sort by impact score
        prioritized_resources.sort(key=lambda x: x["total_impact_score"], reverse=True)
        
        return prioritized_resources[:10]  # Top 10 resources
    
    def _generate_action_plan(self, impact_assessment: Dict) -> Dict:
        """Generate action plan based on impact assessment."""
        return {
            "immediate_actions": [
                r for r in impact_assessment["recommendations"]
                if "URGENT" in r or "Critical" in r
            ],
            "short_term_actions": [
                r for r in impact_assessment["recommendations"]
                if "High" in r or "priority" in r.lower()
            ],
            "long_term_actions": [
                r for r in impact_assessment["recommendations"]
                if "consider" in r.lower() or "continue" in r.lower()
            ],
            "resource_allocation": {
                "security_team": "High priority for critical findings",
                "business_stakeholders": "Review high-impact business risks",
                "executive_oversight": "Monitor overall business risk exposure"
            }
        }


# Global business impact assessment instance
business_impact_engine = BusinessImpactAssessment()
