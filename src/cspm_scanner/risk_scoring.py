"""Risk scoring system for security findings."""

from typing import List, Dict, Optional, Tuple
from collections import Counter
from datetime import datetime, timedelta
import math
import statistics

from .models import SecurityFinding, ScanResult, SeverityLevel, ResourceType


class RiskScoringEngine:
    """Engine for calculating risk scores and aggregating findings."""
    
    def __init__(self):
        self.severity_weights = {
            SeverityLevel.CRITICAL: 100,
            SeverityLevel.HIGH: 75,
            SeverityLevel.MEDIUM: 50,
            SeverityLevel.LOW: 25,
            SeverityLevel.INFO: 10
        }
        
        # Contextual risk multipliers
        self.resource_criticality = {
            ResourceType.KEY_VAULT: 1.5,
            ResourceType.STORAGE_ACCOUNT: 1.3,
            ResourceType.VIRTUAL_MACHINE: 1.4,
            ResourceType.NETWORK_SECURITY_GROUP: 1.2,
            ResourceType.DATABRICKS_WORKSPACE: 1.3,
            ResourceType.DISK: 1.1
        }
        
        # Industry-specific risk factors
        self.industry_factors = {
            "healthcare": 1.3,
            "finance": 1.4,
            "government": 1.5,
            "retail": 1.1,
            "technology": 1.0
        }
        
        # Data sensitivity multipliers
        self.data_sensitivity_factors = {
            "phi": 1.5,  # Protected Health Information
            "pii": 1.4,  # Personally Identifiable Information
            "financial": 1.3,
            "intellectual_property": 1.2,
            "public": 0.8
        }
    
    def calculate_overall_risk_score(self, findings: List[SecurityFinding], context: Optional[Dict] = None) -> int:
        """Calculate overall risk score for a set of findings with contextual factors."""
        if not findings:
            return 0
        
        context = context or {}
        
        # Weighted average based on severity
        total_weight = 0
        weighted_sum = 0
        
        severity_counts = Counter(finding.severity for finding in findings)
        
        for severity, count in severity_counts.items():
            weight = self.severity_weights[severity]
            weighted_sum += weight * count
            total_weight += weight
        
        if total_weight == 0:
            return 0
        
        # Normalize to 0-100 scale
        base_score = (weighted_sum / total_weight) * 100
        
        # Apply density factor (more findings = higher risk)
        density_factor = min(1.5, 1.0 + (len(findings) / 100))
        
        # Apply contextual factors
        context_multiplier = self._calculate_context_multiplier(findings, context)
        
        # Apply temporal decay for older findings
        temporal_factor = self._calculate_temporal_factor(findings)
        
        final_score = min(100, base_score * density_factor * context_multiplier * temporal_factor)
        
        return int(final_score)
    
    def calculate_resource_risk_score(self, resource_findings: List[SecurityFinding], resource_context: Optional[Dict] = None) -> int:
        """Calculate risk score for a specific resource with context."""
        if not resource_findings:
            return 0
        
        resource_context = resource_context or {}
        
        # Use the highest severity finding as the base
        highest_severity = max(finding.severity for finding in resource_findings)
        base_score = self.severity_weights[highest_severity]
        
        # Factor in number of findings
        finding_count_factor = min(1.5, 1.0 + (len(resource_findings) / 10))
        
        # Apply resource criticality multiplier
        resource_type = resource_findings[0].resource_type
        criticality_multiplier = self.resource_criticality.get(resource_type, 1.0)
        
        # Apply business context
        business_multiplier = 1.0
        if resource_context.get("is_production", False):
            business_multiplier *= 1.3
        if resource_context.get("is_internet_facing", False):
            business_multiplier *= 1.2
        if resource_context.get("contains_sensitive_data", False):
            business_multiplier *= 1.4
        
        final_score = min(100, base_score * finding_count_factor * criticality_multiplier * business_multiplier)
        
        return int(final_score)
    
    def get_findings_by_severity(self, findings: List[SecurityFinding]) -> Dict[SeverityLevel, int]:
        """Count findings by severity level."""
        severity_counts = Counter(finding.severity for finding in findings)
        
        # Ensure all severities are represented
        result = {severity: 0 for severity in SeverityLevel}
        result.update(severity_counts)
        
        return result
    
    def calculate_subscription_risk_trend(self, scan_results: List[ScanResult]) -> Dict[str, float]:
        """Calculate risk trend over multiple scans."""
        if len(scan_results) < 2:
            return {"trend": 0.0, "direction": "stable"}
        
        # Get the two most recent scans
        recent_scans = sorted(scan_results, key=lambda x: x.scan_timestamp, reverse=True)[:2]
        current_score = recent_scans[0].risk_score
        previous_score = recent_scans[1].risk_score
        
        if previous_score == 0:
            trend = 0.0
            direction = "stable"
        else:
            change_percent = ((current_score - previous_score) / previous_score) * 100
            trend = round(change_percent, 2)
            
            if trend > 5:
                direction = "improving" if current_score < previous_score else "degrading"
            elif trend < -5:
                direction = "degrading" if current_score > previous_score else "improving"
            else:
                direction = "stable"
        
        return {
            "trend": trend,
            "direction": direction,
            "current_score": current_score,
            "previous_score": previous_score
        }
    
    def get_risk_level(self, risk_score: int) -> str:
        """Get risk level description based on score."""
        if risk_score >= 80:
            return "Critical"
        elif risk_score >= 60:
            return "High"
        elif risk_score >= 40:
            return "Medium"
        elif risk_score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    def prioritize_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Prioritize findings based on risk score and severity."""
        # Sort by severity (critical first) then by risk score (highest first)
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFO: 4
        }
        
        return sorted(
            findings,
            key=lambda f: (severity_order[f.severity], -f.risk_score)
        )
    
    def generate_risk_summary(self, findings: List[SecurityFinding]) -> Dict:
        """Generate a comprehensive risk summary."""
        if not findings:
            return {
                "overall_risk_score": 0,
                "risk_level": "Minimal",
                "total_findings": 0,
                "findings_by_severity": {severity: 0 for severity in SeverityLevel},
                "top_risks": [],
                "recommendations": []
            }
        
        overall_score = self.calculate_overall_risk_score(findings)
        severity_counts = self.get_findings_by_severity(findings)
        prioritized_findings = self.prioritize_findings(findings)
        
        # Get top 5 risks
        top_risks = prioritized_findings[:5]
        
        # Generate recommendations based on findings
        recommendations = self._generate_recommendations(findings)
        
        return {
            "overall_risk_score": overall_score,
            "risk_level": self.get_risk_level(overall_score),
            "total_findings": len(findings),
            "findings_by_severity": severity_counts,
            "top_risks": [
                {
                    "title": finding.title,
                    "severity": finding.severity,
                    "risk_score": finding.risk_score,
                    "resource_name": finding.resource_name,
                    "resource_type": finding.resource_type
                }
                for finding in top_risks
            ],
            "recommendations": recommendations
        }
    
    def _generate_recommendations(self, findings: List[SecurityFinding]) -> List[str]:
        """Generate high-level recommendations based on findings."""
        recommendations = []
        severity_counts = self.get_findings_by_severity(findings)
        
        if severity_counts[SeverityLevel.CRITICAL] > 0:
            recommendations.append(
                f"Address {severity_counts[SeverityLevel.CRITICAL]} critical findings immediately as they pose significant security risks."
            )
        
        if severity_counts[SeverityLevel.HIGH] > 5:
            recommendations.append(
                f"Prioritize fixing the {severity_counts[SeverityLevel.HIGH]} high-severity issues to reduce overall risk exposure."
            )
        
        # Resource-specific recommendations
        resource_types = Counter(finding.resource_type for finding in findings)
        
        if resource_types.get("Microsoft.Storage/storageAccounts", 0) > 3:
            recommendations.append(
                "Review storage account configurations as multiple security issues were detected."
            )
        
        if resource_types.get("Microsoft.Network/networkSecurityGroups", 0) > 2:
            recommendations.append(
                "Audit network security group rules to ensure proper network segmentation."
            )
        
        if resource_types.get("Microsoft.KeyVault/vaults", 0) > 1:
            recommendations.append(
                "Strengthen Key Vault security configurations including firewall rules and access policies."
            )
        
        # General recommendations
        if len(findings) > 20:
            recommendations.append(
                "Consider implementing automated security monitoring and regular security assessments."
            )
        
        if not recommendations:
            recommendations.append("Continue monitoring security posture and implement security best practices.")
        
        return recommendations
    
    def _calculate_context_multiplier(self, findings: List[SecurityFinding], context: Dict) -> float:
        """Calculate contextual risk multiplier based on environment factors."""
        multiplier = 1.0
        
        # Industry factor
        industry = context.get("industry", "technology").lower()
        multiplier *= self.industry_factors.get(industry, 1.0)
        
        # Data sensitivity factor
        data_types = context.get("data_types", [])
        if data_types:
            max_sensitivity = max(self.data_sensitivity_factors.get(dt.lower(), 1.0) for dt in data_types)
            multiplier *= max_sensitivity
        
        # Environment factor
        if context.get("environment") == "production":
            multiplier *= 1.2
        elif context.get("environment") == "development":
            multiplier *= 0.8
        
        # Compliance requirements
        if context.get("compliance_frameworks"):
            compliance_count = len(context["compliance_frameworks"])
            multiplier *= (1.0 + (compliance_count * 0.1))
        
        return multiplier
    
    def _calculate_temporal_factor(self, findings: List[SecurityFinding]) -> float:
        """Calculate temporal decay factor based on finding age."""
        if not findings:
            return 1.0
        
        now = datetime.utcnow()
        ages = []
        
        for finding in findings:
            age_days = (now - finding.timestamp).days
            ages.append(age_days)
        
        avg_age = statistics.mean(ages)
        
        # Apply decay: findings older than 30 days have reduced impact
        if avg_age > 30:
            decay_factor = max(0.7, 1.0 - ((avg_age - 30) / 180))  # Minimum 0.7 factor
        else:
            decay_factor = 1.0
        
        return decay_factor
    
    def calculate_attack_surface_score(self, findings: List[SecurityFinding]) -> Dict[str, int]:
        """Calculate attack surface metrics."""
        attack_surface = {
            "internet_facing": 0,
            "internal_network": 0,
            "data_exposure": 0,
            "credential_exposure": 0,
            "total": 0
        }
        
        for finding in findings:
            score = finding.risk_score
            
            # Categorize by attack vector
            if "public" in finding.title.lower() or "internet" in finding.title.lower():
                attack_surface["internet_facing"] += score
            elif "network" in finding.title.lower() or "firewall" in finding.title.lower():
                attack_surface["internal_network"] += score
            elif "storage" in finding.title.lower() or "data" in finding.title.lower():
                attack_surface["data_exposure"] += score
            elif "key" in finding.title.lower() or "credential" in finding.title.lower():
                attack_surface["credential_exposure"] += score
            
            attack_surface["total"] += score
        
        return attack_surface
    
    def calculate_risk_velocity(self, scan_results: List[ScanResult]) -> Dict[str, float]:
        """Calculate risk velocity metrics."""
        if len(scan_results) < 2:
            return {"velocity": 0.0, "acceleration": 0.0, "trend": "stable"}
        
        # Sort by timestamp
        sorted_scans = sorted(scan_results, key=lambda x: x.scan_timestamp)
        
        # Calculate velocity (change in risk score per day)
        recent_scans = sorted_scans[-3:]  # Last 3 scans
        velocities = []
        
        for i in range(1, len(recent_scans)):
            time_diff = (recent_scans[i].scan_timestamp - recent_scans[i-1].scan_timestamp).days
            score_diff = recent_scans[i].risk_score - recent_scans[i-1].risk_score
            
            if time_diff > 0:
                velocity = score_diff / time_diff
                velocities.append(velocity)
        
        avg_velocity = statistics.mean(velocities) if velocities else 0.0
        
        # Calculate acceleration (change in velocity)
        acceleration = 0.0
        if len(velocities) >= 2:
            acceleration = velocities[-1] - velocities[-2]
        
        # Determine trend
        if abs(avg_velocity) < 0.5:
            trend = "stable"
        elif avg_velocity > 1.0:
            trend = "rapidly_increasing"
        elif avg_velocity > 0.5:
            trend = "increasing"
        elif avg_velocity < -1.0:
            trend = "rapidly_decreasing"
        else:
            trend = "decreasing"
        
        return {
            "velocity": round(avg_velocity, 2),
            "acceleration": round(acceleration, 2),
            "trend": trend
        }
    
    def generate_risk_heatmap(self, findings: List[SecurityFinding]) -> Dict[str, Dict[str, int]]:
        """Generate risk heatmap by resource type and severity."""
        heatmap = {}
        
        for resource_type in ResourceType:
            heatmap[resource_type.value] = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total_risk": 0
            }
        
        for finding in findings:
            resource_type = finding.resource_type.value
            severity = finding.severity.value
            
            if resource_type in heatmap:
                heatmap[resource_type][severity] += 1
                heatmap[resource_type]["total_risk"] += finding.risk_score
        
        return heatmap


# Global risk scoring engine instance
risk_engine = RiskScoringEngine()
