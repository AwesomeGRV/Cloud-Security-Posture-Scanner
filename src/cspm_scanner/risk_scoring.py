"""Risk scoring system for security findings."""

from typing import List, Dict
from collections import Counter

from .models import SecurityFinding, ScanResult, SeverityLevel


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
    
    def calculate_overall_risk_score(self, findings: List[SecurityFinding]) -> int:
        """Calculate overall risk score for a set of findings."""
        if not findings:
            return 0
        
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
        
        final_score = min(100, base_score * density_factor)
        
        return int(final_score)
    
    def calculate_resource_risk_score(self, resource_findings: List[SecurityFinding]) -> int:
        """Calculate risk score for a specific resource."""
        if not resource_findings:
            return 0
        
        # Use the highest severity finding as the base
        highest_severity = max(finding.severity for finding in resource_findings)
        base_score = self.severity_weights[highest_severity]
        
        # Factor in number of findings
        finding_count_factor = min(1.5, 1.0 + (len(resource_findings) / 10))
        
        final_score = min(100, base_score * finding_count_factor)
        
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


# Global risk scoring engine instance
risk_engine = RiskScoringEngine()
