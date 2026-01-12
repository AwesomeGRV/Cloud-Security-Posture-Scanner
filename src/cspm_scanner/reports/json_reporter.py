"""JSON report generation for CSPM Scanner."""

import json
import os
from datetime import datetime
from typing import List, Dict, Any

from ..models import ScanResult, SecurityFinding
from ..risk_scoring import risk_engine


class JSONReporter:
    """Generates JSON security reports."""
    
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_report(self, scan_result: ScanResult) -> str:
        """Generate a comprehensive JSON security report."""
        report_data = self._build_report_data(scan_result)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cspm_report_{scan_result.subscription_id}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        # Write JSON report
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
        
        return filepath
    
    def generate_summary_report(self, scan_results: List[ScanResult]) -> str:
        """Generate a summary report for multiple scans."""
        summary_data = self._build_summary_data(scan_results)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"cspm_summary_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, indent=2, default=str, ensure_ascii=False)
        
        return filepath
    
    def export_findings(self, findings: List[SecurityFinding], format_type: str = "detailed") -> str:
        """Export findings in various JSON formats."""
        if format_type == "detailed":
            data = [finding.dict() for finding in findings]
        elif format_type == "summary":
            data = [
                {
                    "id": finding.id,
                    "resource_name": finding.resource_name,
                    "resource_type": finding.resource_type,
                    "severity": finding.severity,
                    "title": finding.title,
                    "risk_score": finding.risk_score,
                    "recommendation": finding.recommendation
                }
                for finding in findings
            ]
        elif format_type == "compliance":
            data = self._format_for_compliance(findings)
        else:
            raise ValueError(f"Unsupported format type: {format_type}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"findings_{format_type}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        
        return filepath
    
    def _build_report_data(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Build comprehensive report data structure."""
        risk_summary = risk_engine.generate_risk_summary(scan_result.findings)
        
        return {
            "report_metadata": {
                "report_type": "Security Posture Assessment",
                "generated_at": datetime.utcnow().isoformat(),
                "scanner_version": "1.0.0",
                "subscription_id": scan_result.subscription_id,
                "subscription_name": scan_result.subscription_name,
                "scan_duration_seconds": scan_result.scan_duration_seconds
            },
            "executive_summary": {
                "overall_risk_score": scan_result.risk_score,
                "risk_level": risk_engine.get_risk_level(scan_result.risk_score),
                "total_resources_scanned": scan_result.total_resources_scanned,
                "total_findings": scan_result.total_findings,
                "findings_by_severity": scan_result.findings_by_severity,
                "critical_findings_count": scan_result.findings_by_severity.get("critical", 0),
                "high_findings_count": scan_result.findings_by_severity.get("high", 0)
            },
            "risk_analysis": risk_summary,
            "findings": [
                {
                    "id": finding.id,
                    "resource": {
                        "id": finding.resource_id,
                        "name": finding.resource_name,
                        "type": finding.resource_type,
                        "group": finding.resource_group,
                        "location": finding.location
                    },
                    "security_issue": {
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity,
                        "risk_score": finding.risk_score,
                        "recommendation": finding.recommendation
                    },
                    "metadata": finding.metadata,
                    "detected_at": finding.timestamp.isoformat()
                }
                for finding in scan_result.findings
            ],
            "resource_analysis": self._analyze_resources(scan_result.findings),
            "recommendations": self._generate_prioritized_recommendations(scan_result.findings),
            "compliance_mapping": self._map_to_compliance_standards(scan_result.findings)
        }
    
    def _build_summary_data(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Build summary data for multiple scans."""
        if not scan_results:
            return {"error": "No scan results provided"}
        
        total_findings = sum(len(scan.findings) for scan in scan_results)
        avg_risk_score = sum(scan.risk_score for scan in scan_results) / len(scan_results)
        
        # Aggregate findings by severity across all scans
        all_severity_counts = {}
        for scan in scan_results:
            for severity, count in scan.findings_by_severity.items():
                all_severity_counts[severity] = all_severity_counts.get(severity, 0) + count
        
        # Calculate trend
        trend_data = risk_engine.calculate_subscription_risk_trend(scan_results)
        
        return {
            "summary_metadata": {
                "report_type": "Multi-Subscription Security Summary",
                "generated_at": datetime.utcnow().isoformat(),
                "scanner_version": "1.0.0",
                "subscriptions_analyzed": len(scan_results)
            },
            "overall_summary": {
                "total_subscriptions": len(scan_results),
                "total_resources_scanned": sum(scan.total_resources_scanned for scan in scan_results),
                "total_findings": total_findings,
                "average_risk_score": round(avg_risk_score, 2),
                "findings_by_severity": all_severity_counts
            },
            "subscription_details": [
                {
                    "subscription_id": scan.subscription_id,
                    "subscription_name": scan.subscription_name,
                    "risk_score": scan.risk_score,
                    "risk_level": risk_engine.get_risk_level(scan.risk_score),
                    "findings_count": len(scan.findings),
                    "scan_timestamp": scan.scan_timestamp.isoformat()
                }
                for scan in scan_results
            ],
            "risk_trend": trend_data,
            "top_vulnerabilities": self._get_top_vulnerabilities(scan_results),
            "resource_type_analysis": self._analyze_resource_types(scan_results)
        }
    
    def _analyze_resources(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Analyze findings by resource type and location."""
        from collections import Counter, defaultdict
        
        resource_types = Counter(finding.resource_type for finding in findings)
        locations = Counter(finding.location for finding in findings)
        resource_groups = Counter(finding.resource_group for finding in findings)
        
        # Find most affected resources
        resource_findings = defaultdict(list)
        for finding in findings:
            resource_findings[finding.resource_id].append(finding)
        
        most_affected_resources = sorted(
            [(resource_id, len(findings)) for resource_id, findings in resource_findings.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        return {
            "resource_types": dict(resource_types),
            "locations": dict(locations),
            "resource_groups": dict(resource_groups),
            "most_affected_resources": [
                {
                    "resource_id": resource_id,
                    "finding_count": count,
                    "resource_name": resource_findings[resource_id][0].resource_name,
                    "resource_type": resource_findings[resource_id][0].resource_type
                }
                for resource_id, count in most_affected_resources
            ]
        }
    
    def _generate_prioritized_recommendations(self, findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """Generate prioritized remediation recommendations."""
        prioritized_findings = risk_engine.prioritize_findings(findings)
        
        recommendations = []
        for finding in prioritized_findings[:20]:  # Top 20 recommendations
            recommendations.append({
                "priority": "P1" if finding.severity in ["critical", "high"] else "P2",
                "finding_id": finding.id,
                "resource": finding.resource_name,
                "issue": finding.title,
                "recommendation": finding.recommendation,
                "risk_score": finding.risk_score,
                "estimated_effort": self._estimate_remediation_effort(finding)
            })
        
        return recommendations
    
    def _map_to_compliance_standards(self, findings: List[SecurityFinding]) -> Dict[str, List[str]]:
        """Map findings to compliance standards."""
        compliance_mapping = {
            "CIS Controls": [],
            "NIST Cybersecurity Framework": [],
            "ISO 27001": [],
            "SOC 2": []
        }
        
        for finding in findings:
            if "public" in finding.title.lower() and "access" in finding.title.lower():
                compliance_mapping["CIS Controls"].append(f"CIS Control 12 - Network Infrastructure Management")
                compliance_mapping["NIST Cybersecurity Framework"].append("PR.AC - Access Control")
                compliance_mapping["ISO 27001"].append("A.9 - Access Control")
                compliance_mapping["SOC 2"].append("CC6.1 - Logical Access Controls")
            
            if "encryption" in finding.title.lower():
                compliance_mapping["CIS Controls"].append("CIS Control 14 - Controlled Access Based on the Need to Know")
                compliance_mapping["NIST Cybersecurity Framework"].append("PR.DS - Data Security")
                compliance_mapping["ISO 27001"].append("A.8 - Asset Management")
                compliance_mapping["SOC 2"].append("CC6.1 - Logical Access Controls")
            
            if "network" in finding.title.lower() or "firewall" in finding.title.lower():
                compliance_mapping["CIS Controls"].append("CIS Control 12 - Network Infrastructure Management")
                compliance_mapping["NIST Cybersecurity Framework"].append("PR.AC - Access Control")
                compliance_mapping["ISO 27001"].append("A.13 - Communications Security")
                compliance_mapping["SOC 2"].append("CC6.1 - Logical Access Controls")
        
        # Remove duplicates
        for standard in compliance_mapping:
            compliance_mapping[standard] = list(set(compliance_mapping[standard]))
        
        return compliance_mapping
    
    def _format_for_compliance(self, findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """Format findings for compliance reporting."""
        return [
            {
                "control_id": f"AZ-{finding.severity.upper()}-{finding.id[:8]}",
                "control_title": finding.title,
                "requirement": finding.description,
                "compliance_status": "Non-compliant",
                "severity": finding.severity,
                "affected_resource": f"{finding.resource_name} ({finding.resource_type})",
                "remediation_steps": finding.recommendation,
                "evidence": finding.metadata
            }
            for finding in findings
        ]
    
    def _estimate_remediation_effort(self, finding: SecurityFinding) -> str:
        """Estimate remediation effort based on finding type."""
        low_effort_keywords = ["enable", "disable", "configure", "set"]
        medium_effort_keywords = ["implement", "deploy", "create"]
        high_effort_keywords = ["redesign", "migrate", "restructure"]
        
        title_lower = finding.title.lower()
        
        if any(keyword in title_lower for keyword in low_effort_keywords):
            return "Low (1-2 hours)"
        elif any(keyword in title_lower for keyword in medium_effort_keywords):
            return "Medium (4-8 hours)"
        elif any(keyword in title_lower for keyword in high_effort_keywords):
            return "High (1-3 days)"
        else:
            return "Medium (4-8 hours)"
    
    def _get_top_vulnerabilities(self, scan_results: List[ScanResult]) -> List[Dict[str, Any]]:
        """Get most common vulnerabilities across all scans."""
        from collections import Counter
        
        all_findings = []
        for scan in scan_results:
            all_findings.extend(scan.findings)
        
        vulnerability_counts = Counter(finding.title for finding in all_findings)
        
        return [
            {
                "vulnerability": title,
                "occurrences": count,
                "severity": next(
                    (f.severity for f in all_findings if f.title == title),
                    "unknown"
                )
            }
            for title, count in vulnerability_counts.most_common(10)
        ]
    
    def _analyze_resource_types(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Analyze findings by resource type across all scans."""
        from collections import defaultdict, Counter
        
        resource_type_findings = defaultdict(list)
        for scan in scan_results:
            for finding in scan.findings:
                resource_type_findings[finding.resource_type].append(finding)
        
        analysis = {}
        for resource_type, findings in resource_type_findings.items():
            severity_counts = Counter(finding.severity for finding in findings)
            avg_risk_score = sum(finding.risk_score for finding in findings) / len(findings)
            
            analysis[resource_type] = {
                "total_findings": len(findings),
                "severity_breakdown": dict(severity_counts),
                "average_risk_score": round(avg_risk_score, 2),
                "most_common_issue": Counter(finding.title for finding in findings).most_common(1)[0]
            }
        
        return analysis
