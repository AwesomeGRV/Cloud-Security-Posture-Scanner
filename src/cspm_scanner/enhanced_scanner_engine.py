"""Enhanced scanner engine with integrated risk assessment capabilities."""

from typing import List, Dict, Optional, Any
from datetime import datetime
import asyncio
import uuid

from .models import SecurityFinding, ScanResult, SeverityLevel, ResourceType
from .scanner_engine import ScannerEngine
from .risk_scoring import RiskScoringEngine
from .compliance import ComplianceMapper
from .threat_modeling import ThreatModelingEngine
from .business_impact import BusinessImpactAssessment, ResourceBusinessContext
from .mitre_attack import MITREAttackMapper
from .risk_aggregation import RiskAggregationEngine
from .risk_tolerance import RiskToleranceEngine
from .remediation_assessment import RemediationAssessmentEngine
from .reporting import ReportingEngine, ReportType, TimeRange


class EnhancedScannerEngine(ScannerEngine):
    """Enhanced scanner engine with comprehensive risk assessment."""
    
    def __init__(self):
        super().__init__()
        
        # Initialize all assessment engines
        self.risk_engine = RiskScoringEngine()
        self.compliance_mapper = ComplianceMapper()
        self.threat_engine = ThreatModelingEngine()
        self.business_impact_engine = BusinessImpactAssessment()
        self.mitre_attack_mapper = MITREAttackMapper()
        self.risk_aggregation_engine = RiskAggregationEngine()
        self.risk_tolerance_engine = RiskToleranceEngine()
        self.remediation_engine = RemediationAssessmentEngine()
        self.reporting_engine = ReportingEngine()
    
    async def enhanced_scan(self, 
                           subscription_id: str,
                           resource_types: Optional[List[ResourceType]] = None,
                           scan_context: Optional[Dict[str, Any]] = None) -> ScanResult:
        """Perform enhanced security scan with comprehensive risk assessment."""
        scan_context = scan_context or {}
        
        # Start timing
        start_time = datetime.utcnow()
        
        # Perform base scan
        base_scan_result = await super().scan_subscription(
            subscription_id, resource_types
        )
        
        # Enhance findings with additional assessments
        enhanced_findings = await self._enhance_findings(
            base_scan_result.findings, scan_context
        )
        
        # Calculate enhanced risk scores
        enhanced_risk_score = self.risk_engine.calculate_overall_risk_score(
            enhanced_findings, scan_context
        )
        
        # Create enhanced scan result
        enhanced_result = ScanResult(
            subscription_id=subscription_id,
            subscription_name=base_scan_result.subscription_name,
            scan_timestamp=start_time,
            total_resources_scanned=base_scan_result.total_resources_scanned,
            total_findings=len(enhanced_findings),
            findings_by_severity=self.risk_engine.get_findings_by_severity(enhanced_findings),
            findings=enhanced_findings,
            risk_score=enhanced_risk_score,
            scan_duration_seconds=(datetime.utcnow() - start_time).total_seconds()
        )
        
        return enhanced_result
    
    async def _enhance_findings(self, 
                               findings: List[SecurityFinding],
                               context: Dict[str, Any]) -> List[SecurityFinding]:
        """Enhance findings with additional risk assessments."""
        enhanced_findings = []
        
        for finding in findings:
            # Create enhanced finding with additional metadata
            enhanced_finding = SecurityFinding(
                id=finding.id,
                resource_id=finding.resource_id,
                resource_name=finding.resource_name,
                resource_type=finding.resource_type,
                subscription_id=finding.subscription_id,
                resource_group=finding.resource_group,
                location=finding.location,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                recommendation=finding.recommendation,
                risk_score=finding.risk_score,
                metadata=self._create_enhanced_metadata(finding, context),
                timestamp=finding.timestamp
            )
            
            enhanced_findings.append(enhanced_finding)
        
        return enhanced_findings
    
    def _create_enhanced_metadata(self, finding: SecurityFinding, context: Dict[str, Any]) -> Dict[str, Any]:
        """Create enhanced metadata for a finding."""
        enhanced_metadata = finding.metadata.copy()
        
        # Add compliance mappings
        compliance_mappings = self.compliance_mapper.map_finding_to_compliance(finding)
        enhanced_metadata["compliance_mappings"] = compliance_mappings
        
        # Add MITRE ATT&CK mappings
        mitre_matches = self.mitre_attack_mapper.map_finding_to_mitre_attack(finding)
        enhanced_metadata["mitre_attack_mappings"] = [
            {
                "technique_id": match.technique_id.value,
                "technique_name": match.technique_name,
                "tactic": match.tactic.value,
                "tactic_name": match.tactic_name,
                "confidence": match.confidence_score
            }
            for match in mitre_matches
        ]
        
        # Add business context
        enhanced_metadata["business_context"] = context.get("business_context", {})
        
        # Add risk tolerance assessment
        tolerance_assessment = self.risk_tolerance_engine.assess_risk_tolerance(finding, context)
        enhanced_metadata["risk_tolerance"] = {
            "is_acceptable": tolerance_assessment.is_acceptable,
            "tolerance_level": tolerance_assessment.tolerance_level.value,
            "requires_approval": tolerance_assessment.requires_approval,
            "auto_acceptable": tolerance_assessment.auto_acceptable
        }
        
        # Add remediation assessment
        remediation_assessment = self.remediation_engine.assess_remediation_options(finding, context)
        enhanced_metadata["remediation"] = {
            "auto_remediatable": remediation_assessment.auto_remediatable,
            "complexity_score": remediation_assessment.complexity_score,
            "risk_score": remediation_assessment.risk_score,
            "automation_potential": remediation_assessment.automation_potential
        }
        
        return enhanced_metadata
    
    async def generate_comprehensive_report(self,
                                          findings: List[SecurityFinding],
                                          report_type: ReportType = ReportType.DETAILED_ANALYSIS,
                                          time_range: TimeRange = TimeRange.LAST_30_DAYS,
                                          context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        context = context or {}
        
        # Generate report using reporting engine
        report = self.reporting_engine.generate_report(
            findings, report_type, time_range, context.get("subscription_id"), context
        )
        
        # Export to JSON for easy consumption
        report_data = self.reporting_engine.export_report(report, ReportType.JSON)
        
        return {
            "report_data": report_data,
            "report_id": report.report_id,
            "generated_at": report.generated_at.isoformat(),
            "report_type": report.report_type.value,
            "summary": report.summary
        }
    
    async def generate_executive_dashboard(self,
                                         findings: List[SecurityFinding],
                                         context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate executive dashboard data."""
        context = context or {}
        
        # Generate dashboard data
        dashboard_data = self.reporting_engine._generate_dashboard_data(
            findings, "executive_dashboard", context
        )
        
        # Add executive summary
        executive_summary = {
            "overall_risk_score": self.risk_engine.calculate_overall_risk_score(findings, context),
            "critical_findings": len([f for f in findings if f.severity == SeverityLevel.CRITICAL]),
            "compliance_score": self._calculate_overall_compliance_score(findings),
            "remediation_priority": self._calculate_remediation_priority(findings),
            "key_insights": self._extract_executive_insights(findings, context)
        }
        
        dashboard_data["executive_summary"] = executive_summary
        
        return dashboard_data
    
    async def generate_security_operations_dashboard(self,
                                                  findings: List[SecurityFinding],
                                                  context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate security operations dashboard data."""
        context = context or {}
        
        # Generate dashboard data
        dashboard_data = self.reporting_engine._generate_dashboard_data(
            findings, "security_dashboard", context
        )
        
        # Add security operations specific data
        operations_data = {
            "threat_analysis": self.threat_engine.generate_threat_model_report(findings),
            "mitre_attack_analysis": self.mitre_attack_mapper.generate_mitre_attack_report(findings),
            "risk_correlations": self.risk_aggregation_engine.generate_risk_aggregation_report(findings),
            "remediation_assessment": self.remediation_engine.generate_remediation_report(findings, context),
            "active_threats": self._identify_active_threats(findings),
            "attack_surface": self._analyze_attack_surface(findings)
        }
        
        dashboard_data["operations_data"] = operations_data
        
        return dashboard_data
    
    async def generate_compliance_dashboard(self,
                                           findings: List[SecurityFinding],
                                           context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate compliance dashboard data."""
        context = context or {}
        
        # Generate dashboard data
        dashboard_data = self.reporting_engine._generate_dashboard_data(
            findings, "compliance_dashboard", context
        )
        
        # Add compliance specific data
        compliance_data = {
            "compliance_report": self.compliance_mapper.generate_compliance_report(findings),
            "framework_assessments": self._get_framework_assessments(findings, context),
            "violation_tracking": self._track_violations(findings),
            "audit_readiness": self._assess_audit_readiness(findings, context),
            "remediation_timeline": self._generate_compliance_remediation_timeline(findings)
        }
        
        dashboard_data["compliance_data"] = compliance_data
        
        return dashboard_data
    
    def _calculate_overall_compliance_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate overall compliance score."""
        compliance_report = self.compliance_mapper.generate_compliance_report(findings)
        return compliance_report["summary"]["average_compliance_score"]
    
    def _calculate_remediation_priority(self, findings: List[SecurityFinding]) -> str:
        """Calculate overall remediation priority."""
        critical_count = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        high_count = len([f for f in findings if f.severity == SeverityLevel.HIGH])
        
        if critical_count > 0:
            return "immediate"
        elif high_count > 5:
            return "urgent"
        elif high_count > 0:
            return "high"
        else:
            return "medium"
    
    def _extract_executive_insights(self, findings: List[SecurityFinding], context: Dict[str, Any]) -> List[str]:
        """Extract executive-level insights."""
        insights = []
        
        # Risk insights
        overall_risk = self.risk_engine.calculate_overall_risk_score(findings, context)
        if overall_risk >= 80:
            insights.append("Critical risk level requires immediate executive attention")
        elif overall_risk >= 60:
            insights.append("High risk level needs strategic focus")
        
        # Compliance insights
        compliance_score = self._calculate_overall_compliance_score(findings)
        if compliance_score < 80:
            insights.append(f"Compliance score ({compliance_score:.1f}%) below acceptable threshold")
        
        # Business impact insights
        critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        if critical_findings:
            insights.append(f"{len(critical_findings)} critical findings may impact business operations")
        
        # Automation insights
        auto_remediatable = 0
        for finding in findings:
            assessment = self.remediation_engine.assess_remediation_options(finding, context)
            if assessment.auto_remediatable:
                auto_remediatable += 1
        
        if auto_remediatable > len(findings) * 0.5:
            insights.append("High automation potential can reduce operational costs")
        
        return insights
    
    def _identify_active_threats(self, findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """Identify active threats from findings."""
        threat_report = self.threat_engine.generate_threat_model_report(findings)
        
        active_threats = []
        for threat_id, assessment in threat_report["threat_assessment"].items():
            if assessment["risk_score"] > 50:  # High-risk threats
                active_threats.append({
                    "threat_id": threat_id,
                    "threat_name": assessment["threat"]["name"],
                    "risk_score": assessment["risk_score"],
                    "likelihood": assessment["likelihood"],
                    "impact": assessment["impact"],
                    "relevant_findings": len(assessment["relevant_findings"])
                })
        
        return sorted(active_threats, key=lambda x: x["risk_score"], reverse=True)[:5]
    
    def _analyze_attack_surface(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Analyze attack surface from findings."""
        attack_surfaces = self.threat_engine.analyze_attack_surface(findings)
        
        # Calculate attack surface metrics
        total_surface_score = sum(as_.risk_score for as_ in attack_surfaces)
        internet_facing_count = len([as_ for as_ in attack_surfaces if as_.exposure_level == "internet_facing"])
        
        return {
            "total_surface_score": total_surface_score,
            "total_components": len(attack_surfaces),
            "internet_facing_components": internet_facing_count,
            "high_risk_components": len([as_ for as_ in attack_surfaces if as_.risk_score > 70]),
            "top_components": [
                {
                    "name": as_.name,
                    "resource_type": as_.resource_type.value,
                    "risk_score": as_.risk_score,
                    "exposure_level": as_.exposure_level
                }
                for as_ in sorted(attack_surfaces, key=lambda x: x.risk_score, reverse=True)[:5]
            ]
        }
    
    def _get_framework_assessments(self, findings: List[SecurityFinding], context: Dict[str, Any]) -> Dict[str, Any]:
        """Get framework-specific assessments."""
        compliance_report = self.compliance_mapper.generate_compliance_report(findings)
        
        framework_assessments = {}
        for framework, assessment in compliance_report["framework_assessments"].items():
            framework_assessments[framework] = {
                "compliance_score": assessment["compliance_score"],
                "total_controls": assessment["total_controls"],
                "compliant_controls": assessment["compliant_controls"],
                "violations": len(assessment["violations"]),
                "high_risk_violations": len([v for v in assessment["violations"] if v.get("requirement_level") == "mandatory"])
            }
        
        return framework_assessments
    
    def _track_violations(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Track compliance violations."""
        compliance_report = self.compliance_mapper.generate_compliance_report(findings)
        
        violation_tracking = {
            "total_violations": compliance_report["summary"]["total_violations"],
            "violations_by_framework": {},
            "violations_by_category": {},
            "high_priority_violations": 0
        }
        
        for framework, assessment in compliance_report["framework_assessments"].items():
            violation_tracking["violations_by_framework"][framework] = len(assessment["violations"])
            
            # Count violations by category
            for violation in assessment["violations"]:
                category = violation.get("category", "unknown")
                if category not in violation_tracking["violations_by_category"]:
                    violation_tracking["violations_by_category"][category] = 0
                violation_tracking["violations_by_category"][category] += 1
                
                # Count high priority violations
                if violation.get("requirement_level") == "mandatory":
                    violation_tracking["high_priority_violations"] += 1
        
        return violation_tracking
    
    def _assess_audit_readiness(self, findings: List[SecurityFinding], context: Dict[str, Any]) -> Dict[str, Any]:
        """Assess audit readiness."""
        compliance_score = self._calculate_overall_compliance_score(findings)
        
        # Check for critical findings that would fail audit
        critical_findings = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        
        # Check documentation completeness
        documented_findings = len([f for f in findings if f.metadata.get("documented", False)])
        
        audit_readiness = {
            "overall_readiness": "ready" if compliance_score >= 90 and not critical_findings else "needs_improvement",
            "compliance_score": compliance_score,
            "critical_blocking_issues": len(critical_findings),
            "documentation_coverage": (documented_findings / len(findings)) * 100 if findings else 0,
            "recommendations": []
        }
        
        if audit_readiness["critical_blocking_issues"] > 0:
            audit_readiness["recommendations"].append("Address all critical findings before audit")
        
        if audit_readiness["documentation_coverage"] < 80:
            audit_readiness["recommendations"].append("Improve documentation of security controls")
        
        if compliance_score < 90:
            audit_readiness["recommendations"].append("Improve compliance posture to meet audit requirements")
        
        return audit_readiness
    
    def _generate_compliance_remediation_timeline(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Generate compliance remediation timeline."""
        # Group findings by priority and estimate remediation time
        remediation_timeline = {
            "immediate": [],  # 0-7 days
            "short_term": [],  # 8-30 days
            "medium_term": [],  # 31-90 days
            "long_term": []   # 90+ days
        }
        
        for finding in findings:
            assessment = self.remediation_engine.assess_remediation_options(finding)
            
            if assessment.complexity_score <= 2 and assessment.risk_score <= 2:
                remediation_timeline["immediate"].append(finding.id)
            elif assessment.complexity_score <= 3 and assessment.risk_score <= 3:
                remediation_timeline["short_term"].append(finding.id)
            elif assessment.complexity_score <= 4:
                remediation_timeline["medium_term"].append(finding.id)
            else:
                remediation_timeline["long_term"].append(finding.id)
        
        return {
            "timeline": remediation_timeline,
            "total_findings": len(findings),
            "estimated_completion_days": 90,  # Simplified estimate
            "resource_requirements": self._estimate_remediation_resources(findings)
        }
    
    def _estimate_remediation_resources(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Estimate resources needed for remediation."""
        total_complexity = 0
        automated_count = 0
        
        for finding in findings:
            assessment = self.remediation_engine.assess_remediation_options(finding)
            total_complexity += assessment.complexity_score
            if assessment.auto_remediatable:
                automated_count += 1
        
        # Simplified resource estimation
        manual_effort = max(0, len(findings) - automated_count)
        estimated_hours = total_complexity * 2  # 2 hours per complexity point
        
        return {
            "total_findings": len(findings),
            "automated_findings": automated_count,
            "manual_findings": manual_effort,
            "estimated_hours": estimated_hours,
            "recommended_team_size": max(1, estimated_hours // 40),  # 1 person per 40 hours
            "estimated_cost": estimated_hours * 100  # $100 per hour
        }
    
    async def generate_risk_assessment_report(self,
                                             findings: List[SecurityFinding],
                                             context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate comprehensive risk assessment report."""
        context = context or {}
        
        # Generate comprehensive risk analysis
        risk_analysis = {
            "overall_assessment": self.risk_engine.generate_risk_summary(findings),
            "attack_surface_analysis": self.threat_engine.analyze_attack_surface(findings),
            "threat_modeling": self.threat_engine.generate_threat_model_report(findings),
            "risk_correlations": self.risk_aggregation_engine.generate_risk_aggregation_report(findings),
            "mitre_attack_analysis": self.mitre_attack_mapper.generate_mitre_attack_report(findings)
        }
        
        # Add business impact if context provided
        if context.get("business_context"):
            business_context_data = context.get("business_context", {})
            business_analysis = self.business_impact_engine.generate_business_impact_report(
                findings, business_context_data
            )
            risk_analysis["business_impact"] = business_analysis
        
        # Add risk tolerance analysis
        tolerance_analysis = self.risk_tolerance_engine.generate_tolerance_report(findings, context)
        risk_analysis["risk_tolerance"] = tolerance_analysis
        
        return risk_analysis
    
    async def generate_actionable_insights(self,
                                         findings: List[SecurityFinding],
                                         context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate actionable insights for security improvement."""
        context = context or {}
        
        # Collect all recommendations
        all_recommendations = []
        
        # Risk-based recommendations
        risk_summary = self.risk_engine.generate_risk_summary(findings)
        all_recommendations.extend(risk_summary["recommendations"])
        
        # Compliance recommendations
        compliance_report = self.compliance_mapper.generate_compliance_report(findings)
        all_recommendations.extend(compliance_report["recommendations"])
        
        # Threat-based recommendations
        threat_report = self.threat_engine.generate_threat_model_report(findings)
        all_recommendations.extend(threat_report["recommendations"])
        
        # MITRE ATT&CK recommendations
        mitre_report = self.mitre_attack_mapper.generate_mitre_attack_report(findings)
        all_recommendations.extend(mitre_report["recommendations"])
        
        # Risk aggregation recommendations
        aggregation_report = self.risk_aggregation_engine.generate_risk_aggregation_report(findings)
        all_recommendations.extend(aggregation_report["recommendations"])
        
        # Remediation recommendations
        remediation_report = self.remediation_engine.generate_remediation_report(findings, context)
        all_recommendations.extend(remediation_report["recommendations"])
        
        # Prioritize and categorize recommendations
        prioritized_recommendations = self._prioritize_actionable_recommendations(
            all_recommendations, findings, context
        )
        
        return {
            "total_recommendations": len(prioritized_recommendations),
            "immediate_actions": [r for r in prioritized_recommendations if r["priority"] == "immediate"],
            "short_term_actions": [r for r in prioritized_recommendations if r["priority"] == "short_term"],
            "long_term_actions": [r for r in prioritized_recommendations if r["priority"] == "long_term"],
            "automation_opportunities": self._identify_automation_opportunities(findings, context),
            "resource_requirements": self._calculate_action_resource_requirements(findings, context)
        }
    
    def _prioritize_actionable_recommendations(self,
                                             recommendations: List[str],
                                             findings: List[SecurityFinding],
                                             context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize actionable recommendations."""
        prioritized = []
        
        for rec in recommendations:
            priority = self._determine_recommendation_priority(rec, findings, context)
            category = self._categorize_recommendation(rec)
            effort = self._estimate_recommendation_effort(rec, findings)
            
            prioritized.append({
                "recommendation": rec,
                "priority": priority,
                "category": category,
                "estimated_effort": effort,
                "impact": self._estimate_recommendation_impact(rec, findings)
            })
        
        # Sort by priority and impact
        prioritized.sort(key=lambda x: (
            self._priority_to_score(x["priority"]),
            -x["impact"]
        ))
        
        return prioritized
    
    def _determine_recommendation_priority(self, recommendation: str, 
                                         findings: List[SecurityFinding],
                                         context: Dict[str, Any]) -> str:
        """Determine priority of a recommendation."""
        urgent_keywords = ["URGENT", "CRITICAL", "IMMEDIATE", "ADDRESS IMMEDIATELY"]
        high_keywords = ["HIGH", "PRIORITY", "IMPORTANT", "PRIORITIZE"]
        medium_keywords = ["MEDIUM", "CONSIDER", "REVIEW", "PLAN"]
        
        rec_upper = recommendation.upper()
        
        if any(keyword in rec_upper for keyword in urgent_keywords):
            return "immediate"
        elif any(keyword in rec_upper for keyword in high_keywords):
            return "short_term"
        elif any(keyword in rec_upper for keyword in medium_keywords):
            return "long_term"
        else:
            return "long_term"
    
    def _categorize_recommendation(self, recommendation: str) -> str:
        """Categorize a recommendation."""
        categories = {
            "remediation": ["remediation", "fix", "address", "resolve"],
            "compliance": ["compliance", "audit", "policy", "framework"],
            "monitoring": ["monitor", "review", "assess", "track"],
            "implementation": ["implement", "deploy", "configure", "enable"],
            "planning": ["plan", "strategy", "roadmap", "develop"],
            "automation": ["automate", "automated", "workflow", "orchestrate"]
        }
        
        rec_lower = recommendation.lower()
        
        for category, keywords in categories.items():
            if any(keyword in rec_lower for keyword in keywords):
                return category
        
        return "general"
    
    def _estimate_recommendation_effort(self, recommendation: str, findings: List[SecurityFinding]) -> str:
        """Estimate effort required for a recommendation."""
        low_effort_keywords = ["enable", "configure", "simple", "quick"]
        medium_effort_keywords = ["implement", "deploy", "develop", "plan"]
        high_effort_keywords = ["comprehensive", "strategic", "architecture", "redesign"]
        
        rec_lower = recommendation.lower()
        
        if any(keyword in rec_lower for keyword in low_effort_keywords):
            return "low"
        elif any(keyword in rec_lower for keyword in high_effort_keywords):
            return "high"
        else:
            return "medium"
    
    def _estimate_recommendation_impact(self, recommendation: str, findings: List[SecurityFinding]) -> int:
        """Estimate impact of a recommendation (1-10 scale)."""
        # Simplified impact estimation
        high_impact_keywords = ["critical", "significant", "major", "substantial"]
        medium_impact_keywords = ["moderate", "improve", "enhance", "reduce"]
        
        rec_lower = recommendation.lower()
        
        if any(keyword in rec_lower for keyword in high_impact_keywords):
            return 8
        elif any(keyword in rec_lower for keyword in medium_impact_keywords):
            return 5
        else:
            return 3
    
    def _priority_to_score(self, priority: str) -> int:
        """Convert priority to numeric score for sorting."""
        priority_scores = {
            "immediate": 1,
            "short_term": 2,
            "long_term": 3
        }
        return priority_scores.get(priority, 3)
    
    def _identify_automation_opportunities(self, findings: List[SecurityFinding], 
                                          context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify automation opportunities."""
        automation_opportunities = []
        
        for finding in findings:
            assessment = self.remediation_engine.assess_remediation_options(finding, context)
            
            if assessment.auto_remediatable and assessment.automation_potential > 0.7:
                automation_opportunities.append({
                    "finding_id": finding.id,
                    "finding_title": finding.title,
                    "automation_potential": assessment.automation_potential,
                    "complexity": assessment.complexity_score,
                    "recommended_approach": assessment.recommended_approach
                })
        
        return sorted(automation_opportunities, 
                    key=lambda x: x["automation_potential"], 
                    reverse=True)
    
    def _calculate_action_resource_requirements(self, findings: List[SecurityFinding], 
                                              context: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate resource requirements for implementing recommendations."""
        total_complexity = 0
        automated_count = 0
        
        for finding in findings:
            assessment = self.remediation_engine.assess_remediation_options(finding, context)
            total_complexity += assessment.complexity_score
            if assessment.auto_remediatable:
                automated_count += 1
        
        manual_findings = len(findings) - automated_count
        
        return {
            "total_findings": len(findings),
            "automated_findings": automated_count,
            "manual_findings": manual_findings,
            "estimated_person_hours": total_complexity * 4,  # 4 hours per complexity point
            "recommended_team_size": max(1, total_complexity // 10),  # 1 person per 10 complexity points
            "estimated_duration_weeks": max(1, total_complexity // 20)  # 1 week per 20 complexity points
        }


# Global enhanced scanner engine instance
enhanced_scanner_engine = EnhancedScannerEngine()
